"""Tests for the backend-agnostic, request-scoped binding helpers.

Covers the two load-bearing lifecycle properties from the design:

- **Powertools**: two dotted ``append_keys`` binds both survive, and a warm
  invocation does not inherit the previous request's context (``request_scope``
  unbinds on exit).
- **stdlib**: concurrent requests do not bleed context into each other
  (``contextvars``-backed, async-safe).
"""

import asyncio
import logging

import pytest

from nui_shared_utils.logging import (
    F,
    bind_build_context,
    bind_request,
    bind_user,
    log_exception,
    powertools_binder,
    request_body_fields,
    response_output_fields,
    stdlib_binder,
)

pytestmark = pytest.mark.unit


class FakePowertoolsLogger:
    """Minimal stand-in for a Powertools ``Logger``.

    Models the persistent-context semantics the binder depends on: ``append_keys``
    accumulates into a shared dict (shallow, top-level), ``remove_keys`` deletes,
    and ``info`` / ``exception`` snapshot ``context + extra`` for assertions. Using
    a fake keeps the test independent of aws-lambda-powertools being installed.
    """

    def __init__(self):
        self.context = {}
        self.records = []

    def append_keys(self, **keys):
        self.context.update(keys)

    def remove_keys(self, keys):
        for key in keys:
            self.context.pop(key, None)

    def get_current_keys(self):
        return dict(self.context)

    def _emit(self, level, message, extra=None):
        merged = dict(self.context)
        if extra:
            merged.update(extra)
        self.records.append({"level": level, "message": message, "fields": merged})

    def info(self, message, extra=None):
        self._emit("INFO", message, extra)

    def error(self, message, extra=None):
        self._emit("ERROR", message, extra)

    def exception(self, message, extra=None):
        self._emit("EXCEPTION", message, extra)


def _capturing_stdlib_logger(name):
    """A stdlib logger whose emitted records are captured for inspection."""
    logger = logging.getLogger(name)
    logger.setLevel(logging.DEBUG)
    logger.handlers = []
    captured = []

    class _Cap(logging.Handler):
        def emit(self, record):
            captured.append(record)

    logger.addHandler(_Cap())
    return logger, captured


class TestPowertoolsBinder:
    def test_two_dotted_binds_both_survive(self):
        logger = FakePowertoolsLogger()
        binder = powertools_binder(logger)
        binder.bind({"request.a": 1})
        binder.bind({"request.b": 2})
        logger.info("msg")
        fields = logger.records[-1]["fields"]
        assert fields["request.a"] == 1
        assert fields["request.b"] == 2

    def test_request_scope_unbinds_on_exit(self):
        logger = FakePowertoolsLogger()
        binder = powertools_binder(logger)
        with binder.request_scope():
            bind_request(binder, method="POST", path="/orders", request_id="r1")
            assert logger.context[F.REQUEST_METHOD] == "POST"
        assert logger.context == {}, "context should be empty after the scope exits"

    def test_warm_invocation_does_not_inherit_prior_context(self):
        logger = FakePowertoolsLogger()
        binder = powertools_binder(logger)

        # First (warm) invocation.
        with binder.request_scope():
            bind_user(binder, id="user-1", org_id="org-1")
            logger.info("first")
        first_fields = logger.records[-1]["fields"]
        assert first_fields[F.USER_ID] == "user-1"

        # Second invocation on the same warm container: must not see user-1.
        with binder.request_scope():
            bind_user(binder, id="user-2")
            logger.info("second")
        second_fields = logger.records[-1]["fields"]
        assert second_fields[F.USER_ID] == "user-2"
        assert F.USER_ORG_ID not in second_fields, "org-1 leaked into the next invocation"

    def test_none_values_are_dropped(self):
        logger = FakePowertoolsLogger()
        binder = powertools_binder(logger)
        with binder.request_scope():
            bind_request(binder, method="GET", path=None, ip=None, request_id="r9")
            assert F.REQUEST_METHOD in logger.context
            assert F.REQUEST_PATH not in logger.context
            assert F.REQUEST_IP not in logger.context

    def test_scope_restores_prior_persistent_value(self):
        # A key bound at process level (outside a scope) and rebound inside a scope
        # is restored to its prior value on exit, not removed.
        logger = FakePowertoolsLogger()
        binder = powertools_binder(logger)
        bind_build_context(binder, commit="startup-sha")  # process-level
        with binder.request_scope():
            bind_build_context(binder, commit="request-sha")
            assert logger.context[F.GIT_COMMIT] == "request-sha"
        assert logger.context[F.GIT_COMMIT] == "startup-sha", "prior value should be restored"

    def test_scope_removes_keys_that_had_no_prior_value(self):
        logger = FakePowertoolsLogger()
        binder = powertools_binder(logger)
        bind_build_context(binder, commit="startup-sha")  # process-level
        with binder.request_scope():
            bind_user(binder, id="u1")
        assert F.USER_ID not in logger.context, "request-only key should be removed"
        assert logger.context[F.GIT_COMMIT] == "startup-sha", "unrelated persistent key untouched"


class TestStdlibBinder:
    def test_bind_helpers_emit_dotted_keys(self):
        logger, captured = _capturing_stdlib_logger("test.stdlib.emit")
        binder = stdlib_binder(logger)
        with binder.request_scope():
            bind_request(binder, method="POST", path="/orders", request_id="r1")
            bind_user(binder, id="u1", email="a@b.com", org_id="org9")
            logger.info("response", extra={F.RESPONSE_STATUS: 200})
        record = captured[-1]
        assert getattr(record, F.REQUEST_METHOD) == "POST"
        assert getattr(record, F.REQUEST_PATH) == "/orders"
        assert getattr(record, F.USER_ORG_ID) == "org9"
        assert getattr(record, F.RESPONSE_STATUS) == 200

    def test_context_cleared_after_scope(self):
        logger, captured = _capturing_stdlib_logger("test.stdlib.cleared")
        binder = stdlib_binder(logger)
        with binder.request_scope():
            bind_request(binder, method="POST")
        assert binder.current_fields() == {}
        logger.info("after")
        assert not hasattr(captured[-1], F.REQUEST_METHOD)

    def test_context_injected_for_child_logger_records(self):
        # A common layout: the binder is built on a parent logger that owns the
        # handler, but records are emitted via child loggers (getLogger(__name__)).
        parent = logging.getLogger("test.stdlib.parent")
        parent.setLevel(logging.DEBUG)
        parent.handlers = []
        captured = []

        class _Cap(logging.Handler):
            def emit(self, record):
                captured.append(record)

        parent.addHandler(_Cap())
        binder = stdlib_binder(parent)

        child = logging.getLogger("test.stdlib.parent.child")  # propagates to parent
        with binder.request_scope():
            bind_request(binder, method="POST", request_id="r1")
            child.info("emitted via child logger")

        assert getattr(captured[-1], F.REQUEST_METHOD) == "POST"
        assert getattr(captured[-1], F.REQUEST_ID) == "r1"

    def test_install_on_covers_handler_added_after_construction(self):
        logger = logging.getLogger("test.stdlib.late-handler")
        logger.setLevel(logging.DEBUG)
        logger.handlers = []
        binder = stdlib_binder(logger)  # no handler yet

        captured = []

        class _Cap(logging.Handler):
            def emit(self, record):
                captured.append(record)

        handler = _Cap()
        logger.addHandler(handler)
        binder.install_on(handler)  # explicitly attach to the late handler

        with binder.request_scope():
            bind_request(binder, method="GET")
            logger.info("after late handler")
        assert getattr(captured[-1], F.REQUEST_METHOD) == "GET"

    def test_explicit_extra_wins_over_bound_context(self):
        logger, captured = _capturing_stdlib_logger("test.stdlib.override")
        binder = stdlib_binder(logger)
        with binder.request_scope():
            bind_request(binder, method="GET")
            logger.info("override", extra={F.REQUEST_METHOD: "POST"})
        assert getattr(captured[-1], F.REQUEST_METHOD) == "POST"

    def test_build_context_helper(self):
        logger, captured = _capturing_stdlib_logger("test.stdlib.build")
        binder = stdlib_binder(logger)
        with binder.request_scope():
            bind_build_context(binder, commit="abc123", branch="main")
            logger.info("build")
        record = captured[-1]
        assert getattr(record, F.GIT_COMMIT) == "abc123"
        assert getattr(record, F.GIT_BRANCH) == "main"
        assert not hasattr(record, F.GIT_TAG)

    def test_concurrent_request_scopes_do_not_leak(self):
        """Two interleaved async requests must each keep only their own context."""
        logger, _ = _capturing_stdlib_logger("test.stdlib.concurrent")
        binder = stdlib_binder(logger)
        results = {}

        async def handle(user_id):
            with binder.request_scope():
                bind_user(binder, id=user_id, org_id=f"org-{user_id}")
                # Yield control so the other task interleaves between bind and read.
                await asyncio.sleep(0.01)
                results[user_id] = binder.current_fields()

        async def run():
            await asyncio.gather(handle("A"), handle("B"))

        asyncio.run(run())

        assert results["A"] == {F.USER_ID: "A", F.USER_ORG_ID: "org-A"}
        assert results["B"] == {F.USER_ID: "B", F.USER_ORG_ID: "org-B"}

    def test_concurrent_scopes_do_not_leak_into_emitted_records(self):
        """The contextvar filter must inject only the emitting task's fields."""
        logger, captured = _capturing_stdlib_logger("test.stdlib.concurrent.emit")
        binder = stdlib_binder(logger)

        async def handle(user_id):
            with binder.request_scope():
                bind_user(binder, id=user_id)
                await asyncio.sleep(0.01)
                logger.info(f"msg-{user_id}")

        async def run():
            await asyncio.gather(handle("A"), handle("B"))

        asyncio.run(run())

        by_message = {r.getMessage(): getattr(r, F.USER_ID, None) for r in captured}
        assert by_message == {"msg-A": "A", "msg-B": "B"}


class TestLogException:
    def test_sets_explicit_error_fields(self):
        logger, captured = _capturing_stdlib_logger("test.logexc")
        binder = stdlib_binder(logger)
        try:
            raise ValueError("boom")
        except ValueError as exc:
            log_exception(binder, exc, "handler failed")
        record = captured[-1]
        assert getattr(record, F.ERROR_TYPE) == "ValueError"
        assert getattr(record, F.ERROR_MESSAGE) == "boom"
        stack = getattr(record, F.ERROR_STACK)
        assert "ValueError: boom" in stack
        assert "Traceback" in stack

    def test_does_not_duplicate_traceback_via_exc_info(self):
        # Called inside an except block, log_exception must NOT set exc_info (which
        # would make the backend emit its own traceback field on top of error.stack).
        logger, captured = _capturing_stdlib_logger("test.logexc.noexcinfo")
        binder = stdlib_binder(logger)
        try:
            raise ValueError("boom")
        except ValueError as exc:
            log_exception(binder, exc, "handler failed")
        record = captured[-1]
        assert record.levelno == logging.ERROR
        assert record.exc_info is None, "must not carry exc_info (no duplicate backend traceback)"
        assert record.exc_text is None
        assert getattr(record, F.ERROR_STACK)  # trace lives solely in error.stack

    def test_error_stack_is_set_not_left_to_backend(self):
        """error.stack must be populated explicitly, not via exc_info alone."""
        logger = FakePowertoolsLogger()
        binder = powertools_binder(logger)
        try:
            raise KeyError("missing")
        except KeyError as exc:
            log_exception(binder, exc, "failed")
        fields = logger.records[-1]["fields"]
        assert F.ERROR_STACK in fields
        assert fields[F.ERROR_STACK]  # non-empty


class TestBodyHelpers:
    def test_request_body_fields_redacts_and_serialises(self):
        result = request_body_fields({"password": "x", "order_id": "O1"})
        assert set(result) == {F.REQUEST_BODY_JSON}
        payload = result[F.REQUEST_BODY_JSON]
        assert "***REDACTED***" in payload
        assert "O1" in payload
        assert "x" not in payload

    def test_response_output_fields_redacts_and_serialises(self):
        result = response_output_fields({"token": "t", "status": "ok"})
        assert set(result) == {F.RESPONSE_OUTPUT_JSON}
        payload = result[F.RESPONSE_OUTPUT_JSON]
        assert "***REDACTED***" in payload
        assert "ok" in payload

    def test_allow_only_is_honoured(self):
        result = request_body_fields({"email": "person@example.com", "order_id": "O1"}, allow_only=["order_id"])
        payload = result[F.REQUEST_BODY_JSON]
        assert "O1" in payload
        assert "person@example.com" not in payload  # value masked
        assert "***REDACTED***" in payload

    def test_deny_extra_is_forwarded(self):
        result = request_body_fields({"internal_ref": "x", "order_id": "O1"}, deny_extra=["internal_ref"])
        payload = result[F.REQUEST_BODY_JSON]
        assert "***REDACTED***" in payload
        assert "O1" in payload
        assert "x" not in payload.replace("order_id", "")  # the ref value is gone

    def test_custom_redactor_without_deny_extra_still_works(self):
        # A custom redactor that does not accept deny_extra must not break when the
        # caller does not pass deny_extra.
        def only_keys(payload, *, allow_only=None):
            return {"redacted": True}

        result = request_body_fields({"a": 1}, redactor=only_keys)
        assert '"redacted": true' in result[F.REQUEST_BODY_JSON]

    def test_non_serialisable_values_do_not_raise(self):
        class Custom:
            def __str__(self):
                return "custom-repr"

        result = request_body_fields({"obj": Custom(), "n": 1})
        assert "custom-repr" in result[F.REQUEST_BODY_JSON]
