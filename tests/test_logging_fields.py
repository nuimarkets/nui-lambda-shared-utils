"""Tests for the structured-logging field registry and its derivations."""

import pytest

from nui_shared_utils.logging import (
    FIELDS,
    F,
    Field,
    alias_map,
    redaction_keys,
    validate_fields,
    validate_registry,
)
from nui_shared_utils.logging.fields import _key_errors

pytestmark = pytest.mark.unit


class TestRegistryIntegrity:
    def test_registry_is_internally_valid(self):
        """The core registry passes its own import-time guard."""
        assert validate_registry() == []

    def test_registry_key_matches_field_key(self):
        for key, fld in FIELDS.items():
            assert key == fld.key, f"registry key {key!r} != Field.key {fld.key!r}"

    def test_all_keys_are_dotted_snake_case(self):
        for key in FIELDS:
            assert _key_errors(key) == [], f"{key!r} is not a valid field name"

    def test_all_types_are_known(self):
        known = {"keyword", "text", "long", "boolean", "date", "geo_point"}
        for fld in FIELDS.values():
            assert fld.type in known, f"{fld.key}: unknown type {fld.type!r}"

    def test_no_duplicate_keys(self):
        # A dict cannot hold duplicate keys, so assert the F constants and the
        # registry keys are a consistent 1:1 set instead.
        f_values = [getattr(F, n) for n in dir(F) if not n.startswith("_") and isinstance(getattr(F, n), str)]
        assert len(f_values) == len(set(f_values)), "duplicate value in F constants"

    def test_every_F_constant_is_registered(self):
        for name in dir(F):
            if name.startswith("_"):
                continue
            value = getattr(F, name)
            if isinstance(value, str):
                assert value in FIELDS, f"F.{name} = {value!r} missing from FIELDS"

    def test_aliases_are_globally_unique(self):
        seen = {}
        for key, fld in FIELDS.items():
            for alias in fld.aliases:
                assert alias not in seen, f"alias {alias!r} used by {seen.get(alias)!r} and {key!r}"
                seen[alias] = key

    def test_aliases_do_not_collide_with_canonical_keys(self):
        for fld in FIELDS.values():
            for alias in fld.aliases:
                assert alias not in FIELDS, f"alias {alias!r} collides with a canonical field"

    def test_field_is_frozen(self):
        fld = FIELDS["user.email"]
        with pytest.raises(Exception):
            fld.key = "user.other"  # frozen dataclass -> FrozenInstanceError


class TestKeyValidation:
    @pytest.mark.parametrize(
        "key",
        ["target", "request.method", "user.org_id", "response.duration_ms", "git.commit"],
    )
    def test_valid_keys(self, key):
        assert _key_errors(key) == []

    @pytest.mark.parametrize(
        "key",
        ["orderId", "api_status.CODE", "request.device-os", "Request.method", "user..id", "9lives", ""],
    )
    def test_invalid_keys(self, key):
        assert _key_errors(key) != []


class TestValidateFields:
    def test_valid_consumer_module(self):
        class OrderFields:
            ORDER_ID = "order.id"
            ORDER_STATE = "order.state"
            SINGLE = "target"

        assert validate_fields(OrderFields) == []

    def test_invalid_consumer_module_is_flagged(self):
        class BadFields:
            CAMEL = "orderId"
            HYPHEN = "request.device-os"
            GOOD = "order.id"

        errors = validate_fields(BadFields)
        assert any("orderId" in e for e in errors)
        assert any("device-os" in e for e in errors)
        assert not any("order.id" in e for e in errors)

    def test_ignores_non_string_and_private_attrs(self):
        class Mixed:
            FIELD = "order.id"
            _PRIVATE = "camelCase"  # ignored (underscore-prefixed)
            COUNT = 5  # ignored (non-string)

        assert validate_fields(Mixed) == []

    def test_multiple_modules(self):
        class A:
            X = "a.one"

        class B:
            Y = "bad-name"

        errors = validate_fields(A, B)
        assert len(errors) == 1
        assert "bad-name" in errors[0]


class TestRedactionKeys:
    def test_derives_pii_and_redact_leaf_names(self):
        keys = redaction_keys()
        assert "email" in keys  # user.email is pii
        assert "body_json" in keys  # request.body_json is redact
        assert "output_json" in keys  # response.output_json is redact

    def test_excludes_non_sensitive_fields(self):
        keys = redaction_keys()
        assert "method" not in keys
        assert "org_id" not in keys


class TestAliasMap:
    def test_maps_old_names_to_canonical_keys(self):
        mapping = alias_map()
        assert mapping["request.user"] == "user.email"
        assert mapping["request.company"] == "user.org_id"
        assert mapping["request.company_id"] == "user.org_id"
        assert mapping["request.trace_id"] == "trace.id"
        assert mapping["api.duration_ms"] == "response.duration_ms"
        assert mapping["request.url"] == "request.path"

    def test_every_alias_target_is_a_real_field(self):
        for target in alias_map().values():
            assert target in FIELDS
