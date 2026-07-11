"""Tests for the log-payload redactor (deny-list default, allow-list opt-in)."""

import copy

import pytest

from nui_shared_utils.logging import MASK, default_redactor

pytestmark = pytest.mark.unit


class TestDenyList:
    def test_masks_top_level_secret(self):
        assert default_redactor({"password": "hunter2", "ok": 1}) == {"password": MASK, "ok": 1}

    def test_masks_nested_dict_secret(self):
        payload = {"outer": {"token": "abc", "keep": "v"}}
        assert default_redactor(payload) == {"outer": {"token": MASK, "keep": "v"}}

    def test_masks_secret_inside_list(self):
        payload = {"items": [{"api_key": "k"}, {"safe": "s"}]}
        assert default_redactor(payload) == {"items": [{"api_key": MASK}, {"safe": "s"}]}

    def test_separator_and_case_insensitive_match(self):
        payload = {"apiKey": 1, "API_KEY": 2, "X-Api-Key": 3, "AccessToken": 4, "X-Auth-Token": 5}
        redacted = default_redactor(payload)
        assert all(v == MASK for v in redacted.values())

    def test_whole_word_matching_avoids_false_positives(self):
        # Deny tokens must match on word boundaries only: "card" / "auth" / "pin"
        # should NOT mask these unrelated keys.
        payload = {"wildcard": 1, "author": 2, "mapping": 3, "shipping_status": 4}
        assert default_redactor(payload) == payload

    def test_prefixed_and_suffixed_sensitive_words_are_masked(self):
        payload = {"card_number": 1, "user_password": 2, "refresh_token": 3}
        redacted = default_redactor(payload)
        assert all(v == MASK for v in redacted.values())

    def test_concatenated_lowercase_secret_keys_are_masked(self):
        # No delimiter, no camelCase: caught by the curated substring pass.
        payload = {"accesstoken": 1, "apitoken": 2, "sessiontoken": 3, "privatekey": 4, "userpassword": 5}
        redacted = default_redactor(payload)
        assert all(v == MASK for v in redacted.values())

    def test_substring_pass_does_not_mask_innocent_keys(self):
        # "key" is deliberately NOT in the substring set, so these survive.
        payload = {"monkey": 1, "primary_key": 2, "keyboard_layout": 3}
        redacted = default_redactor(payload)
        assert redacted["monkey"] == 1
        assert redacted["keyboard_layout"] == 3
        # primary_key: "key" is not a substring-deny token and not a whole word match
        assert redacted["primary_key"] == 2

    def test_auth_jwt_bearer_masked_without_false_positives(self):
        redacted = default_redactor(
            {"auth": 1, "jwt": 2, "bearer_token": 3, "x_auth": 4, "author": "keep", "authored_by": "keep"}
        )
        assert redacted["auth"] == MASK
        assert redacted["jwt"] == MASK
        assert redacted["bearer_token"] == MASK
        assert redacted["x_auth"] == MASK
        assert redacted["author"] == "keep"  # single word, not "auth"
        assert redacted["authored_by"] == "keep"

    def test_email_variants_masked_but_not_similar_words(self):
        redacted = default_redactor({"user_email": "e", "emailer_config": "keep"})
        assert redacted["user_email"] == MASK  # ..._email -> masked
        assert redacted["emailer_config"] == "keep"  # single word "emailer" != "email"

    def test_registry_derived_pii_key_is_masked(self):
        # user.email is sensitivity=pii, so its leaf name "email" is in the deny set.
        assert default_redactor({"email": "a@b.com"}) == {"email": MASK}

    def test_deny_extra_extends_the_set(self):
        payload = {"custom_secret_field": "x", "note": "n"}
        redacted = default_redactor(payload, deny_extra=["custom_secret_field"])
        assert redacted == {"custom_secret_field": MASK, "note": "n"}

    def test_non_sensitive_keys_survive(self):
        payload = {"order_id": "O1", "status": "confirmed", "count": 3}
        assert default_redactor(payload) == payload


class TestAllowList:
    def test_keeps_only_named_keys(self):
        payload = {"order_id": 1, "secret_note": "s", "email": "e", "status": "ok"}
        redacted = default_redactor(payload, allow_only=["order_id", "status"])
        assert redacted == {"order_id": 1, "secret_note": MASK, "email": MASK, "status": "ok"}

    def test_allow_list_applies_at_every_depth(self):
        payload = {"keep": {"keep": 1, "drop": 2}}
        redacted = default_redactor(payload, allow_only=["keep"])
        assert redacted == {"keep": {"keep": 1, "drop": MASK}}

    def test_deny_list_still_wins_over_allow(self):
        # A key explicitly allowed but also sensitive is still masked (backstop).
        payload = {"password": "x", "order_id": 1}
        redacted = default_redactor(payload, allow_only=["password", "order_id"])
        assert redacted == {"password": MASK, "order_id": 1}


class TestNoMutation:
    def test_caller_dict_is_not_mutated(self):
        payload = {"password": "hunter2", "nested": {"token": "abc"}, "list": [{"secret": "s"}]}
        original = copy.deepcopy(payload)
        default_redactor(payload)
        assert payload == original

    def test_result_is_a_distinct_structure(self):
        payload = {"nested": {"keep": 1}}
        redacted = default_redactor(payload)
        assert redacted is not payload
        assert redacted["nested"] is not payload["nested"]


class TestNonDictPayloads:
    @pytest.mark.parametrize("value", ["hello", 42, 3.14, True, None])
    def test_scalars_pass_through(self, value):
        assert default_redactor(value) == value

    def test_top_level_list(self):
        assert default_redactor([{"password": 1}, {"ok": 2}]) == [{"password": MASK}, {"ok": 2}]

    def test_empty_containers(self):
        assert default_redactor({}) == {}
        assert default_redactor([]) == []
