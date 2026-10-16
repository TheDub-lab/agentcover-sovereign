# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Michael / TheDub-lab
"""Param-schema validation (the param half of least-privilege)."""
from safety_protocol.core import validate_params


def _string_schema(**spec):
    return {"required": ["q"],
            "properties": {"q": {"type": "string", **spec}},
            "additional_properties": False}


def test_max_length_rejects_too_long_and_accepts_at_boundary():
    schema = _string_schema(maxLength=5)
    assert validate_params({"q": "abcde"}, schema) is None
    reason = validate_params({"q": "abcdef"}, schema)
    assert reason and "maxLength 5" in reason


def test_min_length_rejects_too_short():
    schema = _string_schema(minLength=3)
    assert validate_params({"q": "abc"}, schema) is None
    reason = validate_params({"q": "ab"}, schema)
    assert reason and "minLength 3" in reason


def test_length_bounds_do_not_apply_to_non_strings():
    # maxLength is a string constraint; a numeric value must not trip it.
    schema = {"required": ["q"], "properties": {"q": {"type": "number",
              "maxLength": 5}}, "additional_properties": False}
    assert validate_params({"q": 123456789}, schema) is None


def test_unknown_param_rejected_by_default():
    reason = validate_params({"q": "x", "extra": 1}, _string_schema())
    assert reason and "extra" in reason


def test_additional_properties_allows_unknown_param():
    schema = {"properties": {"q": {"type": "string"}},
              "additional_properties": True}
    assert validate_params({"q": "x", "anything": 1}, schema) is None
