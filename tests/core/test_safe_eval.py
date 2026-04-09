"""Tests for the safe expression evaluator."""

import pytest

from guardians.safe_eval import safe_eval


# --- Valid expressions ---

def test_literal():
    assert safe_eval("42", {}) == 42
    assert safe_eval("'hello'", {}) == "hello"
    assert safe_eval("True", {}) is True


def test_variable_lookup():
    assert safe_eval("x", {"x": 10}) == 10


def test_undefined_variable():
    with pytest.raises(ValueError, match="undefined"):
        safe_eval("x", {})


def test_comparisons():
    assert safe_eval("x == 1", {"x": 1}) is True
    assert safe_eval("x != 1", {"x": 2}) is True
    assert safe_eval("x > 0", {"x": 5}) is True
    assert safe_eval("x <= 10", {"x": 10}) is True


def test_membership():
    assert safe_eval("x in [1, 2, 3]", {"x": 2}) is True
    assert safe_eval("x not in [1, 2]", {"x": 3}) is True


def test_boolean_ops():
    assert safe_eval("x > 0 and x < 10", {"x": 5}) is True
    assert safe_eval("x == 1 or x == 2", {"x": 2}) is True
    assert safe_eval("not x", {"x": False}) is True


def test_len():
    assert safe_eval("len(x) > 0", {"x": [1, 2]}) is True
    assert safe_eval("len(x) > 0", {"x": ""}) is False


def test_domain_of():
    assert safe_eval("domain_of(x)", {"x": "alice@company.com"}) == "company.com"
    assert safe_eval("domain_of(x)", {"x": "no-at-sign"}) == "no-at-sign"


def test_domain_of_in_list():
    env = {"to": "alice@company.com", "allowed": ["company.com"]}
    assert safe_eval("domain_of(to) in allowed", env) is True
    env["to"] = "evil@attacker.com"
    assert safe_eval("domain_of(to) in allowed", env) is False


def test_domain_of_list_input():
    """domain_of on a list extracts domains from each element."""
    env = {"r": ["a@x.com", "b@y.com"]}
    result = safe_eval("domain_of(r)", env)
    assert result == ["x.com", "y.com"]


def test_chained_comparison():
    assert safe_eval("0 < x < 10", {"x": 5}) is True
    assert safe_eval("0 < x < 10", {"x": 15}) is False


# --- Rejected expressions ---

def test_reject_attribute_access():
    with pytest.raises(ValueError, match="disallowed"):
        safe_eval("x.__class__", {"x": 1})


def test_reject_arbitrary_call():
    with pytest.raises(ValueError, match="disallowed"):
        safe_eval("exec('import os')", {})


def test_reject_subscript():
    with pytest.raises(ValueError, match="disallowed"):
        safe_eval("x[0]", {"x": [1, 2]})
