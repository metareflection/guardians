"""Tests for condition_to_z3 and expr_names."""

import z3

from guardians.conditions import condition_to_z3, expr_names


# --- expr_names ---

def test_expr_names_simple():
    assert expr_names("x > 0") == {"x"}


def test_expr_names_multiple():
    assert expr_names("x > 0 and y < 10") == {"x", "y"}


def test_expr_names_excludes_builtins():
    """len, domain_of, True, False, None should not appear in expr_names."""
    names = expr_names("len(x) > 0 and domain_of(y) in z")
    assert "len" not in names
    assert "domain_of" not in names
    assert "True" not in names
    assert names == {"x", "y", "z"}


def test_expr_names_excludes_keywords():
    names = expr_names("x and y or not z")
    assert "and" not in names
    assert "or" not in names
    assert "not" not in names
    assert names == {"x", "y", "z"}


# --- condition_to_z3 ---

def test_z3_simple_comparison():
    x = z3.String("x")
    result = condition_to_z3("x == 'hello'", {"x": x})
    assert result is not None
    assert isinstance(result, z3.BoolRef)


def test_z3_in_list():
    x = z3.String("x")
    result = condition_to_z3("x in ['a', 'b']", {"x": x})
    assert result is not None


def test_z3_not_in_list():
    x = z3.String("x")
    result = condition_to_z3("x not in ['a', 'b']", {"x": x})
    assert result is not None


def test_z3_domain_of():
    x = z3.String("to")
    result = condition_to_z3(
        "domain_of(to) in allowed_domains",
        {"to": x, "allowed_domains": ["company.com"]},
    )
    assert result is not None


def test_z3_returns_none_for_unsupported():
    """Unsupported syntax returns None, not an exception."""
    result = condition_to_z3("x.startswith('y')", {"x": z3.String("x")})
    assert result is None


def test_z3_len():
    x = z3.String("x")
    result = condition_to_z3("len(x) > 0", {"x": x})
    assert result is not None
