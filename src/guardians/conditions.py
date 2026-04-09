"""Condition system: one grammar, two backends.

Conditions are Python expressions evaluated by safe_eval (runtime)
or translated to Z3 (verification). Both share the same grammar:

    Supported: literals, variables, lists, comparisons (==, !=, <, >,
    <=, >=, in, not in), boolean ops (and, or, not), len(), domain_of().

    domain_of(x) extracts the domain from an email address
    ("user@d" -> "d") or returns x unchanged.

    forall conditions are handled separately (not Python syntax).
"""

from __future__ import annotations

import ast
from dataclasses import dataclass
from typing import Any

import z3


def condition_to_z3(expr: str, env: dict[str, Any]) -> z3.BoolRef | None:
    """Translate a condition expression to Z3 constraints.

    env maps variable names to either:
    - z3.ExprRef (for tool parameters)
    - Python values (for constants — lists, strings, etc.)

    Returns None if the expression can't be translated.
    """
    try:
        tree = ast.parse(expr, mode="eval")
    except SyntaxError:
        return None
    try:
        result = _to_z3(tree.body, env)
        if isinstance(result, z3.BoolRef):
            return result
        return None
    except _Untranslatable:
        return None


class _Untranslatable(Exception):
    pass


@dataclass
class _DomainOf:
    """Marker: domain_of(z3_var) seen, needs special handling at comparison."""
    var: z3.ExprRef


def _to_z3(node: ast.expr, env: dict[str, Any]) -> Any:
    match node:
        case ast.Constant(value=v):
            if isinstance(v, str):
                return z3.StringVal(v)
            if isinstance(v, bool):
                return z3.BoolVal(v)
            if isinstance(v, int):
                return z3.IntVal(v)
            if isinstance(v, float):
                return z3.IntVal(int(v))
            raise _Untranslatable(f"unsupported literal: {v!r}")

        case ast.Name(id=name):
            val = env.get(name)
            if val is None:
                raise _Untranslatable(f"unknown variable: {name}")
            if isinstance(val, z3.ExprRef):
                return val
            if isinstance(val, str):
                return z3.StringVal(val)
            if isinstance(val, bool):
                return z3.BoolVal(val)
            if isinstance(val, int):
                return z3.IntVal(val)
            if isinstance(val, list):
                return val  # keep as Python list for 'in' handling
            raise _Untranslatable(f"can't convert {type(val)} to Z3")

        case ast.List(elts=elts):
            return [_to_z3(e, env) for e in elts]

        case ast.UnaryOp(op=ast.Not(), operand=operand):
            return z3.Not(_to_z3(operand, env))

        case ast.BoolOp(op=op, values=values):
            z3_vals = [_to_z3(v, env) for v in values]
            if isinstance(op, ast.And):
                return z3.And(*z3_vals)
            return z3.Or(*z3_vals)

        case ast.Compare():
            return _compare_to_z3(node, env)

        case ast.Call(func=ast.Name(id="len"), args=[arg]) if not node.keywords:
            z3_arg = _to_z3(arg, env)
            if isinstance(z3_arg, z3.SeqRef):
                return z3.Length(z3_arg)
            return z3_arg

        case ast.Call(func=ast.Name(id="domain_of"), args=[arg]) if not node.keywords:
            z3_arg = _to_z3(arg, env)
            if isinstance(z3_arg, z3.ExprRef):
                return _DomainOf(var=z3_arg)
            raise _Untranslatable("domain_of on non-Z3 value")

        case _:
            raise _Untranslatable(f"unsupported node: {type(node).__name__}")


def _compare_to_z3(node: ast.Compare, env: dict[str, Any]) -> z3.BoolRef:
    """Translate a comparison to Z3. Handles chains (a < b < c)."""
    parts: list[z3.BoolRef] = []
    left = _to_z3(node.left, env)

    for op, comp_node in zip(node.ops, node.comparators):
        right = _to_z3(comp_node, env)
        parts.append(_single_compare(left, op, right))
        left = right

    if len(parts) == 1:
        return parts[0]
    return z3.And(*parts)


def _single_compare(left: Any, op: ast.cmpop, right: Any) -> z3.BoolRef:
    """Translate a single comparison operation to Z3."""

    # domain_of(x) in [list] — expand to exact-or-suffix disjunction
    if isinstance(left, _DomainOf) and isinstance(right, list):
        domains = _to_string_list(right)
        if isinstance(op, ast.In):
            return z3.Or(*[
                z3.Or(left.var == z3.StringVal(d),
                      z3.SuffixOf(z3.StringVal(f"@{d}"), left.var))
                for d in domains
            ])
        if isinstance(op, ast.NotIn):
            return z3.And(*[
                z3.And(left.var != z3.StringVal(d),
                       z3.Not(z3.SuffixOf(z3.StringVal(f"@{d}"), left.var)))
                for d in domains
            ])
        raise _Untranslatable(f"domain_of with {type(op).__name__}")

    # x in [list] — expand to equality disjunction
    if isinstance(op, ast.In) and isinstance(right, list):
        z3_vals = _to_z3_list(right)
        return z3.Or(*[left == v for v in z3_vals])

    # x not in [list]
    if isinstance(op, ast.NotIn) and isinstance(right, list):
        z3_vals = _to_z3_list(right)
        return z3.And(*[left != v for v in z3_vals])

    # Standard comparisons
    if not isinstance(left, z3.ExprRef) or not isinstance(right, z3.ExprRef):
        raise _Untranslatable("comparison between non-Z3 values")

    match op:
        case ast.Eq():
            return left == right
        case ast.NotEq():
            return left != right
        case ast.Lt():
            return left < right
        case ast.LtE():
            return left <= right
        case ast.Gt():
            return left > right
        case ast.GtE():
            return left >= right
        case _:
            raise _Untranslatable(f"unsupported op: {type(op).__name__}")


def _to_string_list(vals: list) -> list[str]:
    """Extract plain strings from a list of Z3 StringVals or Python strings."""
    result = []
    for v in vals:
        if isinstance(v, str):
            result.append(v)
        elif z3.is_string_value(v):
            result.append(v.as_string())
        else:
            raise _Untranslatable(f"non-string in domain list: {v}")
    return result


def _to_z3_list(vals: list) -> list[z3.ExprRef]:
    """Convert a list to Z3 values."""
    result = []
    for v in vals:
        if isinstance(v, z3.ExprRef):
            result.append(v)
        elif isinstance(v, str):
            result.append(z3.StringVal(v))
        elif isinstance(v, int):
            result.append(z3.IntVal(v))
        else:
            raise _Untranslatable(f"can't convert list element: {v}")
    return result


def expr_names(expr: str) -> set[str]:
    """Extract all variable names referenced in a condition expression.

    Excludes keywords, builtins, and known helper function names
    (len, domain_of).
    """
    try:
        tree = ast.parse(expr, mode="eval")
    except SyntaxError:
        return set()
    import keyword
    return {
        node.id for node in ast.walk(tree)
        if isinstance(node, ast.Name)
        and not keyword.iskeyword(node.id)
        and node.id not in ("len", "domain_of", "True", "False", "None")
    }
