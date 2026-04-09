"""Static verification engine.

Explicit verifier — no effect handlers. Walks the workflow AST with
an explicit abstract state, checking policy rules at each step.

The verifier is intentionally conservative: conditionals always explore
both branches regardless of whether the condition is concretely decidable.
This means unreachable branches can still produce violations.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

import z3

from .conditions import condition_to_z3, expr_names
from .policy import Policy, TaintRule
from .results import VerificationResult, Violation
from .safe_eval import safe_eval
from .tools import ToolRegistry, ToolSpec
from .workflow import Workflow, WorkflowStep, SymRef

MAX_LOOP_ITERATIONS = 3


# --- Abstract values ---

@dataclass
class AbstractValue:
    """A symbolic value carrying taint labels during verification.

    Attributes:
        labels: taint label strings on this value.
        sanitized_for: names of taint rules this value was sanitized for.
        source_tool: the tool that directly produced this value.
        provenance: all tools whose outputs contributed to this value,
            transitively through data flow.  Used by taint checking to
            verify that a taint rule's declared source_tool actually
            appears in the data's lineage.
    """

    labels: set[str] = field(default_factory=set)
    sanitized_for: set[str] = field(default_factory=set)
    source_tool: str = "unknown"
    provenance: set[str] = field(default_factory=set)


# --- Public API ---

def verify(
    workflow: Workflow,
    policy: Policy,
    registry: ToolRegistry,
    *,
    strict: bool = False,
) -> VerificationResult:
    """Run all verification passes on a workflow."""
    result = VerificationResult()

    # Pass 1: well-formedness (scope checking)
    for v in _check_scope(workflow):
        result.add(v)

    # Pass 2: abstract execution with policy checking
    env: dict[str, AbstractValue] = {
        name: AbstractValue(source_tool="input", provenance={"input"})
        for name in workflow.input_variables
    }
    automaton_states: dict[str, set[str]] = {
        a.name: {a.initial_state} for a in policy.automata
    }
    _verify_steps(workflow.steps, policy, registry, env, automaton_states, result)

    # Strict mode: promote warnings to violations
    if strict:
        for w in result.warnings:
            result.add(Violation(category="unparseable", message=w, step_label=""))

    return result


# ===================================================================
# Pass 1: Scope checking
# ===================================================================

def _check_scope(workflow: Workflow) -> list[Violation]:
    violations: list[Violation] = []
    bound: set[str] = set(workflow.input_variables)
    _check_steps_scope(workflow.steps, bound, violations)
    return violations


def _check_steps_scope(
    steps: list[WorkflowStep], bound: set[str], violations: list[Violation],
) -> None:
    for step in steps:
        if step.tool_call:
            tc = step.tool_call
            for ref in _collect_refs(tc.arguments):
                if ref not in bound:
                    violations.append(Violation(
                        category="well_formedness",
                        message=f"Undefined reference @{ref}",
                        step_label=step.label,
                        rule_name="undefined_ref",
                    ))
            if tc.result_binding:
                bound.add(tc.result_binding)

        elif step.conditional:
            c = step.conditional
            for ref in _condition_undefined_refs(c.condition, bound):
                violations.append(Violation(
                    category="well_formedness",
                    message=f"Undefined reference @{ref}",
                    step_label=step.label,
                    rule_name="undefined_ref",
                ))
            then_bound = set(bound)
            else_bound = set(bound)
            _check_steps_scope(c.then_steps, then_bound, violations)
            _check_steps_scope(c.else_steps, else_bound, violations)
            bound.update(then_bound & else_bound)

        elif step.loop:
            lp = step.loop
            if lp.collection_ref not in bound:
                violations.append(Violation(
                    category="well_formedness",
                    message=f"Undefined reference @{lp.collection_ref}",
                    step_label=step.label,
                    rule_name="undefined_ref",
                ))
            if lp.item_binding in bound:
                violations.append(Violation(
                    category="well_formedness",
                    message=f"Loop item binding '{lp.item_binding}' shadows outer variable",
                    step_label=step.label,
                    rule_name="shadowed_binding",
                ))
            loop_bound = set(bound)
            loop_bound.add(lp.item_binding)
            _check_steps_scope(lp.body, loop_bound, violations)


def _collect_refs(val: Any) -> list[str]:
    refs: list[str] = []
    _walk_refs(val, refs)
    return refs


def _walk_refs(val: Any, refs: list[str]) -> None:
    if isinstance(val, SymRef):
        refs.append(val.ref)
    elif isinstance(val, dict):
        for v in val.values():
            _walk_refs(v, refs)
    elif isinstance(val, list):
        for v in val:
            _walk_refs(v, refs)


def _condition_undefined_refs(condition: str, bound: set[str]) -> list[str]:
    """Find names in a condition that are not in scope.

    Uses expr_names which already excludes keywords, len, domain_of, etc.
    """
    return [n for n in expr_names(condition) if n not in bound]


# ===================================================================
# Pass 2: Abstract execution
# ===================================================================

def _verify_steps(
    steps: list[WorkflowStep],
    policy: Policy,
    registry: ToolRegistry,
    env: dict[str, AbstractValue],
    automaton_states: dict[str, set[str]],
    result: VerificationResult,
) -> None:
    for step in steps:
        if step.tool_call:
            _verify_tool_call(step, policy, registry, env, automaton_states, result)
        elif step.conditional:
            _verify_conditional(step, policy, registry, env, automaton_states, result)
        elif step.loop:
            _verify_loop(step, policy, registry, env, automaton_states, result)


def _verify_tool_call(
    step: WorkflowStep,
    policy: Policy,
    registry: ToolRegistry,
    env: dict[str, AbstractValue],
    automaton_states: dict[str, set[str]],
    result: VerificationResult,
) -> None:
    tc = step.tool_call
    assert tc is not None
    spec = registry.get_spec(tc.tool_name)

    # 1. Allowlist
    if tc.tool_name not in set(policy.allowed_tools):
        result.add(Violation(
            category="allowlist",
            message=f"Tool '{tc.tool_name}' is not in the allowed tools list",
            step_label=step.label,
            rule_name="allowed_tools",
        ))

    # 2. Missing spec
    if tc.tool_name in set(policy.allowed_tools) and spec is None:
        result.add(Violation(
            category="missing_spec",
            message=f"Tool '{tc.tool_name}' is allowed but has no registered spec",
            step_label=step.label,
            rule_name="missing_spec",
        ))

    # 3. Resolve arguments
    resolved = _resolve_abstract(tc.arguments, env)

    # 4. Taint checks
    _check_taint_rules(tc.tool_name, resolved, step.label, spec, policy, registry, result)

    # 5. Preconditions (Z3)
    constants = _collect_policy_constants(policy)
    if spec is not None:
        for pre in spec.preconditions:
            _check_z3_condition(
                "precondition", tc.tool_name, pre, resolved, None,
                step.label, constants, spec, result,
            )

    # 6. Automata
    _check_automata(policy, tc.tool_name, resolved, step.label, automaton_states, result)

    # 7. Build abstract result with provenance tracking
    input_labels = _collect_labels(resolved)
    input_provenance = _collect_provenance(resolved)
    spec_labels = set(spec.source_labels) if spec else set()
    abstract_result = AbstractValue(
        labels=spec_labels | input_labels,
        sanitized_for=set(),
        source_tool=tc.tool_name,
        provenance={tc.tool_name} | input_provenance,
    )

    # 8. Apply sanitizer logic
    if spec is not None:
        for rule in policy.taint_rules:
            if tc.tool_name in rule.sanitizers:
                abstract_result.sanitized_for.add(rule.name)

    # 9. Postconditions (Z3)
    if spec is not None:
        for post in spec.postconditions:
            _check_z3_condition(
                "postcondition", tc.tool_name, post, resolved, abstract_result,
                step.label, constants, spec, result,
            )

    # 10. Frame conditions (Z3)
    if spec is not None:
        for frame in spec.frame_conditions:
            _check_z3_condition(
                "frame", tc.tool_name, frame, resolved, None,
                step.label, constants, spec, result,
            )

    # 11. Bind result
    if tc.result_binding:
        env[tc.result_binding] = abstract_result


def _verify_conditional(
    step: WorkflowStep,
    policy: Policy,
    registry: ToolRegistry,
    env: dict[str, AbstractValue],
    automaton_states: dict[str, set[str]],
    result: VerificationResult,
) -> None:
    c = step.conditional
    assert c is not None

    # Always explore both branches (intentionally conservative).
    saved_env = _copy_env(env)
    saved_auto = _copy_auto(automaton_states)

    _verify_steps(c.then_steps, policy, registry, env, automaton_states, result)
    then_env = _copy_env(env)
    then_auto = _copy_auto(automaton_states)

    env.clear()
    env.update(saved_env)
    automaton_states.clear()
    automaton_states.update(saved_auto)
    _verify_steps(c.else_steps, policy, registry, env, automaton_states, result)

    # Join env: merge values present in both branches, drop one-branch-only
    joined: dict[str, AbstractValue] = {}
    all_keys = set(then_env.keys()) | set(env.keys())
    for k in all_keys:
        then_val = then_env.get(k)
        else_val = env.get(k)
        if then_val is not None and else_val is not None:
            joined[k] = AbstractValue(
                labels=then_val.labels | else_val.labels,
                sanitized_for=then_val.sanitized_for & else_val.sanitized_for,
                source_tool=then_val.source_tool,
                provenance=then_val.provenance | else_val.provenance,
            )

    env.clear()
    env.update(joined)

    for name in automaton_states:
        automaton_states[name] = automaton_states[name] | then_auto.get(name, set())


def _verify_loop(
    step: WorkflowStep,
    policy: Policy,
    registry: ToolRegistry,
    env: dict[str, AbstractValue],
    automaton_states: dict[str, set[str]],
    result: VerificationResult,
) -> None:
    lp = step.loop
    assert lp is not None

    collection = env.get(lp.collection_ref)
    before_keys = set(env.keys())

    if isinstance(collection, AbstractValue):
        item_val = AbstractValue(
            labels=set(collection.labels),
            sanitized_for=set(collection.sanitized_for),
            source_tool=collection.source_tool,
            provenance=set(collection.provenance),
        )
    else:
        item_val = AbstractValue(source_tool="literal", provenance=set())

    env[lp.item_binding] = item_val

    converged = False
    for _ in range(MAX_LOOP_ITERATIONS):
        snapshot = _copy_env(env)
        _verify_steps(lp.body, policy, registry, env, automaton_states, result)
        if _env_converged(snapshot, env):
            converged = True
            break

    if not converged:
        result.warn(
            f"Loop '{step.label}' did not converge after {MAX_LOOP_ITERATIONS} "
            f"iterations; analysis may be incomplete"
        )

    for k in list(env.keys()):
        if k not in before_keys:
            del env[k]


# ===================================================================
# Taint checking
# ===================================================================

def _check_taint_rules(
    tool_name: str,
    resolved: dict[str, Any],
    step_label: str,
    spec: ToolSpec | None,
    policy: Policy,
    registry: ToolRegistry,
    result: VerificationResult,
) -> None:
    for rule in policy.taint_rules:
        if rule.sink_tool != tool_name and rule.sink_tool != "*":
            continue

        if rule.sink_param == "*" and spec is not None:
            for p in spec.params:
                if p.is_taint_sink:
                    expanded = TaintRule(
                        name=rule.name,
                        source_tool=rule.source_tool,
                        sink_tool=tool_name,
                        sink_param=p.name,
                        condition=rule.condition,
                        sanitizers=rule.sanitizers,
                    )
                    _check_single_taint(expanded, resolved, step_label, spec, policy, registry, result)
        else:
            _check_single_taint(rule, resolved, step_label, spec, policy, registry, result)


def _check_single_taint(
    rule: TaintRule,
    resolved: dict[str, Any],
    step_label: str,
    spec: ToolSpec | None,
    policy: Policy,
    registry: ToolRegistry,
    result: VerificationResult,
) -> None:
    # Find ALL abstract values nested under the sink param, not just the first.
    abstracts = _find_all_abstracts(resolved.get(rule.sink_param))
    if not abstracts:
        return

    for sym in abstracts:
        if _is_tainted_for_rule(sym, rule, policy, registry, resolved):
            source_desc = "any source" if rule.source_tool == "*" else f"'{rule.source_tool}'"
            result.add(Violation(
                category="taint",
                message=f"Tainted data from {source_desc} flows to '{rule.sink_tool}.{rule.sink_param}'",
                step_label=step_label,
                rule_name=rule.name,
            ))
            return  # one violation per rule per step


def _is_tainted_for_rule(
    sym: AbstractValue,
    rule: TaintRule,
    policy: Policy,
    registry: ToolRegistry,
    resolved: dict[str, Any],
) -> bool:
    """Check whether a single AbstractValue violates a taint rule."""
    # Check source match: both label overlap AND provenance
    if rule.source_tool == "*":
        if not sym.labels:
            return False
    else:
        source_spec = registry.get_spec(rule.source_tool)
        if source_spec is None:
            return False
        if not (sym.labels & set(source_spec.source_labels)):
            return False
        # Provenance check: the declared source tool must actually be
        # in this value's data lineage.
        if rule.source_tool not in sym.provenance:
            return False

    # Already sanitized?
    if rule.name in sym.sanitized_for:
        return False

    # Conditional taint rule?
    if rule.condition:
        eval_env: dict[str, Any] = {}
        eval_env.update(resolved)
        eval_env.update(_collect_policy_constants(policy))
        refs = expr_names(rule.condition)
        has_symbolic = any(isinstance(eval_env.get(n), AbstractValue) for n in refs)
        if not has_symbolic:
            try:
                if not safe_eval(rule.condition, eval_env):
                    return False
            except Exception:
                pass  # can't evaluate — apply rule conservatively

    return True


# ===================================================================
# Z3 condition checking
# ===================================================================

def _check_z3_condition(
    category: str,
    tool_name: str,
    condition: str,
    resolved: dict[str, Any],
    abstract_result: AbstractValue | None,
    step_label: str,
    constants: dict[str, Any],
    spec: ToolSpec,
    result: VerificationResult,
) -> None:
    # Build Z3 env
    z3_env: dict[str, Any] = {}
    has_symbolic: set[str] = set()

    for p in spec.params:
        val = resolved.get(p.name)
        if val is None:
            continue
        if isinstance(val, AbstractValue):
            z3_env[p.name] = _make_z3_symbolic(p.name, p.type)
            has_symbolic.add(p.name)
        else:
            z3_val = _make_z3_literal(val)
            if z3_val is not None:
                z3_env[p.name] = z3_val

    # Postcondition: add "result" using the tool's declared return_type
    if category == "postcondition" and "result" in condition:
        if abstract_result is not None:
            z3_env["result"] = _make_z3_symbolic("result", spec.return_type)
            has_symbolic.add("result")

    if not z3_env:
        return

    z3_env.update(constants)

    # Forall conditions: non-vacuity check
    if condition.strip().startswith("forall "):
        _check_z3_forall(category, condition, step_label, spec, z3_env, has_symbolic, result)
        return

    # Translate and check — catch Z3 sort/type errors
    try:
        z3_expr = condition_to_z3(condition, z3_env)
    except Exception:
        z3_expr = None

    if z3_expr is None:
        result.warn(
            f"Could not parse {category} '{condition}' for "
            f"'{spec.name}' into Z3 — skipped"
        )
        return

    try:
        solver = z3.Solver()
        solver.set("timeout", 5000)
        solver.add(z3.Not(z3_expr))
        check = solver.check()
    except z3.Z3Exception:
        result.warn(
            f"Z3 error checking {category} '{condition}' for "
            f"'{spec.name}' — skipped"
        )
        return

    if check == z3.sat:
        cond_refs = expr_names(condition) & set(z3_env.keys())
        referenced_concrete = {p for p in z3_env if p not in has_symbolic}
        is_definite = cond_refs.issubset(referenced_concrete)
        severity = "violated" if is_definite else "could be violated"

        if not is_definite and category == "postcondition" and "result" in has_symbolic:
            result.warn(
                f"{category.title()} '{condition}' for '{spec.name}' "
                f"could be violated (symbolic result — checked at runtime)"
            )
        else:
            result.add(Violation(
                category=category,
                message=f"{category.title()} '{condition}' for '{spec.name}' {severity}",
                step_label=step_label,
                rule_name=f"{category}:{spec.name}:{condition}",
            ))


def _check_z3_forall(
    category: str,
    condition: str,
    step_label: str,
    spec: ToolSpec,
    z3_env: dict[str, Any],
    has_symbolic: set[str],
    result: VerificationResult,
) -> None:
    """Check a forall frame/postcondition for non-vacuity."""
    z3_only = {k: v for k, v in z3_env.items() if isinstance(v, z3.ExprRef)}
    parsed = _parse_forall_condition(condition, z3_only)
    if parsed is None:
        result.warn(
            f"Could not parse {category} '{condition}' for "
            f"'{spec.name}' into Z3 — skipped"
        )
        return

    antecedent, _qvar = parsed

    solver = z3.Solver()
    solver.set("timeout", 5000)
    solver.add(antecedent)
    check = solver.check()

    if check == z3.unsat:
        cond_refs = set(re.findall(r'\b(\w+)\b', condition)) & set(z3_only.keys())
        referenced_concrete = {p for p in z3_only if p not in has_symbolic}
        is_definite = cond_refs.issubset(referenced_concrete)
        severity = "vacuous" if is_definite else "could be vacuous"
        result.add(Violation(
            category=category,
            message=(
                f"{category.title()} '{condition}' for '{spec.name}' "
                f"is {severity} — scope covers everything"
            ),
            step_label=step_label,
            rule_name=f"{category}:{spec.name}:{condition}",
        ))
    elif check == z3.unknown:
        result.warn(
            f"{category.title()} '{condition}' for '{spec.name}' "
            f"— Z3 timeout on non-vacuity check"
        )


def _parse_forall_condition(
    condition: str, z3_vars: dict[str, z3.ExprRef],
) -> tuple[z3.BoolRef, z3.ExprRef] | None:
    m = re.match(
        r"forall\s+(\w+)\s*:\s*(not\s+)?matches\((\w+)\s*,\s*(\w+)\)"
        r"\s+implies\s+(\w+)\((\w+)\)",
        condition.strip(),
    )
    if not m:
        return None

    qvar_name = m.group(1)
    negated = m.group(2) is not None
    match_var = m.group(3)
    pattern_param = m.group(4)

    if match_var != qvar_name:
        return None
    if pattern_param not in z3_vars:
        return None

    qvar = z3.String(qvar_name)
    match_expr = _build_glob_match(qvar, z3_vars[pattern_param])
    antecedent = z3.Not(match_expr) if negated else match_expr

    return antecedent, qvar


def _build_glob_match(var: z3.ExprRef, pattern: z3.ExprRef) -> z3.BoolRef:
    if z3.is_string_value(pattern):
        p = pattern.as_string()
        if p == "*":
            return z3.BoolVal(True)
        if p.startswith("*") and not p.endswith("*"):
            return z3.SuffixOf(z3.StringVal(p[1:]), var)
        if p.endswith("*") and not p.startswith("*"):
            return z3.PrefixOf(z3.StringVal(p[:-1]), var)
        return var == pattern
    glob_fn = z3.Function(
        "glob_matches", z3.StringSort(), z3.StringSort(), z3.BoolSort(),
    )
    return glob_fn(var, pattern)


# ===================================================================
# Automaton checking
# ===================================================================

def _check_automata(
    policy: Policy,
    tool_name: str,
    resolved: dict[str, Any],
    step_label: str,
    automaton_states: dict[str, set[str]],
    result: VerificationResult,
) -> None:
    for automaton in policy.automata:
        current_states = automaton_states[automaton.name]
        error_states = {s.name for s in automaton.states if s.is_error}
        next_states: set[str] = set()

        for current in current_states:
            transitioned = False
            for trans in automaton.transitions:
                if trans.from_state != current or trans.tool_name != tool_name:
                    continue

                if trans.condition:
                    eval_env: dict[str, Any] = {}
                    eval_env.update(resolved)
                    eval_env.update(automaton.constants)
                    refs = expr_names(trans.condition)
                    has_symbolic = any(
                        isinstance(eval_env.get(n), AbstractValue) for n in refs
                    )

                    if has_symbolic:
                        next_states.add(current)
                        if trans.to_state in error_states:
                            result.add(Violation(
                                category="automaton",
                                message=(
                                    f"Security automaton '{automaton.name}' "
                                    f"could reach error state '{trans.to_state}' "
                                    f"on tool call '{tool_name}' (symbolic argument)"
                                ),
                                step_label=step_label,
                                rule_name=automaton.name,
                            ))
                        next_states.add(trans.to_state)
                        transitioned = True
                        break

                    try:
                        fires = safe_eval(trans.condition, eval_env)
                    except Exception:
                        fires = True  # fail closed

                    if not fires:
                        continue

                if trans.to_state in error_states:
                    result.add(Violation(
                        category="automaton",
                        message=(
                            f"Security automaton '{automaton.name}' "
                            f"reached error state '{trans.to_state}' "
                            f"on tool call '{tool_name}'"
                        ),
                        step_label=step_label,
                        rule_name=automaton.name,
                    ))
                next_states.add(trans.to_state)
                transitioned = True
                break

            if not transitioned:
                next_states.add(current)

        automaton_states[automaton.name] = next_states


# ===================================================================
# Helpers: resolve, collect, copy
# ===================================================================

def _resolve_abstract(arguments: dict[str, Any], env: dict[str, AbstractValue]) -> dict[str, Any]:
    return {k: _resolve_val(v, env) for k, v in arguments.items()}


def _resolve_val(val: Any, env: dict[str, AbstractValue]) -> Any:
    if isinstance(val, SymRef):
        return env.get(val.ref, AbstractValue(source_tool="unknown"))
    if isinstance(val, dict):
        return {k: _resolve_val(v, env) for k, v in val.items()}
    if isinstance(val, list):
        return [_resolve_val(v, env) for v in val]
    return val


def _collect_labels(val: Any) -> set[str]:
    """Collect taint labels recursively from a resolved value tree."""
    labels: set[str] = set()
    _walk_labels(val, labels)
    return labels


def _walk_labels(val: Any, labels: set[str]) -> None:
    if isinstance(val, AbstractValue):
        labels.update(val.labels)
    elif isinstance(val, dict):
        for v in val.values():
            _walk_labels(v, labels)
    elif isinstance(val, list):
        for v in val:
            _walk_labels(v, labels)


def _collect_provenance(val: Any) -> set[str]:
    """Collect provenance (contributing tool names) recursively."""
    prov: set[str] = set()
    _walk_provenance(val, prov)
    return prov


def _walk_provenance(val: Any, prov: set[str]) -> None:
    if isinstance(val, AbstractValue):
        prov.update(val.provenance)
    elif isinstance(val, dict):
        for v in val.values():
            _walk_provenance(v, prov)
    elif isinstance(val, list):
        for v in val:
            _walk_provenance(v, prov)


def _find_all_abstracts(val: Any) -> list[AbstractValue]:
    """Find ALL AbstractValues nested in a resolved value tree."""
    results: list[AbstractValue] = []
    _walk_abstracts(val, results)
    return results


def _walk_abstracts(val: Any, results: list[AbstractValue]) -> None:
    if isinstance(val, AbstractValue):
        results.append(val)
    elif isinstance(val, dict):
        for v in val.values():
            _walk_abstracts(v, results)
    elif isinstance(val, list):
        for v in val:
            _walk_abstracts(v, results)


def _copy_env(env: dict[str, AbstractValue]) -> dict[str, AbstractValue]:
    return {
        k: AbstractValue(
            labels=set(v.labels),
            sanitized_for=set(v.sanitized_for),
            source_tool=v.source_tool,
            provenance=set(v.provenance),
        )
        for k, v in env.items()
    }


def _copy_auto(states: dict[str, set[str]]) -> dict[str, set[str]]:
    return {k: set(v) for k, v in states.items()}


def _env_converged(old: dict[str, AbstractValue], new: dict[str, AbstractValue]) -> bool:
    if set(old.keys()) != set(new.keys()):
        return False
    for k in old:
        o = old[k]
        n = new.get(k)
        if n is None:
            return False
        if o.labels != n.labels or o.sanitized_for != n.sanitized_for:
            return False
        if o.provenance != n.provenance:
            return False
    return True


def _collect_policy_constants(policy: Policy) -> dict[str, Any]:
    constants: dict[str, Any] = {}
    for automaton in policy.automata:
        constants.update(automaton.constants)
    return constants


# ===================================================================
# Z3 helpers
# ===================================================================

def _make_z3_symbolic(name: str, type_hint: str) -> z3.ExprRef:
    if type_hint in ("int", "float"):
        return z3.Int(name)
    if type_hint == "bool":
        return z3.Bool(name)
    return z3.String(name)


def _make_z3_literal(val: Any) -> z3.ExprRef | None:
    if isinstance(val, str):
        return z3.StringVal(val)
    if isinstance(val, bool):
        return z3.BoolVal(val)
    if isinstance(val, int):
        return z3.IntVal(val)
    if isinstance(val, float):
        return z3.IntVal(int(val))
    return None
