"""Runtime workflow executor with monitoring.

Explicit executor — no effect handlers. Walks the workflow AST,
resolving SymRefs and enforcing policy at each step.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from .errors import SecurityViolation
from .policy import Policy
from .safe_eval import safe_eval
from .conditions import expr_names
from .tools import ToolRegistry
from .workflow import Workflow, WorkflowStep, SymRef


@dataclass
class TaintedValue:
    """A runtime value with taint metadata.

    Tool implementations receive the unwrapped `raw` value.
    The executor tracks labels for runtime taint checking.
    """

    raw: Any
    labels: set[str] = field(default_factory=set)
    sanitized_for: set[str] = field(default_factory=set)


class WorkflowExecutor:
    """Execute a verified workflow with runtime monitoring."""

    def __init__(
        self,
        registry: ToolRegistry,
        policy: Policy,
        *,
        auto_approve: bool = False,
        budgets: dict[str, int] | None = None,
        verify_first: bool = True,
    ):
        self.registry = registry
        self.policy = policy
        self.auto_approve = auto_approve
        self.verify_first = verify_first
        self._budgets = budgets or {}
        self._used: dict[str, int] = {}
        self._env: dict[str, TaintedValue | Any] = {}
        self.trace: list[dict[str, Any]] = []
        self._automaton_states: dict[str, str] = {
            a.name: a.initial_state for a in policy.automata
        }

    @property
    def env(self) -> "_EnvProxy":
        """Env proxy: reads unwrap TaintedValues, writes wrap raw values."""
        return _EnvProxy(self._env)

    def run(self, workflow: Workflow) -> "WorkflowExecutor":
        """Execute the workflow."""
        if self.verify_first:
            from .verify import verify
            result = verify(workflow, self.policy, self.registry)
            if not result.ok:
                violations = "\n".join(
                    f"  [{v.category}] {v.message}" for v in result.violations
                )
                raise SecurityViolation(
                    f"Workflow failed verification:\n{violations}"
                )

        # Approval gate
        if not self.auto_approve:
            self._request_approval(workflow)

        # Seed input variables into env
        for name in workflow.input_variables:
            if name not in self._env:
                self._env[name] = TaintedValue(raw=None)

        self._run_steps(workflow.steps)
        return self

    def _run_steps(self, steps: list[WorkflowStep]) -> None:
        for step in steps:
            if step.tool_call:
                self._run_tool_call(step)
            elif step.conditional:
                self._run_conditional(step)
            elif step.loop:
                self._run_loop(step)

    def _run_tool_call(self, step: WorkflowStep) -> None:
        tc = step.tool_call
        assert tc is not None
        spec = self.registry.get_spec(tc.tool_name)

        # 1. Allowlist
        if tc.tool_name not in set(self.policy.allowed_tools):
            raise SecurityViolation(
                f"Tool '{tc.tool_name}' is not in the allowed tools list"
            )

        # 2. Missing spec
        if spec is None:
            raise SecurityViolation(
                f"Tool '{tc.tool_name}' is allowed but has no registered spec"
            )

        # 3. Resolve arguments
        resolved = {k: self._resolve(v) for k, v in tc.arguments.items()}
        raw_args = {k: _unwrap(v) for k, v in resolved.items()}

        # 4. Preconditions
        constants = self._collect_constants()
        for pre in spec.preconditions:
            eval_env = {**raw_args, **constants}
            try:
                holds = safe_eval(pre, eval_env)
            except Exception:
                holds = False
            if not holds:
                raise SecurityViolation(
                    f"Runtime invariant 'precondition:{tc.tool_name}:{pre}' violated"
                )

        # 5. Automata (before call)
        for automaton in self.policy.automata:
            current = self._automaton_states[automaton.name]
            error_states = {s.name for s in automaton.states if s.is_error}
            for trans in automaton.transitions:
                if trans.from_state != current or trans.tool_name != tc.tool_name:
                    continue
                if trans.condition:
                    eval_env = {**raw_args, **automaton.constants}
                    try:
                        if not safe_eval(trans.condition, eval_env):
                            continue
                    except Exception:
                        continue
                self._automaton_states[automaton.name] = trans.to_state
                if trans.to_state in error_states:
                    raise SecurityViolation(
                        f"Security automaton '{automaton.name}' "
                        f"reached error state '{trans.to_state}' "
                        f"on tool call '{tc.tool_name}'"
                    )
                break

        # 6. Budget
        self._tick("tool_call")

        # 7. Execute
        impl = self.registry.get_impl(tc.tool_name)
        if impl is None:
            raise SecurityViolation(
                f"No implementation registered for tool '{tc.tool_name}'"
            )
        result = impl(**raw_args)
        self.trace.append({"tool": tc.tool_name, "args": raw_args, "result": result})

        # 8. Wrap result with taint
        input_labels = _collect_taint_labels(resolved)
        spec_labels = set(spec.source_labels)
        wrapped = TaintedValue(
            raw=result,
            labels=spec_labels | input_labels,
            sanitized_for=set(),
        )

        # 9. Apply sanitizer logic
        for rule in self.policy.taint_rules:
            if tc.tool_name in rule.sanitizers:
                wrapped.sanitized_for.add(rule.name)

        # 10. Postconditions
        for post in spec.postconditions:
            eval_env = {**raw_args, **constants, "result": result}
            try:
                holds = safe_eval(post, eval_env)
            except Exception:
                holds = False
            if not holds:
                raise SecurityViolation(
                    f"Runtime invariant 'postcondition:{tc.tool_name}:{post}' violated"
                )

        # 11. Bind result
        if tc.result_binding:
            self._env[tc.result_binding] = wrapped

    def _run_conditional(self, step: WorkflowStep) -> None:
        c = step.conditional
        assert c is not None

        eval_env = self._build_condition_env(c.condition)
        try:
            cond_val = safe_eval(c.condition, eval_env)
        except Exception:
            raise SecurityViolation(
                f"Could not evaluate condition '{c.condition}' at runtime"
            )

        before_keys = set(self._env.keys())

        if cond_val:
            self._run_steps(c.then_steps)
        else:
            self._run_steps(c.else_steps)

        # Scope enforcement: only bindings created in BOTH branches
        # escape the conditional, matching verifier semantics.
        then_bindings = _bindings_from_steps(c.then_steps)
        else_bindings = _bindings_from_steps(c.else_steps)
        allowed_new = then_bindings & else_bindings
        for k in list(self._env.keys()):
            if k not in before_keys and k not in allowed_new:
                del self._env[k]

    def _run_loop(self, step: WorkflowStep) -> None:
        lp = step.loop
        assert lp is not None

        collection_val = self._env.get(lp.collection_ref)
        collection = _unwrap(collection_val)

        if not isinstance(collection, (list, tuple)):
            raise SecurityViolation(
                f"Loop collection '{lp.collection_ref}' is not iterable"
            )

        if lp.item_binding in self._env:
            raise SecurityViolation(
                f"Loop item binding '{lp.item_binding}' shadows outer variable"
            )

        before_keys = set(self._env.keys())
        taint_labels = set()
        if isinstance(collection_val, TaintedValue):
            taint_labels = collection_val.labels

        for item in collection:
            self._tick("loop_iter")
            self._env[lp.item_binding] = TaintedValue(
                raw=item, labels=set(taint_labels),
            )
            self._run_steps(lp.body)
            # Per-iteration cleanup: body-local bindings do not leak
            # across iterations, matching verifier semantics.
            for k in list(self._env.keys()):
                if k not in before_keys:
                    del self._env[k]

    # --- Helpers ---

    def _resolve(self, val: Any) -> Any:
        """Resolve SymRefs to env values. Recursive over dicts/lists."""
        if isinstance(val, SymRef):
            v = self._env.get(val.ref)
            if v is None:
                raise SecurityViolation(f"Undefined variable '{val.ref}' at runtime")
            return v
        if isinstance(val, dict):
            return {k: self._resolve(v) for k, v in val.items()}
        if isinstance(val, list):
            return [self._resolve(v) for v in val]
        return val

    def _build_condition_env(self, condition: str) -> dict[str, Any]:
        """Build a safe_eval env for a condition from current env."""
        names = expr_names(condition)
        eval_env: dict[str, Any] = {}
        for name in names:
            val = self._env.get(name)
            if val is not None:
                eval_env[name] = _unwrap(val)
        return eval_env

    def _collect_constants(self) -> dict[str, Any]:
        constants: dict[str, Any] = {}
        for automaton in self.policy.automata:
            constants.update(automaton.constants)
        return constants

    def _request_approval(self, workflow: Workflow) -> None:
        """Show workflow summary and ask user to approve."""
        print(f"\n--- Approval Required ---")
        print(f"Goal: {workflow.goal}")
        for i, step in enumerate(workflow.steps, 1):
            print(f"  {i}. {step.label}")
        print()
        response = input("Approve? [y/N] ").strip().lower()
        if response not in ("y", "yes"):
            raise SecurityViolation("User rejected workflow")

    def _tick(self, kind: str) -> None:
        self._used[kind] = self._used.get(kind, 0) + 1
        limit = self._budgets.get(kind)
        if limit is not None and self._used[kind] > limit:
            raise SecurityViolation(
                f"Budget '{kind}' exceeded: {self._used[kind]} > {limit}"
            )


class _EnvProxy:
    """Dict-like proxy that unwraps TaintedValues on read and wraps on write."""

    def __init__(self, inner: dict[str, Any]):
        self._inner = inner

    def __getitem__(self, key: str) -> Any:
        return _unwrap(self._inner[key])

    def __setitem__(self, key: str, val: Any) -> None:
        if isinstance(val, TaintedValue):
            self._inner[key] = val
        else:
            self._inner[key] = TaintedValue(raw=val)

    def __contains__(self, key: str) -> bool:
        return key in self._inner

    def __iter__(self):
        return iter(self._inner)

    def __len__(self) -> int:
        return len(self._inner)

    def keys(self):
        return self._inner.keys()

    def values(self):
        return [_unwrap(v) for v in self._inner.values()]

    def items(self):
        return [(k, _unwrap(v)) for k, v in self._inner.items()]

    def get(self, key: str, default: Any = None) -> Any:
        if key in self._inner:
            return _unwrap(self._inner[key])
        return default

    def __eq__(self, other: Any) -> bool:
        if isinstance(other, dict):
            return dict(self.items()) == other
        return NotImplemented

    def __repr__(self) -> str:
        return repr(dict(self.items()))


def _bindings_from_steps(steps: list[WorkflowStep]) -> set[str]:
    """Collect result_binding names that a step list would produce.

    Mirrors the verifier's scope rules:
    - tool_call result_bindings are added
    - conditional: only bindings in BOTH branches
    - loop: nothing escapes
    """
    bound: set[str] = set()
    for step in steps:
        if step.tool_call and step.tool_call.result_binding:
            bound.add(step.tool_call.result_binding)
        elif step.conditional:
            then_bound = _bindings_from_steps(step.conditional.then_steps)
            else_bound = _bindings_from_steps(step.conditional.else_steps)
            bound.update(then_bound & else_bound)
        # loop: body bindings do not escape
    return bound


def _unwrap(val: Any) -> Any:
    """Unwrap TaintedValue to raw value, recursively."""
    if isinstance(val, TaintedValue):
        return val.raw
    if isinstance(val, dict):
        return {k: _unwrap(v) for k, v in val.items()}
    if isinstance(val, list):
        return [_unwrap(v) for v in val]
    return val


def _collect_taint_labels(val: Any) -> set[str]:
    """Collect taint labels recursively from resolved values."""
    labels: set[str] = set()
    _walk_taint(val, labels)
    return labels


def _walk_taint(val: Any, labels: set[str]) -> None:
    if isinstance(val, TaintedValue):
        labels.update(val.labels)
    elif isinstance(val, dict):
        for v in val.values():
            _walk_taint(v, labels)
    elif isinstance(val, list):
        for v in val:
            _walk_taint(v, labels)
