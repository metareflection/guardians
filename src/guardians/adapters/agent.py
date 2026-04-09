"""GuardedAgent — high-level API over the verification engine.

Tools are decorated functions, security rules are method calls,
run() does generate -> verify -> execute in one step.
"""

from __future__ import annotations

import inspect
from dataclasses import dataclass, field
from typing import Any, Callable

from ..errors import SecurityViolation
from ..execute import WorkflowExecutor
from ..policy import (
    AutomatonState,
    AutomatonTransition,
    Policy,
    SecurityAutomaton,
    TaintRule,
)
from ..tools import ParamSpec, ToolRegistry, ToolSpec
from ..verify import verify
from ..workflow import Workflow
from .planner import Planner, verified_generate


@dataclass
class AgentResult:
    """Result of a guarded agent run."""

    goal: str
    env: dict[str, Any]
    trace: list[dict[str, Any]]
    workflow: Workflow


class GuardedAgent:
    """High-level API for building guarded AI agents.

    Tools are registered with @agent.tool, security rules with
    agent.deny() and agent.no_data_flow(), and agent.run() does
    the full generate -> verify -> execute pipeline.
    """

    def __init__(
        self,
        name: str,
        *,
        planner: Planner | None = None,
        max_attempts: int = 3,
    ):
        self.name = name
        self._planner = planner
        self.max_attempts = max_attempts
        self._registry = ToolRegistry()
        self._tool_names: list[str] = []
        self._automata: list[SecurityAutomaton] = []
        self._taint_rules: list[TaintRule] = []
        self._deny_counter = 0

    # --- Tool registration ---

    def tool(
        self,
        fn: Callable | None = None,
        *,
        taint_labels: list[str] | None = None,
        sink_params: list[str] | None = None,
        preconditions: list[str] | None = None,
        postconditions: list[str] | None = None,
        frame_conditions: list[str] | None = None,
        description: str | None = None,
    ) -> Callable:
        """Register a function as a guarded tool.

        Can be used as @agent.tool or @agent.tool(taint_labels=[...]).
        """
        def decorator(func: Callable) -> Callable:
            spec = _spec_from_function(
                func,
                taint_labels=taint_labels or [],
                sink_params=sink_params or [],
                preconditions=preconditions or [],
                postconditions=postconditions or [],
                frame_conditions=frame_conditions or [],
                description=description,
            )
            self._registry.register(spec, func)
            self._tool_names.append(spec.name)
            return func

        if fn is not None:
            return decorator(fn)
        return decorator

    # --- Security rules ---

    def deny(
        self,
        tool: str,
        param: str,
        *,
        not_in_domain: list[str] | None = None,
        not_in: list[str] | None = None,
    ) -> None:
        """Forbid a tool call when an argument violates a constraint."""
        self._validate_tool_param(tool, param)
        if not_in_domain:
            self._deny_counter += 1
            values = repr(not_in_domain)
            name = f"deny_{tool}_{param}_{self._deny_counter}"
            self._automata.append(SecurityAutomaton(
                name=name,
                states=[
                    AutomatonState(name="safe"),
                    AutomatonState(name="error", is_error=True),
                ],
                initial_state="safe",
                transitions=[
                    AutomatonTransition(
                        from_state="safe",
                        to_state="error",
                        tool_name=tool,
                        condition=f"domain_of({param}) not in {values}",
                    ),
                ],
            ))
            spec = self._registry.get_spec(tool)
            if spec is not None:
                spec.preconditions.append(f"domain_of({param}) in {values}")

        if not_in:
            self._deny_counter += 1
            values = repr(not_in)
            name = f"deny_{tool}_{param}_{self._deny_counter}"
            self._automata.append(SecurityAutomaton(
                name=name,
                states=[
                    AutomatonState(name="safe"),
                    AutomatonState(name="error", is_error=True),
                ],
                initial_state="safe",
                transitions=[
                    AutomatonTransition(
                        from_state="safe",
                        to_state="error",
                        tool_name=tool,
                        condition=f"{param} not in {values}",
                    ),
                ],
            ))
            spec = self._registry.get_spec(tool)
            if spec is not None:
                spec.preconditions.append(f"{param} in {values}")

    def no_data_flow(
        self,
        source: str,
        *,
        to: str,
        unless_through: list[str] | None = None,
    ) -> None:
        """Forbid tainted data from source reaching a sink.

        The `to` parameter uses "tool.param" syntax.
        """
        if "." not in to:
            raise ValueError(f"'to' must be 'tool.param' format, got '{to}'")
        sink_tool, sink_param = to.rsplit(".", 1)
        self._validate_tool_param(sink_tool, sink_param)
        if self._registry.get_spec(source) is None:
            raise ValueError(f"Unknown source tool: {source!r}")
        self._taint_rules.append(TaintRule(
            name=f"no_flow_{source}_to_{sink_tool}_{sink_param}",
            source_tool=source,
            sink_tool=sink_tool,
            sink_param=sink_param,
            sanitizers=unless_through or [],
        ))

    def require_before(
        self,
        tool: str,
        *,
        steps: list[str],
    ) -> None:
        """Require a sequence of tools before tool is allowed."""
        if self._registry.get_spec(tool) is None:
            raise ValueError(f"Unknown tool: {tool!r}")
        for s in steps:
            if self._registry.get_spec(s) is None:
                raise ValueError(f"Unknown tool in steps: {s!r}")

        state_names = ["start"] + [f"after_{s}" for s in steps]
        states = [AutomatonState(name=n) for n in state_names]
        states.append(AutomatonState(name="error", is_error=True))

        transitions = []
        for i, step_tool in enumerate(steps):
            transitions.append(AutomatonTransition(
                from_state=state_names[i],
                to_state=state_names[i + 1],
                tool_name=step_tool,
            ))
        for state_name in state_names[:-1]:
            transitions.append(AutomatonTransition(
                from_state=state_name,
                to_state="error",
                tool_name=tool,
            ))

        self._automata.append(SecurityAutomaton(
            name=f"require_before_{tool}",
            states=states,
            initial_state="start",
            transitions=transitions,
        ))

    def require_count(
        self,
        tool: str,
        *,
        min: int,
        before: str,
    ) -> None:
        """Require tool is called at least min times before target."""
        if self._registry.get_spec(tool) is None:
            raise ValueError(f"Unknown tool: {tool!r}")
        if self._registry.get_spec(before) is None:
            raise ValueError(f"Unknown tool: {before!r}")

        state_names = [f"count_{i}" for i in range(min + 1)]
        states = [AutomatonState(name=n) for n in state_names]
        states.append(AutomatonState(name="error", is_error=True))

        transitions = []
        for i in range(min):
            transitions.append(AutomatonTransition(
                from_state=state_names[i],
                to_state=state_names[i + 1],
                tool_name=tool,
            ))
        for i in range(min):
            transitions.append(AutomatonTransition(
                from_state=state_names[i],
                to_state="error",
                tool_name=before,
            ))

        self._automata.append(SecurityAutomaton(
            name=f"min_{min}_{tool}_before_{before}",
            states=states,
            initial_state="count_0",
            transitions=transitions,
        ))

    def _validate_tool_param(self, tool: str, param: str) -> None:
        spec = self._registry.get_spec(tool)
        if spec is None:
            raise ValueError(f"Unknown tool: {tool!r}")
        if not any(p.name == param for p in spec.params):
            raise ValueError(f"Tool {tool!r} has no parameter {param!r}")

    # --- Build policy ---

    def _build_policy(self) -> Policy:
        return Policy(
            name=self.name,
            allowed_tools=list(self._tool_names),
            automata=list(self._automata),
            taint_rules=list(self._taint_rules),
        )

    # --- Run ---

    def run(
        self,
        goal: str,
        *,
        auto_approve: bool = True,
        budgets: dict[str, int] | None = None,
    ) -> AgentResult:
        """Generate, verify, and execute a workflow from a goal."""
        if self._planner is None:
            raise RuntimeError(
                "No planner configured. Pass a Planner to GuardedAgent() "
                "or use run_workflow() with a pre-built workflow."
            )

        policy = self._build_policy()
        workflow, result = verified_generate(
            self._planner,
            goal=goal,
            registry=self._registry,
            policy=policy,
            max_attempts=self.max_attempts,
        )

        if workflow is None:
            violations = "\n".join(
                f"  [{v.category}] {v.message}" for v in result.violations
            )
            raise SecurityViolation(
                f"Workflow generation failed after {self.max_attempts} "
                f"attempts:\n{violations}"
            )

        executor = WorkflowExecutor(
            self._registry, policy,
            auto_approve=auto_approve,
            budgets=budgets,
            verify_first=False,  # already verified above
        )
        executor.run(workflow)

        return AgentResult(
            goal=goal,
            env=dict(executor.env),
            trace=executor.trace,
            workflow=workflow,
        )

    def verify_goal(self, goal: str) -> tuple[Workflow | None, Any]:
        """Generate and verify without executing. Dry run."""
        if self._planner is None:
            raise RuntimeError("No planner configured.")
        policy = self._build_policy()
        return verified_generate(
            self._planner,
            goal=goal,
            registry=self._registry,
            policy=policy,
            max_attempts=self.max_attempts,
        )

    def run_workflow(
        self,
        workflow: Workflow,
        *,
        auto_approve: bool = True,
        budgets: dict[str, int] | None = None,
    ) -> AgentResult:
        """Execute a pre-built workflow (skip generation)."""
        policy = self._build_policy()

        result = verify(workflow, policy, self._registry)
        if not result.ok:
            violations = "\n".join(
                f"  [{v.category}] {v.message}" for v in result.violations
            )
            raise SecurityViolation(
                f"Workflow failed verification:\n{violations}"
            )

        executor = WorkflowExecutor(
            self._registry, policy,
            auto_approve=auto_approve,
            budgets=budgets,
            verify_first=False,  # already verified above
        )
        executor.run(workflow)

        return AgentResult(
            goal=workflow.goal,
            env=dict(executor.env),
            trace=executor.trace,
            workflow=workflow,
        )


# --- Helpers ---

_TYPE_MAP = {
    str: "str",
    int: "int",
    float: "float",
    bool: "bool",
    list: "list",
    dict: "dict",
}


def _type_hint_to_str(hint: Any) -> str:
    if hint is inspect.Parameter.empty:
        return "str"
    if hint in _TYPE_MAP:
        return _TYPE_MAP[hint]
    origin = getattr(hint, "__origin__", None)
    if origin is not None:
        return str(hint).replace("typing.", "")
    if isinstance(hint, type):
        return hint.__name__
    return str(hint)


def _spec_from_function(
    func: Callable,
    *,
    taint_labels: list[str],
    sink_params: list[str],
    preconditions: list[str],
    postconditions: list[str],
    frame_conditions: list[str],
    description: str | None,
) -> ToolSpec:
    """Derive a ToolSpec from a function's signature and type hints."""
    sig = inspect.signature(func)
    hints = func.__annotations__

    params = []
    for name, _param in sig.parameters.items():
        type_str = _type_hint_to_str(hints.get(name, inspect.Parameter.empty))
        params.append(ParamSpec(
            name=name,
            type=type_str,
            is_taint_sink=name in sink_params,
        ))

    return_hint = hints.get("return")
    return_type = _type_hint_to_str(return_hint) if return_hint else "Any"

    return ToolSpec(
        name=func.__name__,
        description=description or (func.__doc__ or "").strip(),
        params=params,
        return_type=return_type,
        preconditions=list(preconditions),
        postconditions=list(postconditions),
        frame_conditions=list(frame_conditions),
        source_labels=list(taint_labels),
    )
