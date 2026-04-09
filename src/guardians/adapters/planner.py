"""Planner protocol and prompt-formatting helpers.

No external dependencies beyond the core.
"""

from __future__ import annotations

import json
from typing import Protocol

from ..policy import Policy
from ..results import VerificationResult, Violation
from ..tools import ToolRegistry
from ..verify import verify
from ..workflow import Workflow


class Planner(Protocol):
    """Protocol for workflow planners (LLM or otherwise)."""

    def generate(
        self,
        goal: str,
        registry: ToolRegistry,
        policy: Policy,
    ) -> Workflow:
        """Generate a workflow from a user goal."""
        ...


def verified_generate(
    planner: Planner,
    goal: str,
    registry: ToolRegistry,
    policy: Policy,
    *,
    max_attempts: int = 3,
) -> tuple[Workflow | None, VerificationResult]:
    """Generate a workflow and verify it, retrying with violation feedback.

    Returns (workflow, result). If all attempts fail, workflow is None.
    """
    violations_feedback = ""
    result = VerificationResult()

    for _attempt in range(max_attempts):
        current_goal = goal
        if violations_feedback:
            current_goal = (
                f"{goal}\n\n"
                f"IMPORTANT — your previous workflow was REJECTED by the "
                f"static verifier with these violations:\n"
                f"{violations_feedback}\n"
                f"You MUST fix these issues."
            )

        try:
            workflow = planner.generate(current_goal, registry, policy)
        except Exception as exc:
            result = VerificationResult()
            result.add(Violation(
                category="generation",
                message=f"Planner failed: {exc}",
                step_label="",
            ))
            continue

        result = verify(workflow, policy, registry)
        if result.ok:
            return workflow, result

        violations_feedback = "\n".join(
            f"- [{v.category}] {v.message}" for v in result.violations
        )

    return None, result


# --- Prompt formatting helpers ---

def format_tool_specs(registry: ToolRegistry) -> str:
    """Format tool specs as JSON for an LLM prompt."""
    specs = {}
    for name, spec in registry.all_specs().items():
        params_desc = []
        for p in spec.params:
            sink = " [TAINT SINK]" if p.is_taint_sink else ""
            params_desc.append(f"{p.name}: {p.type}{sink} — {p.description}")
        specs[name] = {
            "description": spec.description,
            "params": params_desc if params_desc else ["(none)"],
            "return_type": spec.return_type,
        }
        if spec.source_labels:
            specs[name]["taint_labels"] = spec.source_labels
    return json.dumps(specs, indent=2)


def format_policy_summary(policy: Policy) -> str:
    """Format a policy into a human-readable summary for an LLM prompt."""
    lines = [f"Allowed tools: {', '.join(policy.allowed_tools)}"]
    for rule in policy.taint_rules:
        sanitizer_note = ""
        if rule.sanitizers:
            sanitizer_note = f" (UNLESS data passes through: {', '.join(rule.sanitizers)})"
        lines.append(
            f"FORBIDDEN: data from {rule.source_tool} must not flow to "
            f"{rule.sink_tool}.{rule.sink_param}{sanitizer_note}"
        )
    for automaton in policy.automata:
        for trans in automaton.transitions:
            for state in automaton.states:
                if state.name == trans.to_state and state.is_error:
                    cond = trans.condition or "always"
                    lines.append(f"FORBIDDEN: {trans.tool_name} when {cond}")
    return "\n".join(lines)


WORKFLOW_SYSTEM_PROMPT = """\
You are generating a structured workflow plan. Return valid JSON matching this schema:
{
  "goal": "<the user's goal>",
  "input_variables": [],
  "steps": [
    {
      "label": "Human-readable step description",
      "tool_call": {
        "tool_name": "<tool name>",
        "arguments": {"param": "literal_value", "param2": {"ref": "var_name"}},
        "result_binding": "var_name"
      }
    }
  ]
}

Rules:
- Only use tools from the provided specifications.
- Use {"ref": "var_name"} for symbolic variable references.
- Never embed concrete user data — use symbolic refs for data flow.
- Do NOT list result_binding names in input_variables.
- Each step needs exactly one of: tool_call, conditional, or loop.

For conditionals:
{"label": "...", "conditional": {"condition": "expr", "then_steps": [...], "else_steps": [...]}}

For loops:
{"label": "...", "loop": {"collection_ref": "var", "item_binding": "item", "body": [...]}}
"""
