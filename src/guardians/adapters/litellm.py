"""LiteLLM-based workflow planner.

Requires the `llm` extra: pip install guardians[llm]
"""

from __future__ import annotations

import json
import os

from ..policy import Policy
from ..tools import ToolRegistry
from ..workflow import Workflow
from .planner import WORKFLOW_SYSTEM_PROMPT, format_policy_summary, format_tool_specs

_DEFAULT_MODEL = "bedrock/global.anthropic.claude-sonnet-4-6"


class LiteLLMPlanner:
    """Planner implementation using LiteLLM for LLM calls."""

    def __init__(
        self,
        *,
        model: str | None = None,
        retries: int = 2,
    ):
        self.model = model or os.environ.get("GUARDIANS_MODEL", _DEFAULT_MODEL)
        self.retries = retries

    def generate(
        self,
        goal: str,
        registry: ToolRegistry,
        policy: Policy,
    ) -> Workflow:
        try:
            import litellm
        except ImportError:
            raise ImportError(
                "litellm is required for LiteLLMPlanner. "
                "Install it with: pip install guardians[llm]"
            )

        tool_specs_json = format_tool_specs(registry)
        policy_summary = format_policy_summary(policy)

        user_msg = (
            f"Available tools:\n{tool_specs_json}\n\n"
            f"Security policy:\n{policy_summary}\n\n"
            f"User goal:\n{goal}\n\n"
            f"Return ONLY the JSON workflow, no other text."
        )

        last_exc: Exception | None = None
        for _attempt in range(1 + self.retries):
            try:
                response = litellm.completion(
                    model=self.model,
                    messages=[
                        {"role": "system", "content": WORKFLOW_SYSTEM_PROMPT},
                        {"role": "user", "content": user_msg},
                    ],
                )
                raw = response.choices[0].message.content
                # Strip markdown fences if present
                raw = raw.strip()
                if raw.startswith("```"):
                    raw = raw.split("\n", 1)[1]
                if raw.endswith("```"):
                    raw = raw.rsplit("```", 1)[0]
                raw = raw.strip()

                return Workflow.model_validate_json(raw)
            except Exception as exc:
                last_exc = exc

        raise ValueError(
            f"LLM failed to generate valid workflow after {1 + self.retries} "
            f"attempts: {last_exc}"
        )
