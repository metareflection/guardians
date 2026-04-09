"""Tests for planner helpers (no LLM required)."""

import json

from guardians.tools import ToolSpec, ParamSpec, ToolRegistry
from guardians.policy import (
    Policy, SecurityAutomaton, AutomatonState, AutomatonTransition, TaintRule,
)
from guardians.adapters.planner import format_tool_specs, format_policy_summary


def test_format_tool_specs():
    r = ToolRegistry()
    r.register(
        ToolSpec(
            name="send_email",
            description="Send an email",
            params=[
                ParamSpec(name="to", type="str", is_taint_sink=True),
                ParamSpec(name="body", type="str"),
            ],
            source_labels=["email_content"],
        ),
        lambda to="", body="": None,
    )
    result = format_tool_specs(r)
    parsed = json.loads(result)
    assert "send_email" in parsed
    assert parsed["send_email"]["description"] == "Send an email"
    assert any("TAINT SINK" in p for p in parsed["send_email"]["params"])
    assert parsed["send_email"]["taint_labels"] == ["email_content"]


def test_format_policy_summary():
    policy = Policy(
        name="test",
        allowed_tools=["fetch_mail", "send_email"],
        automata=[
            SecurityAutomaton(
                name="no_ext",
                states=[
                    AutomatonState(name="safe"),
                    AutomatonState(name="error", is_error=True),
                ],
                initial_state="safe",
                transitions=[
                    AutomatonTransition(
                        from_state="safe",
                        to_state="error",
                        tool_name="send_email",
                        condition="domain_of(to) not in allowed_domains",
                    ),
                ],
            ),
        ],
        taint_rules=[
            TaintRule(
                name="no_exfil",
                source_tool="fetch_mail",
                sink_tool="send_email",
                sink_param="body",
                sanitizers=["redact"],
            ),
        ],
    )
    result = format_policy_summary(policy)
    assert "fetch_mail, send_email" in result
    assert "FORBIDDEN" in result
    assert "redact" in result
