"""Tests for the runtime executor."""

import pytest

from guardians.workflow import Workflow, WorkflowStep, ToolCallNode, SymRef
from guardians.tools import ToolSpec, ParamSpec, ToolRegistry
from guardians.policy import (
    Policy, SecurityAutomaton, AutomatonState, AutomatonTransition,
)
from guardians.execute import WorkflowExecutor
from guardians.errors import SecurityViolation


def _simple_registry() -> ToolRegistry:
    r = ToolRegistry()
    r.register(
        ToolSpec(name="greet", params=[ParamSpec(name="name", type="str")]),
        lambda name="world": f"hello {name}",
    )
    r.register(
        ToolSpec(name="noop"),
        lambda: "done",
    )
    return r


def _simple_policy() -> Policy:
    return Policy(name="t", allowed_tools=["greet", "noop"])


# --- Basic execution ---

def test_basic_execution():
    r = _simple_registry()
    p = _simple_policy()
    wf = Workflow(goal="t", steps=[
        WorkflowStep(label="g", tool_call=ToolCallNode(
            tool_name="greet", arguments={"name": "alice"},
            result_binding="msg")),
    ])
    executor = WorkflowExecutor(r, p, auto_approve=True)
    executor.run(wf)
    assert executor.env["msg"] == "hello alice"


def test_execution_with_symref():
    r = _simple_registry()
    p = _simple_policy()
    wf = Workflow(goal="t", input_variables=["who"], steps=[
        WorkflowStep(label="g", tool_call=ToolCallNode(
            tool_name="greet",
            arguments={"name": SymRef(ref="who")},
            result_binding="msg")),
    ])
    executor = WorkflowExecutor(r, p, auto_approve=True)
    executor.env["who"] = "bob"
    executor.run(wf)
    assert executor.env["msg"] == "hello bob"


def test_trace_recorded():
    r = _simple_registry()
    p = _simple_policy()
    wf = Workflow(goal="t", steps=[
        WorkflowStep(label="g", tool_call=ToolCallNode(
            tool_name="greet", arguments={"name": "x"},
            result_binding="msg")),
    ])
    executor = WorkflowExecutor(r, p, auto_approve=True)
    executor.run(wf)
    assert len(executor.trace) == 1
    assert executor.trace[0]["tool"] == "greet"


# --- Allowlist enforcement ---

def test_disallowed_tool_rejected_at_runtime():
    r = _simple_registry()
    p = _simple_policy()
    wf = Workflow(goal="t", steps=[
        WorkflowStep(label="s", tool_call=ToolCallNode(
            tool_name="evil_tool", arguments={})),
    ])
    executor = WorkflowExecutor(r, p, auto_approve=True)
    with pytest.raises(SecurityViolation):
        executor.run(wf)


# --- Precondition enforcement ---

def test_runtime_precondition_enforced():
    r = ToolRegistry()
    r.register(
        ToolSpec(
            name="send_email",
            params=[
                ParamSpec(name="to", type="str"),
                ParamSpec(name="body", type="str"),
            ],
            preconditions=["domain_of(to) in allowed_domains"],
        ),
        lambda to="", body="": {"status": "sent"},
    )
    policy = Policy(
        name="t",
        allowed_tools=["send_email"],
        automata=[
            SecurityAutomaton(
                name="dom",
                states=[AutomatonState(name="ok")],
                initial_state="ok",
                transitions=[],
                constants={"allowed_domains": ["safe.com"]},
            ),
        ],
    )
    wf = Workflow(goal="t", steps=[
        WorkflowStep(label="send", tool_call=ToolCallNode(
            tool_name="send_email",
            arguments={"to": "evil@bad.com", "body": "hi"})),
    ])
    executor = WorkflowExecutor(r, policy, auto_approve=True)
    with pytest.raises(SecurityViolation, match="precondition"):
        executor.run(wf)


# --- Postcondition enforcement ---

def test_runtime_postcondition_enforced():
    r = ToolRegistry()
    r.register(
        ToolSpec(
            name="bad_fetch",
            params=[ParamSpec(name="limit", type="int")],
            postconditions=["len(result) <= limit"],
        ),
        lambda limit=5: list(range(100)),  # violates postcondition
    )
    policy = Policy(name="t", allowed_tools=["bad_fetch"])
    wf = Workflow(goal="t", steps=[
        WorkflowStep(label="fetch", tool_call=ToolCallNode(
            tool_name="bad_fetch", arguments={"limit": 5},
            result_binding="data")),
    ])
    executor = WorkflowExecutor(r, policy, auto_approve=True)
    with pytest.raises(SecurityViolation, match="postcondition"):
        executor.run(wf)


# --- Automaton enforcement ---

def test_runtime_automaton_enforced():
    r = ToolRegistry()
    r.register(
        ToolSpec(
            name="send_email",
            params=[ParamSpec(name="to", type="str"), ParamSpec(name="body", type="str")],
        ),
        lambda to="", body="": {"status": "sent"},
    )
    policy = Policy(
        name="t",
        allowed_tools=["send_email"],
        automata=[
            SecurityAutomaton(
                name="no_external",
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
                constants={"allowed_domains": ["safe.com"]},
            ),
        ],
    )
    wf = Workflow(goal="t", steps=[
        WorkflowStep(label="send", tool_call=ToolCallNode(
            tool_name="send_email",
            arguments={"to": "evil@bad.com", "body": "hi"})),
    ])
    executor = WorkflowExecutor(r, policy, auto_approve=True)
    with pytest.raises(SecurityViolation):
        executor.run(wf)


# --- Budget enforcement ---

def test_budget_enforcement():
    r = _simple_registry()
    p = _simple_policy()
    wf = Workflow(goal="t", steps=[
        WorkflowStep(label=f"call_{i}", tool_call=ToolCallNode(
            tool_name="noop", arguments={}))
        for i in range(5)
    ])
    executor = WorkflowExecutor(r, p, auto_approve=True, budgets={"tool_call": 3})
    with pytest.raises(SecurityViolation, match="[Bb]udget"):
        executor.run(wf)


# --- verify_first default ---

def test_verify_first_blocks_bad_workflow():
    """With verify_first=True (default), a bad workflow should not execute."""
    r = _simple_registry()
    p = _simple_policy()
    wf = Workflow(goal="t", steps=[
        WorkflowStep(label="s", tool_call=ToolCallNode(
            tool_name="evil_tool", arguments={})),
    ])
    executor = WorkflowExecutor(r, p, auto_approve=True, verify_first=True)
    with pytest.raises(SecurityViolation):
        executor.run(wf)


# --- Approval gate ---

def test_approval_rejection_blocks_execution():
    """If user rejects, workflow should not execute."""
    from unittest.mock import patch
    r = _simple_registry()
    p = _simple_policy()
    wf = Workflow(goal="t", steps=[
        WorkflowStep(label="g", tool_call=ToolCallNode(
            tool_name="noop", arguments={}, result_binding="r")),
    ])
    executor = WorkflowExecutor(r, p, auto_approve=False)
    with patch("builtins.input", return_value="n"):
        with pytest.raises(SecurityViolation, match="rejected"):
            executor.run(wf)


def test_approval_acceptance_allows_execution():
    """If user approves, workflow executes normally."""
    from unittest.mock import patch
    r = _simple_registry()
    p = _simple_policy()
    wf = Workflow(goal="t", steps=[
        WorkflowStep(label="g", tool_call=ToolCallNode(
            tool_name="noop", arguments={}, result_binding="r")),
    ])
    executor = WorkflowExecutor(r, p, auto_approve=False)
    with patch("builtins.input", return_value="y"):
        executor.run(wf)
    assert executor.env["r"] == "done"


# --- Runtime scope enforcement (verify_first=False) ---

def test_conditional_one_branch_binding_does_not_escape_at_runtime():
    """A binding created in only one branch must not be accessible after,
    even with verify_first=False."""
    from guardians.workflow import ConditionalNode
    r = _simple_registry()
    p = _simple_policy()
    wf = Workflow(goal="t", steps=[
        WorkflowStep(label="cond", conditional=ConditionalNode(
            condition="True",
            then_steps=[
                WorkflowStep(label="bind", tool_call=ToolCallNode(
                    tool_name="noop", arguments={}, result_binding="only_then")),
            ],
            else_steps=[],
        )),
        WorkflowStep(label="use", tool_call=ToolCallNode(
            tool_name="greet",
            arguments={"name": SymRef(ref="only_then")})),
    ])
    executor = WorkflowExecutor(r, p, auto_approve=True, verify_first=False)
    with pytest.raises(SecurityViolation):
        executor.run(wf)


def test_conditional_both_branch_binding_escapes_at_runtime():
    """A binding created in both branches IS accessible after."""
    from guardians.workflow import ConditionalNode
    r = _simple_registry()
    p = _simple_policy()
    wf = Workflow(goal="t", steps=[
        WorkflowStep(label="cond", conditional=ConditionalNode(
            condition="True",
            then_steps=[
                WorkflowStep(label="then", tool_call=ToolCallNode(
                    tool_name="noop", arguments={}, result_binding="both")),
            ],
            else_steps=[
                WorkflowStep(label="else", tool_call=ToolCallNode(
                    tool_name="noop", arguments={}, result_binding="both")),
            ],
        )),
        WorkflowStep(label="use", tool_call=ToolCallNode(
            tool_name="greet",
            arguments={"name": SymRef(ref="both")},
            result_binding="msg")),
    ])
    executor = WorkflowExecutor(r, p, auto_approve=True, verify_first=False)
    executor.run(wf)
    assert "msg" in executor.env


def test_loop_item_binding_does_not_escape_at_runtime():
    """The loop item_binding must not be accessible after the loop,
    even with verify_first=False."""
    from guardians.workflow import LoopNode
    r = ToolRegistry()
    r.register(ToolSpec(name="use", params=[ParamSpec(name="x", type="str")]),
               lambda x="": None)
    p = Policy(name="t", allowed_tools=["use"])
    wf = Workflow(goal="t", input_variables=["items"], steps=[
        WorkflowStep(label="loop", loop=LoopNode(
            collection_ref="items",
            item_binding="item",
            body=[
                WorkflowStep(label="body", tool_call=ToolCallNode(
                    tool_name="use", arguments={"x": SymRef(ref="item")})),
            ],
        )),
        WorkflowStep(label="after", tool_call=ToolCallNode(
            tool_name="use", arguments={"x": SymRef(ref="item")})),
    ])
    executor = WorkflowExecutor(r, p, auto_approve=True, verify_first=False)
    executor.env["items"] = ["a", "b"]
    with pytest.raises(SecurityViolation):
        executor.run(wf)


def test_loop_body_binding_does_not_escape_at_runtime():
    """A result_binding inside a loop body must not be accessible after."""
    from guardians.workflow import LoopNode
    r = ToolRegistry()
    r.register(ToolSpec(name="process", params=[ParamSpec(name="x", type="str")]),
               lambda x="": "result")
    r.register(ToolSpec(name="use", params=[ParamSpec(name="x", type="str")]),
               lambda x="": None)
    p = Policy(name="t", allowed_tools=["process", "use"])
    wf = Workflow(goal="t", input_variables=["items"], steps=[
        WorkflowStep(label="loop", loop=LoopNode(
            collection_ref="items",
            item_binding="item",
            body=[
                WorkflowStep(label="proc", tool_call=ToolCallNode(
                    tool_name="process",
                    arguments={"x": SymRef(ref="item")},
                    result_binding="loop_result")),
            ],
        )),
        WorkflowStep(label="after", tool_call=ToolCallNode(
            tool_name="use", arguments={"x": SymRef(ref="loop_result")})),
    ])
    executor = WorkflowExecutor(r, p, auto_approve=True, verify_first=False)
    executor.env["items"] = ["a"]
    with pytest.raises(SecurityViolation):
        executor.run(wf)


def test_loop_body_binding_does_not_leak_across_iterations():
    """A binding created in iteration 1 must not be visible in iteration 2.

    Iteration 1 (item=="first"): skip use, then bind tmp.
    Iteration 2 (item=="second"): try to use tmp before rebinding.
    Without per-iteration cleanup, iteration 2 wrongly sees stale tmp.
    """
    from guardians.workflow import LoopNode, ConditionalNode
    r = ToolRegistry()
    r.register(ToolSpec(name="make", params=[ParamSpec(name="x", type="str")]),
               lambda x="": f"made_{x}")
    r.register(ToolSpec(name="use", params=[ParamSpec(name="x", type="str")]),
               lambda x="": None)
    p = Policy(name="t", allowed_tools=["make", "use"])

    wf = Workflow(goal="t", input_variables=["items"], steps=[
        WorkflowStep(label="loop", loop=LoopNode(
            collection_ref="items",
            item_binding="item",
            body=[
                WorkflowStep(label="maybe_use", conditional=ConditionalNode(
                    condition="item == 'second'",
                    then_steps=[
                        WorkflowStep(label="use_tmp", tool_call=ToolCallNode(
                            tool_name="use", arguments={"x": SymRef(ref="tmp")})),
                    ],
                    else_steps=[],
                )),
                WorkflowStep(label="bind_tmp", tool_call=ToolCallNode(
                    tool_name="make", arguments={"x": "val"},
                    result_binding="tmp")),
            ],
        )),
    ])
    executor = WorkflowExecutor(r, p, auto_approve=True, verify_first=False)
    executor.env["items"] = ["first", "second"]
    with pytest.raises(SecurityViolation):
        executor.run(wf)


def test_loop_item_binding_cannot_shadow_outer_variable_at_runtime():
    """A loop whose item_binding shadows an outer variable is rejected."""
    from guardians.workflow import LoopNode
    r = ToolRegistry()
    r.register(ToolSpec(name="use", params=[ParamSpec(name="x", type="str")]),
               lambda x="": None)
    p = Policy(name="t", allowed_tools=["use"])
    wf = Workflow(goal="t", input_variables=["items"], steps=[
        WorkflowStep(label="loop", loop=LoopNode(
            collection_ref="items",
            item_binding="items",  # shadows the outer "items"
            body=[
                WorkflowStep(label="use", tool_call=ToolCallNode(
                    tool_name="use", arguments={"x": SymRef(ref="items")})),
            ],
        )),
    ])
    executor = WorkflowExecutor(r, p, auto_approve=True, verify_first=False)
    executor.env["items"] = ["a", "b"]
    with pytest.raises(SecurityViolation, match="shadow"):
        executor.run(wf)
