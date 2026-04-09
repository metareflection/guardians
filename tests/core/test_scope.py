"""Tests for well-formedness / scope checking in the verifier."""

from guardians.workflow import (
    Workflow, WorkflowStep, ToolCallNode, ConditionalNode, LoopNode, SymRef,
)
from guardians.tools import ToolSpec, ParamSpec, ToolRegistry
from guardians.policy import Policy
from guardians.verify import verify


def _registry() -> ToolRegistry:
    r = ToolRegistry()
    r.register(
        ToolSpec(name="fetch", params=[ParamSpec(name="x", type="str")]),
        lambda x="": ["data"],
    )
    r.register(
        ToolSpec(name="process", params=[ParamSpec(name="input", type="str")]),
        lambda input="": "result",
    )
    r.register(
        ToolSpec(name="sink", params=[ParamSpec(name="data", type="str")]),
        lambda data="": None,
    )
    return r


def _policy() -> Policy:
    return Policy(name="test", allowed_tools=["fetch", "process", "sink"])


# --- Undefined references ---

def test_undefined_ref_caught():
    result = verify(
        Workflow(goal="t", steps=[
            WorkflowStep(label="s", tool_call=ToolCallNode(
                tool_name="sink", arguments={"data": SymRef(ref="nonexistent")})),
        ]),
        _policy(), _registry(),
    )
    assert not result.ok
    wf = [v for v in result.violations if v.category == "well_formedness"]
    assert len(wf) == 1
    assert "nonexistent" in wf[0].message


def test_input_variable_in_scope():
    result = verify(
        Workflow(goal="t", input_variables=["x"], steps=[
            WorkflowStep(label="s", tool_call=ToolCallNode(
                tool_name="sink", arguments={"data": SymRef(ref="x")})),
        ]),
        _policy(), _registry(),
    )
    wf = [v for v in result.violations if v.category == "well_formedness"]
    assert len(wf) == 0


def test_result_binding_brings_var_into_scope():
    result = verify(
        Workflow(goal="t", steps=[
            WorkflowStep(label="f", tool_call=ToolCallNode(
                tool_name="fetch", arguments={"x": "a"}, result_binding="data")),
            WorkflowStep(label="p", tool_call=ToolCallNode(
                tool_name="process", arguments={"input": SymRef(ref="data")})),
        ]),
        _policy(), _registry(),
    )
    wf = [v for v in result.violations if v.category == "well_formedness"]
    assert len(wf) == 0


# --- Nested refs in arguments ---

def test_nested_ref_in_dict_caught():
    """A SymRef nested inside a dict argument must be scope-checked."""
    result = verify(
        Workflow(goal="t", steps=[
            WorkflowStep(label="s", tool_call=ToolCallNode(
                tool_name="sink",
                arguments={"data": {"nested": SymRef(ref="missing")}})),
        ]),
        _policy(), _registry(),
    )
    wf = [v for v in result.violations if v.category == "well_formedness"]
    assert len(wf) == 1
    assert "missing" in wf[0].message


def test_nested_ref_in_list_caught():
    """A SymRef nested inside a list argument must be scope-checked."""
    result = verify(
        Workflow(goal="t", steps=[
            WorkflowStep(label="s", tool_call=ToolCallNode(
                tool_name="sink",
                arguments={"data": [SymRef(ref="missing")]})),
        ]),
        _policy(), _registry(),
    )
    wf = [v for v in result.violations if v.category == "well_formedness"]
    assert len(wf) == 1
    assert "missing" in wf[0].message


def test_json_ref_dict_in_arguments_scope_checked():
    """A {"ref": "x"} dict that was normalized to SymRef should be scope-checked."""
    wf = Workflow.model_validate({
        "goal": "t",
        "steps": [{
            "label": "s",
            "tool_call": {
                "tool_name": "sink",
                "arguments": {"data": {"nested": {"ref": "missing"}}},
            },
        }],
    })
    result = verify(wf, _policy(), _registry())
    wf_v = [v for v in result.violations if v.category == "well_formedness"]
    assert len(wf_v) == 1
    assert "missing" in wf_v[0].message


# --- Conditional scoping ---

def test_binding_in_one_branch_not_available_after():
    """A variable bound in only one branch is not in scope after the conditional."""
    result = verify(
        Workflow(goal="t", steps=[
            WorkflowStep(label="cond", conditional=ConditionalNode(
                condition="True",
                then_steps=[
                    WorkflowStep(label="bind", tool_call=ToolCallNode(
                        tool_name="fetch", arguments={"x": "a"},
                        result_binding="only_then")),
                ],
                else_steps=[],
            )),
            WorkflowStep(label="use", tool_call=ToolCallNode(
                tool_name="sink",
                arguments={"data": SymRef(ref="only_then")})),
        ]),
        _policy(), _registry(),
    )
    wf = [v for v in result.violations if v.category == "well_formedness"]
    assert len(wf) == 1
    assert "only_then" in wf[0].message


def test_binding_in_both_branches_available_after():
    """A variable bound in both branches IS in scope after the conditional."""
    result = verify(
        Workflow(goal="t", steps=[
            WorkflowStep(label="cond", conditional=ConditionalNode(
                condition="True",
                then_steps=[
                    WorkflowStep(label="then", tool_call=ToolCallNode(
                        tool_name="fetch", arguments={"x": "a"},
                        result_binding="both")),
                ],
                else_steps=[
                    WorkflowStep(label="else", tool_call=ToolCallNode(
                        tool_name="fetch", arguments={"x": "b"},
                        result_binding="both")),
                ],
            )),
            WorkflowStep(label="use", tool_call=ToolCallNode(
                tool_name="sink",
                arguments={"data": SymRef(ref="both")})),
        ]),
        _policy(), _registry(),
    )
    wf = [v for v in result.violations if v.category == "well_formedness"]
    assert len(wf) == 0


# --- Loop scoping ---

def test_undefined_loop_collection_caught():
    result = verify(
        Workflow(goal="t", steps=[
            WorkflowStep(label="loop", loop=LoopNode(
                collection_ref="missing_list",
                item_binding="item",
                body=[
                    WorkflowStep(label="use", tool_call=ToolCallNode(
                        tool_name="sink",
                        arguments={"data": SymRef(ref="item")})),
                ],
            )),
        ]),
        _policy(), _registry(),
    )
    wf = [v for v in result.violations if v.category == "well_formedness"]
    assert len(wf) == 1
    assert "missing_list" in wf[0].message


def test_loop_item_binding_available_inside_body():
    """The item_binding is in scope inside the loop body."""
    result = verify(
        Workflow(goal="t", steps=[
            WorkflowStep(label="f", tool_call=ToolCallNode(
                tool_name="fetch", arguments={"x": "a"},
                result_binding="items")),
            WorkflowStep(label="loop", loop=LoopNode(
                collection_ref="items",
                item_binding="item",
                body=[
                    WorkflowStep(label="use", tool_call=ToolCallNode(
                        tool_name="sink",
                        arguments={"data": SymRef(ref="item")})),
                ],
            )),
        ]),
        _policy(), _registry(),
    )
    wf = [v for v in result.violations if v.category == "well_formedness"]
    assert len(wf) == 0


def test_loop_body_binding_does_not_escape():
    """A result_binding created only inside a loop body is not in scope after."""
    result = verify(
        Workflow(goal="t", steps=[
            WorkflowStep(label="f", tool_call=ToolCallNode(
                tool_name="fetch", arguments={"x": "a"},
                result_binding="items")),
            WorkflowStep(label="loop", loop=LoopNode(
                collection_ref="items",
                item_binding="item",
                body=[
                    WorkflowStep(label="proc", tool_call=ToolCallNode(
                        tool_name="process",
                        arguments={"input": SymRef(ref="item")},
                        result_binding="loop_only")),
                ],
            )),
            WorkflowStep(label="use", tool_call=ToolCallNode(
                tool_name="sink",
                arguments={"data": SymRef(ref="loop_only")})),
        ]),
        _policy(), _registry(),
    )
    wf = [v for v in result.violations if v.category == "well_formedness"]
    assert len(wf) == 1
    assert "loop_only" in wf[0].message


def test_loop_item_binding_does_not_escape():
    """The item_binding itself is not in scope after the loop."""
    result = verify(
        Workflow(goal="t", steps=[
            WorkflowStep(label="f", tool_call=ToolCallNode(
                tool_name="fetch", arguments={"x": "a"},
                result_binding="items")),
            WorkflowStep(label="loop", loop=LoopNode(
                collection_ref="items",
                item_binding="item",
                body=[
                    WorkflowStep(label="use", tool_call=ToolCallNode(
                        tool_name="sink",
                        arguments={"data": SymRef(ref="item")})),
                ],
            )),
            WorkflowStep(label="after", tool_call=ToolCallNode(
                tool_name="sink",
                arguments={"data": SymRef(ref="item")})),
        ]),
        _policy(), _registry(),
    )
    wf = [v for v in result.violations if v.category == "well_formedness"]
    assert len(wf) == 1
    assert "item" in wf[0].message


# --- Loop shadowing ---

def test_loop_item_binding_cannot_shadow_outer_variable():
    """A loop item_binding that shadows an existing variable is rejected."""
    result = verify(
        Workflow(goal="t", steps=[
            WorkflowStep(label="f", tool_call=ToolCallNode(
                tool_name="fetch", arguments={"x": "a"},
                result_binding="item")),
            WorkflowStep(label="loop", loop=LoopNode(
                collection_ref="item",
                item_binding="item",  # shadows outer "item"
                body=[
                    WorkflowStep(label="use", tool_call=ToolCallNode(
                        tool_name="sink",
                        arguments={"data": SymRef(ref="item")})),
                ],
            )),
        ]),
        _policy(), _registry(),
    )
    wf = [v for v in result.violations if v.category == "well_formedness"]
    assert any("shadow" in v.message.lower() for v in wf)


# --- Condition expression names ---

def test_domain_of_not_flagged_as_undefined_ref():
    """Helper names like domain_of and len must not be treated as refs."""
    result = verify(
        Workflow(goal="t", input_variables=["emails"], steps=[
            WorkflowStep(label="cond", conditional=ConditionalNode(
                condition="len(emails) > 0",
                then_steps=[
                    WorkflowStep(label="t", tool_call=ToolCallNode(
                        tool_name="fetch", arguments={"x": "a"})),
                ],
                else_steps=[],
            )),
        ]),
        _policy(), _registry(),
    )
    wf = [v for v in result.violations if v.category == "well_formedness"]
    assert len(wf) == 0


def test_domain_of_in_condition_not_flagged():
    """domain_of(x) in a condition should not flag domain_of as a ref."""
    result = verify(
        Workflow(goal="t", input_variables=["recipient"], steps=[
            WorkflowStep(label="cond", conditional=ConditionalNode(
                condition="domain_of(recipient) in ['company.com']",
                then_steps=[
                    WorkflowStep(label="t", tool_call=ToolCallNode(
                        tool_name="fetch", arguments={"x": "a"})),
                ],
                else_steps=[],
            )),
        ]),
        _policy(), _registry(),
    )
    wf = [v for v in result.violations if v.category == "well_formedness"]
    # Should not flag domain_of as undefined
    assert len(wf) == 0
