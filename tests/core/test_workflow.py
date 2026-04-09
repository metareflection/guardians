"""Tests for workflow AST and SymRef representation."""

import json

from guardians.workflow import (
    Workflow, WorkflowStep, ToolCallNode, ConditionalNode, LoopNode, SymRef,
)


# --- SymRef representation ---

class TestSymRef:
    def test_symref_is_explicit_object(self):
        ref = SymRef(ref="emails")
        assert ref.ref == "emails"
        assert str(ref) == "@emails"

    def test_symref_equality_and_hash(self):
        a = SymRef(ref="x")
        b = SymRef(ref="x")
        assert a == b
        assert hash(a) == hash(b)
        assert a != SymRef(ref="y")

    def test_symref_round_trip_json(self):
        """SymRef serializes to {"ref": "name"} and deserializes back."""
        ref = SymRef(ref="emails")
        dumped = ref.model_dump()
        assert dumped == {"ref": "emails"}
        restored = SymRef.model_validate(dumped)
        assert restored == ref

    def test_dict_with_only_ref_key_normalized_to_symref(self):
        """A JSON dict {"ref": "x"} in tool arguments becomes a SymRef."""
        raw = {
            "goal": "test",
            "steps": [{
                "label": "step1",
                "tool_call": {
                    "tool_name": "my_tool",
                    "arguments": {"input": {"ref": "data"}},
                },
            }],
        }
        wf = Workflow.model_validate(raw)
        arg = wf.steps[0].tool_call.arguments["input"]
        assert isinstance(arg, SymRef)
        assert arg.ref == "data"

    def test_dict_with_ref_and_other_keys_stays_literal(self):
        """A dict like {"ref": "x", "extra": 1} is NOT a SymRef."""
        raw = {
            "goal": "test",
            "steps": [{
                "label": "step1",
                "tool_call": {
                    "tool_name": "my_tool",
                    "arguments": {"input": {"ref": "data", "extra": 1}},
                },
            }],
        }
        wf = Workflow.model_validate(raw)
        arg = wf.steps[0].tool_call.arguments["input"]
        assert isinstance(arg, dict)
        assert not isinstance(arg, SymRef)
        assert arg == {"ref": "data", "extra": 1}


# --- Workflow structure ---

class TestWorkflowStructure:
    def test_step_requires_exactly_one_variant(self):
        """WorkflowStep must have exactly one of tool_call, conditional, loop."""
        import pytest
        with pytest.raises(Exception):
            WorkflowStep(label="bad", tool_call=None, conditional=None, loop=None)

    def test_workflow_round_trip_json(self):
        wf = Workflow(
            goal="test",
            steps=[
                WorkflowStep(
                    label="fetch",
                    tool_call=ToolCallNode(
                        tool_name="fetch_mail",
                        arguments={"folder": "inbox", "data": SymRef(ref="x")},
                        result_binding="emails",
                    ),
                ),
            ],
            input_variables=["x"],
        )
        raw = json.loads(wf.model_dump_json())
        restored = Workflow.model_validate(raw)
        assert restored.goal == "test"
        arg = restored.steps[0].tool_call.arguments["data"]
        assert isinstance(arg, SymRef)
        assert arg.ref == "x"

    def test_nested_refs_in_list_arguments(self):
        """SymRefs nested in lists should survive round-trip."""
        raw = {
            "goal": "test",
            "steps": [{
                "label": "step1",
                "tool_call": {
                    "tool_name": "my_tool",
                    "arguments": {"items": [{"ref": "a"}, {"ref": "b"}]},
                },
            }],
        }
        wf = Workflow.model_validate(raw)
        items = wf.steps[0].tool_call.arguments["items"]
        assert isinstance(items, list)
        assert all(isinstance(x, SymRef) for x in items)
        assert items[0].ref == "a"
        assert items[1].ref == "b"

    def test_nested_ref_in_dict_arguments(self):
        """SymRef nested inside a larger dict structure."""
        raw = {
            "goal": "test",
            "steps": [{
                "label": "step1",
                "tool_call": {
                    "tool_name": "my_tool",
                    "arguments": {"config": {"nested": {"ref": "val"}}},
                },
            }],
        }
        wf = Workflow.model_validate(raw)
        config = wf.steps[0].tool_call.arguments["config"]
        assert isinstance(config, dict)
        assert isinstance(config["nested"], SymRef)
        assert config["nested"].ref == "val"
