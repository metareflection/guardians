# Guardians

Static verification for AI agent workflows.

An implementation of the ideas in Erik Meijer's
["Guardians of the Agents"](https://dl.acm.org/doi/10.1145/3777544)
(CACM, January 2026). The paper's thesis: the root cause of prompt
injection in agentic systems is the same as SQL injection — code and
data aren't separated. The fix is the same too.

Instead of letting the LLM call tools one at a time and decide what
to do after each result, the LLM generates a structured plan upfront
using symbolic references (placeholders, not real data). A static
verifier checks the plan against a security policy before any tool
runs. Only verified plans execute.

The verifier uses three independent checks: taint analysis (does
data flow from a source to a forbidden sink?), security automata
(does the tool-call sequence reach an error state?), and Z3 theorem
proving (do preconditions and frame conditions hold?).

The demo scenario from the paper: you ask your AI to summarize your
inbox. A malicious email tells the agent to forward everything to
the attacker. Three checks fire. The workflow never executes.

~1900 lines of core, 100 tests, two dependencies (pydantic,
z3-solver). No LLM calls needed for verification. Python 3.11+.

```
Workflow AST ──→ verify(wf, policy, registry) ──→ WorkflowExecutor.run(wf)
                        │                                  │
                  VerificationResult              env, trace (results)
                  (violations, warnings)
```

## Install

```bash
pip install guardians            # core only (pydantic + z3-solver)
pip install guardians[llm]       # adds litellm for LLM planning
```

## Quick start

```python
from guardians import (
    Workflow, WorkflowStep, ToolCallNode, SymRef,
    ToolSpec, ParamSpec, ToolRegistry,
    Policy, TaintRule,
    verify, WorkflowExecutor,
)

# 1. Define tools
registry = ToolRegistry()
registry.register(
    ToolSpec(name="fetch_data", source_labels=["sensitive"],
             params=[ParamSpec(name="query", type="str")]),
    lambda query="": [{"result": "data"}],
)
registry.register(
    ToolSpec(name="summarize",
             params=[ParamSpec(name="items", type="list")]),
    lambda items=None: "summary",
)

# 2. Define policy
policy = Policy(
    name="example",
    allowed_tools=["fetch_data", "summarize"],
)

# 3. Build a workflow
wf = Workflow(
    goal="Fetch and summarize",
    steps=[
        WorkflowStep(label="Fetch", tool_call=ToolCallNode(
            tool_name="fetch_data", arguments={"query": "recent"},
            result_binding="data")),
        WorkflowStep(label="Summarize", tool_call=ToolCallNode(
            tool_name="summarize",
            arguments={"items": SymRef(ref="data")},
            result_binding="summary")),
    ],
)

# 4. Verify
result = verify(wf, policy, registry)
assert result.ok

# 5. Execute
executor = WorkflowExecutor(registry, policy, auto_approve=True)
executor.run(wf)
print(executor.env["summary"])
```

## What is checked

### Static (verifier, before execution)

| Check | Category |
|---|---|
| Tool in allowlist | `allowlist` |
| Tool has a registered spec | `missing_spec` |
| All symbolic refs are in scope | `well_formedness` |
| Tainted data does not flow to sinks | `taint` |
| Z3 preconditions hold | `precondition` |
| Z3 postconditions hold | `postcondition` |
| Z3 frame conditions hold | `frame` |
| Security automata stay in safe states | `automaton` |

### Runtime (executor, during execution)

Allowlist, preconditions, postconditions, automata, and budgets.

Frame conditions and taint are static-only. The default `verify_first=True`
ensures they are checked before any tool runs.

## Adapters (optional)

```python
from guardians.adapters.agent import GuardedAgent

agent = GuardedAgent("email_agent", planner=my_planner)

@agent.tool(taint_labels=["email_content"])
def fetch_mail(folder: str = "inbox") -> list: ...

@agent.tool(sink_params=["body"])
def send_email(to: str, body: str) -> dict: ...

agent.deny("send_email", "to", not_in_domain=["company.com"])
agent.no_data_flow("fetch_mail", to="send_email.body")

result = agent.run("Summarize my inbox")
```

Adapters live under `guardians.adapters` and are never imported by the core.

## Project layout

```
src/guardians/
    __init__.py          # core exports only
    workflow.py          # Workflow AST, SymRef
    tools.py             # ToolSpec, ToolRegistry
    policy.py            # Policy, automata, taint rules
    conditions.py        # condition grammar, Z3 translation
    safe_eval.py         # runtime expression evaluator
    results.py           # VerificationResult, Violation
    errors.py            # SecurityViolation
    verify.py            # static verifier
    execute.py           # runtime executor
    adapters/
        planner.py       # Planner protocol, prompt helpers
        litellm.py       # LiteLLM planner (requires [llm])
        agent.py         # GuardedAgent high-level API
```

## Documentation

- [Design](DESIGN.md) — architecture, semantics, guarantees
