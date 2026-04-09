# Design

This document describes the architecture of Guardians, an
implementation of the ideas in
[Erik Meijer's "Guardians of the Agents: Formal Verification of AI Workflows" (Communications of the ACM, January 2026)](https://cacm.acm.org/practice/guardians-of-the-agents/).

## The problem

Agentic applications let an LLM call external tools. The LLM sees
tool results and decides what to do next. Attacker-controlled data
(a malicious email, a poisoned tool description) arrives while the
LLM is still making decisions. The LLM cannot reliably distinguish
instructions from data, so it follows the attacker's embedded
instructions. This is prompt injection with side effects — not just
corrupted output, but unauthorized tool calls.

The paper's diagnosis: the root cause is the same as SQL injection.
Code and data are not separated. The fix is the same too: separate
them.

## The architecture: generate, verify, execute

The LLM generates a structured workflow using symbolic references
instead of concrete data. The workflow is verified against a security
policy before any tool runs. Only verified workflows execute.

**Generate.** The LLM produces a workflow AST: a sequence of tool
calls, conditionals, and loops. Arguments use symbolic references
like `@emails_fetched` — placeholders that get bound to real values
only at execution time. The LLM has never seen the user's data at
this point. It is working from the goal and the tool specifications.

**Verify.** A static verifier checks the workflow against a
declarative security policy. No tools are called. The verifier uses
taint analysis, security automata, and Z3 theorem proving. If the
workflow violates the policy, it is rejected before any side effects
occur.

**Execute.** The verified workflow runs. Symbolic references are
resolved to concrete values. Runtime checks (preconditions,
postconditions, automata) provide defense in depth. By the time
attacker-controlled data arrives, the plan is locked.

This is the paper's core contribution: shifting from reactive
monitoring to proactive static verification.

## What the verifier checks

### Taint analysis

The paper proposes CodeQL-style source/sink analysis. A security
policy declares that data from a source tool must not flow to a
sink parameter:

```python
TaintRule(
    source_tool="fetch_mail",
    sink_tool="send_email",
    sink_param="body",
)
```

The verifier tracks taint labels through symbolic references. If
`fetch_mail` produces data labeled `email_content`, and that label
reaches `send_email.body` through any chain of intermediate tools,
the verifier flags a violation.

The implementation extends the paper with provenance tracking:
each abstract value records which tools contributed to it
transitively. A taint rule for `source_tool="fetch_mail"` only
fires if `fetch_mail` is actually in the value's lineage, preventing
false positives when unrelated tools share label names.

Sanitizers can break the taint chain. If a tool like `redact` is
declared as a sanitizer for a rule, data that passes through it is
no longer considered tainted for that rule.

### Security automata

The paper's Figure 2 defines security invariants as finite automata.
A state machine watches tool-call sequences. Certain transitions
lead to error states:

```python
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
)
```

During verification, if a tool argument is symbolic (unknown value),
the automaton conservatively reports "could reach error state."
At runtime, the automaton evaluates conditions against concrete
values and blocks transitions to error states.

### Z3 theorem proving

The paper proposes using Z3 and Dafny to reason about workflow
correctness. The implementation uses Z3 to check preconditions,
postconditions, and frame conditions declared on tool specs:

```python
ToolSpec(
    name="delete_file",
    params=[ParamSpec(name="pattern", type="str")],
    preconditions=["len(pattern) > 0"],
    frame_conditions=["pattern != '*'"],
)
```

The verifier translates conditions to Z3 constraints. For literal
arguments, it proves whether conditions hold or are violated. For
symbolic arguments, it reports "could be violated." Conditions that
Z3 cannot translate produce warnings (or violations in strict mode).

### Frame conditions

The paper discusses the frame problem (McCarthy and Hayes, 1969):
an LLM asked to delete `foo.txt` and `bar.txt` might generate
`delete_file("*.txt")` because it satisfies the postcondition more
simply. The paper's fix is a frame condition requiring that files
not matching the pattern remain unchanged:

```
delete_file(pattern: string)
ensures: forall file :: file not in glob(pattern)
    => file in fileSystem = old(f) in fileSystem
```

The implementation supports a `forall` DSL for frame conditions
and checks non-vacuity: if the pattern is `"*"`, the frame protects
nothing, and the verifier flags it.

### Scope checking

All symbolic references must be defined before use. The verifier
enforces scoping rules that match the executor:
- Variables enter scope via `input_variables`, `result_binding`,
  or `item_binding`.
- Conditional: only variables bound in both branches are available
  afterward.
- Loop: `item_binding` and body-local bindings do not escape.

## Hybrid static and runtime

The paper notes that real security is "a series of hoops," drawing
an analogy to Java bytecode verification: static verification
eliminates broad classes of errors, but some checks (like array
bounds) still happen at runtime.

The implementation follows this hybrid model:

| Check | Static | Runtime |
|---|---|---|
| Tool allowlist | yes | yes |
| Taint analysis | yes | no |
| Security automata | yes | yes |
| Preconditions | yes (Z3) | yes (safe_eval) |
| Postconditions | yes (Z3) | yes (safe_eval) |
| Frame conditions | yes (Z3) | no |
| Scope rules | yes | yes |
| Budget limits | no | yes |
| User approval | no | yes |

The default is `verify_first=True`: the executor runs the verifier
before any tool executes. This means frame conditions and taint
analysis — which are static-only — are always checked before
execution begins.

## Workflow representation

The paper represents workflows as JSON ASTs with named steps and
`"next"` pointers. The implementation uses a sequential list with
nested conditionals and loops — structurally equivalent but simpler
to verify and execute.

```python
Workflow(
    goal="Fetch and summarize emails",
    steps=[
        WorkflowStep(label="Fetch", tool_call=ToolCallNode(
            tool_name="fetch_mail",
            arguments={"folder": "inbox"},
            result_binding="emails")),
        WorkflowStep(label="Summarize", tool_call=ToolCallNode(
            tool_name="summarize",
            arguments={"emails": SymRef(ref="emails")},
            result_binding="summary")),
    ],
)
```

`SymRef` enforces the code/data separation from the paper. JSON
input `{"ref": "x"}` is normalized to `SymRef(ref="x")` at parse
time. A dict with a `"ref"` key alongside other keys stays a
literal dict.

## Package structure

```
src/guardians/
    __init__.py          core exports only
    workflow.py          workflow AST, SymRef
    tools.py             ToolSpec, ToolRegistry
    policy.py            Policy, automata, taint rules
    conditions.py        condition grammar, Z3 translation
    safe_eval.py         runtime expression evaluator
    results.py           VerificationResult, Violation
    errors.py            SecurityViolation
    verify.py            static verifier
    execute.py           runtime executor
    adapters/
        planner.py       Planner protocol, prompt helpers
        litellm.py       LiteLLM planner (optional)
        agent.py         GuardedAgent high-level API (optional)
```

Core dependencies: pydantic, z3-solver. LLM adapters are optional
and never imported by the core.

## What is not implemented

- `old()` references in frame conditions (pre/post state comparison)
- Explicit set membership (`file in fileSystem`)
- Dafny integration
- The paper's graph-with-next-pointers AST shape
- Information-flow-complete taint analysis (the implementation is
  label-based with provenance tracking, not a full IFC type system)
