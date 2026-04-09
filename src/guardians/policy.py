"""Security policies: automata, taint rules, and invariants.

Policies are declarative specifications that the verifier checks
workflows against before execution.
"""

from __future__ import annotations

from pydantic import BaseModel


class AutomatonState(BaseModel):
    """A state in a security automaton."""

    name: str
    is_error: bool = False


class AutomatonTransition(BaseModel):
    """A transition triggered by a tool call.

    Matches (from_state, tool_name) and optionally a condition
    on the tool's arguments. Conditions are Python expressions
    evaluated against {**tool_args, **automaton.constants}.
    """

    from_state: str
    to_state: str
    tool_name: str
    condition: str | None = None


class SecurityAutomaton(BaseModel):
    """Security invariant specified as a finite automaton.

    State machine where certain tool-call sequences lead to error states.
    """

    name: str
    states: list[AutomatonState]
    initial_state: str
    transitions: list[AutomatonTransition]
    constants: dict[str, list[str] | str] = {}


class TaintRule(BaseModel):
    """Data-flow rule: forbids tainted data from reaching a sink.

    If data flows from source_tool's output through symbolic references
    to sink_tool's sink_param, flag a violation.
    """

    name: str
    source_tool: str
    source_output: str = "result"
    sink_tool: str
    sink_param: str
    condition: str | None = None
    sanitizers: list[str] = []


class Policy(BaseModel):
    """Complete security policy for a domain."""

    name: str
    allowed_tools: list[str]
    automata: list[SecurityAutomaton] = []
    taint_rules: list[TaintRule] = []
    invariants: list[str] = []
