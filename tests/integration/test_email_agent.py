"""End-to-end test of the paper's prompt-injection demo.

Drives the full verify -> execute pipeline against the example in
``examples/email_agent.py`` (the "summarize my inbox" scenario with a
malicious exfiltration email). This is the headline claim from the paper:
the malicious plan trips multiple independent static checks and is refused
before any tool runs, and is also blocked at runtime as defense in depth.

Importing the example module directly means this test also serves as
coverage for the shipped example itself.
"""

import importlib.util
from pathlib import Path

import pytest

from guardians import verify, WorkflowExecutor, SecurityViolation

EXAMPLE_PATH = Path(__file__).resolve().parents[2] / "examples" / "email_agent.py"


def _load_example():
    spec = importlib.util.spec_from_file_location("email_agent_example", EXAMPLE_PATH)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture(scope="module")
def example():
    return _load_example()


def test_safe_workflow_verifies_and_executes(example):
    result = verify(example.safe_wf, example.policy, example.registry)
    assert result.ok
    assert not result.violations

    executor = WorkflowExecutor(example.registry, example.policy, auto_approve=True)
    executor.run(example.safe_wf)
    assert "summary" in executor.env
    assert "emails" in executor.env["summary"]


def test_malicious_workflow_fails_verification(example):
    result = verify(example.malicious_wf, example.policy, example.registry)
    assert not result.ok
    assert result.violations


def test_malicious_workflow_trips_independent_checks(example):
    """The paper's claim: several independent checks fire, not just one."""
    result = verify(example.malicious_wf, example.policy, example.registry)
    categories = {v.category for v in result.violations}
    # Exfiltrating tainted email body to an external recipient violates the
    # taint rule, the security automaton, and the send_email precondition.
    assert "taint" in categories
    assert "automaton" in categories
    assert "precondition" in categories


def test_malicious_workflow_blocked_at_runtime(example):
    """Defense in depth: even bypassing static verify, runtime refuses it."""
    executor = WorkflowExecutor(example.registry, example.policy, auto_approve=True)
    with pytest.raises(SecurityViolation):
        executor.run(example.malicious_wf)
