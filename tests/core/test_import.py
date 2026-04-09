"""Tests that top-level import works without optional dependencies."""

import subprocess
import sys


def test_import_guardians_without_litellm():
    """Importing guardians must not require litellm."""
    code = (
        "import guardians; "
        "assert 'litellm' not in __import__('sys').modules, "
        "'litellm was imported by guardians core'"
    )
    result = subprocess.run(
        [sys.executable, "-c", code],
        capture_output=True, text=True,
    )
    assert result.returncode == 0, (
        f"Import failed: {result.stderr}"
    )


def test_core_exports_expected_names():
    """guardians.__init__ should export core concepts."""
    import guardians
    expected = [
        "Workflow", "WorkflowStep", "ToolCallNode", "ConditionalNode",
        "LoopNode", "SymRef",
        "ToolSpec", "ParamSpec", "ToolRegistry",
        "Policy", "SecurityAutomaton", "AutomatonState",
        "AutomatonTransition", "TaintRule",
        "verify", "VerificationResult", "Violation",
        "WorkflowExecutor", "SecurityViolation",
    ]
    for name in expected:
        assert hasattr(guardians, name), f"Missing export: {name}"


def test_adapters_not_imported_by_core():
    """guardians.__init__ must not import adapters."""
    code = (
        "import guardians; "
        "assert 'guardians.adapters' not in __import__('sys').modules, "
        "'adapters were imported by guardians core init'"
    )
    result = subprocess.run(
        [sys.executable, "-c", code],
        capture_output=True, text=True,
    )
    assert result.returncode == 0, (
        f"Import failed: {result.stderr}"
    )
