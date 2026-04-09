"""Verification result types."""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class Violation:
    """A single policy violation found during verification."""

    category: str
    message: str
    step_label: str
    rule_name: str = ""


@dataclass
class VerificationResult:
    """Outcome of static verification."""

    ok: bool = True
    violations: list[Violation] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)

    def add(self, v: Violation) -> None:
        self.ok = False
        self.violations.append(v)

    def warn(self, msg: str) -> None:
        self.warnings.append(msg)
