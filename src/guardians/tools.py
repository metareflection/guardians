"""Tool registry with formal specifications.

Each tool carries pre-conditions, post-conditions, frame conditions,
and taint labels — enabling static verification before execution.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable

from pydantic import BaseModel


class ParamSpec(BaseModel):
    """Schema for a single tool parameter."""

    name: str
    type: str = "str"
    description: str = ""
    is_taint_sink: bool = False


class ToolSpec(BaseModel):
    """Formal specification for a registered tool.

    Pre/post/frame conditions are expressed as strings in a mini-DSL
    that can be translated to Z3 for verification.
    """

    name: str
    description: str = ""
    params: list[ParamSpec] = []
    return_type: str = "Any"

    # Z3-checkable conditions
    preconditions: list[str] = []
    postconditions: list[str] = []
    frame_conditions: list[str] = []

    # Taint labels for data-flow analysis
    source_labels: list[str] = []
    sink_labels: list[str] = []


@dataclass
class ToolRegistry:
    """Registry mapping tool names to their specs and implementations."""

    _specs: dict[str, ToolSpec] = field(default_factory=dict)
    _impls: dict[str, Callable[..., Any]] = field(default_factory=dict)

    def register(self, spec: ToolSpec, impl: Callable[..., Any]) -> None:
        self._specs[spec.name] = spec
        self._impls[spec.name] = impl

    def get_spec(self, name: str) -> ToolSpec | None:
        return self._specs.get(name)

    def get_impl(self, name: str) -> Callable[..., Any] | None:
        return self._impls.get(name)

    def all_specs(self) -> dict[str, ToolSpec]:
        return dict(self._specs)

    def tool_names(self) -> set[str]:
        return set(self._specs.keys())
