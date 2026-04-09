"""Example: GuardedAgent high-level API.

Demonstrates the decorator-based tool registration and security rules.
This example uses run_workflow() with a pre-built workflow (no LLM).

Run with: python examples/guarded_agent.py
"""

from guardians.workflow import Workflow, WorkflowStep, ToolCallNode, SymRef
from guardians.adapters.agent import GuardedAgent


# --- Build agent ---

agent = GuardedAgent("file_manager")


@agent.tool(taint_labels=["file_content"])
def read_file(path: str) -> str:
    """Read a file's contents."""
    return f"[contents of {path}]"


@agent.tool(
    sink_params=["content"],
    preconditions=["len(path) > 0"],
    frame_conditions=["path != '*'"],
)
def write_file(path: str, content: str) -> dict:
    """Write content to a file."""
    print(f"  [write_file] path={path}, content={content[:40]}...")
    return {"status": "written", "path": path}


@agent.tool
def transform(text: str) -> str:
    """Transform text (sanitizer)."""
    return f"transformed: {text}"


# --- Security rules ---

agent.no_data_flow("read_file", to="write_file.content", unless_through=["transform"])


# --- Safe workflow: read → transform → write ---

safe_wf = Workflow(
    goal="Read, transform, and write a file",
    steps=[
        WorkflowStep(label="Read source", tool_call=ToolCallNode(
            tool_name="read_file",
            arguments={"path": "input.txt"},
            result_binding="raw",
        )),
        WorkflowStep(label="Transform", tool_call=ToolCallNode(
            tool_name="transform",
            arguments={"text": SymRef(ref="raw")},
            result_binding="clean",
        )),
        WorkflowStep(label="Write output", tool_call=ToolCallNode(
            tool_name="write_file",
            arguments={"path": "output.txt", "content": SymRef(ref="clean")},
        )),
    ],
)

# --- Unsafe workflow: read → write (skips transform) ---

unsafe_wf = Workflow(
    goal="Copy file without transform",
    steps=[
        WorkflowStep(label="Read", tool_call=ToolCallNode(
            tool_name="read_file",
            arguments={"path": "secret.txt"},
            result_binding="data",
        )),
        WorkflowStep(label="Write", tool_call=ToolCallNode(
            tool_name="write_file",
            arguments={"path": "leak.txt", "content": SymRef(ref="data")},
        )),
    ],
)


if __name__ == "__main__":
    from guardians.errors import SecurityViolation

    print("=== Safe workflow (read → transform → write) ===")
    result = agent.run_workflow(safe_wf)
    print(f"Trace: {[t['tool'] for t in result.trace]}")
    print(f"OK\n")

    print("=== Unsafe workflow (read → write, no transform) ===")
    try:
        agent.run_workflow(unsafe_wf)
    except SecurityViolation as e:
        print(f"Blocked: {e}")

    print("\nDone.")
