"""Error types for the guardians core."""


class SecurityViolation(RuntimeError):
    """Raised when a security check fails at runtime."""
