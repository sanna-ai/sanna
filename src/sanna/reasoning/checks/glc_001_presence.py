from .base import Check


class JustificationPresenceCheck(Check):
    """glc_001: Verify _justification field exists and is non-empty."""

    def check_id(self) -> str:
        return "glc_001_justification_present"

    def method(self) -> str:
        return "deterministic_presence"

    async def _execute(
        self, justification: str, context: dict
    ) -> tuple[bool, float, dict | None]:
        if justification and len(justification.strip()) > 0:
            return True, 1.0, None
        return False, 0.0, {"reason": "justification missing or empty"}
