from .base import Check


class MinimumSubstanceCheck(Check):
    """glc_002: Verify justification meets minimum length requirement."""

    def check_id(self) -> str:
        return "glc_002_minimum_substance"

    def method(self) -> str:
        return "deterministic_regex"

    async def _execute(
        self, justification: str, context: dict
    ) -> tuple[bool, float, dict | None]:
        min_length = self.config.get("min_length", 20)
        actual_length = len(justification.strip())

        if actual_length >= min_length:
            return True, 1.0, None

        return False, 0.0, {
            "reason": f"justification too short ({actual_length} chars, need {min_length})"
        }
