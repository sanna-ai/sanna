from .base import Check


class NoParrotingCheck(Check):
    """glc_003: Verify justification doesn't contain blocklist phrases."""

    def check_id(self) -> str:
        return "glc_003_no_parroting"

    def method(self) -> str:
        return "deterministic_blocklist"

    async def _execute(
        self, justification: str, context: dict
    ) -> tuple[bool, float, dict | None]:
        blocklist = self.config.get(
            "blocklist",
            [
                "because you asked",
                "you told me to",
                "you requested",
            ],
        )

        justification_lower = justification.lower()

        for phrase in blocklist:
            if phrase.lower() in justification_lower:
                return False, 0.0, {"matched": phrase}

        return True, 1.0, None
