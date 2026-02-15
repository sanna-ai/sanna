from abc import ABC, abstractmethod
import time

from sanna.gateway.receipt_v2 import GatewayCheckResult


class Check(ABC):
    """Abstract base class for reasoning checks (async interface)."""

    def __init__(self, config: dict | None = None):
        self.config = config or {}

    @abstractmethod
    def check_id(self) -> str:
        """Unique check identifier (e.g., 'glc_001_justification_present')."""
        pass

    @abstractmethod
    def method(self) -> str:
        """Check method type (e.g., 'deterministic_presence')."""
        pass

    @abstractmethod
    async def _execute(
        self, justification: str, context: dict
    ) -> tuple[bool, float, dict | None]:
        """Execute the check logic (async).

        Returns: (passed, score, details)
        """
        pass

    async def execute(self, justification: str, context: dict) -> GatewayCheckResult:
        """Execute check with latency measurement."""
        start_ms = time.perf_counter() * 1000
        passed, score, details = await self._execute(justification, context)
        latency_ms = int((time.perf_counter() * 1000) - start_ms)

        return GatewayCheckResult(
            check_id=self.check_id(),
            method=self.method(),
            passed=passed,
            score=score,
            latency_ms=latency_ms,
            details=details,
        )
