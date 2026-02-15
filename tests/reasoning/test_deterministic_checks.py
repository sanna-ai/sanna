import pytest

from sanna.reasoning.checks import (
    JustificationPresenceCheck,
    MinimumSubstanceCheck,
    NoParrotingCheck,
)


class TestGLC001Presence:
    @pytest.mark.asyncio
    async def test_missing_justification_fails(self):
        check = JustificationPresenceCheck()
        result = await check.execute("", {})
        assert result.passed is False
        assert result.score == 0.0
        assert result.check_id == "glc_001_justification_present"

    @pytest.mark.asyncio
    async def test_present_justification_passes(self):
        check = JustificationPresenceCheck()
        result = await check.execute("Valid justification", {})
        assert result.passed is True
        assert result.score == 1.0
        assert result.latency_ms < 10  # Deterministic checks are fast

    @pytest.mark.asyncio
    async def test_whitespace_only_fails(self):
        check = JustificationPresenceCheck()
        result = await check.execute("   ", {})
        assert result.passed is False
        assert result.score == 0.0

    @pytest.mark.asyncio
    async def test_method_is_deterministic_presence(self):
        check = JustificationPresenceCheck()
        result = await check.execute("test", {})
        assert result.method == "deterministic_presence"


class TestGLC002Substance:
    @pytest.mark.asyncio
    async def test_short_justification_fails(self):
        check = MinimumSubstanceCheck({"min_length": 20})
        result = await check.execute("too short", {})
        assert result.passed is False
        assert result.score == 0.0

    @pytest.mark.asyncio
    async def test_sufficient_length_passes(self):
        check = MinimumSubstanceCheck({"min_length": 20})
        result = await check.execute("This is a sufficiently long justification", {})
        assert result.passed is True
        assert result.score == 1.0

    @pytest.mark.asyncio
    async def test_configurable_min_length(self):
        check = MinimumSubstanceCheck({"min_length": 50})
        result = await check.execute("This is only 30 chars long!!", {})
        assert result.passed is False

    @pytest.mark.asyncio
    async def test_default_min_length_is_20(self):
        check = MinimumSubstanceCheck()
        result = await check.execute("Exactly twenty chars!", {})
        assert result.passed is True

    @pytest.mark.asyncio
    async def test_method_is_deterministic_regex(self):
        check = MinimumSubstanceCheck()
        result = await check.execute("This is a sufficiently long justification", {})
        assert result.method == "deterministic_regex"


class TestGLC003Parroting:
    @pytest.mark.asyncio
    async def test_blocklist_match_fails(self):
        check = NoParrotingCheck()
        result = await check.execute("I'm doing this because you asked me to", {})
        assert result.passed is False
        assert result.score == 0.0
        assert "because you asked" in result.details["matched"]

    @pytest.mark.asyncio
    async def test_no_blocklist_match_passes(self):
        check = NoParrotingCheck()
        result = await check.execute("Cleanup per data retention policy", {})
        assert result.passed is True
        assert result.score == 1.0

    @pytest.mark.asyncio
    async def test_case_insensitive_matching(self):
        check = NoParrotingCheck()
        result = await check.execute("Because You Asked Me To", {})
        assert result.passed is False

    @pytest.mark.asyncio
    async def test_custom_blocklist(self):
        check = NoParrotingCheck({"blocklist": ["forbidden phrase"]})
        result = await check.execute("This contains forbidden phrase", {})
        assert result.passed is False

    @pytest.mark.asyncio
    async def test_method_is_deterministic_blocklist(self):
        check = NoParrotingCheck()
        result = await check.execute("Valid justification text", {})
        assert result.method == "deterministic_blocklist"

    @pytest.mark.asyncio
    async def test_default_blocklist_you_told_me(self):
        check = NoParrotingCheck()
        result = await check.execute("I did it because you told me to do it", {})
        assert result.passed is False
        assert result.details["matched"] == "you told me to"
