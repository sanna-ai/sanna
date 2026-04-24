"""Cross-SDK NFC normalization scope tests (SAN-225, ADR-004).

These tests assert the ADR-004 decision that NFC normalization applies
at the hash_text() boundary only. hash_obj() / canonical_json_bytes()
preserve the original string encoding and DO NOT recursively NFC-walk.

If these tests ever fail, it means either:
1. The ADR-004 decision has been silently overridden in code, OR
2. The spec has been broadened without a coordinated SPEC_VERSION bump.

Either outcome is a governance regression per CLAUDE.md "Version numbers
mean something" — stop and surface the change before continuing.

Cross-SDK parity: the equivalent test exists in sanna-ts at
packages/core/tests/nfc-scope.test.ts. Both SDKs must produce the same
answers to the same input vectors.

References:
- ADR-004: NFC Normalization Scope in Canonical JSON (decided 2026-02-18)
- spec/sanna-specification-v1.4.md Section 3.1, Section 13.1 item 8
- SAN-252: contingent upgrade path if real-world NFD strings surface
"""

import unicodedata

from sanna.hashing import hash_text, hash_obj


# Composed (NFC): "café" with U+00E9 LATIN SMALL LETTER E WITH ACUTE
COMPOSED = "café"
# Decomposed (NFD): "cafe" + U+0301 COMBINING ACUTE ACCENT — byte-different
# but canonically equivalent to COMPOSED under NFC.
DECOMPOSED = "café"


class TestNFCScope:
    """ADR-004: NFC applies at hash_text boundary; NOT recursive in hash_obj."""

    def test_inputs_differ_byte_wise(self):
        """Sanity check: composed and decomposed forms are BYTE-DIFFERENT
        even though they look identical. If this fails, the test fixture
        itself is broken — the tests below presuppose byte-level inequality
        pre-normalization.
        """
        assert COMPOSED != DECOMPOSED
        assert COMPOSED.encode("utf-8") != DECOMPOSED.encode("utf-8")
        # But they are canonically equivalent under NFC:
        assert unicodedata.normalize("NFC", DECOMPOSED) == COMPOSED

    def test_hash_text_normalizes_nfc(self):
        """hash_text() applies NFC — composed and decomposed strings
        MUST produce identical hashes at the hash_text boundary.
        """
        assert hash_text(COMPOSED) == hash_text(DECOMPOSED), (
            "hash_text must NFC-normalize at the hashing boundary "
            "(spec v1.4 Section 3.1, ADR-004). Composed vs decomposed "
            "forms of canonically-equivalent Unicode MUST hash identically."
        )

    def test_hash_obj_preserves_encoding(self):
        """hash_obj() does NOT recursively NFC-normalize strings
        (ADR-004). Composed vs decomposed strings MUST produce DIFFERENT
        hashes at the hash_obj layer. If this ever fails, the ADR-004
        decision has been silently overridden — stop and consult ADR-004
        and SAN-252 before continuing.
        """
        assert hash_obj({"val": COMPOSED}) != hash_obj({"val": DECOMPOSED}), (
            "hash_obj must NOT recursively NFC-normalize strings per "
            "ADR-004. If this assertion fails, canonical_json_bytes has "
            "been silently changed to NFC-recurse, which invalidates all "
            "existing receipts. Revert the change and file an ADR to "
            "revisit ADR-004 with a coordinated SPEC_VERSION bump (see "
            "SAN-252 for the upgrade path)."
        )

    def test_hash_obj_preserves_encoding_in_nested_dict(self):
        """Nested dict — same invariant applies recursively (i.e., no
        recursion of NFC) at every depth.
        """
        composed_nested = {"outer": {"inner": COMPOSED}}
        decomposed_nested = {"outer": {"inner": DECOMPOSED}}
        assert hash_obj(composed_nested) != hash_obj(decomposed_nested)

    def test_hash_obj_preserves_encoding_in_list(self):
        """List — same invariant applies."""
        assert hash_obj([COMPOSED]) != hash_obj([DECOMPOSED])

    def test_hash_obj_preserves_encoding_in_dict_key(self):
        """Dict keys — same invariant applies. A key's encoding is
        preserved too (no NFC normalization on keys).
        """
        assert hash_obj({COMPOSED: 1}) != hash_obj({DECOMPOSED: 1})
