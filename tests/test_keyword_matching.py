"""Block F tests — keyword matching precision (all() vs any())."""

import pytest

from sanna.enforcement.authority import _matches_condition


class TestKeywordMatching:
    def test_all_keywords_required(self):
        """'delete production database' does NOT match 'list production services'."""
        assert not _matches_condition(
            "delete production database",
            "list production services",
        )

    def test_all_keywords_present(self):
        """'delete production database' DOES match when all words present."""
        assert _matches_condition(
            "delete production database",
            "please delete the production database",
        )

    def test_single_keyword_no_match(self):
        """Single keyword rule still requires that keyword."""
        assert not _matches_condition("delete", "list all items")
        assert _matches_condition("delete", "please delete this item")

    def test_empty_significant_words(self):
        """All words are stopwords → no match (changed from substring fallback)."""
        # "the" and "a" are stop words, "of" too — all < 3 chars or in stop list
        assert not _matches_condition("a the of", "a the of something")

    def test_partial_keyword_overlap(self):
        """Only some keywords present → no match."""
        assert not _matches_condition(
            "update production database",
            "update staging database",
        )

    def test_all_keywords_present_different_order(self):
        """Keywords can appear in any order in context."""
        assert _matches_condition(
            "delete production database",
            "the database in production should be deleted",
        )
