"""Shared sanitization helpers for untrusted content in LLM prompts.

Used by both ``sanna.evaluators.llm`` and ``sanna.reasoning.llm_client``
to prevent prompt injection via XML tag breakout in ``<audit>``-wrapped
content.
"""

from __future__ import annotations


def escape_audit_content(text: str) -> str:
    """Escape XML-like tags in untrusted content to prevent audit tag injection.

    Prevents injection via ``</audit>`` in untrusted content that would
    break out of the ``<audit>`` wrapper in LLM prompts.

    Escapes ``&``, ``<``, and ``>`` to their XML entity equivalents.
    """
    return text.replace('&', '&amp;').replace('<', '&lt;').replace('>', '&gt;')
