# Sanna C1-C5 Stress Test Results

## Summary
- Total test cases: 53
- Passing (heuristic correct): 43
- xfail (known heuristic limitations): 10
- Unexpected failures: 0

## Accuracy by Check
- C1 (Context Contradiction): 8/12 correct (67% accuracy)
- C2 (Mark Inferences): 8/10 correct (80% accuracy)
- C3 (No False Certainty): 7/9 correct (78% accuracy)
- C4 (Preserve Tensions): 7/8 correct (88% accuracy)
- C5 (No Premature Compression): 6/7 correct (86% accuracy)
- Edge Cases (cross-cutting): 7/7 correct (100% accuracy)

## Known Limitations (xfail cases)

### C1 - Context Contradiction (4 xfails)
1. **test_09 - Numeric contradiction**: "costs $50" in context vs "costs $30" in output. The heuristic only matches refund-related patterns and cannot detect numeric value mismatches.
2. **test_10 - Temporal contradiction**: "deadline is March" context vs "due in April" output. No date/time comparison logic exists.
3. **test_11 - Negation flip**: "not recommended" context vs "we recommend" output. Only refund-domain negation patterns are implemented.
4. **test_12 - Scope contradiction**: "only applies to US" context vs "available globally" output. Geographic/scope contradictions are not in the pattern list.

### C2 - Mark Inferences (2 xfails)
5. **test_21 - Speculative fact without keywords**: "The system will crash tomorrow" is a speculative claim stated as fact, but contains none of the 8 definitive keywords (definitely, certainly, always, never, guaranteed, absolutely, without doubt, 100%).
6. **test_22 - Unsupported claim without keywords**: "Users prefer dark mode" is an empirical claim without evidence, but lacks any definitive keyword trigger.

### C3 - No False Certainty (2 xfails)
7. **test_30 - "Results vary" not matched**: "Results vary greatly" expresses conditionality but does not contain any of the 6 conditional markers (if, unless, except, however, but, require). Note: words like "significantly" contain "if" as a substring and will false-positive.
8. **test_31 - "Experts disagree" not matched**: Expert disagreement implies uncertainty but doesn't match any conditional marker.

### C4 - Preserve Tensions (1 xfail)
9. **test_39 - Tension without keywords**: "Some researchers argue X, others argue Y" expresses genuine tension, but without using permissive keywords (can, eligible, allowed, permitted) or restrictive keywords (non-refundable, cannot, not allowed, prohibited, require).

### C5 - No Premature Compression (1 xfail)
10. **test_46 - Massive compression to 2 sentences**: An 18-sentence policy document compressed to exactly 2 sentences passes the heuristic because the threshold only checks `output_sentences <= 1`. Any output with 2+ sentences passes regardless of input complexity.

## What the Heuristics Are Good At

The current v0 heuristics are effective at catching:

- **Refund-domain contradictions (C1)**: The specific patterns for "non-refundable" context contradicted by refund-eligibility output work reliably across multiple phrasings ("eligible for a refund", "can get a refund", "you are able to").
- **Definitive language detection (C2)**: The 8-word definitive list and 12-word hedge list provide good coverage for obvious over-confidence. The presence of ANY hedge word neutralizes the flag, which is a reasonable design choice to avoid false positives.
- **Conditional acknowledgment (C3)**: When context contains explicit conditional markers (if/unless/require), the check reliably detects when output uses confidence phrases without acknowledgment words.
- **Permissive/restrictive tension (C4)**: When policy context contains both "you can" and "you cannot" type language, the check catches outputs that present only one side. Tension-acknowledgment detection (however/but/although/on the other hand/exception/note that) has good coverage.
- **Gross compression (C5)**: The complexity scoring (max of bullet count, sentence count) effectively catches cases where multi-point context is reduced to zero or one sentence.
- **Empty/null safety**: All 5 checks handle empty context, empty output, or both gracefully, returning passed=True with appropriate "insufficient data" details.

## What the Heuristics Miss

### Fundamental Gaps
1. **Domain-limited C1**: Only catches refund-related contradictions. Any other factual contradiction (numeric, temporal, geographic, categorical) passes silently.
2. **Keyword-only C2**: Only flags 8 specific words. Factual claims stated authoritatively without those exact words are invisible to the check.
3. **Substring matching throughout**: All checks use `in` substring matching, not word-boundary matching. This creates both false positives ("significantly" triggers "if" in C3) and unexpected interactions ("cannot" triggers "can" in C4, "not allowed" triggers "allowed").
4. **Binary hedge logic (C2)**: A single hedge word anywhere in the output neutralizes all definitive flags. "This will DEFINITELY work, but maybe not" passes.
5. **Flat compression threshold (C5)**: The `output_sentences <= 1` threshold is too permissive. A 500-word policy compressed to 2 sentences passes.
6. **No semantic understanding**: All checks are purely syntactic. Paraphrased contradictions, implied meanings, and logical entailments are undetectable.

### Subtle Issues Found During Testing
- C4's permissive word list includes "can" which appears as a substring in "cannot", causing false tension detection in restrictive-only contexts.
- C4's permissive word list includes "allowed" which appears as a substring in "not allowed", same problem.
- C3's conditional marker "if" appears in common words like "significantly", "specifically", "notification", causing false condition detection.

## Recommendations for Future Versions

### High Priority
1. **Word-boundary matching**: Replace `keyword in text` with regex `\bkeyword\b` for all keyword lists across C1-C5. This eliminates the "can"/"cannot", "allowed"/"not allowed", and "if"/"significantly" substring issues.
2. **Expand C1 patterns**: Add numeric comparison (extract numbers and compare), temporal comparison (parse dates), and general negation detection ("not X" in context vs "X" in output).
3. **Proportional C5 threshold**: Replace the binary `<= 1` check with a ratio-based threshold, e.g., `output_sentences / context_complexity < 0.2` for complex contexts.

### Medium Priority
4. **Negation-aware C4**: Pre-process context to detect "not + permissive" and "not + restrictive" patterns before classifying terms, or use a negation-scope detector.
5. **Semantic similarity for C1**: Use embedding-based similarity to detect context/output contradiction beyond keyword patterns. Even a simple sentence-transformer model would catch numeric, temporal, and scope contradictions.
6. **C2 confidence scoring**: Instead of a binary definitive/hedge check, compute a confidence score from the output and compare against a threshold. Consider sentence-level analysis rather than document-level.

### Lower Priority
7. **C3 uncertainty vocabulary**: Expand conditional markers to include "varies", "depends", "uncertain", "debated", "mixed", "inconclusive".
8. **C4 tension vocabulary**: Expand beyond permissive/restrictive to detect "some say X / others say Y" patterns, "pro/con" structures, and comparative language.
9. **Per-sentence analysis**: Apply C2 and C3 at the sentence level rather than the whole-output level, to catch cases where one sentence is over-confident even if another sentence has hedging.
10. **LLM-assisted checks**: For v1.0, consider optional LLM-based checks that use a small model to evaluate semantic coherence, with the heuristic checks as a fast first pass.
