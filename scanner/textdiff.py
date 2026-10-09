"""
textdiff.py - Small helpers for comparing HTTP response bodies.

Scanners that rely on "did the page change?" (boolean-based SQLi, username
enumeration) must ignore markup noise such as scripts, tags and whitespace,
otherwise tiny cosmetic differences look like findings.
"""

import re

_SCRIPT_STYLE_RE = re.compile(r"<(script|style)\b.*?</\1>", re.IGNORECASE | re.DOTALL)
_TAG_RE = re.compile(r"<[^>]+>")
_WS_RE = re.compile(r"\s+")


def visible_text(html: str) -> str:
    """Return the lower-cased, whitespace-normalised text a user would see."""
    text = _SCRIPT_STYLE_RE.sub(" ", html or "")
    text = _TAG_RE.sub(" ", text)
    return _WS_RE.sub(" ", text).strip().lower()


def similarity(a: str, b: str) -> float:
    """Jaccard similarity of the word sets of two pages (1.0 = same words)."""
    words_a, words_b = set(visible_text(a).split()), set(visible_text(b).split())
    if not words_a and not words_b:
        return 1.0
    return len(words_a & words_b) / len(words_a | words_b)


def differs(a: str, b: str, min_similarity: float = 0.98, max_length_change: float = 0.02) -> bool:
    """
    True if two responses are meaningfully different.

    Pages are "the same" when their visible text is identical, or when they share
    almost all words and have almost the same length (so a changing timestamp
    does not count). Callers that need robustness against dynamic pages should
    first check that two requests for the *same* URL do not differ.
    """
    text_a, text_b = visible_text(a), visible_text(b)
    if text_a == text_b:
        return False
    longest = max(len(text_a), len(text_b))
    length_change = abs(len(text_a) - len(text_b)) / longest if longest else 0.0
    return similarity(a, b) < min_similarity or length_change > max_length_change
