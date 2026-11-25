"""Text normalisation shared by every analyser.

Arabic and English text is normalised character-by-character while keeping a map back to the
original offsets, so that every rule match can be quoted *exactly* as it appears in the evidence.
"""
from __future__ import annotations

import re
from dataclasses import dataclass

# Arabic diacritics (tashkeel), superscript alef and tatweel are dropped.
_DROP = set(chr(c) for c in range(0x064B, 0x0653)) | {"ٰ", "ـ", "\u200f", "\u200e", "\u200b"}
_MAP = {
    "أ": "ا", "إ": "ا", "آ": "ا", "ٱ": "ا",
    "ى": "ي", "ئ": "ي", "ؤ": "و", "ة": "ه",
    # Arabic-Indic and Persian digits -> ASCII
    **{chr(0x0660 + i): str(i) for i in range(10)},
    **{chr(0x06F0 + i): str(i) for i in range(10)},
    "’": "'", "‘": "'", "“": '"', "”": '"',
}


@dataclass(frozen=True)
class NormalizedText:
    original: str
    norm: str
    index: tuple[int, ...]  # norm position -> original position

    def span_to_original(self, start: int, end: int) -> tuple[int, int]:
        if not self.index or start >= len(self.index):
            return (len(self.original), len(self.original))
        o_start = self.index[start]
        o_end = self.index[max(start, end - 1)] + 1
        return (o_start, o_end)


def normalize(text: str) -> NormalizedText:
    out: list[str] = []
    idx: list[int] = []
    for i, ch in enumerate(text):
        if ch in _DROP:
            continue
        mapped = _MAP.get(ch)
        if mapped is None:
            low = ch.lower()
            mapped = low[0] if low else ch
        out.append(mapped)
        idx.append(i)
    return NormalizedText(text, "".join(out), tuple(idx))


def normalize_pattern(pattern: str) -> str:
    """Apply the same Arabic letter folding to a regex pattern (ASCII is left untouched)."""
    return "".join(_MAP.get(c, c) for c in pattern if c not in _DROP)


def snippet(text: str, start: int, end: int, radius: int = 48) -> str:
    s = max(0, start - radius)
    e = min(len(text), end + radius)
    prefix = "…" if s > 0 else ""
    suffix = "…" if e < len(text) else ""
    return prefix + re.sub(r"\s+", " ", text[s:e]).strip() + suffix


def contains_arabic(text: str) -> bool:
    return bool(re.search(r"[؀-ۿ]", text))
