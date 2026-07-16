"""Long-term memory — vector/lexical store of prior findings (RAG across campaigns).

Cross-campaign retrieval lets the Threat Modeler recall "we've seen this pattern
before." The store is pluggable: if a synchronous ``embed_fn`` (→ list[float]) is
injected it does semantic cosine search; otherwise it falls back to lexical
token-overlap, so the memory is usable offline and in tests without an embedding
endpoint.
"""
from __future__ import annotations

import math
import re
from typing import Any, Callable, Optional, TypedDict

__all__ = ["FindingRecord", "LongTermMemory"]

_WORD_RE = re.compile(r"[a-z0-9]+")


class FindingRecord(TypedDict):
    id: str
    cwe: Optional[str]
    title: str
    text: str
    meta: dict[str, Any]


def _tokens(text: str) -> set[str]:
    return set(_WORD_RE.findall((text or "").lower()))


class LongTermMemory:
    """A retrieval store over prior findings (semantic if embed_fn given)."""

    def __init__(self, embed_fn: Optional[Callable[[str], list[float]]] = None) -> None:
        """
        Args:
            embed_fn: Optional sync callable mapping text → embedding vector.
                When provided, :meth:`search` uses cosine similarity; otherwise
                lexical token-overlap.
        """
        self._embed = embed_fn
        self._records: list[FindingRecord] = []
        self._vectors: list[list[float]] = []

    def __len__(self) -> int:
        return len(self._records)

    def add(
        self,
        id: str,
        text: str,
        *,
        cwe: Optional[str] = None,
        title: str = "",
        meta: Optional[dict[str, Any]] = None,
    ) -> None:
        """Index a prior finding. Silently replaces an existing id."""
        record = FindingRecord(
            id=id, cwe=cwe, title=title or text[:80], text=text, meta=meta or {}
        )
        vec = self._embed(text) if self._embed else []
        for i, r in enumerate(self._records):
            if r["id"] == id:
                self._records[i] = record
                if self._vectors:
                    self._vectors[i] = vec
                return
        self._records.append(record)
        if self._embed:
            self._vectors.append(vec)

    def search(self, query: str, k: int = 5) -> list[FindingRecord]:
        """Return the top-``k`` records most similar to ``query``."""
        if not self._records:
            return []
        if self._embed and self._vectors:
            return self._semantic(query, k)
        return self._lexical(query, k)

    def _semantic(self, query: str, k: int) -> list[FindingRecord]:
        qv = self._embed(query) if self._embed else []  # type: ignore[misc]
        scored = sorted(
            zip(self._records, self._vectors),
            key=lambda rv: -self._cosine(qv, rv[1]),
        )
        return [r for r, _ in scored[:k]]

    def _lexical(self, query: str, k: int) -> list[FindingRecord]:
        q_tokens = _tokens(query)
        scored = sorted(
            self._records,
            key=lambda r: len(q_tokens & _tokens(f"{r['title']} {r['text']} {r['cwe'] or ''}")),
            reverse=True,
        )
        return scored[:k]

    @staticmethod
    def _cosine(a: list[float], b: list[float]) -> float:
        if not a or not b:
            return 0.0
        dot = sum(x * y for x, y in zip(a, b))
        na = math.sqrt(sum(x * x for x in a))
        nb = math.sqrt(sum(y * y for y in b))
        return dot / (na * nb) if na and nb else 0.0
