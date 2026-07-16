"""Tests for new agent_swarm skills, long-term memory, and routing policies."""
from __future__ import annotations

import pytest


# --------------------------------------------------------------------------- #
# New skills
# --------------------------------------------------------------------------- #
async def test_cwe_knowledge_known_and_unknown():
    from agent_swarm.skills import cwe_knowledge

    known = await cwe_knowledge("89")
    assert known["cwe"] == "CWE-89"
    assert known["known"] is True
    assert "SQL" in known["name"]

    unknown = await cwe_knowledge("cwe-99999")
    assert unknown["known"] is False


async def test_craft_pov_inputs_dedup_and_cap():
    from agent_swarm.skills import craft_pov_inputs

    variants = await craft_pov_inputs("hello", count=8)
    assert len(variants) <= 8
    assert len(variants) == len(set(variants))  # deduped
    assert "" in variants  # boundary value present


def test_parse_fuzzer_stats():
    from agent_swarm.skills import parse_fuzzer_stats

    stats = parse_fuzzer_stats("#1024 INITED cov: 1234 ft: 56 corp: 7 exec speed: 1000 crashes: 3")
    assert stats["coverage_edges"] == 1234
    assert stats["feature_edges"] == 56
    assert stats["corpus_size"] in (7, 1024)
    assert stats["execs_per_sec"] == 1000


async def test_fuzzer_bridge_builds_libfuzzer_command():
    from agent_swarm.skills import fuzzer_bridge

    desc = await fuzzer_bridge("/srv/target", engine="libfuzzer", harness="./h", duration_s=10)
    assert desc["engine"] == "libfuzzer"
    assert any("max_total_time=10" in c for c in desc["command"])


async def test_fuzzer_bridge_rejects_unknown_engine():
    from agent_swarm.skills import fuzzer_bridge, ToolError

    with pytest.raises(ToolError):
        await fuzzer_bridge("/srv/target", engine="qira")


async def test_disasm_missing_binary_raises(tmp_path):
    from agent_swarm.skills import disasm, ToolError

    with pytest.raises(ToolError):
        await disasm(str(tmp_path / "nope.elf"))


# --------------------------------------------------------------------------- #
# Long-term memory (lexical + semantic fallbacks)
# --------------------------------------------------------------------------- #
def test_long_term_memory_lexical_search():
    from agent_swarm.memory import LongTermMemory

    mem = LongTermMemory()
    mem.add("F-1", "SQL injection via unsanitized id parameter", cwe="CWE-89", title="SQLi")
    mem.add("F-2", "use after free in parser", cwe="CWE-416", title="UAF")
    results = mem.search("sql injection query", k=2)
    assert results and results[0]["id"] == "F-1"


def test_long_term_memory_semantic_with_injected_embed():
    from agent_swarm.memory import LongTermMemory

    # Trivial embed_fn: bag-of-words over a tiny vocabulary → cosine works.
    def embed(text: str) -> list[float]:
        words = text.lower().split()
        return [float("injection" in words), float("memory" in words or "free" in words)]

    mem = LongTermMemory(embed_fn=embed)
    mem.add("F-1", "sql injection bug", cwe="CWE-89")
    mem.add("F-2", "use after free memory bug", cwe="CWE-416")
    results = mem.search("injection", k=1)
    assert results[0]["id"] == "F-1"


# --------------------------------------------------------------------------- #
# Routing policies
# --------------------------------------------------------------------------- #
def test_routing_policies():
    from agent_swarm.routing import prioritize, should_terminate

    empty: dict = {"iteration": 0, "max_iterations": 10, "hypotheses": []}
    assert should_terminate(empty) is True  # no hypotheses

    exhausted = {"iteration": 10, "max_iterations": 10, "hypotheses": [{"id": "H1", "status": "pending", "confidence": 0.5}]}
    assert should_terminate(exhausted) is True  # budget

    active = {
        "iteration": 0, "max_iterations": 10,
        "hypotheses": [
            {"id": "H1", "status": "pending", "confidence": 0.3},
            {"id": "H2", "status": "pending", "confidence": 0.9},
        ],
    }
    assert should_terminate(active) is False
    ranked = prioritize(active)
    assert ranked[0]["id"] == "H2"  # higher confidence first

    all_resolved = {"iteration": 0, "max_iterations": 10,
                    "hypotheses": [{"id": "H1", "status": "verified", "confidence": 0.9}]}
    assert should_terminate(all_resolved) is True
