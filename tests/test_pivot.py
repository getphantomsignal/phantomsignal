"""Tests for the recursive pivot engine (Phase 1)."""
import asyncio

import pytest

from phantomsignal.intel.pivot import (
    RecursivePivotEngine,
    PivotConfig,
    classify,
    extract_entities,
)


def test_classify_kinds():
    assert classify("8.8.8.8") == "ip"
    assert classify("999.1.1.1") is None          # octet validation
    assert classify("example.com") == "domain"
    assert classify("api.example.com") == "subdomain"
    assert classify("admin@example.com") == "email"
    assert classify("justausername") is None       # not pivotable
    assert classify("") is None


def test_extract_entities_from_result_data():
    results = [
        {"source": "shodan", "data": {"ip": "1.2.3.4", "domain": "example.com"}},
        {"source": "crtsh", "data": {"subdomain": ["api.example.com", "api.example.com"]}},
        {"source": "hunter", "data": {"email": "root@example.com"}},
        {"source": "noise", "data": {"value": "not-an-entity!!"}},
    ]
    ents = {(e.kind, e.value) for e in extract_entities(results)}
    assert ("ip", "1.2.3.4") in ents
    assert ("domain", "example.com") in ents
    assert ("subdomain", "api.example.com") in ents
    assert ("email", "root@example.com") in ents
    # dedup across the duplicated subdomain
    assert sum(1 for e in extract_entities(results) if e.value == "api.example.com") == 1


def _run(coro):
    return asyncio.run(coro)


def test_pivot_expands_and_dedups():
    # Fake pass: example.com -> a subdomain; that subdomain -> an IP; IP -> nothing.
    graph = {
        "example.com": [{"source": "x", "data": {"subdomain": "api.example.com"}}],
        "api.example.com": [{"source": "x", "data": {"ip": "1.2.3.4"}}],
        "1.2.3.4": [{"source": "x", "data": {"subdomain": "api.example.com"}}],  # loop back
    }
    visited = []

    async def fake_pass(t):
        visited.append(t)
        return graph.get(t, [])

    engine = RecursivePivotEngine(fake_pass, PivotConfig(max_depth=3))
    results, stats = _run(engine.expand("example.com"))

    # visits each unique target exactly once despite the loop-back
    assert visited.count("api.example.com") == 1
    assert visited.count("1.2.3.4") == 1
    assert stats.passes == 3
    # every result carries a pivot_depth annotation for graph reconstruction
    assert all("pivot_depth" in r for r in results)
    # the subdomain was discovered at the root (depth 0) pass
    root_sub = next(r for r in results if r["data"].get("subdomain") == "api.example.com")
    assert root_sub["pivot_depth"] == 0


def test_pivot_depth_guard():
    graph = {
        "example.com": [{"source": "x", "data": {"subdomain": "a.example.com"}}],
        "a.example.com": [{"source": "x", "data": {"subdomain": "b.example.com"}}],
        "b.example.com": [{"source": "x", "data": {"subdomain": "c.example.com"}}],
    }

    async def fake_pass(t):
        return graph.get(t, [])

    engine = RecursivePivotEngine(fake_pass, PivotConfig(max_depth=1))
    _, stats = _run(engine.expand("example.com"))
    # depth 0 (root) + depth 1 (a.example.com) only
    assert set(stats.targets_visited) == {"example.com", "a.example.com"}


def test_pivot_scope_blocks_cross_domain():
    graph = {
        "example.com": [{"source": "x", "data": {"domain": "unrelated.org"}}],
    }
    seen = []

    async def fake_pass(t):
        seen.append(t)
        return graph.get(t, [])

    # default scope: cross-domain blocked
    engine = RecursivePivotEngine(fake_pass, PivotConfig(max_depth=2))
    _run(engine.expand("example.com"))
    assert "unrelated.org" not in seen

    # opt-in: cross-domain followed
    seen.clear()
    engine2 = RecursivePivotEngine(
        fake_pass, PivotConfig(max_depth=2, allow_cross_domain=True))
    _run(engine2.expand("example.com"))
    assert "unrelated.org" in seen


def test_pivot_entity_budget():
    # root fans out to many subdomains; budget caps total targets
    subs = [f"h{i}.example.com" for i in range(100)]

    async def fake_pass(t):
        if t == "example.com":
            return [{"source": "x", "data": {"subdomain": subs}}]
        return []

    engine = RecursivePivotEngine(fake_pass, PivotConfig(max_depth=2, max_entities=10))
    _, stats = _run(engine.expand("example.com"))
    assert stats.truncated
    # root + at most (budget-1) children
    assert stats.passes <= 10
