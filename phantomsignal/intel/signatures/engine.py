"""
PhantomSignal Signature Engine

A small, dependency-light matcher engine inspired by Nuclei. Templates are YAML
files carrying either a ``match`` block (matchers evaluated against the aggregated
intel results) or a ``dork`` block (GHDB-style queries rendered against the
target). Findings are emitted as standard PhantomSignal result dicts so they flow
through the existing storage/export layer unchanged.

Author:  the-clipper
AI:      Claude (Anthropic)
License: MIT — see LICENSE
"""
from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

import yaml

logger = logging.getLogger("phantomsignal.intel.signatures")

TEMPLATE_ROOT = Path(__file__).parent / "templates"

_SEVERITY_RELEVANCE = {
    "critical": 1.0, "high": 0.9, "medium": 0.7, "low": 0.5, "info": 0.3,
}


@dataclass
class Signature:
    """A parsed template. Exactly one of ``match`` / ``dork`` is populated."""
    id: str
    name: str
    severity: str = "info"
    tags: List[str] = field(default_factory=list)
    references: List[str] = field(default_factory=list)
    match: Optional[Dict[str, Any]] = None
    dork: Optional[Dict[str, Any]] = None
    source_path: str = ""

    @property
    def kind(self) -> str:
        return "dork" if self.dork else "match"


def _as_list(v) -> List:
    if v is None:
        return []
    return v if isinstance(v, list) else [v]


def load_templates(root: Optional[Path] = None) -> List[Signature]:
    """Load and validate every ``*.yaml`` template under ``root`` recursively."""
    root = root or TEMPLATE_ROOT
    sigs: List[Signature] = []
    for path in sorted(root.rglob("*.yaml")):
        try:
            doc = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
        except yaml.YAMLError as e:
            logger.error("Skipping malformed template %s: %s", path, e)
            continue
        info = doc.get("info", {}) or {}
        if "id" not in doc or ("match" not in doc and "dork" not in doc):
            logger.error("Skipping template %s: missing id or match/dork block", path)
            continue
        sigs.append(Signature(
            id=doc["id"],
            name=info.get("name", doc["id"]),
            severity=str(info.get("severity", "info")).lower(),
            tags=_as_list(info.get("tags")),
            references=_as_list(info.get("reference") or info.get("references")),
            match=doc.get("match"),
            dork=doc.get("dork"),
            source_path=str(path),
        ))
    logger.debug("Loaded %d signature templates from %s", len(sigs), root)
    return sigs


class SignatureEngine:
    """Evaluate loaded signatures against a target and its aggregated results."""

    def __init__(self, signatures: Optional[List[Signature]] = None):
        self.signatures = signatures if signatures is not None else load_templates()

    # ── part extraction ────────────────────────────────────────────────────

    @staticmethod
    def _extract_part(result: Dict, part: str) -> List[str]:
        """Resolve a matcher ``part`` to a list of stringifiable haystacks."""
        if part == "type":
            return [str(result.get("type", ""))]
        if part == "source":
            return [str(result.get("source", ""))]
        if part == "tags":
            return [str(t) for t in result.get("tags", [])]
        if part in ("data", "all"):
            return [str(result.get("data", ""))]
        if part.startswith("data."):
            data = result.get("data", {})
            key = part.split(".", 1)[1]
            if isinstance(data, dict) and key in data:
                val = data[key]
                return [str(x) for x in val] if isinstance(val, list) else [str(val)]
            return []
        return []

    @staticmethod
    def _match_one(haystacks: List[str], mtype: str, needles: List[str],
                   condition: str) -> bool:
        if not needles:
            return False
        results = []
        for needle in needles:
            if mtype == "regex":
                pat = re.compile(needle, re.IGNORECASE)
                hit = any(pat.search(h) for h in haystacks)
            elif mtype == "keyword":  # exact token match (e.g. a tag)
                hit = any(h.lower() == needle.lower() for h in haystacks)
            else:  # "word" — case-insensitive substring
                hit = any(needle.lower() in h.lower() for h in haystacks)
            results.append(hit)
        return all(results) if condition == "and" else any(results)

    def _eval_matchers(self, result: Dict, block: Dict) -> bool:
        matchers = block.get("matchers", [])
        if not matchers:
            return False
        outcomes = []
        for m in matchers:
            part = m.get("part", "data")
            mtype = m.get("type", "word")
            needles = _as_list(m.get("words") or m.get("patterns"))
            cond = m.get("condition", "or")
            haystacks = self._extract_part(result, part)
            outcomes.append(self._match_one(haystacks, mtype, needles, cond))
        overall = block.get("matchers-condition", "and")
        return all(outcomes) if overall == "and" else any(outcomes)

    # ── evaluation ─────────────────────────────────────────────────────────

    def _finding(self, sig: Signature, ftype: str, data: Dict) -> Dict:
        return {
            "type": ftype,
            "source": f"signature:{sig.id}",
            "data": {
                "signature_id": sig.id,
                "name": sig.name,
                "severity": sig.severity,
                "references": sig.references,
                **data,
            },
            "confidence": 0.9,
            "relevance_score": _SEVERITY_RELEVANCE.get(sig.severity, 0.5),
            "tags": ["signature", sig.severity, *sig.tags],
            "is_anomaly": sig.severity in ("critical", "high"),
            "timestamp": datetime.utcnow().isoformat(),
        }

    def evaluate(self, target: str, results: List[Dict],
                 target_kind: Optional[str] = None) -> List[Dict]:
        """Run every signature; return a list of PhantomSignal finding dicts."""
        findings: List[Dict] = []
        for sig in self.signatures:
            try:
                if sig.kind == "dork":
                    findings.extend(self._eval_dork(sig, target, target_kind))
                else:
                    findings.extend(self._eval_match(sig, results))
            except Exception as e:  # one bad template must not break the run
                logger.error("Signature %s failed: %s", sig.id, e)
        return findings

    def _eval_match(self, sig: Signature, results: List[Dict]) -> List[Dict]:
        block = sig.match or {}
        gate = set(_as_list(block.get("result-types")))
        out = []
        for r in results or []:
            if gate and str(r.get("type", "")) not in gate:
                continue
            if self._eval_matchers(r, block):
                out.append(self._finding(sig, "signature_match", {
                    "matched_source": r.get("source"),
                    "matched_type": r.get("type"),
                    "evidence": r.get("data"),
                }))
        return out

    def _eval_dork(self, sig: Signature, target: str,
                   target_kind: Optional[str]) -> List[Dict]:
        block = sig.dork or {}
        kinds = set(_as_list(block.get("target-kinds")))
        if target_kind and kinds and target_kind not in kinds:
            return []
        engine = block.get("engine", "google")
        queries = [q.replace("{target}", target) for q in _as_list(block.get("queries"))]
        if not queries:
            return []
        return [self._finding(sig, "dork", {
            "engine": engine,
            "queries": queries,
            "target": target,
        })]
