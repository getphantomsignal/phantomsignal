"""
PhantomSignal Document Metadata Extraction — Paper Trail Recon

Phase 3 (FOCA / metagoofil lineage). Discovers a domain's public documents via
passive archive sources, downloads them, and mines their embedded metadata for
internal usernames, software + versions, local/UNC paths, emails, and geodata —
the artefacts authors forget they are publishing.

Scope is deliberate and honest:
  • OOXML  (docx/xlsx/pptx + macro variants) — parsed from the ZIP with stdlib.
  • PDF    — Info dictionary + XMP packet, from the UNCOMPRESSED regions only.
             Metadata buried in object/xref streams or encrypted PDFs is out of
             scope (a hand-rolled full PDF parser would be silently wrong).
  • Images (JPEG/TIFF) — EXIF via Pillow, incl. GPS when present.
Legacy OLE (.doc/.xls/.ppt) is NOT attempted — it needs a real OLE parser.

Design: network I/O in the class; sniffing, parsing and aggregation are pure
module-level functions with unit tests.

Author:  the-clipper
AI:      Claude (Anthropic)
License: MIT — see LICENSE
"""
from __future__ import annotations

import asyncio
import io
import logging
import re
import xml.etree.ElementTree as ET
import zipfile
from typing import Dict, List, Optional, Set
from urllib.parse import urlparse

import httpx

from phantomsignal.scrapers.archive_miner import parse_wayback_cdx

logger = logging.getLogger("phantomsignal.scrapers.doc_metadata")

# Formats we can parse correctly. Legacy OLE (.doc/.xls/.ppt) is excluded on
# purpose — see the module docstring.
PARSEABLE_EXT = (
    ".pdf", ".docx", ".xlsx", ".pptx", ".docm", ".xlsm", ".pptm",
    ".jpg", ".jpeg", ".tif", ".tiff",
)

_MAX_UNZIP_BYTES = 8 * 1024 * 1024      # per-member decompressed cap (zip-bomb guard)

EMAIL_RE = re.compile(r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}")
# Local drive paths (C:\Users\jdoe\…) and UNC shares (\\server\share\…).
PATH_RE = re.compile(r"(?:[A-Za-z]:\\[^\s\"'<>|]+|\\\\[^\s\"'<>|]+\\[^\s\"'<>|]+)")

# Values in a "person" field that are really software, not a human/username.
_SOFTWARE_MARKERS = (
    "microsoft", "adobe", "acrobat", "word", "excel", "powerpoint", "libreoffice",
    "openoffice", "pdf", "ghostscript", "quartz", "pages", "numbers", "keynote",
    "google", "wkhtmltopdf", "tcpdf", "itext", "reportlab", "latex", "pdftex",
)

_PERSON_KEYS   = ("author", "last_modified_by", "manager", "artist")
_SOFTWARE_KEYS = ("creator_tool", "producer", "exif_software", "exif_make", "exif_model")


# ── document sniffing ───────────────────────────────────────────────────────

def sniff_doc_type(raw: bytes) -> Optional[str]:
    """Identify a document by magic bytes → 'pdf' | 'ooxml' | 'image' | None."""
    if raw[:5] == b"%PDF-":
        return "pdf"
    if raw[:2] == b"PK":                                  # ZIP container → maybe OOXML
        return "ooxml"
    if raw[:3] == b"\xff\xd8\xff" or raw[:4] in (b"II*\x00", b"MM\x00*"):
        return "image"
    return None


def is_parseable_doc_url(url: str) -> bool:
    path = urlparse(url).path.lower()
    return path.endswith(PARSEABLE_EXT)


# ── OOXML (docx/xlsx/pptx) ──────────────────────────────────────────────────

_OOXML_NS = {
    "cp":      "http://schemas.openxmlformats.org/package/2006/metadata/core-properties",
    "dc":      "http://purl.org/dc/elements/1.1/",
    "dcterms": "http://purl.org/dc/terms/",
    "ep":      "http://schemas.openxmlformats.org/officeDocument/2006/extended-properties",
}
_CORE_FIELDS = {
    "author": "dc:creator", "last_modified_by": "cp:lastModifiedBy",
    "title": "dc:title", "subject": "dc:subject", "description": "dc:description",
    "keywords": "cp:keywords", "revision": "cp:revision", "category": "cp:category",
    "created": "dcterms:created", "modified": "dcterms:modified",
    "content_status": "cp:contentStatus",
}
_APP_FIELDS = {
    "application": "ep:Application", "app_version": "ep:AppVersion",
    "company": "ep:Company", "manager": "ep:Manager", "template": "ep:Template",
    "total_edit_time": "ep:TotalTime",
}


def _read_capped(zf: zipfile.ZipFile, name: str) -> Optional[bytes]:
    """Read a zip member, bounding *actual* decompressed bytes (not the declared
    size, which a crafted archive can understate) as a zip-bomb guard."""
    try:
        with zf.open(name) as f:
            data = f.read(_MAX_UNZIP_BYTES + 1)
    except Exception:
        return None
    return None if len(data) > _MAX_UNZIP_BYTES else data


def _xml_root(data: Optional[bytes]):
    if not data:
        return None
    try:
        return ET.fromstring(data)
    except Exception:
        return None


def parse_ooxml_metadata(raw: bytes) -> Dict:
    """Extract core.xml + app.xml properties from an OOXML (docx/xlsx/pptx) file."""
    try:
        zf = zipfile.ZipFile(io.BytesIO(raw))
    except Exception:
        return {}
    names = set(zf.namelist())
    if "[Content_Types].xml" not in names:      # a ZIP, but not an OOXML package
        return {}

    meta: Dict = {}
    if "docProps/core.xml" in names:
        root = _xml_root(_read_capped(zf, "docProps/core.xml"))
        if root is not None:
            for field, tag in _CORE_FIELDS.items():
                el = root.find(tag, _OOXML_NS)
                if el is not None and el.text and el.text.strip():
                    meta[field] = el.text.strip()
    if "docProps/app.xml" in names:
        root = _xml_root(_read_capped(zf, "docProps/app.xml"))
        if root is not None:
            for field, tag in _APP_FIELDS.items():
                el = root.find(tag, _OOXML_NS)
                if el is not None and el.text and el.text.strip():
                    meta[field] = el.text.strip()
    return meta


# ── PDF (Info dictionary + XMP) ─────────────────────────────────────────────

_PDF_INFO_KEYS = {
    b"/Author": "author", b"/Creator": "creator_tool", b"/Producer": "producer",
    b"/Title": "title", b"/Subject": "subject", b"/Keywords": "keywords",
    b"/CreationDate": "creation_date", b"/ModDate": "mod_date",
}
_PDF_ESCAPES = {0x6e: 0x0a, 0x72: 0x0d, 0x74: 0x09, 0x62: 0x08,
                0x66: 0x0c, 0x28: 0x28, 0x29: 0x29, 0x5c: 0x5c}


def _decode_pdf_bytes(data: bytes) -> str:
    if data[:2] == b"\xfe\xff":
        try:
            return data[2:].decode("utf-16-be").strip("\x00 \t\r\n")
        except Exception:
            pass
    return data.decode("latin-1").strip("\x00 \t\r\n")


def _read_literal_string(raw: bytes, i: int) -> Optional[str]:
    """Read a PDF literal string starting at the '(' at index i (balanced/escaped)."""
    n = len(raw)
    j = i + 1
    depth = 1
    out = bytearray()
    while j < n and depth > 0:
        c = raw[j]
        if c == 0x5c:                                   # backslash escape
            nxt = raw[j + 1] if j + 1 < n else -1
            if nxt in _PDF_ESCAPES:
                out.append(_PDF_ESCAPES[nxt]); j += 2
            elif 0x30 <= nxt <= 0x37:                   # octal (up to 3 digits)
                k, digits = j + 1, bytearray()
                while k < n and len(digits) < 3 and 0x30 <= raw[k] <= 0x37:
                    digits.append(raw[k]); k += 1
                out.append(int(bytes(digits), 8) & 0xFF); j = k
            else:
                j += 2                                  # ignore (incl line continuation)
        elif c == 0x28:                                 # nested (
            depth += 1; out.append(c); j += 1
        elif c == 0x29:                                 # )
            depth -= 1
            if depth > 0:
                out.append(c)
            j += 1
        else:
            out.append(c); j += 1
    if depth != 0:                                      # unterminated
        return None
    return _decode_pdf_bytes(bytes(out))


def _read_hex_string(raw: bytes, i: int) -> Optional[str]:
    """Read a PDF hex string <...> starting at index i."""
    end = raw.find(b">", i)
    if end == -1:
        return None
    hexs = bytes(ch for ch in raw[i + 1:end] if ch not in b" \t\r\n")
    if len(hexs) % 2:
        hexs += b"0"
    try:
        return _decode_pdf_bytes(bytes.fromhex(hexs.decode("ascii")))
    except Exception:
        return None


def _extract_pdf_value(raw: bytes, key: bytes) -> Optional[str]:
    """Find `key` followed by a PDF string token and decode it."""
    for m in re.finditer(re.escape(key) + rb"\s*", raw):
        i = m.end()
        if i >= len(raw):
            continue
        c = raw[i:i + 1]
        if c == b"(":
            val = _read_literal_string(raw, i)
        elif c == b"<" and raw[i + 1:i + 2] != b"<":     # '<<' is a dict, not a string
            val = _read_hex_string(raw, i)
        else:
            continue
        if val:
            return val
    return None


_XMP_NS = {
    "dc":  "http://purl.org/dc/elements/1.1/",
    "xmp": "http://ns.adobe.com/xap/1.0/",
    "pdf": "http://ns.adobe.com/pdf/1.3/",
    "rdf": "http://www.w3.org/1999/02/22-rdf-syntax-ns#",
}


def _extract_xmp(raw: bytes) -> Dict:
    m = re.search(rb"<x:xmpmeta[^>]*>.*?</x:xmpmeta>", raw, re.DOTALL)
    if not m:
        return {}
    root = _xml_root(m.group(0))
    if root is None:
        return {}
    out: Dict = {}
    for li in root.findall(".//dc:creator//rdf:li", _XMP_NS):
        if li.text and li.text.strip():
            out["author"] = li.text.strip()
            break
    ct = root.find(".//xmp:CreatorTool", _XMP_NS)
    if ct is not None and ct.text and ct.text.strip():
        out["creator_tool"] = ct.text.strip()
    pr = root.find(".//pdf:Producer", _XMP_NS)
    if pr is not None and pr.text and pr.text.strip():
        out["producer"] = pr.text.strip()
    return out


def parse_pdf_metadata(raw: bytes) -> Dict:
    """Extract the Info dictionary and XMP packet from a PDF's uncompressed bytes."""
    meta: Dict = {}
    for key, field in _PDF_INFO_KEYS.items():
        val = _extract_pdf_value(raw, key)
        if val:
            meta[field] = val
    for field, val in _extract_xmp(raw).items():        # XMP fills gaps only
        meta.setdefault(field, val)
    return meta


# ── Images (EXIF via Pillow) ────────────────────────────────────────────────

_EXIF_TAGS = {0x010F: "exif_make", 0x0110: "exif_model", 0x0131: "exif_software",
              0x013B: "artist", 0x0132: "datetime", 0x8298: "copyright"}


def _exif_gps(exif) -> Optional[Dict]:
    try:
        gps = exif.get_ifd(0x8825)
    except Exception:
        return None
    if not gps:
        return None

    def to_deg(coord, ref) -> float:
        d, m, s = (float(x) for x in coord)
        val = d + m / 60.0 + s / 3600.0
        return -val if str(ref).upper() in ("S", "W") else val

    try:
        return {"lat": round(to_deg(gps[2], gps[1]), 6),
                "lon": round(to_deg(gps[4], gps[3]), 6)}
    except Exception:
        return None


def parse_exif_metadata(raw: bytes) -> Dict:
    try:
        from PIL import Image
    except Exception:
        return {}
    try:
        exif = Image.open(io.BytesIO(raw)).getexif()
    except Exception:
        return {}
    if not exif:
        return {}
    meta: Dict = {}
    for tag_id, field in _EXIF_TAGS.items():
        val = exif.get(tag_id)
        if val not in (None, ""):
            meta[field] = str(val).strip()
    gps = _exif_gps(exif)
    if gps:
        meta["gps"] = gps
    return meta


def parse_document(raw: bytes) -> Optional[Dict]:
    """Sniff and parse a document → {doc_type, metadata} or None if unsupported/empty."""
    dtype = sniff_doc_type(raw)
    if dtype == "pdf":
        meta = parse_pdf_metadata(raw)
    elif dtype == "ooxml":
        meta = parse_ooxml_metadata(raw)
    elif dtype == "image":
        meta = parse_exif_metadata(raw)
    else:
        return None
    return {"doc_type": dtype, "metadata": meta} if meta else None


# ── aggregation (pure) ──────────────────────────────────────────────────────

def _looks_like_software(value: str) -> bool:
    low = value.lower()
    return any(marker in low for marker in _SOFTWARE_MARKERS)


def usernames_from_meta(meta: Dict) -> Set[str]:
    """Person/username fields — the OSINT gold (drop values that are clearly software)."""
    out: Set[str] = set()
    for key in _PERSON_KEYS:
        v = meta.get(key)
        if v and not _looks_like_software(v):
            out.add(v)
    return out


def software_from_meta(meta: Dict) -> Set[str]:
    out: Set[str] = set()
    app = meta.get("application")
    if app:
        out.add(f"{app} {meta['app_version']}" if meta.get("app_version") else app)
    for key in _SOFTWARE_KEYS:
        if meta.get(key):
            out.add(meta[key])
    return out


def _text_blob(meta: Dict) -> str:
    return " ".join(str(v) for v in meta.values() if isinstance(v, str))


def emails_from_meta(meta: Dict) -> Set[str]:
    return set(EMAIL_RE.findall(_text_blob(meta)))


def paths_from_meta(meta: Dict) -> Set[str]:
    return set(PATH_RE.findall(_text_blob(meta)))


class DocMetadataExtractor:
    """Discover public documents for a domain and mine their metadata."""

    def __init__(self, config):
        self.config    = config
        self.max_docs  = config.get("doc_metadata", "max_docs",  default=40)
        self.max_bytes = config.get("doc_metadata", "max_bytes", default=20 * 1024 * 1024)
        self.timeout   = config.get("doc_metadata", "timeout",   default=20)

    async def run(self, target: str) -> List[Dict]:
        # A direct link to a parseable document → just that file.
        if is_parseable_doc_url(target):
            urls = [target if "://" in target else f"http://{target}"]
            scope = urlparse(urls[0]).netloc
        else:
            scope = self._extract_domain(target)
            if not scope:
                return []
            urls = await self._discover(scope)
        if not urls:
            return []

        logger.info("Document metadata: %d candidate doc(s) for %s", len(urls), scope)
        docs = await self._download_and_parse(urls)
        return self._build_results(scope, len(urls), docs)

    async def _discover(self, domain: str) -> List[str]:
        cdx = ("http://web.archive.org/cdx/search/cdx"
               f"?url=*.{domain}/*&output=json&fl=original&collapse=urlkey&limit=5000")
        try:
            async with httpx.AsyncClient(
                timeout=25, follow_redirects=True,
                headers={"User-Agent": "PhantomSignal-OSINT/1.0"},
            ) as client:
                r = await client.get(cdx)
                urls = parse_wayback_cdx(r.json()) if r.status_code == 200 else set()
        except Exception as exc:
            logger.debug("doc discovery failed for %s: %s", domain, exc)
            return []
        docs = sorted(u for u in urls if is_parseable_doc_url(u))
        return docs[:self.max_docs]

    async def _download_and_parse(self, urls: List[str]) -> List[Dict]:
        sem = asyncio.Semaphore(8)

        async def one(client, url):
            async with sem:
                raw = await self._fetch_capped(client, url)
                if raw is None:
                    return None
                parsed = parse_document(raw)
                if not parsed:
                    return None
                parsed["url"] = url
                return parsed

        async with httpx.AsyncClient(
            timeout=self.timeout, follow_redirects=True,
            headers={"User-Agent": "PhantomSignal-OSINT/1.0"},
        ) as client:
            gathered = await asyncio.gather(*(one(client, u) for u in urls),
                                            return_exceptions=True)
        return [g for g in gathered if isinstance(g, dict)]

    async def _fetch_capped(self, client, url: str) -> Optional[bytes]:
        """Stream a URL, aborting if it exceeds max_bytes (don't truncate — skip)."""
        try:
            async with client.stream("GET", url) as resp:
                if resp.status_code != 200:
                    return None
                buf = bytearray()
                async for chunk in resp.aiter_bytes():
                    buf += chunk
                    if len(buf) > self.max_bytes:
                        logger.debug("skipping oversized doc: %s", url)
                        return None
                return bytes(buf)
        except Exception as exc:
            logger.debug("fetch failed %s: %s", url, exc)
            return None

    def _build_results(self, scope: str, candidates: int, docs: List[Dict]) -> List[Dict]:
        results: List[Dict] = []
        all_users: Set[str] = set()
        all_software: Set[str] = set()
        all_emails: Set[str] = set()
        all_paths: Set[str] = set()

        for d in docs:
            m = d["metadata"]
            users = usernames_from_meta(m)
            software = software_from_meta(m)
            emails = emails_from_meta(m)
            paths = paths_from_meta(m)
            all_users |= users
            all_software |= software
            all_emails |= emails
            all_paths |= paths

            results.append({
                "type":   "document_metadata",
                "source": "doc_metadata",
                "data": {
                    "url":      d["url"],
                    "doc_type": d["doc_type"],
                    "authors":  sorted(users),
                    "software": sorted(software),
                    "emails":   sorted(emails),
                    "paths":    sorted(paths),
                    "fields":   m,
                },
                "confidence":      1.0,
                "relevance_score": 0.7 if (users or paths) else 0.5,
                "tags":            ["document", "metadata", d["doc_type"]],
                "is_anomaly":      bool(paths),
            })

            if m.get("gps"):
                results.append({
                    "type":   "document_geolocation",
                    "source": "doc_metadata",
                    "data":   {"url": d["url"], **m["gps"]},
                    "confidence":      0.9,
                    "relevance_score": 0.9,
                    "tags":            ["document", "metadata", "geolocation", "exif"],
                    "is_anomaly":      True,
                })

        results.extend(self._summaries(scope, candidates, docs,
                                       all_users, all_software, all_emails, all_paths))
        return results

    def _summaries(self, scope, candidates, docs, users, software, emails, paths):
        out: List[Dict] = []
        if users:
            out.append({
                "type": "metadata_usernames", "source": "doc_metadata",
                "data": {"scope": scope, "count": len(users), "usernames": sorted(users)},
                "confidence": 0.9, "relevance_score": 0.9,
                "tags": ["metadata", "usernames", "identity"], "is_anomaly": True,
            })
        if software:
            out.append({
                "type": "metadata_software", "source": "doc_metadata",
                "data": {"scope": scope, "count": len(software), "software": sorted(software)},
                "confidence": 0.9, "relevance_score": 0.6,
                "tags": ["metadata", "software", "fingerprint"],
            })
        if paths:
            out.append({
                "type": "metadata_paths", "source": "doc_metadata",
                "data": {"scope": scope, "count": len(paths), "paths": sorted(paths)},
                "confidence": 0.9, "relevance_score": 0.85,
                "tags": ["metadata", "paths", "internal"], "is_anomaly": True,
            })
        if emails:
            out.append({
                "type": "metadata_emails", "source": "doc_metadata",
                "data": {"scope": scope, "count": len(emails), "emails": sorted(emails)},
                "confidence": 0.9, "relevance_score": 0.7,
                "tags": ["metadata", "emails", "identity"],
            })
        out.append({
            "type": "doc_metadata_summary", "source": "doc_metadata",
            "data": {
                "scope": scope,
                "candidates": candidates,
                "documents_parsed": len(docs),
                "unique_usernames": len(users),
                "unique_software": len(software),
                "unique_emails": len(emails),
                "unique_paths": len(paths),
            },
            "confidence": 1.0, "relevance_score": 0.8,
            "tags": ["metadata", "summary"],
        })
        return out

    def _extract_domain(self, target: str) -> Optional[str]:
        t = (target or "").strip().lower()
        t = t.split("://", 1)[-1].split("/", 1)[0].split(":", 1)[0].split("@")[-1]
        return t if t and re.match(r"^(?:(?!-)[a-z0-9_-]{1,63}(?<!-)\.)+[a-z]{2,63}$", t) else None
