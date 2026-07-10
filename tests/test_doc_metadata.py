"""Tests for document metadata extraction (Phase 3, doc_metadata).

The parsers are the error-prone core, so they're validated against real
documents built in-memory: an OOXML package (zip + core/app XML), crafted PDF
bytes exercising literal / hex / UTF-16 strings and an XMP packet, and a
Pillow-generated JPEG carrying EXIF. Discovery/download (network) is not tested.
"""
import io
import zipfile

from phantomsignal.scrapers.doc_metadata import (
    sniff_doc_type, is_parseable_doc_url,
    parse_ooxml_metadata, parse_pdf_metadata, parse_exif_metadata, parse_document,
    usernames_from_meta, software_from_meta, emails_from_meta, paths_from_meta,
)


# ── sniffing ────────────────────────────────────────────────────────────────

def test_sniff_doc_type():
    assert sniff_doc_type(b"%PDF-1.7\n...") == "pdf"
    assert sniff_doc_type(b"PK\x03\x04....") == "ooxml"
    assert sniff_doc_type(b"\xff\xd8\xff\xe0JFIF") == "image"
    assert sniff_doc_type(b"II*\x00") == "image"
    assert sniff_doc_type(b"not a document") is None


def test_is_parseable_doc_url():
    assert is_parseable_doc_url("https://x.com/report.pdf")
    assert is_parseable_doc_url("https://x.com/a/b/Sheet.XLSX?y=1")
    assert not is_parseable_doc_url("https://x.com/legacy.doc")     # OLE: not supported
    assert not is_parseable_doc_url("https://x.com/index.html")


# ── OOXML ───────────────────────────────────────────────────────────────────

_CORE_XML = (
    '<?xml version="1.0"?>'
    '<cp:coreProperties '
    'xmlns:cp="http://schemas.openxmlformats.org/package/2006/metadata/core-properties" '
    'xmlns:dc="http://purl.org/dc/elements/1.1/" '
    'xmlns:dcterms="http://purl.org/dc/terms/">'
    '<dc:creator>Jane Doe</dc:creator>'
    '<cp:lastModifiedBy>jdoe</cp:lastModifiedBy>'
    '<dc:title>Q3 Financials</dc:title>'
    '</cp:coreProperties>'
)
_APP_XML = (
    '<?xml version="1.0"?>'
    '<Properties '
    'xmlns="http://schemas.openxmlformats.org/officeDocument/2006/extended-properties">'
    '<Application>Microsoft Excel</Application>'
    '<AppVersion>16.0300</AppVersion>'
    '<Company>Acme Corp</Company>'
    '<Template>\\\\fileserver\\templates\\budget.xltx</Template>'
    '</Properties>'
)


def _make_ooxml(core=_CORE_XML, app=_APP_XML, content_types=True) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        if content_types:
            zf.writestr("[Content_Types].xml", "<Types/>")
        zf.writestr("docProps/core.xml", core)
        zf.writestr("docProps/app.xml", app)
    return buf.getvalue()


def test_parse_ooxml_metadata():
    meta = parse_ooxml_metadata(_make_ooxml())
    assert meta["author"] == "Jane Doe"
    assert meta["last_modified_by"] == "jdoe"
    assert meta["title"] == "Q3 Financials"
    assert meta["application"] == "Microsoft Excel"
    assert meta["app_version"] == "16.0300"
    assert meta["company"] == "Acme Corp"
    assert meta["template"] == "\\\\fileserver\\templates\\budget.xltx"


def test_parse_ooxml_rejects_plain_zip():
    # a ZIP without [Content_Types].xml is not an OOXML package
    assert parse_ooxml_metadata(_make_ooxml(content_types=False)) == {}
    assert parse_ooxml_metadata(b"not a zip") == {}


# ── PDF ─────────────────────────────────────────────────────────────────────

def test_parse_pdf_literal_and_hex_and_utf16():
    # /Author literal, /Producer hex (UTF-16BE "Ghost"), /Title with escaped paren
    utf16_hex = "FEFF00470068006F00730074"       # "Ghost" in UTF-16BE with BOM
    pdf = (
        b"%PDF-1.5\n"
        b"5 0 obj\n<< /Author (John Q. Smith)"
        b" /Creator (Microsoft Word)"
        b" /Producer <" + utf16_hex.encode() + b">"
        b" /Title (Draft \\(final\\)) >>\nendobj\n"
        b"trailer<< /Info 5 0 R >>\n%%EOF"
    )
    meta = parse_pdf_metadata(pdf)
    assert meta["author"] == "John Q. Smith"
    assert meta["creator_tool"] == "Microsoft Word"
    assert meta["producer"] == "Ghost"
    assert meta["title"] == "Draft (final)"


def test_parse_pdf_literal_octal_escape():
    # \351 is octal for é (0xE9) in PDFDocEncoding/Latin-1; \124 = 'T'
    pdf = b"%PDF-1.4\n<< /Author (Andr\\351 \\124an) >>\n%%EOF"
    meta = parse_pdf_metadata(pdf)
    assert meta["author"] == "Andr\xe9 Tan"


def test_parse_pdf_creator_not_confused_with_creationdate():
    pdf = b"%PDF-1.4\n<< /CreationDate (D:20240101) /Creator (Acme Tool) >>\n%%EOF"
    meta = parse_pdf_metadata(pdf)
    assert meta["creator_tool"] == "Acme Tool"
    assert meta["creation_date"] == "D:20240101"


def test_parse_pdf_xmp_fills_author():
    pdf = (
        b"%PDF-1.6\n"
        b'<x:xmpmeta xmlns:x="adobe:ns:meta/">'
        b'<rdf:RDF xmlns:rdf="http://www.w3.org/1999/02/22-rdf-syntax-ns#"'
        b' xmlns:dc="http://purl.org/dc/elements/1.1/"'
        b' xmlns:xmp="http://ns.adobe.com/xap/1.0/">'
        b'<rdf:Description>'
        b"<dc:creator><rdf:Seq><rdf:li>Alice Admin</rdf:li></rdf:Seq></dc:creator>"
        b"<xmp:CreatorTool>LibreOffice 7.5</xmp:CreatorTool>"
        b"</rdf:Description></rdf:RDF></x:xmpmeta>\n%%EOF"
    )
    meta = parse_pdf_metadata(pdf)
    assert meta["author"] == "Alice Admin"
    assert meta["creator_tool"] == "LibreOffice 7.5"


# ── EXIF (Pillow) ───────────────────────────────────────────────────────────

def _make_jpeg_with_exif() -> bytes:
    from PIL import Image
    img = Image.new("RGB", (8, 8), (100, 120, 140))
    exif = img.getexif()
    exif[0x0131] = "Adobe Photoshop 25.0"          # Software
    exif[0x013B] = "Bob Photographer"              # Artist
    exif[0x010F] = "Canon"                         # Make
    buf = io.BytesIO()
    img.save(buf, format="JPEG", exif=exif)
    return buf.getvalue()


def test_parse_exif_metadata():
    meta = parse_exif_metadata(_make_jpeg_with_exif())
    assert meta["exif_software"] == "Adobe Photoshop 25.0"
    assert meta["artist"] == "Bob Photographer"
    assert meta["exif_make"] == "Canon"


def test_parse_document_dispatches():
    d = parse_document(_make_ooxml())
    assert d["doc_type"] == "ooxml" and d["metadata"]["author"] == "Jane Doe"
    assert parse_document(b"garbage bytes") is None


# ── aggregation ─────────────────────────────────────────────────────────────

def test_usernames_drops_software_values():
    meta = {"author": "Jane Doe", "last_modified_by": "jdoe",
            "creator_tool": "Microsoft Word", "artist": "Adobe Photoshop"}
    users = usernames_from_meta(meta)
    assert users == {"Jane Doe", "jdoe"}               # software-looking artist dropped


def test_software_aggregation_joins_app_and_version():
    meta = {"application": "Microsoft Excel", "app_version": "16.0300",
            "producer": "Ghostscript 9.5"}
    assert "Microsoft Excel 16.0300" in software_from_meta(meta)
    assert "Ghostscript 9.5" in software_from_meta(meta)


def test_emails_and_paths_extraction():
    meta = {"author": "jane@acme.com",
            "template": "C:\\Users\\jdoe\\Documents\\budget.xltx",
            "company": r"\\fileserver\share\dir"}
    assert emails_from_meta(meta) == {"jane@acme.com"}
    paths = paths_from_meta(meta)
    assert "C:\\Users\\jdoe\\Documents\\budget.xltx" in paths
    assert "\\\\fileserver\\share\\dir" in paths
