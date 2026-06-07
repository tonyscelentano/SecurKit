"""Metadata scrubbing for common evidence file formats.

Each scrubber is a pure bytes→bytes function. The orchestrator (`scrub_file`)
returns a `FileScrubResult` whose `bytes_out` is either:
  - the scrubbed file content, OR
  - the original content (on failure — we include unscrubbed and warn), OR
  - None (the caller should stream the original from disk — for files we
    deliberately skip, e.g. unknown extension or above the size cap).

Format support:
  JPEG (.jpg/.jpeg)      hand-written segment walker — lossless, no re-encode
  PNG (.png)             hand-written chunk walker — lossless
  TIFF/WebP/GIF/BMP      Pillow re-save (lossless for TIFF/PNG-like, near-lossless otherwise)
  PDF (.pdf)             pikepdf — clears /Info dict and XMP metadata stream
  Office (.docx/.xlsx/.pptx)   zip rewrite, replaces docProps/* with empty stubs
  LibreOffice (.odt/.ods/.odp) zip rewrite, replaces meta.xml with empty stub
"""

from __future__ import annotations

import fnmatch
import io
import zipfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable

import pikepdf
from PIL import Image

from securkit import _ooxml

# Files larger than this are passed through unscrubbed (we don't want to load
# multi-GB evidence files into memory). User gets a 'too large' note in the report.
SCRUB_MAX_SIZE = 256 * 1024 * 1024  # 256 MiB


@dataclass(frozen=True)
class FileScrubResult:
    path: Path
    handler: str  # 'jpeg' | 'png' | 'pillow' | 'pdf' | 'office' | 'libreoffice' | 'passthrough' | 'failed'
    findings: tuple[str, ...]
    bytes_out: bytes | None  # None → caller should stream original from disk


_CAVEAT_PREFIX = "⚠ "


@dataclass
class ScrubReport:
    files: list[FileScrubResult] = field(default_factory=list)

    def add(self, r: FileScrubResult) -> None:
        self.files.append(r)

    @property
    def total(self) -> int:
        return len(self.files)

    @property
    def scrubbed(self) -> int:
        """Files that were processed AND had at least one piece of metadata removed."""
        return sum(
            1 for r in self.files
            if r.handler not in ("passthrough", "failed")
            and any(not f.startswith(_CAVEAT_PREFIX) for f in r.findings)
        )

    @property
    def clean(self) -> int:
        """Files that were processed but already had no metadata to remove."""
        return sum(
            1 for r in self.files
            if r.handler not in ("passthrough", "failed")
            and not any(not f.startswith(_CAVEAT_PREFIX) for f in r.findings)
        )

    @property
    def failed(self) -> int:
        return sum(1 for r in self.files if r.handler == "failed")

    @property
    def passthrough(self) -> int:
        return sum(1 for r in self.files if r.handler == "passthrough")

    @property
    def caveats(self) -> list[tuple[Path, str]]:
        """Findings flagged with the ⚠ prefix — limitations the user must review manually."""
        out: list[tuple[Path, str]] = []
        for r in self.files:
            for f in r.findings:
                if f.startswith(_CAVEAT_PREFIX):
                    out.append((r.path, f[len(_CAVEAT_PREFIX):]))
        return out

    def summary_lines(self) -> list[str]:
        out = [
            f"Scanned {self.total} files: "
            f"{self.scrubbed} scrubbed, {self.clean} already clean, "
            f"{self.passthrough} passed through, {self.failed} failed."
        ]
        if self.caveats:
            out.append("Manual review needed (scrubber limitations):")
            for path, msg in self.caveats:
                out.append(f"  • {path.name}: {msg}")
        if self.failed:
            out.append("Failures (included unscrubbed — review before sharing):")
            for r in self.files:
                if r.handler == "failed":
                    out.append(f"  • {r.path.name}: {r.findings[0] if r.findings else 'unknown'}")
        return out


# --- JPEG -----------------------------------------------------------------
# Strip APP1 (EXIF / XMP), APP13 (IPTC / Photoshop), APP14 (Adobe), COM.
# Keep APP0 (JFIF) and APP2 (ICC profile) so viewers and color rendering work.

_JPEG_STRIP_MARKERS: set[int] = {0xE1, 0xED, 0xEE, 0xFE}


def scrub_jpeg(data: bytes) -> tuple[bytes, list[str]]:
    if not data.startswith(b"\xff\xd8"):
        raise ValueError("not a JPEG (missing SOI)")
    out = bytearray(b"\xff\xd8")
    findings: list[str] = []
    i = 2
    n = len(data)
    while i < n:
        # Skip 0xFF fill bytes between segments
        while i < n and data[i] == 0xFF:
            i += 1
        if i >= n:
            break
        marker = data[i]
        i += 1
        # Standalone markers (no length): TEM, RST0-RST7, EOI
        if marker == 0xD9:  # EOI
            out.extend(b"\xff\xd9")
            return bytes(out), findings
        if marker == 0x01 or 0xD0 <= marker <= 0xD7:
            out.extend(bytes([0xFF, marker]))
            continue
        # Length-prefixed segment
        if i + 2 > n:
            raise ValueError("truncated JPEG segment header")
        seg_len = int.from_bytes(data[i : i + 2], "big")
        if seg_len < 2 or i + seg_len > n:
            raise ValueError("invalid JPEG segment length")
        payload = data[i + 2 : i + seg_len]
        seg_total = i + seg_len
        # SOS (0xDA) — kept; entropy data follows, copy verbatim through EOI
        if marker == 0xDA:
            out.extend(bytes([0xFF, marker]) + seg_len.to_bytes(2, "big") + payload)
            out.extend(data[seg_total:])
            return bytes(out), findings
        if marker in _JPEG_STRIP_MARKERS:
            label = {
                0xE1: "APP1 (EXIF/XMP)",
                0xED: "APP13 (IPTC/Photoshop)",
                0xEE: "APP14 (Adobe)",
                0xFE: "comment",
            }[marker]
            findings.append(f"stripped {label}: {len(payload)} bytes")
        else:
            out.extend(bytes([0xFF, marker]) + seg_len.to_bytes(2, "big") + payload)
        i = seg_total
    return bytes(out), findings


# --- PNG ------------------------------------------------------------------

_PNG_SIG = b"\x89PNG\r\n\x1a\n"
_PNG_STRIP_TYPES: set[bytes] = {b"tEXt", b"zTXt", b"iTXt", b"tIME", b"eXIf"}


def scrub_png(data: bytes) -> tuple[bytes, list[str]]:
    if not data.startswith(_PNG_SIG):
        raise ValueError("not a PNG (bad signature)")
    out = bytearray(_PNG_SIG)
    findings: list[str] = []
    i = len(_PNG_SIG)
    n = len(data)
    while i < n:
        if i + 8 > n:
            raise ValueError("truncated PNG chunk header")
        length = int.from_bytes(data[i : i + 4], "big")
        ctype = bytes(data[i + 4 : i + 8])
        end = i + 8 + length + 4  # length(4) + type(4) + data + crc(4)
        if end > n:
            raise ValueError("truncated PNG chunk body")
        if ctype in _PNG_STRIP_TYPES:
            findings.append(f"stripped {ctype.decode('ascii', 'replace')} chunk ({length} bytes)")
        else:
            out.extend(data[i:end])
        i = end
        if ctype == b"IEND":
            break
    return bytes(out), findings


# --- Pillow-handled formats (TIFF / WebP / GIF / BMP) --------------------


def scrub_pillow(data: bytes, fmt: str) -> tuple[bytes, list[str]]:
    """Re-save through Pillow with no info/EXIF/XMP attached."""
    findings: list[str] = []
    src = Image.open(io.BytesIO(data))
    src.load()
    had_exif = bool(src.info.get("exif")) or bool(getattr(src, "_getexif", lambda: None)())
    had_xmp = "XML:com.adobe.xmp" in src.info or "xmp" in src.info
    had_icc = "icc_profile" in src.info
    other_info_keys = [
        k for k in src.info
        if k not in ("exif", "xmp", "XML:com.adobe.xmp", "icc_profile")
    ]
    # New image with same data, no metadata
    clean = Image.new(src.mode, src.size)
    clean.putdata(list(src.getdata()))
    if had_exif:
        findings.append("stripped EXIF")
    if had_xmp:
        findings.append("stripped XMP")
    if other_info_keys:
        findings.append(f"stripped info keys: {', '.join(other_info_keys)}")
    # Preserve ICC profile so colors render correctly — it's not identifying.
    save_kwargs: dict = {}
    if had_icc:
        save_kwargs["icc_profile"] = src.info["icc_profile"]
    buf = io.BytesIO()
    clean.save(buf, format=fmt, **save_kwargs)
    return buf.getvalue(), findings


# --- PDF (pikepdf) --------------------------------------------------------


def scrub_pdf(data: bytes) -> tuple[bytes, list[str]]:
    findings: list[str] = []
    with pikepdf.open(io.BytesIO(data)) as pdf:
        # /Info dict (the legacy metadata location)
        if pdf.docinfo is not None:
            keys = [str(k) for k in pdf.docinfo.keys()]
            if keys:
                findings.append(f"cleared PDF /Info: {', '.join(keys)}")
                for k in list(pdf.docinfo.keys()):
                    del pdf.docinfo[k]
        # XMP metadata stream (modern location)
        try:
            with pdf.open_metadata() as meta:
                n_entries = len(list(meta))
                if n_entries > 0:
                    findings.append(f"cleared XMP metadata ({n_entries} entries)")
                    meta.clear()
        except Exception:
            # Some PDFs have malformed XMP — non-fatal, /Info already handled.
            pass
        # Drop document-level /Metadata stream reference (defense in depth)
        try:
            root = pdf.Root
            if "/Metadata" in root.keys():
                del root["/Metadata"]
                if "cleared XMP" not in " ".join(findings):
                    findings.append("removed /Metadata stream from root")
        except Exception:
            pass
        out = io.BytesIO()
        pdf.save(out)
    return out.getvalue(), findings


# --- Office (docx / xlsx / pptx) -----------------------------------------
# These are ZIP packages. docProps/core.xml carries Author / LastModifiedBy
# / Created / Modified; docProps/app.xml carries Application / Company.
# Replace with minimal stubs so Office still opens them, instead of deleting
# (deletion can confuse some readers that expect the files referenced from
# [Content_Types].xml to be present).

_OFFICE_CORE_XML_STUB = (
    b'<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n'
    b'<cp:coreProperties '
    b'xmlns:cp="http://schemas.openxmlformats.org/package/2006/metadata/core-properties" '
    b'xmlns:dc="http://purl.org/dc/elements/1.1/" '
    b'xmlns:dcterms="http://purl.org/dc/terms/" '
    b'xmlns:dcmitype="http://purl.org/dc/dcmitype/" '
    b'xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"/>'
)
_OFFICE_APP_XML_STUB = (
    b'<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n'
    b'<Properties '
    b'xmlns="http://schemas.openxmlformats.org/officeDocument/2006/extended-properties"/>'
)
# Identifying files we delete outright (no required reference from [Content_Types]).
_OFFICE_DELETE = (
    "docProps/custom.xml",
    "word/people.xml",  # tracked-changes author list
)
_OFFICE_DELETE_GLOBS: tuple[str, ...] = ()
_OFFICE_STUB = {
    "docProps/core.xml": _OFFICE_CORE_XML_STUB,
    "docProps/app.xml": _OFFICE_APP_XML_STUB,
}
# ZIP epoch — anything before 1980-01-01 is invalid in the zip spec.
_ZIP_EPOCH = (1980, 1, 1, 0, 0, 0)


XmlTransformer = Callable[[bytes], tuple[bytes, list[str]]]


def _rewrite_zip(
    data: bytes,
    *,
    delete: tuple[str, ...] = (),
    delete_globs: tuple[str, ...] = (),
    replace: dict[str, bytes] | None = None,
    transforms: tuple[tuple[str, XmlTransformer], ...] = (),
) -> tuple[bytes, list[str]]:
    """Rewrite a zip package with deletes, replacements, and per-entry XML transforms.

    `transforms` is a tuple of (filename-glob, transformer) pairs. The first
    matching glob wins per entry. A transformer that raises is treated as a
    soft failure: the original bytes are kept and a warning is added to findings.
    """
    replace = replace or {}
    findings: list[str] = []
    src = zipfile.ZipFile(io.BytesIO(data), "r")
    out_buf = io.BytesIO()
    with src, zipfile.ZipFile(out_buf, "w", zipfile.ZIP_DEFLATED) as dst:
        for item in src.infolist():
            name = item.filename
            if name in delete or any(fnmatch.fnmatch(name, g) for g in delete_globs):
                findings.append(f"removed {name}")
                continue
            if name in replace:
                findings.append(f"replaced {name} with empty stub")
                new = zipfile.ZipInfo(name, date_time=_ZIP_EPOCH)
                new.compress_type = zipfile.ZIP_DEFLATED
                dst.writestr(new, replace[name])
                continue
            content = src.read(name)
            # Apply the first matching transformer, if any.
            for glob, transformer in transforms:
                if fnmatch.fnmatch(name, glob):
                    try:
                        content, sub_findings = transformer(content)
                        for f in sub_findings:
                            findings.append(f"{name}: {f}")
                    except Exception as e:
                        findings.append(
                            f"⚠ {name}: in-XML scrub failed ({type(e).__name__}); "
                            "kept original — review manually"
                        )
                    break
            new = zipfile.ZipInfo(name, date_time=_ZIP_EPOCH)
            new.compress_type = item.compress_type
            new.external_attr = item.external_attr
            dst.writestr(new, content)
    return out_buf.getvalue(), findings


def _stub_customxml_item(_data: bytes) -> tuple[bytes, list[str]]:
    """Stub customXml/item*.xml. We can't delete (manifest references it) but we
    can blank its content. The empty <root/> is generic enough that Office,
    python-docx, and SharePoint integrations all accept it as a no-op payload.
    """
    return (
        b'<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n<root/>',
        ["replaced customXml content with empty stub"],
    )


def _stub_customxml_itemprops(_data: bytes) -> tuple[bytes, list[str]]:
    """Stub customXml/itemProps*.xml — declares the custom XML schema. Replace
    with a minimal valid datastoreItem so Office still accepts the part."""
    return (
        b'<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n'
        b'<ds:datastoreItem '
        b'ds:itemID="{00000000-0000-0000-0000-000000000000}" '
        b'xmlns:ds="http://schemas.openxmlformats.org/officeDocument/2006/customXml"/>',
        ["replaced customXml schema with empty stub"],
    )


# Per-file XML transforms applied to OOXML zip entries. First matching glob wins.
_OFFICE_TRANSFORMS: tuple[tuple[str, XmlTransformer], ...] = (
    # Word
    ("word/document.xml", _ooxml.scrub_word_document_xml),
    ("word/header*.xml", _ooxml.scrub_word_document_xml),
    ("word/footer*.xml", _ooxml.scrub_word_document_xml),
    ("word/footnotes.xml", _ooxml.scrub_word_document_xml),
    ("word/endnotes.xml", _ooxml.scrub_word_document_xml),
    ("word/comments.xml", _ooxml.scrub_word_comments_xml),
    ("word/commentsExtended.xml", _ooxml.scrub_word_comments_xml),
    ("word/settings.xml", _ooxml.scrub_word_settings_xml),
    # NOTE: word/styles.xml deliberately NOT transformed. Stripping all rsids
    # there has been observed to break custom-style preservation in some Word
    # builds (styles can be looked up by rsid). The rsids in styles.xml are
    # tool fingerprints, not author identifiers, so the risk/reward favors
    # leaving it alone.
    # Excel
    ("xl/comments*.xml", _ooxml.scrub_excel_comments_xml),
    # PowerPoint
    ("ppt/commentAuthors.xml", _ooxml.scrub_pptx_authors_xml),
    ("ppt/comments/comment*.xml", _ooxml.scrub_pptx_comment_xml),
    # customXml: blank the content (can't delete — [Content_Types].xml manifest
    # references these parts and deletion breaks python-docx/Word reading).
    ("customXml/itemProps*.xml", _stub_customxml_itemprops),
    ("customXml/item*.xml", _stub_customxml_item),
)

_OFFICE_CAVEAT = (
    "⚠ docProps and in-document author/revision metadata scrubbed, but "
    "embedded objects (OLE attachments, embedded fonts, custom XML parts) "
    "are NOT touched and may carry identifying data — review manually if "
    "the document contains them"
)


def scrub_office(data: bytes) -> tuple[bytes, list[str]]:
    """Comprehensive OOXML scrub for .docx / .xlsx / .pptx.

    Removes:
      - docProps/core.xml, app.xml          (replaced with empty stubs)
      - docProps/custom.xml, word/people.xml, customXml/itemProps1.xml  (deleted)
      - Track-changes author/date/initials  (w:ins, w:del, w:moveFrom/To,
                                              w:rPrChange, w:pPrChange, etc.)
      - w:rsid* session-fingerprint attributes  (everywhere)
      - <w:rsids> registry block, <w:rsidRoot>, <w:printerSettings>, w14:docId
      - Comment author/date/initials  (Word, Excel, PowerPoint)

    Still leaves the user a narrow caveat about embedded objects.
    """
    out_bytes, findings = _rewrite_zip(
        data,
        delete=_OFFICE_DELETE,
        delete_globs=_OFFICE_DELETE_GLOBS,
        replace=_OFFICE_STUB,
        transforms=_OFFICE_TRANSFORMS,
    )
    findings.append(_OFFICE_CAVEAT)
    return out_bytes, findings


# --- LibreOffice (odt / ods / odp) ---------------------------------------

_ODF_META_XML_STUB = (
    b'<?xml version="1.0" encoding="UTF-8"?>\n'
    b'<office:document-meta '
    b'xmlns:office="urn:oasis:names:tc:opendocument:xmlns:office:1.0" '
    b'office:version="1.2"/>'
)
_ODF_DELETE: tuple[str, ...] = ()
_ODF_STUB = {"meta.xml": _ODF_META_XML_STUB}


_ODF_TRANSFORMS: tuple[tuple[str, XmlTransformer], ...] = (
    ("content.xml", _ooxml.scrub_odf_content_xml),
    # styles.xml can also carry change-info; same transformer works
    ("styles.xml", _ooxml.scrub_odf_content_xml),
)

_ODF_CAVEAT = (
    "⚠ meta.xml and in-document change-info scrubbed, but embedded objects "
    "(OLE attachments, embedded media) are NOT touched and may carry "
    "identifying data — review manually if the document contains them"
)


def scrub_libreoffice(data: bytes) -> tuple[bytes, list[str]]:
    """ODF (.odt/.ods/.odp) scrub: meta.xml replaced + content.xml change-info cleared."""
    out_bytes, findings = _rewrite_zip(
        data,
        delete=_ODF_DELETE,
        replace=_ODF_STUB,
        transforms=_ODF_TRANSFORMS,
    )
    findings.append(_ODF_CAVEAT)
    return out_bytes, findings


# --- Dispatch -------------------------------------------------------------

_DISPATCH: dict[str, tuple[str, Callable[[bytes], tuple[bytes, list[str]]]]] = {
    ".jpg": ("jpeg", scrub_jpeg),
    ".jpeg": ("jpeg", scrub_jpeg),
    ".jpe": ("jpeg", scrub_jpeg),
    ".png": ("png", scrub_png),
    ".tif": ("pillow", lambda d: scrub_pillow(d, "TIFF")),
    ".tiff": ("pillow", lambda d: scrub_pillow(d, "TIFF")),
    ".webp": ("pillow", lambda d: scrub_pillow(d, "WEBP")),
    ".gif": ("pillow", lambda d: scrub_pillow(d, "GIF")),
    ".bmp": ("pillow", lambda d: scrub_pillow(d, "BMP")),
    ".pdf": ("pdf", scrub_pdf),
    ".docx": ("office", scrub_office),
    ".xlsx": ("office", scrub_office),
    ".pptx": ("office", scrub_office),
    ".odt": ("libreoffice", scrub_libreoffice),
    ".ods": ("libreoffice", scrub_libreoffice),
    ".odp": ("libreoffice", scrub_libreoffice),
}


def is_scrubbable_ext(path: Path) -> bool:
    return path.suffix.lower() in _DISPATCH


def scrub_file(path: Path) -> FileScrubResult:
    """Dispatch on extension. Returns result with bytes_out=None for files
    we deliberately stream unmodified (unknown ext or above the size cap)."""
    ext = path.suffix.lower()
    if ext not in _DISPATCH:
        return FileScrubResult(
            path=path,
            handler="passthrough",
            findings=(f"no scrubber for {ext or '(no extension)'}; included as-is",),
            bytes_out=None,
        )
    try:
        size = path.stat().st_size
    except OSError as e:
        return FileScrubResult(
            path=path,
            handler="failed",
            findings=(f"could not stat file: {e}",),
            bytes_out=None,
        )
    if size > SCRUB_MAX_SIZE:
        return FileScrubResult(
            path=path,
            handler="passthrough",
            findings=(f"file too large to scrub in-memory ({size:,} bytes); included as-is",),
            bytes_out=None,
        )

    handler, func = _DISPATCH[ext]
    try:
        raw = path.read_bytes()
    except OSError as e:
        return FileScrubResult(
            path=path,
            handler="failed",
            findings=(f"could not read file: {e}",),
            bytes_out=None,
        )
    try:
        scrubbed, findings = func(raw)
    except Exception as e:
        return FileScrubResult(
            path=path,
            handler="failed",
            findings=(f"scrub failed ({type(e).__name__}: {e}); included unscrubbed",),
            bytes_out=raw,
        )
    return FileScrubResult(
        path=path,
        handler=handler,
        findings=tuple(findings),
        bytes_out=scrubbed,
    )
