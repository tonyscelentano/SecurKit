"""Per-format scrubber tests + end-to-end via archive_folder."""

from __future__ import annotations

import io
import zipfile
from pathlib import Path

import pikepdf
import pytest
from PIL import Image, PngImagePlugin

from securkit.archive import archive_folder, extract_skit
from securkit.crypto import KdfParams
from securkit.scrubber import (
    FileScrubResult,
    ScrubReport,
    SCRUB_MAX_SIZE,
    scrub_file,
    scrub_jpeg,
    scrub_office,
    scrub_pdf,
    scrub_png,
)

CHEAP_KDF = KdfParams(time_cost=1, memory_cost_kib=8, parallelism=1)
PASS = "scrubber-test-passphrase"


# --- JPEG ----------------------------------------------------------------


def _jpeg_with_fake_app1(tag: bytes = b"TestCamera") -> bytes:
    """A real JPEG with a hand-injected APP1 segment carrying `tag` bytes."""
    img = Image.new("RGB", (8, 8), "red")
    buf = io.BytesIO()
    img.save(buf, format="JPEG")
    base = buf.getvalue()
    # Build APP1 segment: marker FFE1 + len(BE16, includes len bytes) + "Exif\0\0" + tag
    exif_blob = b"Exif\x00\x00" + tag + b"\x00" * 8
    app1 = b"\xff\xe1" + (len(exif_blob) + 2).to_bytes(2, "big") + exif_blob
    return base[:2] + app1 + base[2:]


def test_scrub_jpeg_removes_app1() -> None:
    dirty = _jpeg_with_fake_app1(b"SECRET_GPS_COORDS")
    assert b"SECRET_GPS_COORDS" in dirty
    clean, findings = scrub_jpeg(dirty)
    assert b"SECRET_GPS_COORDS" not in clean
    assert any("APP1" in f for f in findings)
    # Must still parse as a valid image
    img = Image.open(io.BytesIO(clean))
    img.load()
    assert img.size == (8, 8)


def test_scrub_jpeg_preserves_image_data() -> None:
    """Lossless EXIF removal: image pixels must be byte-identical after scrub.

    Build a pristine JPEG matching the one inside `_jpeg_with_fake_app1`
    (same dimensions, same color), then compare pixels after scrub.
    """
    img = Image.new("RGB", (8, 8), "red")
    buf = io.BytesIO()
    img.save(buf, format="JPEG")
    pristine = buf.getvalue()

    dirty = _jpeg_with_fake_app1(b"NOISE_TO_BE_REMOVED")
    assert dirty != pristine  # APP1 was injected

    clean, _ = scrub_jpeg(dirty)
    clean_img = Image.open(io.BytesIO(clean))
    clean_img.load()
    pristine_img = Image.open(io.BytesIO(pristine))
    pristine_img.load()
    assert clean_img.size == pristine_img.size
    assert list(clean_img.getdata()) == list(pristine_img.getdata())


def test_scrub_jpeg_entropy_section_byte_identical() -> None:
    """Stronger lossless test: the SOS marker through EOI (entropy-coded image
    data) must appear byte-for-byte unchanged in the scrubbed output.

    This catches off-by-one bugs in the segment walker that the pixel-compare
    test would silently allow (since JPEG decoders are forgiving of minor
    stream noise).
    """
    pristine = _jpeg_with_fake_app1(b"")[
        : 2  # SOI
    ]  # we'll rebuild a clean JPEG without injection to extract its entropy region
    img = Image.new("RGB", (8, 8), "red")
    buf = io.BytesIO()
    img.save(buf, format="JPEG")
    base = buf.getvalue()
    sos_at = base.index(b"\xff\xda")
    entropy_region = base[sos_at:]  # SOS marker through EOI

    dirty = _jpeg_with_fake_app1(b"X" * 64)
    clean, _ = scrub_jpeg(dirty)
    assert entropy_region in clean, "entropy-coded section was altered by the scrubber"


def test_scrub_jpeg_rejects_non_jpeg() -> None:
    with pytest.raises(ValueError, match="not a JPEG"):
        scrub_jpeg(b"\x89PNG\r\n\x1a\nnotreallyapng")


# --- PNG -----------------------------------------------------------------


def _png_with_text(key: str, value: str) -> bytes:
    img = Image.new("RGB", (4, 4), "green")
    info = PngImagePlugin.PngInfo()
    info.add_text(key, value)
    buf = io.BytesIO()
    img.save(buf, format="PNG", pnginfo=info)
    return buf.getvalue()


def test_scrub_png_removes_text_chunks() -> None:
    dirty = _png_with_text("Author", "Jane Doe")
    assert b"Jane Doe" in dirty
    clean, findings = scrub_png(dirty)
    assert b"Jane Doe" not in clean
    assert any("tEXt" in f or "iTXt" in f for f in findings)
    img = Image.open(io.BytesIO(clean))
    img.load()
    assert img.size == (4, 4)


def test_scrub_png_rejects_non_png() -> None:
    with pytest.raises(ValueError, match="not a PNG"):
        scrub_png(b"GIF89a-not-actually-a-png")


# --- PDF -----------------------------------------------------------------


def _pdf_with_metadata() -> bytes:
    pdf = pikepdf.new()
    pdf.add_blank_page(page_size=(72, 72))
    with pdf.open_metadata() as m:
        m["dc:creator"] = ["Whistleblower Source"]
        m["dc:title"] = "SECRET REPORT"
    pdf.docinfo["/Author"] = "Whistleblower Source"
    pdf.docinfo["/Title"] = "SECRET REPORT"
    pdf.docinfo["/Producer"] = "Acme Corp Internal Publishing System v3.2"
    buf = io.BytesIO()
    pdf.save(buf)
    return buf.getvalue()


def test_scrub_pdf_clears_info_and_xmp() -> None:
    dirty = _pdf_with_metadata()
    clean, findings = scrub_pdf(dirty)
    assert any("Info" in f or "XMP" in f for f in findings)

    with pikepdf.open(io.BytesIO(clean)) as pdf:
        for k in ("/Author", "/Title"):
            assert k not in pdf.docinfo, f"PDF still has {k}"
        with pdf.open_metadata() as m:
            assert len(list(m)) == 0


# --- Office (docx-like) --------------------------------------------------


def _docx_with_author(author: str = "JaneDoeAuthor") -> bytes:
    buf = io.BytesIO()
    # Use ZIP_STORED so the author string is findable in raw bytes for assertions
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_STORED) as z:
        z.writestr(
            "[Content_Types].xml",
            '<?xml version="1.0"?><Types xmlns="x"/>',
        )
        z.writestr(
            "docProps/core.xml",
            f'<?xml version="1.0"?><cp:coreProperties xmlns:cp="x" xmlns:dc="y">'
            f'<dc:creator>{author}</dc:creator>'
            f'<cp:lastModifiedBy>{author}</cp:lastModifiedBy>'
            f'</cp:coreProperties>',
        )
        z.writestr(
            "docProps/app.xml",
            '<?xml version="1.0"?><Properties xmlns="x"><Company>Acme Corp</Company></Properties>',
        )
        z.writestr("docProps/custom.xml", f"<custom><User>{author}</User></custom>")
        z.writestr("word/people.xml", f"<people><person>{author}</person></people>")
        z.writestr("word/document.xml", "<doc>The actual document body.</doc>")
    return buf.getvalue()


def test_scrub_office_removes_author_and_company() -> None:
    author = "UNIQUE_AUTHOR_STRING_FOR_TEST"
    dirty = _docx_with_author(author)
    assert author.encode() in dirty
    assert b"Acme Corp" in dirty
    clean, findings = scrub_office(dirty)

    # Decompress and check XML contents (scrub_office uses ZIP_DEFLATED on output)
    with zipfile.ZipFile(io.BytesIO(clean)) as z:
        all_xml = b"".join(z.read(name) for name in z.namelist())
    assert author.encode() not in all_xml
    assert b"Acme Corp" not in all_xml
    # But the document body must remain
    assert b"The actual document body." in all_xml
    # The metadata files are replaced (not removed), so Office can still open
    with zipfile.ZipFile(io.BytesIO(clean)) as z:
        names = z.namelist()
        assert "docProps/core.xml" in names
        assert "docProps/app.xml" in names
        # Deleted entries should be gone
        assert "docProps/custom.xml" not in names
        assert "word/people.xml" not in names
    assert any("docProps/core.xml" in f for f in findings)


# --- Dispatch + ScrubReport --------------------------------------------


def test_scrub_file_dispatch_passthrough(tmp_path: Path) -> None:
    p = tmp_path / "notes.txt"
    p.write_bytes(b"plain text, no metadata format")
    result = scrub_file(p)
    assert result.handler == "passthrough"
    assert result.bytes_out is None  # caller streams the original
    assert "no scrubber" in result.findings[0]


def test_scrub_file_dispatch_jpeg(tmp_path: Path) -> None:
    p = tmp_path / "photo.jpg"
    p.write_bytes(_jpeg_with_fake_app1(b"GPS:37.7,-122.4"))
    result = scrub_file(p)
    assert result.handler == "jpeg"
    assert result.bytes_out is not None
    assert b"GPS:37.7,-122.4" not in result.bytes_out
    assert result.findings


def test_scrub_file_failure_includes_unscrubbed(tmp_path: Path, monkeypatch) -> None:
    """A scrubber raising must NOT lose the file — bytes_out holds the original."""
    p = tmp_path / "broken.jpg"
    p.write_bytes(b"not actually a jpeg")
    result = scrub_file(p)
    assert result.handler == "failed"
    assert result.bytes_out == b"not actually a jpeg"
    assert "scrub failed" in result.findings[0]


def test_scrub_file_too_large_passthrough(tmp_path: Path, monkeypatch) -> None:
    p = tmp_path / "huge.pdf"
    # Just touch a small file; monkeypatch the size cap so we trigger the branch
    p.write_bytes(b"%PDF-1.4\n%fake but small\n")
    monkeypatch.setattr("securkit.scrubber.SCRUB_MAX_SIZE", 1)
    result = scrub_file(p)
    assert result.handler == "passthrough"
    assert "too large" in result.findings[0]
    assert result.bytes_out is None


def test_scrub_report_summary() -> None:
    report = ScrubReport()
    report.add(FileScrubResult(Path("a.jpg"), "jpeg", ("stripped EXIF",), b""))
    report.add(FileScrubResult(Path("b.txt"), "passthrough", ("no scrubber",), None))
    report.add(FileScrubResult(Path("c.pdf"), "failed", ("scrub failed: x",), b""))
    report.add(FileScrubResult(Path("d.jpg"), "jpeg", (), b""))  # already clean
    assert report.total == 4
    assert report.scrubbed == 1
    assert report.clean == 1
    assert report.passthrough == 1
    assert report.failed == 1
    lines = report.summary_lines()
    assert any("4 files" in line for line in lines)
    assert any("c.pdf" in line for line in lines)  # failures listed by name


def test_scrub_report_caveats_surfaced() -> None:
    """Caveats (⚠-prefixed findings) appear in summary even on successful scrubs."""
    report = ScrubReport()
    report.add(
        FileScrubResult(
            Path("memo.docx"),
            "office",
            ("replaced docProps/core.xml with empty stub", "⚠ track changes not scrubbed"),
            b"",
        )
    )
    assert len(report.caveats) == 1
    assert report.caveats[0][0] == Path("memo.docx")
    assert "track changes" in report.caveats[0][1]
    lines = report.summary_lines()
    assert any("Manual review needed" in line for line in lines)
    assert any("track changes" in line for line in lines)


def test_scrub_office_emits_narrowed_caveat() -> None:
    """After the OOXML XML scrubber landed, the caveat narrows from
    'track changes NOT scrubbed' to 'embedded objects not touched'.
    Track-changes ARE scrubbed now (see test_ooxml_scrub.py)."""
    dirty = _docx_with_author("Anyone")
    _, findings = scrub_office(dirty)
    caveats = [f for f in findings if f.startswith("⚠")]
    assert caveats, "should still have at least one caveat (embedded objects)"
    assert any("embedded objects" in c for c in caveats)
    # The old "track changes not scrubbed" caveat must NOT be present anymore
    for c in caveats:
        assert "track changes" not in c.lower(), (
            f"caveat falsely claims track changes aren't scrubbed: {c}"
        )


# --- End-to-end ----------------------------------------------------------


def test_archive_with_scrub_strips_image_metadata(tmp_path: Path) -> None:
    src = tmp_path / "evidence"
    src.mkdir()
    # A real-shaped folder: photo + plain text + an unscrubbable type
    (src / "photo.jpg").write_bytes(_jpeg_with_fake_app1(b"GPS:39.6,-105.0"))
    (src / "note.txt").write_text("the cover letter")
    (src / "data.bin").write_bytes(b"\x00\x01\x02\x03")

    bundle = tmp_path / "out.skit"
    out, sha, report = archive_folder(
        src, bundle, PASS, kdf=CHEAP_KDF, scrub_metadata=True
    )
    assert report.total == 3
    assert report.scrubbed == 1
    assert report.passthrough == 2  # .txt and .bin
    assert report.failed == 0

    # Round-trip and verify the photo no longer carries the GPS bytes
    extracted, _ = extract_skit(bundle, tmp_path / "out", PASS)
    photo_bytes = (extracted / "photo.jpg").read_bytes()
    assert b"GPS:39.6,-105.0" not in photo_bytes
    # Plain text passed through untouched
    assert (extracted / "note.txt").read_text() == "the cover letter"


def test_archive_scrub_disabled_preserves_metadata(tmp_path: Path) -> None:
    src = tmp_path / "evidence"
    src.mkdir()
    (src / "photo.jpg").write_bytes(_jpeg_with_fake_app1(b"GPS:KEEP_ME"))

    bundle = tmp_path / "out.skit"
    _, _, report = archive_folder(
        src, bundle, PASS, kdf=CHEAP_KDF, scrub_metadata=False
    )
    # With scrub disabled, report is empty
    assert report.total == 0

    extracted, _ = extract_skit(bundle, tmp_path / "out", PASS)
    photo_bytes = (extracted / "photo.jpg").read_bytes()
    assert b"GPS:KEEP_ME" in photo_bytes  # metadata survived as expected
