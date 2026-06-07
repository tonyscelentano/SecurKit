"""XML-level scrubber tests: Word track changes, rsids, comments, Excel/PPT/ODF."""

from __future__ import annotations

import io
import zipfile

import pytest
from lxml import etree as ET

from securkit._ooxml import (
    DC_NS,
    OFFICE_NS,
    PPTX_P_NS,
    W_NS,
    XLSX_S_NS,
    scrub_excel_comments_xml,
    scrub_odf_content_xml,
    scrub_pptx_authors_xml,
    scrub_pptx_comment_xml,
    scrub_word_comments_xml,
    scrub_word_document_xml,
    scrub_word_settings_xml,
)
from securkit.scrubber import scrub_libreoffice, scrub_office


# --- Word document.xml ---------------------------------------------------


_WORD_DOC_XML = f"""<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<w:document xmlns:w="{W_NS}">
  <w:body>
    <w:p w:rsidR="00ABC123" w:rsidRDefault="00DEF456">
      <w:ins w:id="1" w:author="Jane Doe" w:date="2024-03-14T10:00:00Z" w:initials="JD">
        <w:r><w:t>inserted text</w:t></w:r>
      </w:ins>
      <w:del w:id="2" w:author="John Smith" w:date="2024-03-15T11:00:00Z" w:initials="JS">
        <w:r><w:delText>deleted text</w:delText></w:r>
      </w:del>
      <w:r w:rsidRPr="00111111"><w:t>normal text</w:t></w:r>
    </w:p>
    <w:p w:rsidR="00FFEEDD">
      <w:pPr>
        <w:pPrChange w:id="3" w:author="Jane Doe" w:date="2024-03-16T12:00:00Z">
          <w:pPr/>
        </w:pPrChange>
      </w:pPr>
    </w:p>
  </w:body>
</w:document>
""".encode()


def test_scrub_word_document_strips_authors_and_rsids() -> None:
    raw = _WORD_DOC_XML
    assert b"Jane Doe" in raw
    assert b"00ABC123" in raw
    assert b"pPrChange" in raw

    clean, findings = scrub_word_document_xml(raw)
    assert b"Jane Doe" not in clean
    assert b"John Smith" not in clean
    assert b"2024-03-14" not in clean
    assert b"00ABC123" not in clean
    assert b"00DEF456" not in clean
    assert b"00FFEEDD" not in clean
    assert b"00111111" not in clean
    # Element structure preserved — text content survives
    assert b"inserted text" in clean
    assert b"deleted text" in clean
    assert b"normal text" in clean
    # The pPrChange ELEMENT is preserved (only the attrs are stripped); that's
    # fine because the ELEMENT alone doesn't identify anyone.
    assert b"pPrChange" in clean
    # Findings narrate what happened
    assert any("author" in f for f in findings)
    assert any("rsid" in f for f in findings)


def test_scrub_word_document_is_valid_xml() -> None:
    clean, _ = scrub_word_document_xml(_WORD_DOC_XML)
    # Must parse back cleanly
    root = ET.fromstring(clean)
    # Namespace preserved
    assert root.tag == f"{{{W_NS}}}document"
    # No w:rsid* attrs anywhere
    for elem in root.iter():
        for attr in elem.attrib:
            assert not attr.startswith(f"{{{W_NS}}}rsid"), f"rsid leaked: {attr}"
            assert not attr.endswith("}author"), f"author leaked: {attr}"


# --- Word comments.xml ---------------------------------------------------


_WORD_COMMENTS_XML = f"""<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<w:comments xmlns:w="{W_NS}">
  <w:comment w:id="0" w:author="Jane Doe" w:date="2024-03-14T10:00:00Z" w:initials="JD">
    <w:p><w:r><w:t>Need a citation here?</w:t></w:r></w:p>
  </w:comment>
  <w:comment w:id="1" w:author="John Smith" w:date="2024-03-15T11:00:00Z" w:initials="JS">
    <w:p><w:r><w:t>Approved.</w:t></w:r></w:p>
  </w:comment>
</w:comments>
""".encode()


def test_scrub_word_comments_clears_authors_but_keeps_body() -> None:
    clean, findings = scrub_word_comments_xml(_WORD_COMMENTS_XML)
    assert b"Jane Doe" not in clean
    assert b"John Smith" not in clean
    assert b"2024-03-14" not in clean
    # The comment bodies are evidence the user chose to bundle — keep them.
    assert b"Need a citation here?" in clean
    assert b"Approved." in clean
    assert any("comment" in f for f in findings)


# --- Word settings.xml ---------------------------------------------------


_WORD_SETTINGS_XML = f"""<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<w:settings xmlns:w="{W_NS}" xmlns:w14="http://schemas.microsoft.com/office/word/2010/wordml">
  <w:rsidRoot w:val="00ABCDEF"/>
  <w:rsids>
    <w:rsid w:val="00111111"/>
    <w:rsid w:val="00222222"/>
    <w:rsid w:val="00333333"/>
  </w:rsids>
  <w14:docId w14:val="ABCDEF12-3456-7890-ABCD-EF1234567890"/>
  <w:printerSettings r:id="rId99" xmlns:r="x"/>
  <w:zoom w:percent="100"/>
</w:settings>
""".encode()


def test_scrub_word_settings_removes_rsids_and_docid() -> None:
    clean, findings = scrub_word_settings_xml(_WORD_SETTINGS_XML)
    assert b"00ABCDEF" not in clean
    assert b"00111111" not in clean
    assert b"00222222" not in clean
    assert b"ABCDEF12" not in clean
    assert b"printerSettings" not in clean
    # Keep the legitimate settings
    assert b"zoom" in clean
    assert any("rsids" in f or "rsidRoot" in f for f in findings)


# --- Excel comments.xml -------------------------------------------------


_XLSX_COMMENTS_XML = f"""<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<comments xmlns="{XLSX_S_NS}">
  <authors>
    <author>Jane Doe</author>
    <author>John Smith</author>
  </authors>
  <commentList>
    <comment ref="A1" authorId="0"><text><t>note one</t></text></comment>
    <comment ref="B2" authorId="1"><text><t>note two</t></text></comment>
  </commentList>
</comments>
""".encode()


def test_scrub_excel_comments_anonymizes_authors() -> None:
    clean, findings = scrub_excel_comments_xml(_XLSX_COMMENTS_XML)
    assert b"Jane Doe" not in clean
    assert b"John Smith" not in clean
    # Comment text preserved
    assert b"note one" in clean
    assert b"note two" in clean
    # Both comments should now point to authorId="0"
    root = ET.fromstring(clean)
    for c in root.iter(f"{{{XLSX_S_NS}}}comment"):
        assert c.get("authorId") == "0"
    assert any("anonymous" in f for f in findings)


# --- PowerPoint commentAuthors + comments ------------------------------


_PPTX_AUTHORS_XML = f"""<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<p:cmAuthorLst xmlns:p="{PPTX_P_NS}">
  <p:cmAuthor id="0" name="Jane Doe" initials="JD" lastIdx="3" clrIdx="0"/>
  <p:cmAuthor id="1" name="John Smith" initials="JS" lastIdx="1" clrIdx="1"/>
</p:cmAuthorLst>
""".encode()


def test_scrub_pptx_authors_collapses_to_one_anonymous() -> None:
    clean, findings = scrub_pptx_authors_xml(_PPTX_AUTHORS_XML)
    assert b"Jane Doe" not in clean
    assert b"John Smith" not in clean
    assert b'initials="JD"' not in clean
    root = ET.fromstring(clean)
    authors = list(root.iter(f"{{{PPTX_P_NS}}}cmAuthor"))
    assert len(authors) == 1
    assert authors[0].get("name") == ""
    assert authors[0].get("initials") == ""
    assert any("anonymized" in f for f in findings)


_PPTX_COMMENT_XML = f"""<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<p:cmLst xmlns:p="{PPTX_P_NS}">
  <p:cm authorId="0" dt="2024-03-14T10:00:00Z" idx="1"><p:text>hi</p:text></p:cm>
  <p:cm authorId="1" dt="2024-03-15T11:00:00Z" idx="2"><p:text>hello</p:text></p:cm>
</p:cmLst>
""".encode()


def test_scrub_pptx_comment_repoints_and_strips_dt() -> None:
    clean, _ = scrub_pptx_comment_xml(_PPTX_COMMENT_XML)
    assert b"2024-03-14" not in clean
    assert b"2024-03-15" not in clean
    root = ET.fromstring(clean)
    for c in root.iter(f"{{{PPTX_P_NS}}}cm"):
        assert c.get("authorId") == "0"
        assert "dt" not in c.attrib


# --- ODF content.xml ----------------------------------------------------


_ODF_CONTENT_XML = f"""<?xml version="1.0" encoding="UTF-8"?>
<office:document-content xmlns:office="{OFFICE_NS}"
    xmlns:dc="{DC_NS}"
    xmlns:text="http://example.org/text">
  <office:body>
    <text:tracked-changes>
      <text:changed-region xml:id="ct1">
        <text:insertion>
          <office:change-info>
            <dc:creator>Jane Doe</dc:creator>
            <dc:date>2024-03-14T10:00:00</dc:date>
          </office:change-info>
        </text:insertion>
      </text:changed-region>
    </text:tracked-changes>
  </office:body>
</office:document-content>
""".encode()


def test_scrub_odf_content_clears_change_info() -> None:
    clean, findings = scrub_odf_content_xml(_ODF_CONTENT_XML)
    assert b"Jane Doe" not in clean
    assert b"2024-03-14" not in clean
    # change-info element itself survives (empty)
    assert b"change-info" in clean
    assert any("change-info" in f for f in findings)


# --- End-to-end: full scrub_office on a realistic docx -----------------


def _build_paranoid_docx(author: str) -> bytes:
    """Build a docx-shaped zip with track changes, comments, settings rsids,
    AND docProps. Verifies the whole stack."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_STORED) as z:
        z.writestr("[Content_Types].xml", '<?xml version="1.0"?><Types xmlns="x"/>')
        z.writestr(
            "docProps/core.xml",
            f'<?xml version="1.0"?><cp:coreProperties xmlns:cp="x" xmlns:dc="y">'
            f"<dc:creator>{author}</dc:creator></cp:coreProperties>",
        )
        z.writestr(
            "docProps/app.xml",
            '<?xml version="1.0"?><Properties xmlns="x"><Company>Acme</Company></Properties>',
        )
        z.writestr(
            "word/document.xml",
            f'<?xml version="1.0"?>'
            f'<w:document xmlns:w="{W_NS}">'
            f'  <w:body>'
            f'    <w:p w:rsidR="00ABC123">'
            f'      <w:ins w:author="{author}" w:date="2024-01-01T00:00:00Z">'
            f'        <w:r><w:t>tracked content</w:t></w:r>'
            f'      </w:ins>'
            f'    </w:p>'
            f'  </w:body>'
            f'</w:document>',
        )
        z.writestr(
            "word/comments.xml",
            f'<?xml version="1.0"?>'
            f'<w:comments xmlns:w="{W_NS}">'
            f'  <w:comment w:id="0" w:author="{author}" w:date="2024-01-01T00:00:00Z">'
            f'    <w:p><w:r><w:t>my comment</w:t></w:r></w:p>'
            f'  </w:comment>'
            f'</w:comments>',
        )
        z.writestr(
            "word/settings.xml",
            f'<?xml version="1.0"?>'
            f'<w:settings xmlns:w="{W_NS}">'
            f'  <w:rsids>'
            f'    <w:rsid w:val="00ABC123"/>'
            f'  </w:rsids>'
            f'</w:settings>',
        )
    return buf.getvalue()


def test_scrub_office_paranoid_end_to_end() -> None:
    author = "ParanoidTestAuthor"
    dirty = _build_paranoid_docx(author)
    assert author.encode() in dirty
    assert b"00ABC123" in dirty

    clean, findings = scrub_office(dirty)

    # Decompress and verify no trace of the author or rsid anywhere
    with zipfile.ZipFile(io.BytesIO(clean)) as z:
        all_content = b"".join(z.read(name) for name in z.namelist())

    assert author.encode() not in all_content, "author leaked somewhere"
    assert b"00ABC123" not in all_content, "rsid leaked somewhere"
    assert b"2024-01-01" not in all_content, "date leaked somewhere"
    assert b"Acme" not in all_content, "company leaked"

    # But the actual content (tracked text + comment body) survives
    assert b"tracked content" in all_content
    assert b"my comment" in all_content

    # Caveat now mentions only embedded objects, not track changes
    caveats = [f for f in findings if f.startswith("⚠")]
    assert any("embedded objects" in c for c in caveats)
    assert not any("track changes" in c.lower() for c in caveats), (
        "caveat should no longer claim track changes aren't scrubbed"
    )


def test_scrub_office_xml_failure_is_soft() -> None:
    """A malformed XML file inside the docx must not blow up the whole scrub —
    the original bytes are kept and a warning surfaces."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_STORED) as z:
        z.writestr("[Content_Types].xml", '<?xml version="1.0"?><Types xmlns="x"/>')
        z.writestr("docProps/core.xml", "<core/>")
        z.writestr("docProps/app.xml", "<app/>")
        z.writestr("word/document.xml", "this is not XML at all")
    dirty = buf.getvalue()
    clean, findings = scrub_office(dirty)
    # Should not raise; should warn
    assert any("in-XML scrub failed" in f or "XML" in f for f in findings)
    # Original malformed file is still in the package (not lost)
    with zipfile.ZipFile(io.BytesIO(clean)) as z:
        assert z.read("word/document.xml") == b"this is not XML at all"


def test_scrub_libreoffice_clears_content_change_info() -> None:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_STORED) as z:
        z.writestr("META-INF/manifest.xml", '<?xml version="1.0"?><manifest:manifest xmlns:manifest="x"/>')
        z.writestr("meta.xml", '<?xml version="1.0"?><office:document-meta xmlns:office="y"><dc:creator xmlns:dc="z">Jane Doe</dc:creator></office:document-meta>')
        z.writestr("content.xml", _ODF_CONTENT_XML.decode())
    dirty = buf.getvalue()
    assert b"Jane Doe" in dirty

    clean, findings = scrub_libreoffice(dirty)
    with zipfile.ZipFile(io.BytesIO(clean)) as z:
        all_content = b"".join(z.read(name) for name in z.namelist())
    assert b"Jane Doe" not in all_content
    caveats = [f for f in findings if f.startswith("⚠")]
    assert any("embedded objects" in c for c in caveats)
