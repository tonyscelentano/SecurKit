"""XML-level scrubbers for OOXML (Word/Excel/PowerPoint) and ODF documents.

These complement the zip-level scrubbing in `scrubber.py` by reaching INTO
the content XML files to strip metadata that lives there:

  - track-changes author/date/initials  (<w:ins>, <w:del>, w:rPrChange, …)
  - rsid* session-fingerprint attributes (uniquely identify editing sessions
    and can correlate the same author across multiple documents)
  - comment author/date/initials
  - the <w:rsids> registry block in word/settings.xml
  - <office:change-info><dc:creator> in ODF content.xml

Uses lxml because Office is finicky about namespace prefix preservation when
the document round-trips, and lxml preserves the source's prefix declarations
where stdlib ElementTree may rename them.

Each function is a pure bytes→bytes transform that returns the modified XML
plus a list of human-readable findings.
"""

from __future__ import annotations

from lxml import etree as ET

# --- OOXML namespaces ----------------------------------------------------

W_NS = "http://schemas.openxmlformats.org/wordprocessingml/2006/main"
W14_NS = "http://schemas.microsoft.com/office/word/2010/wordml"
W15_NS = "http://schemas.microsoft.com/office/word/2012/wordml"
DC_NS = "http://purl.org/dc/elements/1.1/"
DCTERMS_NS = "http://purl.org/dc/terms/"
OFFICE_NS = "urn:oasis:names:tc:opendocument:xmlns:office:1.0"
TEXT_NS = "urn:oasis:names:tc:opendocument:xmlns:text:1.0"

# Attributes that identify the human behind a revision or comment.
_W_AUTHOR_ATTRS = frozenset(
    {
        f"{{{W_NS}}}author",
        f"{{{W_NS}}}date",
        f"{{{W_NS}}}initials",
        f"{{{W14_NS}}}author",
        f"{{{W14_NS}}}date",
        f"{{{W14_NS}}}initials",
        f"{{{W15_NS}}}author",
        f"{{{W15_NS}}}date",
        f"{{{W15_NS}}}initials",
    }
)


def _is_rsid_attr(name: str) -> bool:
    """Match w:rsidR, w:rsidP, w:rsidRPr, w:rsidDel, w:rsidTr, w:rsidRDefault, etc."""
    return name.startswith(f"{{{W_NS}}}rsid") or name.startswith(f"{{{W14_NS}}}rsid")


# Elements in settings.xml that we remove wholesale.
_W_SETTINGS_REMOVE_TAGS = frozenset(
    {
        f"{{{W_NS}}}rsids",
        f"{{{W_NS}}}rsidRoot",
        f"{{{W_NS}}}printerSettings",
        f"{{{W14_NS}}}docId",  # unique document GUID
        f"{{{W15_NS}}}docId",
    }
)


def _parse(xml_bytes: bytes) -> ET._Element:
    """Parse OOXML XML with a hardened parser (no external entities, no DTD load)."""
    parser = ET.XMLParser(
        resolve_entities=False,
        no_network=True,
        load_dtd=False,
        huge_tree=False,
        recover=False,
    )
    return ET.fromstring(xml_bytes, parser=parser)


def _serialize(root: ET._Element) -> bytes:
    """Serialize back to bytes with the XML declaration Office expects."""
    return ET.tostring(
        root, xml_declaration=True, encoding="UTF-8", standalone=True
    )


# --- Word: document.xml / headers / footers / footnotes / endnotes ------


def scrub_word_document_xml(xml_bytes: bytes) -> tuple[bytes, list[str]]:
    """Strip w:author/date/initials from revision markers AND every w:rsid* attr.

    Applied to word/document.xml, word/header*.xml, word/footer*.xml,
    word/footnotes.xml, word/endnotes.xml.
    """
    root = _parse(xml_bytes)
    author_removed = 0
    rsid_removed = 0
    for elem in root.iter():
        for attr in list(elem.attrib.keys()):
            if attr in _W_AUTHOR_ATTRS:
                del elem.attrib[attr]
                author_removed += 1
            elif _is_rsid_attr(attr):
                del elem.attrib[attr]
                rsid_removed += 1
    findings: list[str] = []
    if author_removed:
        findings.append(f"stripped {author_removed} author/date attribute(s) from revisions")
    if rsid_removed:
        findings.append(f"stripped {rsid_removed} rsid session-fingerprint attribute(s)")
    return _serialize(root), findings


# --- Word: comments.xml ------------------------------------------------


def scrub_word_comments_xml(xml_bytes: bytes) -> tuple[bytes, list[str]]:
    """Clear author/date/initials from every <w:comment> element. The comment
    body is preserved (it's part of the document evidence the user chose to
    include), but who-said-it is gone."""
    root = _parse(xml_bytes)
    cleared = 0
    for elem in root.iter(f"{{{W_NS}}}comment"):
        for attr in list(elem.attrib.keys()):
            if attr in _W_AUTHOR_ATTRS:
                del elem.attrib[attr]
                cleared += 1
    findings = []
    if cleared:
        findings.append(f"cleared {cleared} comment author/date attribute(s)")
    return _serialize(root), findings


# --- Word: settings.xml ------------------------------------------------


def scrub_word_settings_xml(xml_bytes: bytes) -> tuple[bytes, list[str]]:
    """Remove <w:rsids>, <w:rsidRoot>, <w:printerSettings>, and any docId.
    Also strip any rsid* attributes from anywhere in the file."""
    root = _parse(xml_bytes)
    findings: list[str] = []
    removed_tags: dict[str, int] = {}
    # Remove top-level (and nested) instances of identifying elements
    for elem in list(root.iter()):
        if elem.tag in _W_SETTINGS_REMOVE_TAGS:
            parent = elem.getparent()
            if parent is not None:
                parent.remove(elem)
                short = elem.tag.rsplit("}", 1)[-1]
                removed_tags[short] = removed_tags.get(short, 0) + 1
    # Strip stray rsid* attrs (settings.xml itself usually has none, but
    # defensive)
    rsid_attrs_removed = 0
    for elem in root.iter():
        for attr in list(elem.attrib.keys()):
            if _is_rsid_attr(attr):
                del elem.attrib[attr]
                rsid_attrs_removed += 1
    for tag, count in removed_tags.items():
        findings.append(f"removed {count} <w:{tag}> element(s) from settings.xml")
    if rsid_attrs_removed:
        findings.append(f"stripped {rsid_attrs_removed} rsid attribute(s) from settings.xml")
    return _serialize(root), findings


# --- Excel: xl/comments*.xml ------------------------------------------

XLSX_S_NS = "http://schemas.openxmlformats.org/spreadsheetml/2006/main"


def scrub_excel_comments_xml(xml_bytes: bytes) -> tuple[bytes, list[str]]:
    """Replace the <authors>…</authors> list with a single anonymous entry.

    Excel comments are keyed by index into the authors array, so we keep the
    array intact (with one entry) and rewrite each comment's authorId=0.
    """
    root = _parse(xml_bytes)
    findings: list[str] = []
    authors_elem = root.find(f"{{{XLSX_S_NS}}}authors")
    if authors_elem is not None:
        old_count = len(list(authors_elem))
        if old_count:
            findings.append(f"collapsed {old_count} Excel comment author(s) to anonymous")
        # Drop all author entries
        for child in list(authors_elem):
            authors_elem.remove(child)
        # Add a single anonymous entry so authorId=0 references still resolve
        anon = ET.SubElement(authors_elem, f"{{{XLSX_S_NS}}}author")
        anon.text = ""
    # Re-point every commentList/comment authorId to 0
    repointed = 0
    for comment in root.iter(f"{{{XLSX_S_NS}}}comment"):
        if comment.get("authorId") not in (None, "0"):
            comment.set("authorId", "0")
            repointed += 1
    if repointed:
        findings.append(f"re-pointed {repointed} Excel comment(s) to anonymous author")
    return _serialize(root), findings


# --- PowerPoint: ppt/commentAuthors.xml ------------------------------------

PPTX_P_NS = "http://schemas.openxmlformats.org/presentationml/2006/main"


def scrub_pptx_authors_xml(xml_bytes: bytes) -> tuple[bytes, list[str]]:
    """Replace the comment-authors list with a single anonymous entry."""
    root = _parse(xml_bytes)
    findings: list[str] = []
    removed = 0
    keep_one_id = None
    for elem in list(root):
        if elem.tag == f"{{{PPTX_P_NS}}}cmAuthor":
            if keep_one_id is None:
                keep_one_id = elem.get("id", "0")
                # Strip identifying attrs on the kept entry
                elem.set("name", "")
                elem.set("initials", "")
            else:
                root.remove(elem)
                removed += 1
    # If a cmAuthor was kept, zero its identifying attributes (re-state for safety)
    if keep_one_id is not None:
        for elem in root.iter(f"{{{PPTX_P_NS}}}cmAuthor"):
            elem.set("name", "")
            elem.set("initials", "")
            findings.append("anonymized PowerPoint comment author")
            break
    if removed:
        findings.append(f"removed {removed} additional PowerPoint comment author(s)")
    return _serialize(root), findings


def scrub_pptx_comment_xml(xml_bytes: bytes) -> tuple[bytes, list[str]]:
    """Force every PPT comment's authorId to 0 (matches scrub_pptx_authors_xml)."""
    root = _parse(xml_bytes)
    findings: list[str] = []
    repointed = 0
    for comment in root.iter(f"{{{PPTX_P_NS}}}cm"):
        if comment.get("authorId") not in (None, "0"):
            comment.set("authorId", "0")
            repointed += 1
        # Also strip the dt (datetime) attribute
        if "dt" in comment.attrib:
            del comment.attrib["dt"]
    if repointed:
        findings.append(f"re-pointed {repointed} PowerPoint comment(s) to anonymous author")
    return _serialize(root), findings


# --- ODF: content.xml --------------------------------------------------


def scrub_odf_content_xml(xml_bytes: bytes) -> tuple[bytes, list[str]]:
    """Clear <dc:creator>, <dc:date>, and contributor info from every
    <office:change-info> in ODF tracked-changes."""
    root = _parse(xml_bytes)
    findings: list[str] = []
    cleared = 0
    for ci in root.iter(f"{{{OFFICE_NS}}}change-info"):
        for child in list(ci):
            if child.tag in (
                f"{{{DC_NS}}}creator",
                f"{{{DC_NS}}}date",
                f"{{{DCTERMS_NS}}}creator",
                f"{{{DCTERMS_NS}}}date",
            ):
                ci.remove(child)
                cleared += 1
    if cleared:
        findings.append(f"cleared {cleared} ODF change-info author/date element(s)")
    return _serialize(root), findings
