"""Smoke tests — imports clean, hotlines data loads."""

from __future__ import annotations


def test_package_imports() -> None:
    import securkit
    import securkit.archive  # noqa: F401
    import securkit.crypto  # noqa: F401
    import securkit.hotlines  # noqa: F401
    import securkit.scrubber  # noqa: F401

    assert securkit.__version__


def test_hotlines_load() -> None:
    from securkit.hotlines import load_hotlines

    entries = load_hotlines()
    assert len(entries) >= 10
    ids = {e.id for e in entries}
    for required in {"sec-whistleblower", "irs-whistleblower", "icij-leak"}:
        assert required in ids, f"missing hotline: {required}"


def test_hotlines_include_eu_regulators() -> None:
    from securkit.hotlines import load_hotlines

    entries = load_hotlines()
    ids = {e.id for e in entries}
    for required in {"eu-olaf", "eu-eppo", "de-bafin", "fr-amf"}:
        assert required in ids, f"missing EU hotline: {required}"

    # Both regions are represented so the dashboard can group them.
    regions = {e.region for e in entries}
    assert {"United States", "Europe"} <= regions

    # National regulators keep their real jurisdiction, not a flattened "EU".
    bafin = next(e for e in entries if e.id == "de-bafin")
    assert bafin.jurisdiction == "Germany"
    assert bafin.region == "Europe"
