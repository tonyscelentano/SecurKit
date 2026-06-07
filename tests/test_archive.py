"""Archive pipeline tests: round-trip + adversarial."""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from securkit.archive import ArchiveError, archive_folder, extract_skit
from securkit.crypto import KdfParams, SkitAuthError, encrypt_stream

CHEAP_KDF = KdfParams(time_cost=1, memory_cost_kib=8, parallelism=1)
PASS = "river-pine-amber-knife-clay-storm-thumb"


def _make_tree(root: Path) -> dict[str, bytes]:
    """Populate `root` with a small mixed tree. Returns {relpath: bytes}."""
    expected: dict[str, bytes] = {}

    def put(rel: str, data: bytes) -> None:
        p = root / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_bytes(data)
        expected[rel] = data

    put("notes.txt", b"This is the cover letter.\n")
    put("scan.bin", os.urandom(20_000))
    put("subdir/photo.jpg", os.urandom(8192))
    put("subdir/deep/log.csv", b"a,b,c\n1,2,3\n4,5,6\n")
    put("excluded/secret.tmp", b"should be filtered")
    return expected


def _read_tree(root: Path) -> dict[str, bytes]:
    out: dict[str, bytes] = {}
    for p in root.rglob("*"):
        if p.is_file():
            out[p.relative_to(root).as_posix()] = p.read_bytes()
    return out


# --- round-trip -----------------------------------------------------------


def test_roundtrip_nested_tree(tmp_path: Path) -> None:
    src = tmp_path / "evidence"
    src.mkdir()
    expected = _make_tree(src)

    bundle = tmp_path / "out.skit"
    out, sha_enc, _ = archive_folder(src, bundle, PASS, kdf=CHEAP_KDF)
    assert out == bundle
    assert bundle.exists() and bundle.stat().st_size > 0
    assert len(sha_enc) == 32

    extract_dir = tmp_path / "extracted"
    root, sha_dec = extract_skit(bundle, extract_dir, PASS)
    assert sha_enc == sha_dec
    assert root.name == "evidence"
    actual = _read_tree(root)
    assert actual == expected


def test_roundtrip_empty_folder(tmp_path: Path) -> None:
    src = tmp_path / "empty"
    src.mkdir()
    bundle = tmp_path / "empty.skit"
    archive_folder(src, bundle, PASS, kdf=CHEAP_KDF)
    out = tmp_path / "extracted"
    root, _sha = extract_skit(bundle, out, PASS)
    assert root.name == "empty"
    assert list(root.iterdir()) == []


def test_excludes_filter_files(tmp_path: Path) -> None:
    src = tmp_path / "evidence"
    src.mkdir()
    expected = _make_tree(src)

    bundle = tmp_path / "out.skit"
    archive_folder(src, bundle, PASS, kdf=CHEAP_KDF, excludes=("excluded/*",))
    root, _ = extract_skit(bundle, tmp_path / "extracted", PASS)
    actual = _read_tree(root)
    # 'excluded/secret.tmp' should be gone, everything else present
    assert "excluded/secret.tmp" not in actual
    expected.pop("excluded/secret.tmp")
    assert actual == expected


def test_plaintext_sha_deterministic(tmp_path: Path) -> None:
    """Same input folder + same walk order + normalized headers → same plaintext digest.

    The .skit ciphertext differs (random salt + nonce), but the plaintext SHA-256
    returned by archive_folder is content-stable — useful for cross-verifying that
    two bundles came from the same source.
    """
    src = tmp_path / "evidence"
    src.mkdir()
    _make_tree(src)

    b1 = tmp_path / "a.skit"
    b2 = tmp_path / "b.skit"
    _, sha_a, _ = archive_folder(src, b1, PASS, kdf=CHEAP_KDF)
    _, sha_b, _ = archive_folder(src, b2, PASS, kdf=CHEAP_KDF)
    assert sha_a == sha_b
    # And the ciphertexts MUST differ (random salt/nonce)
    assert b1.read_bytes() != b2.read_bytes()


# --- adversarial / safety ------------------------------------------------


def test_wrong_passphrase_leaves_no_files(tmp_path: Path) -> None:
    src = tmp_path / "evidence"
    src.mkdir()
    _make_tree(src)
    bundle = tmp_path / "out.skit"
    archive_folder(src, bundle, PASS, kdf=CHEAP_KDF)

    out = tmp_path / "extracted"
    with pytest.raises((SkitAuthError, ArchiveError)):
        extract_skit(bundle, out, "wrong-passphrase")
    # dest_dir exists (we created it) but should be empty
    assert list(out.iterdir()) == []


def test_tampered_bundle_leaves_no_files(tmp_path: Path) -> None:
    src = tmp_path / "evidence"
    src.mkdir()
    _make_tree(src)
    bundle = tmp_path / "out.skit"
    archive_folder(src, bundle, PASS, kdf=CHEAP_KDF)

    # Flip a byte deep in the ciphertext
    data = bytearray(bundle.read_bytes())
    data[200] ^= 0x01
    bundle.write_bytes(bytes(data))

    out = tmp_path / "extracted"
    with pytest.raises((SkitAuthError, ArchiveError)):
        extract_skit(bundle, out, PASS)
    assert list(out.iterdir()) == []


def test_partial_encrypt_failure_cleans_up(tmp_path: Path) -> None:
    """A failure during encryption must not leave a .skit at the destination."""
    src = tmp_path / "evidence"
    src.mkdir()
    _make_tree(src)
    bundle = tmp_path / "out.skit"

    # Force failure by passing an invalid KDF (parallelism=0 fails validate())
    bad_kdf = KdfParams.__new__(KdfParams)
    object.__setattr__(bad_kdf, "time_cost", 1)
    object.__setattr__(bad_kdf, "memory_cost_kib", 8)
    object.__setattr__(bad_kdf, "parallelism", 0)
    with pytest.raises(Exception):
        archive_folder(src, bundle, PASS, kdf=bad_kdf)
    assert not bundle.exists(), "partial bundle should be cleaned up"
    # Also: no .tmp leftovers in the dest dir
    leftovers = [p for p in tmp_path.iterdir() if p.suffix == ".tmp"]
    assert leftovers == []


def test_rejects_output_inside_source(tmp_path: Path) -> None:
    src = tmp_path / "evidence"
    src.mkdir()
    (src / "a.txt").write_text("hi")
    nested_out = src / "inside.skit"
    with pytest.raises(ValueError, match="must not be inside"):
        archive_folder(src, nested_out, PASS, kdf=CHEAP_KDF)


def test_malicious_path_traversal_rejected(tmp_path: Path) -> None:
    """A hand-crafted bundle containing a '../../escape.txt' tar entry must
    not extract files outside the destination directory.

    Defense in depth: extract_skit's single-top-level check catches this first,
    and Python 3.12's tarfile.data_filter would catch any path with '..' even
    if the layout check were bypassed.
    """
    import io
    import tarfile

    evil_tar = io.BytesIO()
    with tarfile.open(fileobj=evil_tar, mode="w") as tf:
        info = tarfile.TarInfo(name="../../escape.txt")
        payload = b"pwned"
        info.size = len(payload)
        tf.addfile(info, io.BytesIO(payload))

    bundle = tmp_path / "evil.skit"
    with bundle.open("wb") as out:
        encrypt_stream(io.BytesIO(evil_tar.getvalue()), out, PASS, kdf=CHEAP_KDF)

    out_dir = tmp_path / "out"
    with pytest.raises((ArchiveError, Exception)):
        extract_skit(bundle, out_dir, PASS)

    # No escape file anywhere outside out_dir
    for parent in (tmp_path, tmp_path.parent, tmp_path.parent.parent):
        assert not (parent / "escape.txt").exists(), f"escape file at {parent}"
    # And dest_dir is empty
    if out_dir.exists():
        assert list(out_dir.iterdir()) == []


def test_refuses_to_overwrite_extracted_dir(tmp_path: Path) -> None:
    src = tmp_path / "evidence"
    src.mkdir()
    (src / "a.txt").write_text("hi")
    bundle = tmp_path / "out.skit"
    archive_folder(src, bundle, PASS, kdf=CHEAP_KDF)

    out = tmp_path / "extracted"
    extract_skit(bundle, out, PASS)
    # Second extract into the same parent collides on `evidence/`
    with pytest.raises(FileExistsError):
        extract_skit(bundle, out, PASS)


# --- progress -------------------------------------------------------------


def test_progress_callback_fires(tmp_path: Path) -> None:
    src = tmp_path / "evidence"
    src.mkdir()
    (src / "blob.bin").write_bytes(os.urandom(64_000))
    bundle = tmp_path / "out.skit"

    encrypt_calls: list[tuple[int, int]] = []
    decrypt_calls: list[tuple[int, int]] = []

    archive_folder(
        src, bundle, PASS, kdf=CHEAP_KDF,
        on_progress=lambda done, total: encrypt_calls.append((done, total)),
    )
    extract_skit(
        bundle, tmp_path / "out", PASS,
        on_progress=lambda done, total: decrypt_calls.append((done, total)),
    )

    assert encrypt_calls, "encrypt progress never fired"
    assert decrypt_calls, "decrypt progress never fired"
    # Monotonic non-decreasing
    for prev, nxt in zip(encrypt_calls, encrypt_calls[1:]):
        assert nxt[0] >= prev[0]
    # Final report should equal total (or be very close)
    last_done, last_total = encrypt_calls[-1]
    assert last_done == last_total
