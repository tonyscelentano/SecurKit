"""Crypto tests: SKIT1 round-trip and adversarial cases.

Uses cheap Argon2id params so the suite stays under a couple of seconds.
Real-world bundles use the production defaults from `KdfParams()`.
"""

from __future__ import annotations

import io
import os
import struct

import pytest

from securkit.crypto import (
    HEADER_LEN,
    KdfParams,
    SkitAuthError,
    SkitFormatError,
    decrypt_stream,
    derive_key,
    encrypt_stream,
)

CHEAP_KDF = KdfParams(time_cost=1, memory_cost_kib=8, parallelism=1)
PASS = "correct horse battery staple"


def _roundtrip(data: bytes, *, chunk_size: int = 4096) -> bytes:
    src = io.BytesIO(data)
    bundle = io.BytesIO()
    encrypt_stream(src, bundle, PASS, kdf=CHEAP_KDF, chunk_size=chunk_size)
    bundle.seek(0)
    out = io.BytesIO()
    decrypt_stream(bundle, out, PASS)
    return out.getvalue()


# --- KDF -----------------------------------------------------------------


def test_kdf_deterministic() -> None:
    salt = b"x" * 16
    a = derive_key("hunter2", salt, CHEAP_KDF)
    b = derive_key("hunter2", salt, CHEAP_KDF)
    assert a == b
    assert len(a) == 32


def test_kdf_salt_matters() -> None:
    a = derive_key("hunter2", b"a" * 16, CHEAP_KDF)
    b = derive_key("hunter2", b"b" * 16, CHEAP_KDF)
    assert a != b


def test_kdf_rejects_bad_salt() -> None:
    with pytest.raises(ValueError):
        derive_key("x", b"too short", CHEAP_KDF)


# --- Round-trip ----------------------------------------------------------


def test_roundtrip_empty() -> None:
    assert _roundtrip(b"") == b""


def test_roundtrip_small() -> None:
    payload = b"the quick brown fox jumps over the lazy dog\n"
    assert _roundtrip(payload) == payload


def test_roundtrip_multi_chunk() -> None:
    payload = os.urandom(4096 * 5 + 17)  # forces 6 data chunks at chunk_size=4096
    assert _roundtrip(payload, chunk_size=4096) == payload


def test_roundtrip_exact_chunk_boundary() -> None:
    payload = os.urandom(4096 * 3)  # exactly 3 chunks, no remainder
    assert _roundtrip(payload, chunk_size=4096) == payload


# --- Adversarial ---------------------------------------------------------


def _make_bundle(data: bytes, chunk_size: int = 4096) -> bytes:
    src = io.BytesIO(data)
    out = io.BytesIO()
    encrypt_stream(src, out, PASS, kdf=CHEAP_KDF, chunk_size=chunk_size)
    return out.getvalue()


def _try_decrypt(bundle_bytes: bytes, passphrase: str = PASS) -> bytes:
    out = io.BytesIO()
    decrypt_stream(io.BytesIO(bundle_bytes), out, passphrase)
    return out.getvalue()


def test_wrong_passphrase_fails() -> None:
    bundle = _make_bundle(b"top secret payload")
    with pytest.raises(SkitAuthError):
        _try_decrypt(bundle, passphrase="wrong")


def test_tampered_ciphertext_fails() -> None:
    bundle = bytearray(_make_bundle(b"top secret payload"))
    # Flip a byte in the first chunk's ciphertext (skip header + 4-byte len prefix)
    bundle[HEADER_LEN + 4] ^= 0x01
    with pytest.raises(SkitAuthError):
        _try_decrypt(bytes(bundle))


def test_tampered_header_salt_fails() -> None:
    bundle = bytearray(_make_bundle(b"top secret payload"))
    # Flip a byte inside the salt region (header offset 12..27)
    bundle[20] ^= 0x01
    with pytest.raises((SkitAuthError, SkitFormatError)):
        _try_decrypt(bytes(bundle))


def test_tampered_kdf_params_fails() -> None:
    """Rollback defense: flipping a bit in the KDF params region must fail.

    Header offsets 8..16 hold time_cost (u32) and memory_cost_kib (u32). Flipping
    a low bit changes the params just enough to derive a different key, while
    still parsing as valid Argon2id parameters.
    """
    bundle = bytearray(_make_bundle(b"top secret payload"))
    bundle[8] ^= 0x01  # flips low bit of time_cost
    with pytest.raises((SkitAuthError, SkitFormatError)):
        _try_decrypt(bytes(bundle))


def test_malicious_kdf_memory_rejected() -> None:
    """A bundle whose declared KDF memory exceeds the decrypt cap is rejected
    BEFORE any key derivation — preventing DoS via attacker-supplied params."""
    bundle = bytearray(_make_bundle(b"x"))
    # memory_cost_kib lives at header offset 12 (after magic|ver|cipher|kdf|t = 5+1+1+1+4)
    # Overwrite with 4 GiB worth of KiB.
    struct.pack_into(">I", bundle, 12, 4 * 1024 * 1024)
    with pytest.raises(SkitFormatError, match="memory_cost_kib"):
        _try_decrypt(bytes(bundle))


def test_header_only_no_chunks_fails() -> None:
    """A bundle that's exactly the header and no chunks must be rejected."""
    bundle = bytearray(_make_bundle(b"x"))
    header_only = bytes(bundle[:53])  # HEADER_LEN
    with pytest.raises(SkitFormatError, match="empty bundle"):
        _try_decrypt(header_only)


def test_truncation_attack_detected() -> None:
    """Dropping the SHA trailer chunk must NOT pass."""
    payload = os.urandom(8192)  # 2 data chunks at chunk_size=4096
    bundle = bytearray(_make_bundle(payload, chunk_size=4096))

    # Find the last chunk (the SHA trailer) and remove it.
    # Parse chunk lengths from after the header.
    pos = HEADER_LEN
    last_chunk_start = pos
    while pos < len(bundle):
        (clen,) = struct.unpack(">I", bundle[pos : pos + 4])
        last_chunk_start = pos
        pos += 4 + clen
    assert pos == len(bundle)

    truncated = bytes(bundle[:last_chunk_start])
    with pytest.raises((SkitAuthError, SkitFormatError)):
        _try_decrypt(truncated)


def test_reorder_attack_detected() -> None:
    """Swapping two data chunks must fail authentication."""
    payload = os.urandom(8192)
    bundle = bytearray(_make_bundle(payload, chunk_size=4096))

    # Locate chunks 0 and 1 by walking length prefixes.
    pos = HEADER_LEN
    spans: list[tuple[int, int]] = []  # (start, full_length_incl_prefix)
    while pos < len(bundle):
        (clen,) = struct.unpack(">I", bundle[pos : pos + 4])
        spans.append((pos, 4 + clen))
        pos += 4 + clen

    assert len(spans) >= 3, "expected >=2 data chunks + 1 trailer"
    (s0, l0), (s1, l1) = spans[0], spans[1]
    swapped = bytearray(bundle)
    c0 = bytes(swapped[s0 : s0 + l0])
    c1 = bytes(swapped[s1 : s1 + l1])
    # Equal-length chunks (full chunk size) — safe to swap in place
    assert l0 == l1, "chunks must be equal-length for this swap test"
    swapped[s0 : s0 + l0] = c1
    swapped[s1 : s1 + l1] = c0

    with pytest.raises(SkitAuthError):
        _try_decrypt(bytes(swapped))


def test_bad_magic_fails() -> None:
    bundle = bytearray(_make_bundle(b"hi"))
    bundle[0] = ord("X")
    with pytest.raises(SkitFormatError):
        _try_decrypt(bytes(bundle))


def test_trailing_garbage_fails() -> None:
    bundle = _make_bundle(b"hi") + b"EXTRA"
    with pytest.raises(SkitFormatError):
        _try_decrypt(bundle)


def test_passphrase_bytes_or_str_equivalent() -> None:
    src = io.BytesIO(b"unicode-friendly: \xe2\x98\x83")
    bundle = io.BytesIO()
    encrypt_stream(src, bundle, "snowman", kdf=CHEAP_KDF, chunk_size=4096)
    bundle.seek(0)
    out = io.BytesIO()
    decrypt_stream(bundle, out, b"snowman")  # decrypt with bytes form of same passphrase
    assert out.getvalue() == b"unicode-friendly: \xe2\x98\x83"
