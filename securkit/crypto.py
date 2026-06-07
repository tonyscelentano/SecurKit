"""Cryptographic primitives for SecurKit's SKIT1 bundle format.

AEAD: AES-256-GCM (`cryptography`)
KDF:  Argon2id (`argon2-cffi`)
Hash: SHA-256 (stdlib) — emitted as a sealed trailer chunk

SKIT1 framing
-------------
header (53 bytes, fully authenticated as AAD on every chunk):
    magic        b"SKIT1"        5
    version      u8              1
    cipher_id    u8              1   1 = AES-256-GCM
    kdf_id       u8              1   1 = Argon2id
    kdf.t        u32 big-endian  4
    kdf.m_kib    u32 big-endian  4
    kdf.p        u8              1
    salt                        16
    base_nonce                  12
    chunk_size   u64 big-endian  8

chunk_i, for i in 0..n-1:
    u32 big-endian ciphertext-length || ciphertext || gcm-tag(16)
    nonce_i = base_nonce[:4] || (base_nonce[4:] XOR i_be64)
    aad_i   = header || i_be64 || final_flag_u8

final chunk (i = n-1, final_flag = 1):
    plaintext = SHA-256(plaintext_archive)   # 32 bytes

The final flag is what defends against truncation: an attacker who drops the
trailer chunk will produce a bundle whose last data chunk was signed with
final_flag=0, so decryption never sees a "this is the end" marker and raises.
The counter in AAD defends against chunk reordering. The full header in AAD
defends against tampering with KDF params, salt, or nonce.
"""

from __future__ import annotations

import hashlib
import os
import struct
from dataclasses import dataclass
from typing import BinaryIO

from argon2.low_level import Type, hash_secret_raw
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

MAGIC = b"SKIT1"
VERSION = 1
CIPHER_ID_AES_256_GCM = 1
KDF_ID_ARGON2ID = 1

DEFAULT_CHUNK_SIZE = 1 << 20  # 1 MiB
SALT_LEN = 16
NONCE_LEN = 12
KEY_LEN = 32
TAG_LEN = 16
SHA256_LEN = 32

_HEADER_FMT = ">5sBBBIIB16s12sQ"
HEADER_LEN = struct.calcsize(_HEADER_FMT)  # 53

# Sanity guard: a malformed bundle could claim a multi-GB chunk length and
# force the decryptor to allocate it. Cap reads at 64 MiB per chunk.
_MAX_CHUNK_BYTES = 64 * 1024 * 1024

# Decryption-time caps on attacker-controlled KDF parameters. A malicious bundle
# could otherwise claim e.g. 4 TiB of Argon2 memory, DoSing the verifier before
# any tag is checked. These caps are intentionally generous for legitimate use
# (well above OWASP recommendations) but bounded.
_DECRYPT_MAX_MEMORY_KIB = 1 * 1024 * 1024  # 1 GiB
_DECRYPT_MAX_TIME_COST = 64
_DECRYPT_MAX_PARALLELISM = 16


class SkitFormatError(ValueError):
    """Bundle is not a valid SKIT1 stream."""


class SkitAuthError(ValueError):
    """Decryption failed: wrong passphrase or tampered bundle."""


@dataclass(frozen=True)
class KdfParams:
    time_cost: int = 3
    memory_cost_kib: int = 256 * 1024  # 256 MiB — OWASP 2024 recommendation
    parallelism: int = 1

    def validate(self) -> None:
        if not (1 <= self.time_cost <= 2**32 - 1):
            raise ValueError("time_cost out of range")
        if not (8 * self.parallelism <= self.memory_cost_kib <= 2**32 - 1):
            raise ValueError("memory_cost_kib out of range")
        if not (1 <= self.parallelism <= 255):
            raise ValueError("parallelism out of range")


def _coerce_passphrase(passphrase: str | bytes) -> bytes:
    if isinstance(passphrase, str):
        return passphrase.encode("utf-8")
    return bytes(passphrase)


def derive_key(passphrase: str | bytes, salt: bytes, params: KdfParams) -> bytes:
    """Argon2id(passphrase, salt) -> 32-byte key."""
    if len(salt) != SALT_LEN:
        raise ValueError(f"salt must be {SALT_LEN} bytes, got {len(salt)}")
    params.validate()
    return hash_secret_raw(
        secret=_coerce_passphrase(passphrase),
        salt=salt,
        time_cost=params.time_cost,
        memory_cost=params.memory_cost_kib,
        parallelism=params.parallelism,
        hash_len=KEY_LEN,
        type=Type.ID,
    )


def _nonce_for(base_nonce: bytes, counter: int) -> bytes:
    """12-byte nonce = base[:4] || (base[4:] XOR counter_be64)."""
    ctr = counter.to_bytes(8, "big")
    tail = bytes(a ^ b for a, b in zip(base_nonce[4:], ctr))
    return base_nonce[:4] + tail


def _aad(header: bytes, counter: int, is_final: bool) -> bytes:
    return header + counter.to_bytes(8, "big") + (b"\x01" if is_final else b"\x00")


def _pack_header(kdf: KdfParams, salt: bytes, base_nonce: bytes, chunk_size: int) -> bytes:
    return struct.pack(
        _HEADER_FMT,
        MAGIC,
        VERSION,
        CIPHER_ID_AES_256_GCM,
        KDF_ID_ARGON2ID,
        kdf.time_cost,
        kdf.memory_cost_kib,
        kdf.parallelism,
        salt,
        base_nonce,
        chunk_size,
    )


def _unpack_header(buf: bytes) -> tuple[KdfParams, bytes, bytes, int]:
    if len(buf) != HEADER_LEN:
        raise SkitFormatError(f"header must be {HEADER_LEN} bytes, got {len(buf)}")
    magic, version, cipher, kdf_id, t, m, p, salt, base_nonce, chunk_size = struct.unpack(
        _HEADER_FMT, buf
    )
    if magic != MAGIC:
        raise SkitFormatError("not a SKIT1 bundle (bad magic)")
    if version != VERSION:
        raise SkitFormatError(f"unsupported SKIT version: {version}")
    if cipher != CIPHER_ID_AES_256_GCM:
        raise SkitFormatError(f"unsupported cipher id: {cipher}")
    if kdf_id != KDF_ID_ARGON2ID:
        raise SkitFormatError(f"unsupported kdf id: {kdf_id}")
    params = KdfParams(time_cost=t, memory_cost_kib=m, parallelism=p)
    params.validate()
    # Reject bundles whose KDF params would force pathological resource use.
    # See _DECRYPT_MAX_* — defends against malicious .skit files.
    if params.memory_cost_kib > _DECRYPT_MAX_MEMORY_KIB:
        raise SkitFormatError(
            f"bundle KDF memory_cost_kib={params.memory_cost_kib} exceeds cap "
            f"{_DECRYPT_MAX_MEMORY_KIB}"
        )
    if params.time_cost > _DECRYPT_MAX_TIME_COST:
        raise SkitFormatError(
            f"bundle KDF time_cost={params.time_cost} exceeds cap {_DECRYPT_MAX_TIME_COST}"
        )
    if params.parallelism > _DECRYPT_MAX_PARALLELISM:
        raise SkitFormatError(
            f"bundle KDF parallelism={params.parallelism} exceeds cap "
            f"{_DECRYPT_MAX_PARALLELISM}"
        )
    return params, salt, base_nonce, chunk_size


def _read_exact(stream: BinaryIO, n: int) -> bytes:
    buf = stream.read(n)
    if len(buf) != n:
        raise SkitFormatError(f"unexpected EOF: wanted {n} bytes, got {len(buf)}")
    return buf


def _read_chunk(stream: BinaryIO) -> bytes | None:
    """Read [u32 len][ciphertext]. Returns None at clean EOF before length prefix."""
    len_buf = stream.read(4)
    if not len_buf:
        return None
    if len(len_buf) != 4:
        raise SkitFormatError("truncated chunk length prefix")
    (clen,) = struct.unpack(">I", len_buf)
    if clen < TAG_LEN:
        raise SkitFormatError(f"chunk too small to contain GCM tag: {clen}")
    if clen > _MAX_CHUNK_BYTES:
        raise SkitFormatError(f"chunk length {clen} exceeds cap {_MAX_CHUNK_BYTES}")
    return _read_exact(stream, clen)


def encrypt_stream(
    plaintext: BinaryIO,
    ciphertext: BinaryIO,
    passphrase: str | bytes,
    *,
    kdf: KdfParams = KdfParams(),
    chunk_size: int = DEFAULT_CHUNK_SIZE,
) -> bytes:
    """Read plaintext, write a SKIT1 bundle. Returns the plaintext SHA-256."""
    if chunk_size < 1 or chunk_size > _MAX_CHUNK_BYTES:
        raise ValueError("chunk_size out of range")
    kdf.validate()

    salt = os.urandom(SALT_LEN)
    base_nonce = os.urandom(NONCE_LEN)
    header = _pack_header(kdf, salt, base_nonce, chunk_size)
    ciphertext.write(header)

    key = derive_key(passphrase, salt, kdf)
    aead = AESGCM(key)
    sha = hashlib.sha256()
    counter = 0

    # Always emit at least one data chunk (possibly empty) before the trailer,
    # so the bundle shape is uniform: n data chunks (final_flag=0) + 1 trailer.
    while True:
        block = plaintext.read(chunk_size)
        if not block:
            break
        sha.update(block)
        ct = aead.encrypt(_nonce_for(base_nonce, counter), block, _aad(header, counter, False))
        ciphertext.write(struct.pack(">I", len(ct)))
        ciphertext.write(ct)
        counter += 1

    digest = sha.digest()
    trailer_ct = aead.encrypt(_nonce_for(base_nonce, counter), digest, _aad(header, counter, True))
    ciphertext.write(struct.pack(">I", len(trailer_ct)))
    ciphertext.write(trailer_ct)
    return digest


def decrypt_stream(
    ciphertext: BinaryIO,
    plaintext: BinaryIO,
    passphrase: str | bytes,
) -> bytes:
    """Read a SKIT1 bundle, write the verified plaintext archive. Returns SHA-256."""
    header = _read_exact(ciphertext, HEADER_LEN)
    kdf, salt, base_nonce, _chunk_size = _unpack_header(header)
    key = derive_key(passphrase, salt, kdf)
    aead = AESGCM(key)
    sha = hashlib.sha256()
    counter = 0

    current = _read_chunk(ciphertext)
    if current is None:
        raise SkitFormatError("empty bundle: no chunks present")

    while True:
        nxt = _read_chunk(ciphertext)
        is_final = nxt is None
        try:
            pt = aead.decrypt(
                _nonce_for(base_nonce, counter), current, _aad(header, counter, is_final)
            )
        except InvalidTag as exc:
            raise SkitAuthError("authentication failed: wrong passphrase or tampered bundle") from exc

        if is_final:
            if len(pt) != SHA256_LEN:
                raise SkitFormatError(f"malformed trailer: expected {SHA256_LEN} bytes")
            if pt != sha.digest():
                raise SkitAuthError("plaintext SHA-256 mismatch (defense-in-depth check failed)")
            extra = ciphertext.read(1)
            if extra:
                raise SkitFormatError("unexpected trailing data after final chunk")
            return pt

        plaintext.write(pt)
        sha.update(pt)
        counter += 1
        current = nxt
