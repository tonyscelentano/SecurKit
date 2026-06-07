"""Friendly error translation."""

from __future__ import annotations

from securkit.crypto import SkitAuthError, SkitFormatError
from securkit.tui.errors import FriendlyError, friendly


def test_auth_error_says_passphrase() -> None:
    err = friendly(SkitAuthError("authentication failed: wrong passphrase or tampered bundle"))
    assert isinstance(err, FriendlyError)
    assert "passphrase" in err.body.lower()
    assert "authentication" not in err.title.lower()


def test_bad_magic_message_is_friendly() -> None:
    err = friendly(SkitFormatError("not a SKIT1 bundle (bad magic)"))
    assert "SecurKit" in err.title or "SecurKit" in err.body


def test_malicious_kdf_message_is_friendly() -> None:
    err = friendly(SkitFormatError("bundle KDF memory_cost_kib=4194304 exceeds cap 1048576"))
    assert "memory_cost_kib" not in err.body
    assert "safety" in err.body.lower() or "unsafe" in err.title.lower()


def test_truncation_message_is_friendly() -> None:
    err = friendly(SkitFormatError("empty bundle: no chunks present"))
    assert "incomplete" in err.title.lower() or "incomplete" in err.body.lower()


def test_file_not_found_translated() -> None:
    err = friendly(FileNotFoundError(2, "No such file", "missing.skit"))
    assert "missing.skit" in err.body


def test_unknown_exception_falls_back() -> None:
    err = friendly(RuntimeError("oh no"))
    assert "RuntimeError" in err.body
