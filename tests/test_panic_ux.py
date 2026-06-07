"""Tests for the panic-grade UX patches: friendly errors, autofill, .skit
append, strength-meter toggle, Ctrl+C non-quit."""

from __future__ import annotations

from pathlib import Path

from securkit.crypto import SkitAuthError, SkitFormatError
from securkit.tui.errors import FriendlyError, friendly
from securkit.tui.widgets.passphrase_field import PassphraseField


# --- FileExistsError → friendly translator ------------------------------


def test_file_exists_error_is_friendly() -> None:
    exc = FileExistsError("refusing to overwrite existing path: C:\\Users\\x\\Paq\\SecRep")
    err = friendly(exc)
    assert isinstance(err, FriendlyError)
    assert "already exists" in err.title.lower()
    # The conflicting path must be surfaced so the user can see what to delete
    assert "SecRep" in err.body
    # Plain-language guidance on what to do next
    assert "different" in err.body.lower() or "delete" in err.body.lower()


def test_file_exists_error_with_filename_attr() -> None:
    """When FileExistsError carries a .filename attribute (OS-raised form),
    we surface that path too."""
    exc = FileExistsError(17, "exists", "C:\\Users\\x\\Paq\\SecRep")
    err = friendly(exc)
    assert "SecRep" in err.body


def test_no_developer_jargon_in_file_exists_message() -> None:
    """A panicked user must NOT see 'FileExistsError' in the surfaced message."""
    exc = FileExistsError("refusing to overwrite existing path: /some/path")
    err = friendly(exc)
    assert "FileExistsError" not in err.title
    assert "FileExistsError" not in err.body
    assert "refusing to overwrite" not in err.body.lower()  # we rephrase


def test_other_errors_still_translate() -> None:
    """Regression: existing translations still work after FileExistsError added."""
    for exc in (
        SkitAuthError("auth failed"),
        SkitFormatError("not a SKIT1 bundle (bad magic)"),
        FileNotFoundError(2, "no such file", "missing.skit"),
    ):
        err = friendly(exc)
        assert isinstance(err, FriendlyError)
        assert err.title and err.body


# --- PassphraseField show_strength / show_suggest -----------------------


def test_passphrase_field_default_shows_all() -> None:
    f = PassphraseField()
    assert f._require_confirm is True
    assert f._show_strength is True
    assert f._show_suggest is True


def test_passphrase_field_decrypt_config() -> None:
    """Decrypt pane's config: no confirm, no strength, no suggest."""
    f = PassphraseField(require_confirm=False, show_strength=False, show_suggest=False)
    assert f._require_confirm is False
    assert f._show_strength is False
    assert f._show_suggest is False


# --- Ctrl+C is no longer wired to quit ----------------------------------


def test_ctrl_c_is_not_quit() -> None:
    """A panicked user hitting Ctrl+C to copy text must NOT exit the app."""
    from securkit.tui.app import SecurKitApp

    bindings_by_key = {b.key: b.action for b in SecurKitApp.BINDINGS}
    assert "ctrl+c" in bindings_by_key, "ctrl+c binding missing (would default to quit)"
    assert bindings_by_key["ctrl+c"] != "quit", "ctrl+c still maps to quit — panic footgun!"
    # The action must be noop (or some other non-destructive action)
    assert bindings_by_key["ctrl+c"] == "noop"
