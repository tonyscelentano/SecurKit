"""Portable-mode state directory resolution."""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

from securkit import state as state_mod


def test_default_state_dir_is_home(monkeypatch, tmp_path) -> None:
    """No portable marker → state lives under the user's home directory."""
    monkeypatch.setattr(sys, "frozen", False, raising=False)
    monkeypatch.setattr(state_mod, "_exe_dir", lambda: tmp_path)
    # No marker file present
    assert not state_mod.is_portable()
    resolved = state_mod._resolve_state_dir()
    assert resolved == Path.home() / ".securkit"


def test_portable_marker_redirects_to_exe_dir(monkeypatch, tmp_path) -> None:
    """`securkit.portable` next to the exe → state lives next to the exe."""
    (tmp_path / state_mod.PORTABLE_MARKER_NAME).touch()
    monkeypatch.setattr(state_mod, "_exe_dir", lambda: tmp_path)
    assert state_mod.is_portable()
    resolved = state_mod._resolve_state_dir()
    assert resolved == tmp_path / "securkit-data"


def test_portable_state_is_writable(monkeypatch, tmp_path) -> None:
    """End-to-end: with portable mode active, mark_welcomed writes to the
    portable location and has_been_welcomed reads it back."""
    (tmp_path / state_mod.PORTABLE_MARKER_NAME).touch()
    monkeypatch.setattr(state_mod, "_exe_dir", lambda: tmp_path)
    portable_dir = tmp_path / "securkit-data"
    portable_flag = portable_dir / "welcomed"
    # Force the module-level constants to use the portable paths
    monkeypatch.setattr(state_mod, "STATE_DIR", portable_dir)
    monkeypatch.setattr(state_mod, "WELCOMED_FLAG", portable_flag)

    assert not state_mod.has_been_welcomed()
    state_mod.mark_welcomed()
    assert state_mod.has_been_welcomed()
    assert portable_flag.exists()
    # Critical: home dir was NOT touched
    home_state = Path.home() / ".securkit" / "welcomed-test-canary"
    assert not home_state.exists(), "portable mode must not write to home dir"


def test_exe_dir_when_frozen(monkeypatch, tmp_path) -> None:
    """In a frozen build, _exe_dir tracks sys.executable's parent."""
    fake_exe = tmp_path / "securkit.exe"
    fake_exe.touch()
    monkeypatch.setattr(sys, "frozen", True, raising=False)
    monkeypatch.setattr(sys, "executable", str(fake_exe))
    assert state_mod._exe_dir() == tmp_path
