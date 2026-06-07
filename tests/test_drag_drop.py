"""Tests for drag-and-drop path normalization.

True drag-and-drop is a terminal-emulator feature (the terminal pastes the
dragged path's text into the focused input), so what we test here is what
the application sees AFTER the paste: a path string that may have
surrounding quotes. The clean_path helper and the input handlers must
remove those quotes transparently.
"""

from __future__ import annotations

import tempfile
from pathlib import Path

import pytest
from textual.widgets import Button, Input

from securkit.tui._input_utils import clean_path
from securkit.tui.app import SecurKitApp
from securkit.tui.screens.welcome import WelcomeScreen


# --- clean_path unit tests ----------------------------------------------


@pytest.mark.parametrize(
    "raw,expected",
    [
        # Windows Terminal drag of a path with spaces (most common case)
        ('"C:\\Users\\Tony\\My Documents\\evidence"', "C:\\Users\\Tony\\My Documents\\evidence"),
        # Single quotes (some terminals)
        ("'/home/user/My Folder'", "/home/user/My Folder"),
        # Unquoted: leave alone
        ("C:\\plain\\path", "C:\\plain\\path"),
        # Whitespace stripping
        ("  C:\\path  ", "C:\\path"),
        # Whitespace INSIDE quotes — strip after unwrap
        ('"  C:\\path  "', "C:\\path"),
        # Trailing space after the closing quote (sometimes happens)
        ('"C:\\path" ', "C:\\path"),
        # Mismatched quotes — leave alone (likely a typo, don't silently mangle)
        ('"C:\\path', '"C:\\path'),
        ('C:\\path"', 'C:\\path"'),
        # Mixed quotes — also leave alone
        ('"C:\\path\'', '"C:\\path\''),
        # Empty / whitespace-only
        ("", ""),
        ("   ", ""),
        ('""', ""),
        # A pure quote with no path content
        ('"   "', ""),
    ],
)
def test_clean_path(raw: str, expected: str) -> None:
    assert clean_path(raw) == expected


def test_clean_path_handles_already_clean() -> None:
    """Idempotent: cleaning an already-clean path is a no-op."""
    for s in ("C:\\foo", "/home/x", "relative/path", ""):
        assert clean_path(s) == s.strip()


# --- TUI-level integration ----------------------------------------------


@pytest.mark.asyncio
async def test_encrypt_src_field_strips_dragged_quotes() -> None:
    """Simulate a Windows-Terminal drag-and-drop into the source field:
    the field's value should self-clean to a usable path."""
    app = SecurKitApp()
    async with app.run_test(size=(120, 40)) as pilot:
        await pilot.pause()
        if isinstance(app.screen, WelcomeScreen):
            app.screen.query_one("#ok", Button).press()
            await pilot.pause()

        src = app.query_one("#src", Input)
        # What the terminal would paste for a dragged "My Documents\evidence":
        src.value = '"C:\\Users\\Tony\\My Documents\\evidence"'
        await pilot.pause()
        assert src.value == "C:\\Users\\Tony\\My Documents\\evidence", (
            f"expected dequoted path, got: {src.value!r}"
        )


@pytest.mark.asyncio
async def test_decrypt_src_field_strips_dragged_quotes() -> None:
    """Same on the Decrypt pane — dragging a .skit file with spaces in its path."""
    app = SecurKitApp()
    async with app.run_test(size=(120, 40)) as pilot:
        await pilot.pause()
        if isinstance(app.screen, WelcomeScreen):
            app.screen.query_one("#ok", Button).press()
            await pilot.pause()

        await pilot.click("#nav-decrypt")
        await pilot.pause()

        src = app.query_one("#src", Input)
        src.value = '"D:\\Encrypted Files\\bundle.skit"'
        await pilot.pause()
        assert src.value == "D:\\Encrypted Files\\bundle.skit"


@pytest.mark.asyncio
async def test_dragged_path_then_encrypt_works(tmp_path) -> None:
    """End-to-end: simulate dragging a real folder (the path arrives
    quoted), then encrypt actually succeeds — proves the quote-stripping
    persists through the submit path."""
    src_dir = tmp_path / "drag drop test"  # space in name forces quoting
    src_dir.mkdir()
    (src_dir / "note.txt").write_text("hi")

    app = SecurKitApp()
    async with app.run_test(size=(120, 40)) as pilot:
        await pilot.pause()
        if isinstance(app.screen, WelcomeScreen):
            app.screen.query_one("#ok", Button).press()
            await pilot.pause()

        # Simulate the terminal pasting a quoted path
        quoted = f'"{src_dir}"'
        src_input = app.query_one("#src", Input)
        src_input.value = quoted
        await pilot.pause()
        assert src_input.value == str(src_dir), "drag paste didn't dequote"

        bundle = tmp_path / "out.skit"
        app.query_one("#dest", Input).value = str(bundle)
        app.query_one("#pf-pass", Input).value = "drag-drop-test-pass-1234"
        app.query_one("#pf-confirm", Input).value = "drag-drop-test-pass-1234"
        await pilot.pause()

        app.query_one("#go", Button).press()
        await pilot.pause()
        await app.workers.wait_for_complete()
        await pilot.pause()

        assert bundle.exists(), "encrypt failed after drag-paste of quoted path"
