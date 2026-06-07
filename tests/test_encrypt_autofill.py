"""TUI-level test: source folder autofill + .skit auto-append on encrypt."""

from __future__ import annotations

import asyncio
import tempfile
from pathlib import Path

import pytest
from textual.widgets import Button, Input

from securkit.tui.app import SecurKitApp
from securkit.tui.screens.welcome import WelcomeScreen


@pytest.mark.asyncio
async def test_dest_autofills_when_src_changes() -> None:
    """Typing into the source field populates the output bundle field."""
    app = SecurKitApp()
    async with app.run_test(size=(120, 40)) as pilot:
        await pilot.pause()
        if isinstance(app.screen, WelcomeScreen):
            app.screen.query_one("#ok", Button).press()
            await pilot.pause()

        src_input = app.query_one("#src", Input)
        dest_input = app.query_one("#dest", Input)
        assert dest_input.value == "", "dest should start empty"

        src_input.value = r"C:\Users\Tony\evidence"
        await pilot.pause()

        # Autofill should produce a sibling .skit file
        assert dest_input.value.endswith("evidence.skit"), (
            f"expected autofill to end with evidence.skit, got: {dest_input.value!r}"
        )


@pytest.mark.asyncio
async def test_autofill_respects_user_edit() -> None:
    """Once the user has typed into dest, we stop autofilling on src change."""
    app = SecurKitApp()
    async with app.run_test(size=(120, 40)) as pilot:
        await pilot.pause()
        if isinstance(app.screen, WelcomeScreen):
            app.screen.query_one("#ok", Button).press()
            await pilot.pause()

        src_input = app.query_one("#src", Input)
        dest_input = app.query_one("#dest", Input)

        dest_input.value = "my-custom-output.skit"
        await pilot.pause()
        # Now change src — dest should NOT be overwritten
        src_input.value = r"C:\some\other\folder"
        await pilot.pause()
        assert dest_input.value == "my-custom-output.skit", (
            f"user-typed dest was clobbered by autofill: {dest_input.value!r}"
        )


@pytest.mark.asyncio
async def test_skit_extension_appended_on_submit() -> None:
    """If user submits with a dest that doesn't end in .skit, the field is
    updated visibly with the appended extension."""
    with tempfile.TemporaryDirectory() as td:
        td_path = Path(td)
        src = td_path / "ev"
        src.mkdir()
        (src / "x.txt").write_text("hi")

        app = SecurKitApp()
        async with app.run_test(size=(120, 40)) as pilot:
            await pilot.pause()
            if isinstance(app.screen, WelcomeScreen):
                app.screen.query_one("#ok", Button).press()
                await pilot.pause()

            app.query_one("#src", Input).value = str(src)
            # Set dest to something WITHOUT .skit, marked as user-edited
            app.query_one("#dest", Input).value = str(td_path / "Output")
            app.query_one("#pf-pass", Input).value = "test-passphrase-1234"
            app.query_one("#pf-confirm", Input).value = "test-passphrase-1234"
            await pilot.pause()

            # Submit (button press, not Enter — testing the submit path)
            app.query_one("#go", Button).press()
            await pilot.pause()

            # Field should now show the .skit-extended path BEFORE the worker
            # has even finished
            new_dest = app.query_one("#dest", Input).value
            assert new_dest.endswith(".skit"), (
                f"submit did not append .skit; dest is now: {new_dest!r}"
            )

            # Let the worker finish so we don't leave threads dangling
            await app.workers.wait_for_complete()
            await pilot.pause()


@pytest.mark.asyncio
async def test_enter_from_confirm_submits_encrypt() -> None:
    """Pressing Enter in the confirm-passphrase field should kick off encrypt,
    same as clicking the button."""
    with tempfile.TemporaryDirectory() as td:
        td_path = Path(td)
        src = td_path / "ev"
        src.mkdir()
        (src / "x.txt").write_text("hi")

        app = SecurKitApp()
        async with app.run_test(size=(120, 40)) as pilot:
            await pilot.pause()
            if isinstance(app.screen, WelcomeScreen):
                app.screen.query_one("#ok", Button).press()
                await pilot.pause()

            bundle = td_path / "out.skit"
            app.query_one("#src", Input).value = str(src)
            app.query_one("#dest", Input).value = str(bundle)
            app.query_one("#pf-pass", Input).value = "test-pass-1234"
            app.query_one("#pf-confirm", Input).value = "test-pass-1234"
            await pilot.pause()

            # Focus the confirm input and press Enter via the Input.action_submit
            confirm = app.query_one("#pf-confirm", Input)
            confirm.focus()
            await pilot.pause()
            await pilot.press("enter")
            await pilot.pause()
            await app.workers.wait_for_complete()
            await pilot.pause()

            assert bundle.exists(), "enter-to-submit did not encrypt"
