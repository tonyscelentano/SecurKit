"""Capture SVG screenshots of every SecurKit TUI screen for documentation.

Run:  python scripts/capture_screens.py
Writes to: screenshots/*.svg (openable in any browser)
"""

from __future__ import annotations

import asyncio
import os
from pathlib import Path

from textual.widgets import Button, Input

from securkit.state import WELCOMED_FLAG
from securkit.tui.app import SecurKitApp
from securkit.tui.screens.welcome import WelcomeScreen
from securkit.tui.widgets.passphrase_field import PassphraseField

OUT_DIR = Path(__file__).resolve().parent.parent / "screenshots"


async def capture() -> None:
    OUT_DIR.mkdir(exist_ok=True)
    # Force the welcome screen to appear by removing the flag (we'll restore behavior)
    flag_existed = WELCOMED_FLAG.exists()
    if flag_existed:
        WELCOMED_FLAG.unlink()

    app = SecurKitApp()
    async with app.run_test(size=(110, 36)) as pilot:
        await pilot.pause()

        # 1. Welcome screen
        assert isinstance(app.screen, WelcomeScreen), "expected welcome screen on first run"
        app.save_screenshot(str(OUT_DIR / "01-welcome.svg"))
        print(f"saved 01-welcome.svg")

        # Dismiss welcome (button lives on the welcome Screen, not the default)
        app.screen.query_one("#ok", Button).press()
        await pilot.pause()

        # 2. Encrypt pane (empty)
        app.save_screenshot(str(OUT_DIR / "02-encrypt-empty.svg"))
        print(f"saved 02-encrypt-empty.svg")

        # 3. Encrypt pane after Suggest pressed (shows strength meter + suggested passphrase)
        app.query_one("#src", Input).value = r"C:\evidence\quarterly-emails"
        app.query_one("#dest", Input).value = r"C:\out\emails.skit"
        app.query_one("#pf-suggest", Button).press()
        await pilot.pause()
        app.save_screenshot(str(OUT_DIR / "03-encrypt-with-suggestion.svg"))
        print(f"saved 03-encrypt-with-suggestion.svg")

        # 4. Encrypt pane with a weak passphrase typed in (shows red strength meter)
        pw = app.query_one("#pf-pass", Input)
        cnf = app.query_one("#pf-confirm", Input)
        pw.value = "password123"
        cnf.value = "wrongmatch"
        await pilot.pause()
        app.save_screenshot(str(OUT_DIR / "04-encrypt-weak-and-mismatch.svg"))
        print(f"saved 04-encrypt-weak-and-mismatch.svg")

        # 5. Decrypt pane
        await pilot.click("#nav-decrypt")
        await pilot.pause()
        app.query_one("#src", Input).value = r"C:\out\emails.skit"
        app.query_one("#dest", Input).value = r"C:\restored"
        app.query_one("#pf-pass", Input).value = "river-pine-amber-knife-clay-storm-thumb"
        await pilot.pause()
        app.save_screenshot(str(OUT_DIR / "05-decrypt.svg"))
        print(f"saved 05-decrypt.svg")

        # 6. Hotlines pane (master list)
        await pilot.click("#nav-hotlines")
        await pilot.pause()
        app.save_screenshot(str(OUT_DIR / "06-hotlines-list.svg"))
        print(f"saved 06-hotlines-list.svg")

        # 7. Hotlines pane with SEC entry selected
        await pilot.click("#hl-sec-whistleblower")
        await pilot.pause()
        app.save_screenshot(str(OUT_DIR / "07-hotlines-sec-selected.svg"))
        print(f"saved 07-hotlines-sec-selected.svg")

        # 8. About pane
        await pilot.click("#nav-about")
        await pilot.pause()
        app.save_screenshot(str(OUT_DIR / "08-about.svg"))
        print(f"saved 08-about.svg")

    # Restore the welcomed flag if the user had already dismissed it
    if flag_existed:
        WELCOMED_FLAG.parent.mkdir(parents=True, exist_ok=True)
        WELCOMED_FLAG.touch()


if __name__ == "__main__":
    asyncio.run(capture())
    print(f"\nAll screenshots written to: {OUT_DIR}")
