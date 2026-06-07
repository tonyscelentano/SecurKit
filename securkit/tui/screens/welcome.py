"""First-run welcome screen with the lost-passphrase warning."""

from __future__ import annotations

from textual.app import ComposeResult
from textual.containers import Center, Vertical, VerticalScroll
from textual.screen import Screen
from textual.widgets import Button, Static

from securkit.state import mark_welcomed

WELCOME_BODY = """\
[b]Welcome to SecurKit.[/b]

This tool helps you bundle up a folder of evidence into a single, locked file
that only you (and people you give the passphrase to) can open. It also points
you at legitimate places to send what you've gathered — government regulator
hotlines, inspectors general, and a few trusted journalism intake portals.

[b]How it works in plain terms:[/b]

  1. You pick a folder.
  2. SecurKit removes identifying metadata from your files (EXIF, document
     properties, timestamps), tars them up, and encrypts the result with
     industry-standard AES-256-GCM. Your passphrase is the only key.
  3. You get a single [b].skit[/b] file. Hand it to a lawyer, upload it to a
     regulator's secure portal, or hold onto it.

[b on red]IMPORTANT — read this twice:[/b on red]

If you forget your passphrase, [b]no one[/b] — not Anthropic, not the SecurKit
author, not the FBI — can recover your files. There is no "forgot password"
link. The encryption is the real thing. Pick a passphrase you will not lose,
and consider writing it down somewhere a flood, fire, or laptop theft won't
take with it.

[b]A few more things to know:[/b]

  • SecurKit protects your file [b]at rest[/b]. If the computer you're using is
    compromised (keylogger, screen capture, hostile admin), no encryption tool
    can help you. For high-stakes work, use a clean machine — ideally Tails.

  • Before you blow any whistle, [b]talk to a lawyer[/b]. The Hotlines screen
    has links to free intake consultations (Government Accountability Project,
    National Whistleblower Center). Use them.

  • Anonymous submission protects you from being identified; it does [b]not[/b]
    protect you from retaliation if your employer figures out who had access
    to the documents you sent. Think about that before you send.
"""


class WelcomeScreen(Screen):
    CSS = """
    WelcomeScreen { align: center middle; }
    #welcome-card {
        width: 90%;
        max-width: 90;
        height: auto;
        max-height: 90%;
        border: round $primary;
        padding: 1 2;
    }
    #welcome-body { padding: 1 0; height: auto; }
    #welcome-actions { height: 3; padding-top: 1; }
    """

    BINDINGS = [("escape", "dismiss_screen", "Continue")]

    def compose(self) -> ComposeResult:
        with Vertical(id="welcome-card"):
            yield Static("[b]SecurKit[/b]   [dim]first-run briefing[/dim]")
            with VerticalScroll(id="welcome-body"):
                yield Static(WELCOME_BODY)
            with Center(id="welcome-actions"):
                yield Button("I understand — continue", variant="primary", id="ok")

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "ok":
            self.action_dismiss_screen()

    def action_dismiss_screen(self) -> None:
        try:
            mark_welcomed()
        except OSError:
            pass  # non-fatal; we'll just show it again next time
        self.dismiss()
