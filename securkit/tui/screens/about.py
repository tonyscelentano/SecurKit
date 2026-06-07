"""About pane — version, KDF preview, threat-model reminders."""

from __future__ import annotations

from textual.app import ComposeResult
from textual.containers import Vertical
from textual.widgets import Static

from securkit import __version__
from securkit._kdf_autotune import autotune_kdf, describe as describe_kdf
from securkit.state import STATE_DIR, is_portable


class AboutPane(Vertical):
    def compose(self) -> ComposeResult:
        tune = autotune_kdf()
        ram_line = (
            f"{tune.available_mib} MiB available"
            if tune.available_mib is not None
            else "RAM probe unavailable"
        )
        portable_line = (
            f"[green]portable mode active[/green] — state at {STATE_DIR}"
            if is_portable()
            else f"[dim]home-dir mode — state at {STATE_DIR}[/dim]"
        )

        yield Static("About SecurKit", classes="pane-title")
        yield Static(
            "\n".join(
                [
                    f"[b]SecurKit v{__version__}[/b]",
                    "",
                    "Encrypts a folder of evidence with AES-256-GCM + Argon2id,",
                    "scrubs identifying metadata, points you at legitimate intake channels.",
                    "",
                    "[b]On this machine right now:[/b]",
                    f"  RAM:           {ram_line}",
                    f"  KDF settings:  {describe_kdf(tune.params)}",
                    f"  Storage:       {portable_line}",
                    "",
                    "[b]Remember:[/b]",
                    "  • This tool is not a substitute for legal counsel.",
                    "    Talk to a whistleblower attorney before disclosing.",
                    "  • If you forget your passphrase, no one can recover your files.",
                    "  • SecurKit protects files at rest. A compromised endpoint",
                    "    (keylogger, screen capture) defeats every encryption tool.",
                    "    For high-stakes work use Tails or a clean live OS.",
                    "",
                    "[dim]Press ? at any time to re-read the first-run briefing.[/dim]",
                ]
            )
        )
