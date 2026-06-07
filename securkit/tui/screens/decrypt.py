"""Decrypt pane — panic-grade UX:
- No strength meter (the passphrase was chosen by the sender, not the user;
  coaching here is misleading)
- Enter from passphrase field submits
- Success message puts extracted path + SHA on prominent lines
- FileExistsError surfaced via the friendly translator
"""

from __future__ import annotations

from pathlib import Path

from rich.console import Group
from rich.panel import Panel
from rich.text import Text
from textual import work
from textual.app import ComposeResult
from textual.containers import Vertical
from textual.widgets import Button, Input, ProgressBar, Static

from securkit.archive import extract_skit
from securkit.tui._input_utils import clean_path
from securkit.tui.errors import friendly
from securkit.tui.widgets.passphrase_field import PassphraseField


class DecryptPane(Vertical):
    def compose(self) -> ComposeResult:
        yield Static("Decrypt a .skit bundle", classes="pane-title")
        yield Static(
            "[dim]Verifies the bundle's integrity before extracting. If the "
            "passphrase is wrong or the file was tampered with, nothing gets "
            "written to disk. Press Enter from the passphrase field to decrypt. "
            "[b]Drag the .skit file or destination folder[/b] from File "
            "Explorer to paste its path.[/dim]"
        )
        yield Static("")
        yield Static("Bundle file")
        yield Input(placeholder="evidence.skit", id="src")
        yield Static("Extract into")
        yield Input(placeholder=r"C:\path\to\out", id="dest")
        yield Static("Passphrase")
        # No confirm field on decrypt — the bundle's tag is the source of truth.
        # No strength meter — the passphrase was chosen by the sender.
        # No Suggest button — you're typing what was given to you, not picking.
        yield PassphraseField(
            require_confirm=False,
            show_strength=False,
            show_suggest=False,
            id="pf",
        )
        yield Button("Decrypt", variant="primary", id="go")
        yield ProgressBar(total=100, show_eta=False, id="prog")
        yield Static("", id="status")

    def on_mount(self) -> None:
        self.query_one("#prog", ProgressBar).display = False

    # --- form ergonomics -----------------------------------------------

    def on_input_changed(self, event: Input.Changed) -> None:
        # Drag-and-drop normalization (strip quotes a terminal added when
        # the user dragged a path containing spaces).
        if event.input.id in ("src", "dest"):
            cleaned = clean_path(event.value)
            if cleaned != event.value:
                event.input.value = cleaned

    def on_input_submitted(self, event: Input.Submitted) -> None:
        if event.input.id == "pf-pass":
            self._submit()

    # --- button + submit -----------------------------------------------

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "go":
            event.stop()
            self._submit()

    def _submit(self) -> None:
        status = self.query_one("#status", Static)
        try:
            src = self.query_one("#src", Input).value.strip()
            dest = self.query_one("#dest", Input).value.strip()
            pf = self.query_one(PassphraseField)

            if not src or not dest:
                status.update("[yellow]Please fill in both the bundle and the extract path.[/yellow]")
                return
            if not pf.passphrase:
                status.update("[yellow]Please enter the passphrase that was used to encrypt this bundle.[/yellow]")
                return

            src_path = Path(src)
            if not src_path.exists():
                raise FileNotFoundError(src)
            if not src_path.is_file():
                raise IsADirectoryError(src)

            self._set_busy(True)
            status.update("[dim]Verifying & decrypting…[/dim]")
            self._do_decrypt(src, dest, pf.passphrase)
        except Exception as exc:
            self._set_busy(False)
            err = friendly(exc)
            status.update(f"[red][b]{err.title}[/b][/red]\n{err.body}")

    # --- worker ---------------------------------------------------------

    @work(thread=True, exclusive=True, group="archive")
    def _do_decrypt(self, src: str, dest: str, passphrase: str) -> None:
        app = self.app
        def progress(done: int, total: int) -> None:
            app.call_from_thread(self._on_progress, done, total)

        try:
            root, sha = extract_skit(src, dest, passphrase, on_progress=progress)
        except BaseException as exc:  # noqa: BLE001
            app.call_from_thread(self._on_error, exc)
            return
        app.call_from_thread(self._on_success, root, sha)

    # --- main-thread UI updates ----------------------------------------

    def _on_progress(self, done: int, total: int) -> None:
        bar = self.query_one("#prog", ProgressBar)
        bar.display = True
        bar.update(total=max(total, 1), progress=done)
        if done < total:
            pct = (done / total * 100) if total else 0
            self.query_one("#status", Static).update(
                f"[dim]Reading bundle… {done:,} / {total:,} bytes ({pct:.0f}%)[/dim]"
            )

    def _on_success(self, root: Path, sha: bytes) -> None:
        self._set_busy(False)
        fp = sha.hex()
        grouped = " ".join(fp[i : i + 4] for i in range(0, len(fp), 4))

        verify_panel = Panel(
            Text.from_markup(
                "Compare the [bold gold1]fingerprint[/bold gold1] above with what "
                "the sender told you. If they [bold]don't match[/bold], the bundle "
                "was altered after the sender created it — [bold red]do not trust "
                "the extracted files[/bold red]."
            ),
            title="▶ verify before trusting",
            title_align="left",
            border_style="yellow",
            padding=(0, 1),
        )

        self.query_one("#status", Static).update(
            Group(
                Text.from_markup("[bold green]✓ EXTRACTED[/bold green]"),
                Text(""),
                Text.from_markup(f"[bold]Files at:[/bold]    {root}"),
                Text.from_markup(
                    f"[bold gold1]Fingerprint:[/bold gold1] "
                    f"[bold gold1]{grouped}[/bold gold1]"
                ),
                Text(""),
                verify_panel,
            )
        )

    def _on_error(self, exc: BaseException) -> None:
        self._set_busy(False)
        self.query_one("#prog", ProgressBar).display = False
        err = friendly(exc)
        self.query_one("#status", Static).update(
            f"[red][b]{err.title}[/b][/red]\n{err.body}"
        )

    def _set_busy(self, busy: bool) -> None:
        self.query_one("#go", Button).disabled = busy
        bar = self.query_one("#prog", ProgressBar)
        if busy:
            bar.update(total=None, progress=0)
            bar.display = True
        else:
            bar.display = False
        try:
            self.app.query_one("#nav-list").disabled = busy
        except Exception:
            pass
