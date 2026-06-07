"""Encrypt pane — panic-grade UX:
- Auto-fill output path from source folder (saves the slowest typing step)
- Auto-append .skit on submit if missing
- Enter from confirm field submits the form (no mouse needed)
- Success screen puts path + SHA fingerprint on prominent top lines
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

from securkit._kdf_autotune import autotune_kdf, describe as describe_kdf
from securkit.archive import archive_folder
from securkit.scrubber import ScrubReport
from securkit.tui._input_utils import clean_path
from securkit.tui.errors import friendly
from securkit.tui.widgets.passphrase_field import PassphraseField


class EncryptPane(Vertical):
    def compose(self) -> ComposeResult:
        yield Static("Encrypt a folder", classes="pane-title")
        yield Static(
            "[dim]Pick a folder. SecurKit bundles it up, scrubs metadata, "
            "and locks it with your passphrase. Tab between fields; press "
            "Enter from the confirm field to encrypt. "
            "[b]Drag a folder from File Explorer[/b] into the source field "
            "to paste its path.[/dim]"
        )
        yield Static("")
        yield Static("Source folder")
        yield Input(placeholder=r"C:\path\to\evidence", id="src")
        yield Static("Output bundle")
        yield Input(placeholder="auto-fills from source — or type your own", id="dest")
        yield Static("Passphrase")
        yield PassphraseField(require_confirm=True, id="pf")
        yield Button("Encrypt", variant="primary", id="go")
        yield ProgressBar(total=100, show_eta=False, id="prog")
        yield Static("", id="status")

    def on_mount(self) -> None:
        self.query_one("#prog", ProgressBar).display = False

    # --- form ergonomics -----------------------------------------------

    def on_input_changed(self, event: Input.Changed) -> None:
        # Drag-and-drop normalization: Windows Terminal wraps dragged paths
        # in quotes when they contain spaces. Strip them transparently so the
        # field always shows a clean, usable path. (Re-entrant safe: setting
        # the same value as current is a no-op in Textual's Input.)
        if event.input.id in ("src", "dest"):
            cleaned = clean_path(event.value)
            if cleaned != event.value:
                event.input.value = cleaned
                return  # the value setter re-fires this handler with the clean value

        # Auto-fill the output path the moment the source field changes,
        # but only while the dest field is empty — once the user types
        # anything into dest, we leave it alone.
        if event.input.id != "src":
            return
        dest_input = self.query_one("#dest", Input)
        if dest_input.value.strip():
            return
        src = event.value.strip().rstrip("\\/")
        if not src:
            return
        try:
            src_path = Path(src)
            default_name = (src_path.name or "bundle") + ".skit"
            dest_input.value = str(src_path.parent / default_name)
        except (OSError, ValueError):
            pass  # malformed path — let the user finish typing

    def on_input_submitted(self, event: Input.Submitted) -> None:
        # Enter from the confirm field submits — no Tab-to-button needed
        if event.input.id == "pf-confirm":
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
            dest_input = self.query_one("#dest", Input)
            dest = dest_input.value.strip()
            pf = self.query_one(PassphraseField)

            if not src or not dest:
                status.update("[yellow]Please fill in both the source folder and output bundle.[/yellow]")
                return
            if not pf.passphrase:
                status.update("[yellow]Please enter a passphrase.[/yellow]")
                return
            if not pf.confirms:
                status.update("[yellow]The two passphrase fields don't match.[/yellow]")
                return

            # Auto-append .skit if the user left it off — show the change in
            # the field so they see what file we'll create.
            appended = False
            if not dest.lower().endswith(".skit"):
                dest = dest + ".skit"
                dest_input.value = dest
                appended = True

            src_path = Path(src)
            if not src_path.exists():
                raise FileNotFoundError(src)
            if not src_path.is_dir():
                raise NotADirectoryError(src)

            report = pf.report()
            warn = ""
            if report.score < 2:
                warn = f"  [yellow]⚠ passphrase rated [b]{report.label}[/b][/yellow]"
            note = "  [dim](added .skit extension)[/dim]" if appended else ""

            self._set_busy(True)
            status.update(f"[dim]Deriving key (Argon2id)…[/dim]{warn}{note}")
            self._do_encrypt(src, dest, pf.passphrase)
        except Exception as exc:
            self._set_busy(False)
            err = friendly(exc)
            status.update(f"[red][b]{err.title}[/b][/red]\n{err.body}")

    # --- worker ---------------------------------------------------------

    @work(thread=True, exclusive=True, group="archive")
    def _do_encrypt(self, src: str, dest: str, passphrase: str) -> None:
        app = self.app
        def progress(done: int, total: int) -> None:
            app.call_from_thread(self._on_progress, done, total)

        tune = autotune_kdf()
        try:
            out, sha, report = archive_folder(
                src, dest, passphrase, on_progress=progress, kdf=tune.params
            )
        except BaseException as exc:  # noqa: BLE001
            app.call_from_thread(self._on_error, exc)
            return
        app.call_from_thread(self._on_success, out, sha, report, tune)

    # --- main-thread UI updates ----------------------------------------

    def _on_progress(self, done: int, total: int) -> None:
        bar = self.query_one("#prog", ProgressBar)
        bar.display = True
        bar.update(total=max(total, 1), progress=done)
        if done < total:
            pct = (done / total * 100) if total else 0
            self.query_one("#status", Static).update(
                f"[dim]Encrypting… {done:,} / {total:,} bytes ({pct:.0f}%)[/dim]"
            )

    def _on_success(self, out_path: Path, sha: bytes, report: ScrubReport, tune) -> None:
        self._set_busy(False)
        fp = sha.hex()
        # Group into 4-char chunks for legibility
        grouped = " ".join(fp[i : i + 4] for i in range(0, len(fp), 4))

        parts: list = [
            Text.from_markup("[bold green]✓ ENCRYPTED[/bold green]"),
            Text(""),
            Text.from_markup(f"[bold]Bundle:[/bold]      {out_path}"),
            # Fingerprint line in gold — the thing a rushed user needs to grab
            Text.from_markup(
                f"[bold gold1]Fingerprint:[/bold gold1] [bold gold1]{grouped}[/bold gold1]"
            ),
        ]

        if report.total:
            color = "yellow" if (report.failed or report.caveats) else "green"
            parts.append(Text(""))
            parts.append(
                Text.from_markup(
                    f"[bold {color}]Metadata:[/bold {color}] "
                    f"{report.scrubbed} scrubbed, {report.clean} already clean, "
                    f"{report.passthrough} passed through, {report.failed} failed"
                )
            )
            if report.caveats or report.failed:
                for line in report.summary_lines()[1:]:
                    parts.append(Text(line, style="dim"))

        # Framed next-step panel — the action prompt for what to do next
        next_steps = Text.from_markup(
            "[bold]1.[/bold] Send the fingerprint to the recipient over a separate "
            "channel (Signal, in person) so they can verify nothing was swapped "
            "in transit.\n"
            "[bold]2.[/bold] Open the [bold]Hotlines[/bold] pane on the left to "
            "find where to send the bundle."
        )
        parts.append(Text(""))
        parts.append(
            Panel(
                next_steps,
                title="▶ next steps",
                title_align="left",
                border_style="yellow",
                padding=(0, 1),
            )
        )

        ram_note = (
            f" · auto-tuned for {tune.available_mib} MiB RAM"
            if tune.available_mib is not None
            else ""
        )
        parts.append(Text(""))
        parts.append(
            Text(
                f"Key derivation: {describe_kdf(tune.params)}{ram_note}",
                style="dim",
            )
        )

        self.query_one("#status", Static).update(Group(*parts))

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
