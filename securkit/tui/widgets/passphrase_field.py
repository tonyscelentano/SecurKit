"""Compound widget: passphrase entry + confirm + strength meter + suggest button.

Coaches the user but never blocks them — selecting Encrypt with a weak
passphrase will warn and proceed (the user explicitly chose this stance).
"""

from __future__ import annotations

from textual.app import ComposeResult
from textual.containers import Horizontal, Vertical
from textual.widgets import Button, Input, Static

from securkit.passphrase import StrengthReport, estimate_strength, suggest, suggestion_bits

_SCORE_COLORS = {
    0: "red",
    1: "red",
    2: "yellow",
    3: "green",
    4: "bright_green",
}


def _bar(score: int) -> str:
    filled = score + 1  # 1..5
    color = _SCORE_COLORS[score]
    return f"[{color}]{'█' * filled}{'░' * (5 - filled)}[/{color}]"


class PassphraseField(Vertical):
    DEFAULT_CSS = """
    PassphraseField { height: auto; }
    PassphraseField > Input { margin-bottom: 0; }
    .pf-row { height: auto; }
    .pf-strength { padding: 0 1; height: 1; }
    .pf-feedback { padding: 0 1; color: $warning; height: auto; }
    .pf-match { padding: 0 1; height: 1; }
    .pf-suggest { width: 14; margin-left: 1; }
    """

    def __init__(
        self,
        *,
        require_confirm: bool = True,
        show_strength: bool = True,
        show_suggest: bool = True,
        **kwargs,
    ) -> None:
        super().__init__(**kwargs)
        self._require_confirm = require_confirm
        self._show_strength = show_strength
        self._show_suggest = show_suggest

    def compose(self) -> ComposeResult:
        with Horizontal(classes="pf-row"):
            yield Input(placeholder="passphrase", password=True, id="pf-pass")
            if self._show_suggest:
                yield Button("Suggest", id="pf-suggest", classes="pf-suggest")
        if self._require_confirm:
            yield Input(placeholder="confirm passphrase", password=True, id="pf-confirm")
            yield Static("", id="pf-match", classes="pf-match")
        if self._show_strength:
            yield Static(
                "Strength: [dim]type something[/dim]",
                id="pf-strength",
                classes="pf-strength",
            )
            yield Static("", id="pf-feedback", classes="pf-feedback")

    # --- public API ---

    @property
    def passphrase(self) -> str:
        return self.query_one("#pf-pass", Input).value

    @property
    def confirms(self) -> bool:
        if not self._require_confirm:
            return True
        a = self.query_one("#pf-pass", Input).value
        b = self.query_one("#pf-confirm", Input).value
        return a == b and a != ""

    def report(self) -> StrengthReport:
        return estimate_strength(self.passphrase)

    # --- handlers ---

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "pf-suggest":
            event.stop()
            pw = suggest(n_words=7)
            self.query_one("#pf-pass", Input).value = pw
            if self._require_confirm:
                self.query_one("#pf-confirm", Input).value = pw
            self._refresh_strength()
            self._refresh_match()
            if self._show_strength:
                self.query_one("#pf-feedback", Static).update(
                    f"[green]Suggested a {suggestion_bits(7):.0f}-bit passphrase. "
                    "Write it down before you continue.[/green]"
                )

    def on_input_changed(self, event: Input.Changed) -> None:
        if event.input.id == "pf-pass":
            self._refresh_strength()
            self._refresh_match()
        elif event.input.id == "pf-confirm":
            self._refresh_match()

    def _refresh_strength(self) -> None:
        if not self._show_strength:
            return
        report = self.report()
        meter = self.query_one("#pf-strength", Static)
        feedback = self.query_one("#pf-feedback", Static)
        if not self.passphrase:
            meter.update("Strength: [dim]type something[/dim]")
            feedback.update("")
            return
        meter.update(
            f"Strength: {_bar(report.score)} [b]{report.label}[/b]  "
            f"[dim]~{report.bits:.0f} bits · {report.crack_time_human} to crack[/dim]"
        )
        lines: list[str] = []
        if report.warning:
            lines.append(f"[yellow]⚠ {report.warning}[/yellow]")
        for s in report.suggestions[:2]:
            lines.append(f"[dim]· {s}[/dim]")
        feedback.update("\n".join(lines))

    def _refresh_match(self) -> None:
        if not self._require_confirm:
            return
        match = self.query_one("#pf-match", Static)
        a = self.query_one("#pf-pass", Input).value
        b = self.query_one("#pf-confirm", Input).value
        if not b:
            match.update("")
        elif a == b:
            match.update("[green]✓ matches[/green]")
        else:
            match.update("[red]✗ doesn't match[/red]")
