"""SecurKit Textual app: welcome on first run + sidebar nav + content pane."""

from __future__ import annotations

from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, Vertical
from textual.widgets import Footer, Header, ListItem, ListView, Static

from securkit.state import has_been_welcomed
from securkit.tui.screens.about import AboutPane
from securkit.tui.screens.decrypt import DecryptPane
from securkit.tui.screens.encrypt import EncryptPane
from securkit.tui.screens.hotlines import HotlinesPane
from securkit.tui.screens.welcome import WelcomeScreen

NAV_ITEMS = [
    ("encrypt", "Encrypt", EncryptPane),
    ("decrypt", "Decrypt", DecryptPane),
    ("hotlines", "Hotlines", HotlinesPane),
    ("about", "About", AboutPane),
]


class SecurKitApp(App):
    CSS = """
    Screen { layout: horizontal; }
    #nav { width: 22; border-right: solid $primary; }
    #nav > ListView { height: 1fr; }
    #content { width: 1fr; padding: 1 2; }
    .pane-title { text-style: bold; color: $accent; padding-bottom: 1; }
    .hl-group { color: $accent; background: $boost; }
    .hl-group.-disabled { opacity: 1; }
    """

    BINDINGS = [
        Binding("q", "quit", "Quit"),
        # Ctrl+C is deliberately a no-op: a panicked user hitting Ctrl+C to
        # copy the SHA fingerprint must NOT lose their session. To copy from
        # the TUI, use the terminal's native selection (mouse drag, or
        # Ctrl+Shift+C in Windows Terminal). To quit, press q.
        Binding("ctrl+c", "noop", show=False, priority=True),
        Binding("?", "show_welcome", "Briefing"),
    ]

    def compose(self) -> ComposeResult:
        yield Header(show_clock=False)
        with Horizontal():
            with Vertical(id="nav"):
                yield Static(" SecurKit ", classes="pane-title")
                yield ListView(
                    *[ListItem(Static(label), id=f"nav-{key}") for key, label, _ in NAV_ITEMS],
                    id="nav-list",
                )
            with Vertical(id="content"):
                yield EncryptPane()
        yield Footer()

    def on_mount(self) -> None:
        if not has_been_welcomed():
            self.push_screen(WelcomeScreen())

    def action_show_welcome(self) -> None:
        self.push_screen(WelcomeScreen())

    def action_noop(self) -> None:
        """No-op action — used to swallow keybindings without doing anything."""
        pass

    async def on_list_view_selected(self, event: ListView.Selected) -> None:
        if not event.item or not event.item.id:
            return
        key = event.item.id.removeprefix("nav-")
        for k, _, cls in NAV_ITEMS:
            if k == key:
                content = self.query_one("#content", Vertical)
                await content.remove_children()
                await content.mount(cls())
                return


if __name__ == "__main__":
    SecurKitApp().run()
