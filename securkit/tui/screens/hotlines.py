"""Hotlines pane — browsable directory of reporting channels."""

from __future__ import annotations

from textual.app import ComposeResult
from textual.containers import Horizontal, Vertical, VerticalScroll
from textual.widgets import ListItem, ListView, Static

from securkit.hotlines import REGION_ORDER, Hotline, load_hotlines


class HotlinesPane(Vertical):
    def compose(self) -> ComposeResult:
        yield Static("Reporting channels", classes="pane-title")
        try:
            self._hotlines: list[Hotline] = load_hotlines()
        except Exception as exc:  # pragma: no cover
            yield Static(f"[!] Failed to load hotlines: {exc}")
            self._hotlines = []
            return

        with Horizontal():
            with Vertical(id="hl-list-wrap"):
                yield ListView(*self._build_items(), id="hl-list")
            with VerticalScroll(id="hl-detail"):
                yield Static("Select a channel on the left.", id="hl-body")

    def _build_items(self) -> list[ListItem]:
        """Flat list of ListItems with a disabled header before each region group.

        ListView is flat, so we fake grouping by inserting non-selectable header
        rows. Regions follow REGION_ORDER; any unknown region falls in after them.
        """
        seen = [r for r in REGION_ORDER if any(h.region == r for h in self._hotlines)]
        extras = sorted({h.region for h in self._hotlines} - set(seen))
        items: list[ListItem] = []
        for region in [*seen, *extras]:
            items.append(
                ListItem(
                    Static(f"[b]── {region} ──[/b]"),
                    id=f"hlhdr-{region.replace(' ', '-').lower()}",
                    classes="hl-group",
                    disabled=True,
                )
            )
            for h in (h for h in self._hotlines if h.region == region):
                items.append(
                    ListItem(Static(f"{h.name}\n  {h.agency}"), id=f"hl-{h.id}")
                )
        return items

    def on_list_view_selected(self, event: ListView.Selected) -> None:
        if not event.item or not event.item.id:
            return
        hl_id = event.item.id.removeprefix("hl-")
        match = next((h for h in self._hotlines if h.id == hl_id), None)
        if not match:
            return
        body = self.query_one("#hl-body", Static)
        lines = [
            f"[b]{match.name}[/b]",
            f"[dim]{match.agency}[/dim]",
            "",
            f"[b]Scope[/b]  {match.scope}",
            "",
            "[b]Channels[/b]",
        ]
        for kind, value in match.channels.items():
            lines.append(f"  {kind}: {value}")
        if match.retaliation_protection:
            lines += ["", f"[b]Retaliation protection[/b]  {match.retaliation_protection}"]
        if match.notes:
            lines += ["", "[b]Notes[/b]", match.notes.strip()]
        lines += ["", f"[dim]Anonymous OK: {match.anonymous_ok}[/dim]"]
        body.update("\n".join(lines))
