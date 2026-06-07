"""Hotlines / regulator directory loader.

Data lives in `securkit/data/hotlines.yaml`. Each entry describes a legitimate
intake channel (regulator, IG, NGO, secure-drop instance) with scope, link,
and submission notes.
"""

from __future__ import annotations

from dataclasses import dataclass
from importlib import resources
from typing import Literal

import yaml

Channel = Literal["web", "phone", "email", "securedrop", "signal", "postal"]


@dataclass(frozen=True)
class Hotline:
    id: str
    name: str
    agency: str
    scope: str
    channels: dict[Channel, str]
    # Where the channel has authority. Use the real value — "United States",
    # "European Union" (EU-wide bodies), or a member state ("Germany", "France").
    # The dashboard groups these into regions (see `region`); don't flatten a
    # national regulator into "European Union" just to make grouping easier.
    jurisdiction: str = "United States"
    notes: str = ""
    anonymous_ok: bool = True
    retaliation_protection: str = ""

    @property
    def region(self) -> str:
        """Coarse bucket used to group the dashboard list."""
        return "United States" if self.jurisdiction == "United States" else "Europe"


# Order in which region groups are shown in the dashboard.
REGION_ORDER = ["United States", "Europe"]


def load_hotlines() -> list[Hotline]:
    raw = resources.files("securkit.data").joinpath("hotlines.yaml").read_text(encoding="utf-8")
    data = yaml.safe_load(raw)
    return [Hotline(**entry) for entry in data["hotlines"]]
