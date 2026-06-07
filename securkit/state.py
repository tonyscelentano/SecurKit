r"""Persisted-state helpers with portable (thumb-drive) mode.

By default, state lives at `~/.securkit/` — fine for the normal install case
but **leaks a trace** that the user ran SecurKit, which matters when launching
from a USB stick on a borrowed or work computer.

PORTABLE MODE
-------------
Drop a file literally named `securkit.portable` next to the SecurKit
executable (or alongside `__main__.py` for a dev checkout). When SecurKit
sees that marker, all state — currently just the welcome-dismissed flag —
goes to `<exe_dir>/securkit-data/` instead.

This means:
  • Nothing about SecurKit is written to the host machine's home directory.
  • If you yank the thumb drive, every trace goes with you.
  • If you forget to add the marker, you fall back to the normal home-dir
    behavior — no surprises, no silent data loss.

To activate portable mode on a thumb drive:
  D:\>  copy securkit.exe .
  D:\>  type nul > securkit.portable      (Windows)
  D:\$  touch securkit.portable           (POSIX)
"""

from __future__ import annotations

import sys
from pathlib import Path

PORTABLE_MARKER_NAME = "securkit.portable"


def _exe_dir() -> Path:
    """Directory holding the SecurKit executable (frozen) or the source root (dev)."""
    if getattr(sys, "frozen", False):
        # PyInstaller bundle: sys.executable is the bundled .exe
        return Path(sys.executable).resolve().parent
    # Dev checkout: walk up from this file to the project root
    return Path(__file__).resolve().parent.parent


def is_portable() -> bool:
    """True if a `securkit.portable` marker exists next to the executable."""
    return (_exe_dir() / PORTABLE_MARKER_NAME).exists()


def _resolve_state_dir() -> Path:
    if is_portable():
        return _exe_dir() / "securkit-data"
    return Path.home() / ".securkit"


# Resolved once at import. If a user creates/removes the portable marker
# they need to restart SecurKit — that's fine and matches what users expect.
STATE_DIR: Path = _resolve_state_dir()
WELCOMED_FLAG: Path = STATE_DIR / "welcomed"


def has_been_welcomed() -> bool:
    return WELCOMED_FLAG.exists()


def mark_welcomed() -> None:
    STATE_DIR.mkdir(parents=True, exist_ok=True)
    WELCOMED_FLAG.touch()
