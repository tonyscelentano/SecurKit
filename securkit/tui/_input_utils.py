"""Small input-handling helpers shared across panes."""

from __future__ import annotations


def clean_path(raw: str) -> str:
    """Normalize a user-entered (or drag-and-dropped) path string.

    Why this exists: when you drag a folder or file from Windows Explorer
    onto a terminal window, the terminal pastes the path as text — and if
    the path contains spaces, Windows Terminal (and most other terminals)
    wraps the whole thing in double quotes:

        "C:\\Users\\Tony\\My Documents\\evidence"

    Path resolution (Path, os.path) does NOT strip those quotes, so the
    user gets a "file not found" error. This helper strips a single
    surrounding pair of straight quotes (either kind) plus any whitespace,
    so drag-and-drop "just works" from a panicked user's perspective.

    Defensive: only strips if BOTH ends are the same quote character —
    so a malformed input like ``"C:\\foo`` (one-sided quote) is left
    alone rather than silently mangled.
    """
    s = raw.strip()
    if len(s) >= 2 and s[0] == s[-1] and s[0] in ('"', "'"):
        s = s[1:-1].strip()
    return s
