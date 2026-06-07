"""Translate technical exceptions into plain-English (title, body) pairs.

`crypto.py` keeps its precise exception types and messages for tests and
machine-readable logs. The TUI calls `friendly()` at the screen boundary so
end users never see "authentication failed: wrong passphrase or tampered bundle".
"""

from __future__ import annotations

from dataclasses import dataclass

from securkit.crypto import SkitAuthError, SkitFormatError


@dataclass(frozen=True)
class FriendlyError:
    title: str
    body: str


def friendly(exc: BaseException) -> FriendlyError:
    if isinstance(exc, SkitAuthError):
        return FriendlyError(
            title="Couldn't unlock the bundle",
            body=(
                "Either the passphrase is wrong, or the file has been changed since "
                "it was created. Double-check the passphrase exactly — capitalization "
                "and spaces matter. If you typed it correctly and it still fails, the "
                "file may have been tampered with or corrupted."
            ),
        )

    if isinstance(exc, SkitFormatError):
        msg = str(exc).lower()
        if "magic" in msg:
            return FriendlyError(
                title="Not a SecurKit bundle",
                body="This file doesn't look like a .skit bundle. Pick a file created "
                     "by SecurKit's Encrypt screen.",
            )
        if "memory_cost_kib" in msg or "time_cost" in msg or "parallelism" in msg:
            return FriendlyError(
                title="Bundle settings look unsafe",
                body="This bundle claims unusual encryption settings that could lock "
                     "up your computer if we tried to open it. We've refused as a "
                     "safety measure. Don't open .skit files from sources you don't "
                     "trust.",
            )
        if "empty bundle" in msg or "truncated" in msg or "eof" in msg:
            return FriendlyError(
                title="Bundle is incomplete",
                body="This file is missing data — it may have been cut off during "
                     "download, copy, or transfer. Try getting a fresh copy.",
            )
        if "trailing data" in msg:
            return FriendlyError(
                title="Bundle has extra data attached",
                body="There's unexpected data after the end of this bundle. Don't "
                     "open it — it may have been altered.",
            )
        return FriendlyError(
            title="Couldn't read the bundle",
            body=f"The file isn't a valid SecurKit bundle. Details: {exc}",
        )

    if isinstance(exc, FileNotFoundError):
        return FriendlyError(
            title="File not found",
            body=f"Couldn't find: {exc.filename or exc}. Check the path and try again.",
        )

    if isinstance(exc, PermissionError):
        return FriendlyError(
            title="Permission denied",
            body=f"This computer won't let SecurKit touch: {exc.filename or exc}. "
                 "Try a different location, or run from an account that owns the file.",
        )

    if isinstance(exc, IsADirectoryError):
        return FriendlyError(
            title="That's a folder, not a file",
            body="The output bundle needs to be a single file (ending in .skit), "
                 "not a folder.",
        )

    if isinstance(exc, FileExistsError):
        # extract_skit raises this when the destination already has a folder
        # with the same name as the bundle's top-level dir. The exception's
        # message embeds the offending path; we surface it so the user can
        # immediately see where the collision is.
        path_hint = exc.filename or str(exc).replace("refusing to overwrite existing path:", "").strip()
        return FriendlyError(
            title="A folder with that name already exists",
            body=(
                f"SecurKit refuses to overwrite existing files during decrypt — "
                f"this is intentional so a botched second attempt can't destroy "
                f"the first one's output.\n\n"
                f"Conflict: {path_hint}\n\n"
                f"Either pick a different 'Extract into' folder, or delete the "
                f"existing one if you no longer need it."
            ),
        )

    if isinstance(exc, NotADirectoryError):
        return FriendlyError(
            title="That's a file, not a folder",
            body="Encryption needs a folder of evidence as input, not a single file. "
                 "Put your files inside a folder first.",
        )

    if isinstance(exc, ValueError):
        return FriendlyError(
            title="Invalid setting",
            body=str(exc) or "One of the values isn't valid. Check the inputs.",
        )

    # Last-resort generic
    return FriendlyError(
        title="Something went wrong",
        body=f"{type(exc).__name__}: {exc}",
    )
