"""Entry point: `python -m securkit` and the `securkit` script / .exe."""

from __future__ import annotations

import argparse
import sys

from securkit import __version__


def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="securkit",
        description=(
            "SecurKit — encrypt, scrub, and route a folder of whistleblower "
            "evidence. Run without arguments to launch the TUI."
        ),
    )
    p.add_argument(
        "--version",
        action="store_true",
        help="Print version and exit (also reports portable-mode state).",
    )
    p.add_argument(
        "--state-info",
        action="store_true",
        help="Show where SecurKit will write its tiny state file, then exit.",
    )
    return p


def main(argv: list[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)

    if args.version:
        # Print extra context the user might want when running the bundled exe
        from securkit.state import STATE_DIR, is_portable

        print(f"SecurKit {__version__}")
        print(f"  portable mode: {'yes' if is_portable() else 'no'}")
        print(f"  state dir:     {STATE_DIR}")
        return 0

    if args.state_info:
        from securkit.state import STATE_DIR, WELCOMED_FLAG, is_portable

        print(f"portable mode: {'yes' if is_portable() else 'no'}")
        print(f"state dir:     {STATE_DIR}")
        print(f"welcomed flag: {WELCOMED_FLAG}")
        return 0

    # Default: launch the TUI
    from securkit.tui.app import SecurKitApp

    SecurKitApp().run()
    return 0


if __name__ == "__main__":
    sys.exit(main())
