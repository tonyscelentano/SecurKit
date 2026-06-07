"""Build the SecurKit single-file executable via PyInstaller.

Usage:
    python scripts/build.py

Output:
    dist/securkit.exe   (Windows)
    dist/securkit       (POSIX)

Then verify:
    .\dist\securkit.exe --version
    .\dist\securkit.exe --state-info
"""

from __future__ import annotations

import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SPEC = ROOT / "securkit.spec"


def main() -> int:
    if not SPEC.exists():
        print(f"error: {SPEC} not found", file=sys.stderr)
        return 2

    # Clean previous artifacts so we don't ship stale binaries
    for d in (ROOT / "build", ROOT / "dist"):
        if d.exists():
            shutil.rmtree(d)

    cmd = [
        sys.executable, "-m", "PyInstaller",
        str(SPEC),
        "--clean",
        "--noconfirm",
        "--distpath", str(ROOT / "dist"),
        "--workpath", str(ROOT / "build"),
    ]
    print("$", " ".join(cmd))
    result = subprocess.run(cmd, cwd=str(ROOT))
    if result.returncode != 0:
        print(f"\nbuild failed (exit {result.returncode})", file=sys.stderr)
        return result.returncode

    exe = ROOT / "dist" / ("securkit.exe" if sys.platform == "win32" else "securkit")
    if not exe.exists():
        print(f"\nexpected binary not found: {exe}", file=sys.stderr)
        return 1

    size_mb = exe.stat().st_size / (1024 * 1024)
    print(f"\nbuilt: {exe}  ({size_mb:.1f} MB)")
    print(f"smoke test: {exe} --version")

    proc = subprocess.run(
        [str(exe), "--version"], capture_output=True, text=True, timeout=60
    )
    if proc.returncode != 0:
        print(f"\nsmoke test FAILED (exit {proc.returncode}):", file=sys.stderr)
        print(proc.stdout)
        print(proc.stderr, file=sys.stderr)
        return 1

    print(proc.stdout.strip())
    print("\nOK")
    return 0


if __name__ == "__main__":
    sys.exit(main())
