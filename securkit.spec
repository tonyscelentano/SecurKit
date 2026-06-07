# PyInstaller spec for SecurKit — onefile Windows .exe.
#
# Build:    python -m PyInstaller securkit.spec --clean --noconfirm
# Easier:   python scripts/build.py
#
# Notes
# -----
# - onefile mode means the .exe extracts its bundled deps to %TEMP%\_MEIxxxxxx
#   on launch. That's a transient trace on the host machine, not a permanent
#   one — PyInstaller cleans it up on exit. For the "absolutely no trace"
#   threat model, build onedir instead (set ONEFILE=False below) and put the
#   resulting folder on the thumb drive.
# - UPX is intentionally disabled. UPX-packed binaries get false-positive
#   flagged by every consumer antivirus on Earth, which is exactly what you
#   don't want for a tool a whistleblower might run on a work laptop.
# - The .ico is skipped (we don't ship a custom icon). Add `icon='path.ico'`
#   to EXE() later if/when we have one.

from PyInstaller.utils.hooks import collect_all, collect_data_files

ONEFILE = True

# Textual ships CSS / themes / widget assets that must travel with the binary.
textual_datas, textual_binaries, textual_hidden = collect_all("textual")

# zxcvbn includes its frequency lists / matcher data as importable resources.
zxcvbn_datas, zxcvbn_binaries, zxcvbn_hidden = collect_all("zxcvbn")

# Our own data file — hotlines directory loaded via importlib.resources.
securkit_datas = [("securkit/data/hotlines.yaml", "securkit/data")]

# Textual screen modules are loaded dynamically by name in our nav handler
# (cls(...) where cls comes from NAV_ITEMS). Make sure PyInstaller's static
# analyzer doesn't miss them.
securkit_hidden = [
    "securkit.tui.screens.encrypt",
    "securkit.tui.screens.decrypt",
    "securkit.tui.screens.hotlines",
    "securkit.tui.screens.about",
    "securkit.tui.screens.welcome",
    "securkit.tui.widgets.passphrase_field",
    "securkit._ooxml",
]

# Heavy packages we definitely do NOT want pulled in transitively.
EXCLUDES = [
    "tkinter",
    "numpy",
    "scipy",
    "matplotlib",
    "pandas",
    "IPython",
    "jupyter",
    "notebook",
    "pytest",
    "PyInstaller",
    "docx",        # python-docx is dev-only (test validator)
    "openpyxl",    # dev-only (test validator)
]


a = Analysis(
    ["securkit/__main__.py"],
    pathex=[],
    binaries=textual_binaries + zxcvbn_binaries,
    datas=textual_datas + zxcvbn_datas + securkit_datas,
    hiddenimports=textual_hidden + zxcvbn_hidden + securkit_hidden,
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=EXCLUDES,
    noarchive=False,
    optimize=0,
)

pyz = PYZ(a.pure)

if ONEFILE:
    exe = EXE(
        pyz,
        a.scripts,
        a.binaries,
        a.datas,
        [],
        name="securkit",
        debug=False,
        bootloader_ignore_signals=False,
        strip=False,
        upx=False,
        upx_exclude=[],
        runtime_tmpdir=None,
        console=True,            # TUI needs a console attached
        disable_windowed_traceback=False,
        argv_emulation=False,
        target_arch=None,
        codesign_identity=None,
        entitlements_file=None,
    )
else:
    exe = EXE(
        pyz,
        a.scripts,
        [],
        exclude_binaries=True,
        name="securkit",
        debug=False,
        bootloader_ignore_signals=False,
        strip=False,
        upx=False,
        console=True,
    )
    coll = COLLECT(
        exe,
        a.binaries,
        a.datas,
        strip=False,
        upx=False,
        upx_exclude=[],
        name="securkit",
    )
