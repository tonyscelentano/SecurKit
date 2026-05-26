```
 ███████╗███████╗ ██████╗██╗   ██╗██████╗ ██╗  ██╗██╗████████╗
 ██╔════╝██╔════╝██╔════╝██║   ██║██╔══██╗██║ ██╔╝██║╚══██╔══╝
 ███████╗█████╗  ██║     ██║   ██║██████╔╝█████╔╝ ██║   ██║
 ╚════██║██╔══╝  ██║     ██║   ██║██╔══██╗██╔═██╗ ██║   ██║
 ███████║███████╗╚██████╗╚██████╔╝██║  ██║██║  ██╗██║   ██║
 ╚══════╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝   ╚═╝
```

**A whistleblower kit in your terminal.** Encrypt a folder, scrub identifying metadata, point yourself at the right regulator. One file, runs from a thumb drive.

## What it does

You point SecurKit at a folder of evidence. It:

1. **Scrubs identifying metadata** — EXIF/GPS from photos, Author / Last-Modified-By / track-changes / rsids from Office docs, `/Info` and XMP from PDFs, comment authors in Word/Excel/PowerPoint, change-info in LibreOffice.
2. **Bundles and encrypts** with AES-256-GCM. Key derived via Argon2id, memory-tuned to your machine (256 MiB on a desktop, 64 MiB floor on a memory-starved laptop).
3. **Returns a SHA-256 fingerprint** to share with the recipient over a separate channel (Signal, in person) so they can verify the bundle wasn't swapped in transit.
4. **Points you at a regulator** — a built-in directory of 15 vetted US intake channels (SEC, CFTC, FinCEN, OSHA, DOJ, FBI, IRS Whistleblower, ICIJ SecureDrop, NYT Tips, plus the Government Accountability Project for free legal counsel).

<img width="1400" height="828" alt="{FE56286F-B94F-4A47-83AD-79D933868FDA}" src="https://github.com/user-attachments/assets/14e2bb3a-df4a-406d-af80-b386dd69fa94" /> <img width="1398" height="818" alt="{D164404F-07EE-4343-AD37-2B8BC9928690}" src="https://github.com/user-attachments/assets/e3895d00-7780-4999-aedc-c57d79573340" />


## Quick start

**Windows (recommended):** grab `securkit.exe` from Releases. No Python required.

```powershell
.\securkit.exe
```

Type Source / Output paths (drag from File Explorer to paste), enter a passphrase (or hit Suggest), press Enter from the confirm field. Done.

**Run from a thumb drive** without leaving traces on the host machine:

```powershell
Copy-Item securkit.exe D:\
New-Item D:\securkit.portable -ItemType File
D:\securkit.exe
```

The marker file activates portable mode — state goes to `D:\securkit-data\` instead of the host's home directory. Yank the drive, nothing on the host survives.

**From source:**

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -e ".[dev]"
securkit
```

**Build the `.exe` yourself:**

```powershell
python scripts/build.py
```

## Bundle format (`.skit` v1)

```
magic        "SKIT1"        5 bytes
version      u8             1
cipher_id    u8             1 = AES-256-GCM
kdf_id       u8             1 = Argon2id
kdf_params   u32 t, u32 m_kib, u8 p
salt         16 bytes
base_nonce   12 bytes       (per-chunk nonce = base_nonce XOR counter_be64)
chunk_size   u64
chunks       repeated: u32 len || ciphertext || gcm_tag(16)
trailer      sealed SHA-256(plaintext) as the final chunk
```

Each chunk's AAD includes the full header, an 8-byte chunk counter, and a 1-byte final-flag. The flag defends against **truncation** (dropping the trailer); the counter defends against **reordering**; including the header in AAD defends against **rollback** of KDF params, salt, or nonce.

## Threat model

**Defends against:** at-rest disclosure of the bundle, passphrase brute-force (within Argon2id cost), tampering with the encrypted archive, common metadata leaks in source files, and malicious `.skit` files DoS-ing the verifier via attacker-supplied KDF params (capped at 1 GiB memory on decrypt).

**Does NOT defend against:** a compromised endpoint (keylogger, screen capture, hostile admin), a coerced passphrase, traffic analysis at upload time, embedded objects inside Office documents (OLE attachments, embedded fonts — surfaced via in-app warning), the user choosing a weak passphrase (the tool coaches but never blocks).

For high-stakes work use Tails or a clean live environment. **Talk to a whistleblower attorney before disclosing** — the Hotlines pane links to free intake consultations (Government Accountability Project, National Whistleblower Center).

## Distribution caveats

The shipped `.exe` is unsigned. Windows SmartScreen will warn *"Microsoft Defender SmartScreen prevented an unrecognized app from starting"* — click *More info → Run anyway*. Some antivirus vendors false-positive on PyInstaller binaries; verify the published SHA-256 of the release against your downloaded file before running.

## License

MIT
