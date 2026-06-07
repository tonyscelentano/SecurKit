"""Archive pipeline: folder ↔ encrypted .skit bundle.

The pipeline streams through an OS pipe — no unencrypted plaintext ever hits
disk during encryption, which matters because forensic recovery on SSDs / swap
files can survive normal "delete" operations.

      ┌─────────────────────┐  ┌─────────────────────┐
      │ producer thread     │  │ main thread         │
      │  tarfile.open(w|)   │──│  encrypt_stream     │── .skit.tmp ─→ atomic rename
      │  walk + addfile     │  │  (Argon2id + GCM)   │
      └─────────────────────┘  └─────────────────────┘

Tar headers are normalized (mtime=0, uid/gid=0, no uname/gname) so the bundle
content depends only on the file bytes — a baseline metadata scrub before the
full `scrubber.py` pass lands. The bundle is written to a temp file in the
destination directory and renamed on success, so a failed encryption leaves
no half-written .skit behind.
"""

from __future__ import annotations

import fnmatch
import io
import os
import shutil
import tarfile
import tempfile
import threading
from pathlib import Path
from typing import BinaryIO, Callable, Iterable

from securkit._kdf_autotune import autotune_kdf
from securkit.crypto import (
    DEFAULT_CHUNK_SIZE,
    KdfParams,
    decrypt_stream,
    encrypt_stream,
)
from securkit.scrubber import ScrubReport, scrub_file

ProgressCb = Callable[[int, int], None]  # (bytes_done, bytes_total)


class ArchiveError(RuntimeError):
    """Raised when the tar producer thread fails."""


def _matches_any(rel_posix: str, patterns: Iterable[str]) -> bool:
    return any(fnmatch.fnmatch(rel_posix, p) for p in patterns)


def _walk_sorted(root: Path, excludes: Iterable[str]) -> list[tuple[Path, str]]:
    """Enumerate (absolute_path, arcname) pairs in deterministic order.

    arcname is rooted at the basename of `root` to avoid leaking absolute paths
    of the user's machine into the archive.
    """
    excludes = tuple(excludes)
    out: list[tuple[Path, str]] = []
    base = root.name or "bundle"
    for dirpath, dirnames, filenames in os.walk(root):
        # Stable order
        dirnames.sort()
        filenames.sort()
        d = Path(dirpath)
        rel_dir = d.relative_to(root)
        # Filter directories in place so os.walk skips excluded subtrees
        keep_dirs: list[str] = []
        for dn in dirnames:
            rel = (rel_dir / dn).as_posix()
            if not _matches_any(rel, excludes):
                keep_dirs.append(dn)
        dirnames[:] = keep_dirs
        # Add the directory itself (skip the root — tar will reconstruct it via arcname)
        if rel_dir != Path("."):
            arc = (Path(base) / rel_dir).as_posix()
            out.append((d, arc))
        for fn in filenames:
            rel = (rel_dir / fn).as_posix()
            if _matches_any(rel, excludes):
                continue
            out.append((d / fn, (Path(base) / rel_dir / fn).as_posix()))
    # Always include the root directory entry first (with arcname = base)
    out.insert(0, (root, base))
    return out


def _normalize_tarinfo(ti: tarfile.TarInfo) -> tarfile.TarInfo:
    """Strip identifying metadata from a tar header."""
    ti.mtime = 0
    ti.uid = 0
    ti.gid = 0
    ti.uname = ""
    ti.gname = ""
    return ti


class _ProgressReader:
    """Wraps a binary read stream and reports bytes consumed."""

    def __init__(self, inner: BinaryIO, total: int, cb: ProgressCb) -> None:
        self._inner = inner
        self._total = max(total, 1)
        self._cb = cb
        self._done = 0

    def read(self, size: int = -1) -> bytes:
        chunk = self._inner.read(size)
        if chunk:
            self._done += len(chunk)
            # Clamp displayed progress so tar-overhead doesn't push past 100%
            try:
                self._cb(min(self._done, self._total), self._total)
            except Exception:
                pass  # progress is best-effort; never break the pipeline
        return chunk

    def readable(self) -> bool:
        return True

    def close(self) -> None:
        self._inner.close()


def _sum_bytes(entries: Iterable[tuple[Path, str]]) -> int:
    total = 0
    for path, _arc in entries:
        try:
            if path.is_file() and not path.is_symlink():
                total += path.stat().st_size
        except OSError:
            pass
    return total


def archive_folder(
    src: Path | str,
    dest_skit: Path | str,
    passphrase: str | bytes,
    *,
    scrub_metadata: bool = True,
    excludes: Iterable[str] = (),
    on_progress: ProgressCb | None = None,
    kdf: KdfParams | None = None,
    chunk_size: int = DEFAULT_CHUNK_SIZE,
) -> tuple[Path, bytes, ScrubReport]:
    """Bundle `src` (a folder) into a .skit at `dest_skit`.

    Returns (output_path, plaintext_sha256, scrub_report). The scrub_report
    is empty when scrub_metadata=False.

    KDF parameters
    --------------
    If `kdf` is None (the default), Argon2id parameters are auto-tuned from
    available RAM — 256 MiB on a desktop, scaling down to a 64 MiB security
    floor on memory-constrained machines. The actual params used are encoded
    in the bundle header, so decryption always works regardless of where the
    bundle was created.

    Pass an explicit `KdfParams(...)` to override (tests, power users).
    """
    src = Path(src).resolve()
    dest_skit = Path(dest_skit)

    if not src.exists():
        raise FileNotFoundError(str(src))
    if not src.is_dir():
        raise NotADirectoryError(str(src))

    # Don't let the user put the output inside the input.
    try:
        dest_skit.resolve().relative_to(src)
    except ValueError:
        pass  # good — dest is not inside src
    else:
        raise ValueError("output bundle must not be inside the source folder")

    # Auto-tune Argon2id params when caller didn't override.
    if kdf is None:
        kdf = autotune_kdf().params

    # Baseline tar-header normalization always happens; content-level metadata
    # scrubbing (EXIF/PDF/Office) only when scrub_metadata=True.
    report = ScrubReport()
    entries = _walk_sorted(src, excludes)
    total_bytes = _sum_bytes(entries)

    dest_skit.parent.mkdir(parents=True, exist_ok=True)
    tmp_fd, tmp_name = tempfile.mkstemp(
        dir=str(dest_skit.parent), prefix=dest_skit.name + ".", suffix=".tmp"
    )
    os.close(tmp_fd)
    tmp_path = Path(tmp_name)

    r_fd, w_fd = os.pipe()
    producer_exc: list[BaseException] = []

    def producer() -> None:
        try:
            with os.fdopen(w_fd, "wb") as wf, tarfile.open(fileobj=wf, mode="w|") as tf:
                for path, arcname in entries:
                    try:
                        ti = tf.gettarinfo(str(path), arcname=arcname)
                    except OSError as e:
                        producer_exc.append(e)
                        return
                    if ti is None:
                        continue
                    _normalize_tarinfo(ti)
                    if ti.isfile():
                        if scrub_metadata:
                            result = scrub_file(path)
                            report.add(result)
                            if result.bytes_out is not None:
                                ti.size = len(result.bytes_out)
                                tf.addfile(ti, io.BytesIO(result.bytes_out))
                                continue
                        with open(path, "rb") as f:
                            tf.addfile(ti, f)
                    else:
                        tf.addfile(ti)
        except BaseException as e:  # noqa: BLE001 — re-raised on join
            producer_exc.append(e)

    t = threading.Thread(target=producer, daemon=True)
    t.start()

    try:
        with os.fdopen(r_fd, "rb") as rf:
            reader: BinaryIO = (
                _ProgressReader(rf, total_bytes, on_progress) if on_progress else rf
            )
            with tmp_path.open("wb") as out:
                digest = encrypt_stream(
                    reader, out, passphrase, kdf=kdf, chunk_size=chunk_size
                )
        t.join()
        if producer_exc:
            raise ArchiveError("failed to archive folder") from producer_exc[0]

        os.replace(tmp_path, dest_skit)  # atomic on POSIX and Windows (same volume)
        return dest_skit, digest, report
    except BaseException:
        if tmp_path.exists():
            try:
                tmp_path.unlink()
            except OSError:
                pass
        raise


def extract_skit(
    src_skit: Path | str,
    dest_dir: Path | str,
    passphrase: str | bytes,
    *,
    on_progress: ProgressCb | None = None,
) -> tuple[Path, bytes]:
    """Verify and extract a .skit bundle. Returns (extracted_root, sha256).

    Extraction goes to a sibling temp directory and is moved into place only
    after the full bundle decrypts and verifies — so a failed decrypt (bad
    passphrase, tampered bundle) never leaves partial files in `dest_dir`.
    """
    src_skit = Path(src_skit)
    dest_dir = Path(dest_dir)

    if not src_skit.exists():
        raise FileNotFoundError(str(src_skit))
    if not src_skit.is_file():
        raise IsADirectoryError(str(src_skit))

    total_bytes = src_skit.stat().st_size
    dest_dir.mkdir(parents=True, exist_ok=True)

    # Stage extraction in a temp dir adjacent to dest_dir so the move is on-volume.
    staging = Path(
        tempfile.mkdtemp(dir=str(dest_dir.parent), prefix=".skit-extract-")
    )

    r_fd, w_fd = os.pipe()
    consumer_exc: list[BaseException] = []
    digest_holder: list[bytes] = []

    def consumer() -> None:
        try:
            with os.fdopen(r_fd, "rb") as rf, tarfile.open(fileobj=rf, mode="r|") as tf:
                # Python 3.12+: the 'data' filter blocks absolute paths, '..',
                # device files, and unsafe symlinks — critical for not extracting
                # a hostile bundle outside dest_dir.
                if hasattr(tarfile, "data_filter"):
                    tf.extraction_filter = tarfile.data_filter  # type: ignore[attr-defined]
                tf.extractall(path=staging)
        except BaseException as e:  # noqa: BLE001
            consumer_exc.append(e)

    t = threading.Thread(target=consumer, daemon=True)
    t.start()

    try:
        with src_skit.open("rb") as f:
            reader: BinaryIO = (
                _ProgressReader(f, total_bytes, on_progress) if on_progress else f
            )
            with os.fdopen(w_fd, "wb") as wf:
                digest = decrypt_stream(reader, wf, passphrase)
                digest_holder.append(digest)
        t.join()
        if consumer_exc:
            raise ArchiveError("failed to extract bundle") from consumer_exc[0]

        # Promote staging contents into dest_dir.
        # Bundle layout: staging/<top>/...   where <top> is the original folder name.
        children = list(staging.iterdir())
        if len(children) != 1 or not children[0].is_dir():
            # Defensive: malformed bundle (shouldn't happen with bundles we created).
            raise ArchiveError("bundle does not contain a single top-level directory")
        extracted_root = dest_dir / children[0].name
        if extracted_root.exists():
            raise FileExistsError(
                f"refusing to overwrite existing path: {extracted_root}"
            )
        shutil.move(str(children[0]), str(extracted_root))
        return extracted_root, digest_holder[0]
    except BaseException:
        # Make sure the pipe writer thread doesn't deadlock on a stalled consumer
        try:
            os.close(w_fd)
        except OSError:
            pass
        raise
    finally:
        if staging.exists():
            shutil.rmtree(staging, ignore_errors=True)
