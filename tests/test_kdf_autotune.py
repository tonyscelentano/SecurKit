"""KDF auto-tune tests."""

from __future__ import annotations

import io

import pytest

from securkit._kdf_autotune import (
    _FALLBACK,
    _SCHEDULE,
    autotune_kdf,
    describe,
)
from securkit.archive import archive_folder, extract_skit
from securkit.crypto import KdfParams, decrypt_stream, encrypt_stream


# --- Schedule mapping ----------------------------------------------------


@pytest.mark.parametrize(
    "available_mib,expected_memory_mib,expected_time",
    [
        (32_000, 256, 3),   # 32 GiB desktop
        (8_000, 256, 3),    # 8 GiB laptop
        (2_048, 256, 3),    # exactly at the 2 GiB threshold
        (2_047, 128, 4),    # just below
        (1_500, 128, 4),    # 1.5 GiB
        (768, 128, 4),      # exactly at the 768 MiB threshold
        (767, 64, 6),       # just below
        (500, 64, 6),       # mid-tier
        (256, 64, 6),       # threshold
        (255, 64, 8),       # below — floor with boosted time_cost
        (100, 64, 8),       # very tight
        (10, 64, 8),        # absurdly tight — still hits the floor
        (0, 64, 8),         # pathological — still safe
    ],
)
def test_schedule_buckets(available_mib, expected_memory_mib, expected_time) -> None:
    result = autotune_kdf(available_mib=available_mib)
    assert result.params.memory_cost_kib == expected_memory_mib * 1024
    assert result.params.time_cost == expected_time
    assert result.params.parallelism == 1


def test_security_floor_never_below_64_mib() -> None:
    """Even with 0 MiB available, the floor stays at 64 MiB. Defines the
    minimum security guarantee the tool provides."""
    for available in (0, 1, 16, 64, 200, 255):
        result = autotune_kdf(available_mib=available)
        assert result.params.memory_cost_kib >= 64 * 1024, (
            f"floor breached at {available} MiB available: "
            f"{result.params.memory_cost_kib} KiB"
        )


def test_all_schedule_results_validate() -> None:
    """Every params object produced by the schedule must pass KdfParams.validate()."""
    for threshold, _m, _t in _SCHEDULE:
        result = autotune_kdf(available_mib=threshold)
        result.params.validate()  # raises on bad params


def test_describe_format() -> None:
    s = describe(KdfParams(time_cost=3, memory_cost_kib=256 * 1024, parallelism=1))
    assert "Argon2id" in s
    assert "256" in s
    assert "t=3" in s
    assert "p=1" in s


def test_probe_fallback_when_psutil_fails(monkeypatch) -> None:
    """If the RAM probe raises or returns None, fall back to the middle tier
    rather than failing or guessing wildly."""
    import securkit._kdf_autotune as autotune_mod

    monkeypatch.setattr(autotune_mod, "_probe_available_mib", lambda: None)
    result = autotune_kdf()  # no override → triggers probe
    assert result.params == _FALLBACK
    assert result.available_mib is None
    assert "probe unavailable" in result.tier_label


def test_tier_labels_are_human_readable() -> None:
    for available in (8000, 1500, 500, 100):
        result = autotune_kdf(available_mib=available)
        # Should mention MiB and t=
        assert "MiB" in result.tier_label
        assert "t=" in result.tier_label


# --- Integration: archive_folder with kdf=None auto-tunes ---------------


def test_archive_with_kdf_none_uses_autotuned_params(tmp_path) -> None:
    """archive_folder(kdf=None) should auto-tune and the bundle should still
    round-trip cleanly — proves the autotuned params are encoded in the header
    and the decryptor picks them up."""
    src = tmp_path / "ev"
    src.mkdir()
    (src / "note.txt").write_text("hello world")

    bundle = tmp_path / "out.skit"
    # kdf=None → autotune. We pass a real passphrase but no kdf, so this
    # exercises the production path. May take ~1-2 sec for real Argon2id.
    out, sha, _ = archive_folder(
        src, bundle, "test-passphrase-1234", kdf=None
    )
    assert out.exists()

    extracted, sha2 = extract_skit(bundle, tmp_path / "out", "test-passphrase-1234")
    assert sha == sha2
    assert (extracted / "note.txt").read_text() == "hello world"


def test_explicit_kdf_bypasses_autotune(tmp_path) -> None:
    """Passing kdf=KdfParams(...) explicitly must NOT auto-tune. Test by
    using cheap params and confirming they're what landed in the bundle."""
    src = tmp_path / "ev"
    src.mkdir()
    (src / "x.txt").write_text("x")

    cheap = KdfParams(time_cost=1, memory_cost_kib=8, parallelism=1)
    bundle = tmp_path / "out.skit"
    archive_folder(src, bundle, "pw", kdf=cheap)

    # Decrypt and inspect the header to verify the cheap params were used
    from securkit.crypto import HEADER_LEN, _unpack_header
    header = bundle.read_bytes()[:HEADER_LEN]
    parsed_kdf, _salt, _nonce, _chunk = _unpack_header(header)
    assert parsed_kdf.time_cost == 1
    assert parsed_kdf.memory_cost_kib == 8
    assert parsed_kdf.parallelism == 1
