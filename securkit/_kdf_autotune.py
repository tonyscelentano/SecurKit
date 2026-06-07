"""Adaptive Argon2id parameters based on available RAM.

The default ``KdfParams()`` uses 256 MiB — OWASP's 2024 recommendation. That's
ideal on a modern desktop but punishing on a 4 GiB laptop with a browser open:
the OS pages out other apps to make room, which both **hurts UX** (a 30-second
KDF instead of 2) and **defeats the threat model** (Argon2id's memory-hardness
guarantee assumes the working set stays in RAM, not on disk where forensic
recovery can survive a power-off).

Schedule (4 tiers, with a 64 MiB security floor):

    available RAM        memory_cost   time_cost   total work factor
    ───────────────────────────────────────────────────────────────────
    ≥ 2 GiB              256 MiB       3           = baseline (768)
    768 MiB – 2 GiB      128 MiB       4           = 512  (66%)
    256 – 768 MiB         64 MiB       6           = 384  (50%)
    < 256 MiB             64 MiB       8           = 512  (66%)

The floor stays at 64 MiB even on a starved machine. OWASP's minimum is 9 MiB
but for a tool whose threat model includes nation-state-scale adversaries we
want margin — and time_cost climbs to keep the total work factor reasonable.

If the RAM probe fails (psutil missing, sandbox without /proc, etc.) we fall
back to the 128/4 middle tier — a conservative guess that works on most
machines without overcommitting on truly tiny ones.
"""

from __future__ import annotations

from dataclasses import dataclass

from securkit.crypto import KdfParams

# 4-tier schedule. Each entry: (min_available_mib, memory_mib, time_cost).
# Iterated top-to-bottom; first match wins.
_SCHEDULE: tuple[tuple[int, int, int], ...] = (
    (2048, 256, 3),
    (768, 128, 4),
    (256, 64, 6),
    (0, 64, 8),  # security floor: 64 MiB even when memory is critically tight
)

# Conservative fallback when we can't probe at all.
_FALLBACK = KdfParams(time_cost=4, memory_cost_kib=128 * 1024, parallelism=1)


@dataclass(frozen=True)
class AutotuneResult:
    params: KdfParams
    available_mib: int | None  # None if probe failed
    tier_label: str  # human-friendly description of which tier was picked


def _probe_available_mib() -> int | None:
    """Return MiB of available memory, or None if probing failed."""
    try:
        import psutil  # late import — keeps crypto.py importable without psutil

        return int(psutil.virtual_memory().available // (1024 * 1024))
    except Exception:
        return None


def _select_from_schedule(available_mib: int) -> tuple[KdfParams, str]:
    for threshold, m_mib, t in _SCHEDULE:
        if available_mib >= threshold:
            params = KdfParams(time_cost=t, memory_cost_kib=m_mib * 1024, parallelism=1)
            label = f"{m_mib} MiB / t={t}"
            return params, label
    # Unreachable: the last schedule entry has threshold=0.
    return _FALLBACK, "fallback"


def autotune_kdf(available_mib: int | None = None) -> AutotuneResult:
    """Pick Argon2id params for the current machine.

    Args:
      available_mib: override the RAM probe (useful for tests). When None,
        probes via psutil; falls back to the conservative middle tier if
        the probe fails.
    """
    probed = available_mib if available_mib is not None else _probe_available_mib()
    if probed is None:
        return AutotuneResult(
            params=_FALLBACK,
            available_mib=None,
            tier_label=f"{_FALLBACK.memory_cost_kib // 1024} MiB / "
            f"t={_FALLBACK.time_cost} (RAM probe unavailable)",
        )
    params, label = _select_from_schedule(probed)
    return AutotuneResult(params=params, available_mib=probed, tier_label=label)


def describe(params: KdfParams) -> str:
    """One-line human description of KDF params — for status displays."""
    mib = params.memory_cost_kib / 1024
    return f"Argon2id, {mib:.0f} MiB memory, t={params.time_cost}, p={params.parallelism}"
