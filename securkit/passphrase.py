"""Passphrase coaching: suggest diceware-style passphrases and estimate strength.

Word selection uses `secrets.choice` (CSPRNG). Strength estimation uses zxcvbn,
which catches common patterns (keyboard walks, common substitutions, dates)
that naive entropy-by-charset metrics miss.
"""

from __future__ import annotations

import math
import secrets
from dataclasses import dataclass
from typing import Literal

from zxcvbn import zxcvbn

# 256 simple, common English words: 3-7 chars, no homophones, no ambiguity.
# 256 = 2^8 → exactly 8 bits of entropy per word with secrets.choice.
# 7 words ≈ 56 bits; 8 words ≈ 64 bits.
WORDS: tuple[str, ...] = (
    # animals (32)
    "cat", "dog", "fox", "bear", "wolf", "deer", "hawk", "owl",
    "fish", "frog", "duck", "swan", "crow", "mouse", "sheep", "horse",
    "otter", "badger", "eagle", "rabbit", "snail", "snake", "tiger", "whale",
    "zebra", "koala", "lion", "lamb", "mole", "finch", "robin", "raven",
    # nature (32)
    "tree", "rock", "leaf", "moss", "sand", "stone", "river", "lake",
    "hill", "cliff", "beach", "cave", "peak", "ridge", "brook", "creek",
    "dune", "field", "forest", "marsh", "valley", "glade", "pond", "wave",
    "cloud", "rain", "snow", "frost", "mist", "storm", "star", "moon",
    # plants and food (32)
    "apple", "peach", "plum", "pear", "grape", "lemon", "lime", "mint",
    "sage", "basil", "thyme", "clove", "ginger", "honey", "bread", "cheese",
    "olive", "onion", "melon", "berry", "oat", "rice", "bean", "corn",
    "walnut", "almond", "maple", "oak", "pine", "fern", "rose", "lily",
    # colors and materials (32)
    "red", "blue", "green", "gold", "silver", "copper", "iron", "steel",
    "brass", "glass", "paper", "cloth", "wool", "silk", "linen", "brick",
    "clay", "marble", "wood", "ivory", "pearl", "jade", "amber", "ruby",
    "opal", "coral", "ash", "ember", "smoke", "flame", "spark", "ice",
    # tools and objects (32)
    "hammer", "nail", "rope", "knife", "spoon", "fork", "bowl", "plate",
    "cup", "kettle", "lamp", "candle", "mirror", "brush", "comb", "broom",
    "anchor", "boat", "oar", "paddle", "drum", "flute", "harp", "bell",
    "clock", "watch", "key", "lock", "chest", "basket", "ladder", "bridge",
    # buildings (16)
    "house", "barn", "shed", "tower", "castle", "manor", "cabin", "hut",
    "dome", "vault", "hall", "gate", "arch", "wall", "attic", "porch",
    # body (16)
    "hand", "foot", "eye", "ear", "nose", "lip", "hair", "brow",
    "palm", "thumb", "knee", "ankle", "elbow", "wrist", "chin", "heart",
    # actions (32)
    "walk", "run", "jump", "swim", "sing", "dance", "sleep", "dream",
    "smile", "laugh", "shout", "climb", "build", "grow", "bloom", "drift",
    "ride", "write", "read", "draw", "paint", "cook", "bake", "plant",
    "learn", "teach", "listen", "find", "carry", "weave", "carve", "forge",
    # qualities (32)
    "hope", "peace", "joy", "calm", "brave", "quiet", "kind", "bright",
    "dark", "sharp", "smooth", "soft", "warm", "cool", "light", "swift",
    "slow", "deep", "wide", "tall", "short", "plain", "fair", "true",
    "free", "wild", "rare", "fresh", "clean", "simple", "gentle", "noble",
)

assert len(WORDS) == 256, f"wordlist must be exactly 256 entries, got {len(WORDS)}"
assert len(set(WORDS)) == 256, "wordlist contains duplicates"

BITS_PER_WORD = math.log2(len(WORDS))  # 8.0


StrengthLabel = Literal["very weak", "weak", "fair", "strong", "very strong"]


@dataclass(frozen=True)
class StrengthReport:
    score: int  # 0..4, from zxcvbn
    label: StrengthLabel
    crack_time_human: str  # e.g. "centuries", "3 hours"
    bits: float  # log2(guesses)
    suggestions: tuple[str, ...]  # actionable advice for the user
    warning: str  # zxcvbn's headline warning, may be empty


_LABELS: dict[int, StrengthLabel] = {
    0: "very weak",
    1: "weak",
    2: "fair",
    3: "strong",
    4: "very strong",
}


def suggest(n_words: int = 7, separator: str = "-") -> str:
    """Return a diceware-style passphrase. 7 words = 56 bits of entropy.

    Words are drawn from a 256-word list using a CSPRNG. The separator defaults
    to '-' for safer copy/paste (no whitespace splitting in shells / forms).
    """
    if n_words < 1:
        raise ValueError("n_words must be >= 1")
    chosen = [secrets.choice(WORDS) for _ in range(n_words)]
    return separator.join(chosen)


def suggestion_bits(n_words: int) -> float:
    return n_words * BITS_PER_WORD


def estimate_strength(passphrase: str) -> StrengthReport:
    """Wrap zxcvbn into a stable StrengthReport. Empty passphrase = score 0."""
    if not passphrase:
        return StrengthReport(
            score=0,
            label="very weak",
            crack_time_human="instant",
            bits=0.0,
            suggestions=("Type something.",),
            warning="Empty passphrase",
        )
    result = zxcvbn(passphrase)
    score = int(result["score"])
    guesses = float(result["guesses"])
    bits = math.log2(guesses) if guesses > 1 else 0.0
    feedback = result.get("feedback", {}) or {}
    return StrengthReport(
        score=score,
        label=_LABELS[score],
        crack_time_human=str(
            result["crack_times_display"]["offline_slow_hashing_1e4_per_second"]
        ),
        bits=bits,
        suggestions=tuple(feedback.get("suggestions") or ()),
        warning=str(feedback.get("warning") or ""),
    )
