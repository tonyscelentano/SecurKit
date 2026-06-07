"""Passphrase suggestion + strength estimation."""

from __future__ import annotations

from securkit.passphrase import (
    BITS_PER_WORD,
    WORDS,
    estimate_strength,
    suggest,
    suggestion_bits,
)


def test_wordlist_size_and_uniqueness() -> None:
    assert len(WORDS) == 256
    assert len(set(WORDS)) == 256
    assert BITS_PER_WORD == 8.0


def test_wordlist_words_are_reasonable() -> None:
    for w in WORDS:
        assert w.isascii() and w.isalpha() and w.islower(), f"bad word: {w!r}"
        assert 2 <= len(w) <= 8, f"word length suspicious: {w!r}"


def test_suggest_default_shape() -> None:
    pw = suggest()
    parts = pw.split("-")
    assert len(parts) == 7
    for p in parts:
        assert p in WORDS


def test_suggest_custom_separator() -> None:
    pw = suggest(n_words=4, separator=" ")
    assert len(pw.split(" ")) == 4


def test_suggest_distinct_across_calls() -> None:
    # Vanishingly unlikely to collide: collision odds ~ 2^-56 per pair.
    samples = {suggest() for _ in range(20)}
    assert len(samples) == 20


def test_suggestion_bits() -> None:
    assert suggestion_bits(7) == 56.0
    assert suggestion_bits(8) == 64.0


def test_estimate_strength_empty() -> None:
    r = estimate_strength("")
    assert r.score == 0
    assert r.label == "very weak"
    assert r.bits == 0.0


def test_estimate_strength_buckets() -> None:
    # Don't pin to specific scores (zxcvbn versions vary slightly); just verify
    # that weak < strong and that the suggested passphrases land high.
    weak = estimate_strength("password")
    common = estimate_strength("Password123!")
    strong = estimate_strength(suggest(n_words=8))

    assert weak.score <= 1
    assert common.score <= 2, "zxcvbn must catch common passwords"
    assert strong.score >= 3
    assert strong.bits > weak.bits


def test_estimate_strength_has_feedback_on_weak() -> None:
    r = estimate_strength("password")
    assert r.warning or r.suggestions, "weak passphrase should have feedback"
