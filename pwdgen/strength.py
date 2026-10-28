"""Entropy, crack-time estimation and a tiny deny-list."""

from __future__ import annotations

import math
import re

COMMON = frozenset(
    """
    password 123456 123456789 qwerty abc123 password1 iloveyou admin welcome
    letmein monkey dragon football baseball master sunshine princess shadow
    superman michael jennifer trustno1 passw0rd p@ssw0rd 111111 000000
    """.split()
)

GUESSES_PER_SECOND = 1e10  # a modern offline attack against a fast hash


def shannon_entropy(password: str) -> float:
    """Entropy of the observed characters - reflects the password itself, not its space."""
    if not password:
        return 0.0
    counts = {c: password.count(c) for c in set(password)}
    total = len(password)
    return -sum((n / total) * math.log2(n / total) for n in counts.values()) * total


def keyspace_bits(password: str) -> float:
    """Upper bound: length x log2(alphabet actually used)."""
    pool = 0
    if re.search(r"[a-z]", password):
        pool += 26
    if re.search(r"[A-Z]", password):
        pool += 26
    if re.search(r"\d", password):
        pool += 10
    if re.search(r"[^A-Za-z0-9]", password):
        pool += 33
    return len(password) * math.log2(pool) if pool else 0.0


def crack_time_seconds(bits: float) -> float:
    return 2 ** bits / GUESSES_PER_SECOND


def humanise_seconds(seconds: float) -> str:
    if seconds < 1:
        return "instantly"
    units = [
        ("second", 60),
        ("minute", 60),
        ("hour", 24),
        ("day", 365),
        ("year", 100),
        ("century", 10),
        ("millennium", 1000),
    ]
    value = seconds
    for name, factor in units:
        if value < factor:
            return f"{value:.0f} {name}{'s' if value >= 2 else ''}"
        value /= factor
    return f"{value * 1000:.0f} millennia"


def score(password: str) -> tuple[int, str]:
    """0-4 with a label, loosely modelled on zxcvbn's shape but far simpler."""
    if not password:
        return 0, "empty"
    if password.lower() in COMMON or re.fullmatch(r"(.)\1*", password):
        return 0, "common or repeated"
    bits = keyspace_bits(password)
    if password.lower() in COMMON:
        return 0, "common"
    penalties = 0
    if re.search(r"(abc|123|qwerty|password)", password.lower()):
        penalties += 12
    if re.fullmatch(r"[a-z]+", password):
        penalties += 6
    if len(set(password)) <= 3:
        penalties += 10
    effective = bits - penalties
    if effective < 28:
        return 1, "very weak"
    if effective < 40:
        return 2, "weak"
    if effective < 60:
        return 3, "reasonable"
    return 4, "strong"


def audit(password: str) -> dict[str, object]:
    bits = keyspace_bits(password)
    rating, label = score(password)
    return {
        "length": len(password),
        "classes": sum(
            bool(re.search(p, password))
            for p in (r"[a-z]", r"[A-Z]", r"\d", r"[^A-Za-z0-9]")
        ),
        "keyspace_bits": round(bits, 1),
        "shannon_bits": round(shannon_entropy(password), 1),
        "crack_time": humanise_seconds(crack_time_seconds(bits)),
        "score": rating,
        "label": label,
        "is_common": password.lower() in COMMON,
    }
