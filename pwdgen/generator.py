"""Generation built on `secrets` only - never `random`."""

from __future__ import annotations

import secrets
import string
from dataclasses import dataclass, field

from .wordlist import WORDS

LOWER = string.ascii_lowercase
UPPER = string.ascii_uppercase
DIGITS = string.digits
SYMBOLS = "!@#$%^&*()-_=+[]{};:,.?"
AMBIGUOUS = "O0oIl1|`'\""


@dataclass(slots=True)
class Charset:
    lower: bool = True
    upper: bool = True
    digits: bool = True
    symbols: bool = True
    exclude_ambiguous: bool = False

    def alphabet(self) -> str:
        pools = []
        if self.lower:
            pools.append(LOWER)
        if self.upper:
            pools.append(UPPER)
        if self.digits:
            pools.append(DIGITS)
        if self.symbols:
            pools.append(SYMBOLS)
        alphabet = "".join(pools)
        if self.exclude_ambiguous:
            alphabet = "".join(c for c in alphabet if c not in AMBIGUOUS)
        return alphabet


def generate(length: int = 16, charset: Charset | None = None) -> str:
    """Uniformly random password that contains at least one character per enabled pool."""
    if length < 4:
        raise ValueError("length must be at least 4")
    charset = charset or Charset()
    pools = [
        p
        for p, on in (
            (LOWER, charset.lower),
            (UPPER, charset.upper),
            (DIGITS, charset.digits),
            (SYMBOLS, charset.symbols),
        )
        if on
    ]
    if not pools:
        raise ValueError("at least one character class must be enabled")
    if charset.exclude_ambiguous:
        pools = ["".join(c for c in p if c not in AMBIGUOUS) for p in pools]

    # Guarantee one character from each pool, fill the rest, then shuffle.
    chars = [secrets.choice(pool) for pool in pools]
    alphabet = "".join(pools)
    chars += [secrets.choice(alphabet) for _ in range(length - len(chars))]
    secrets.SystemRandom().shuffle(chars)
    return "".join(chars)


def generate_passphrase(words: int = 5, separator: str = "-", *, capitalise: bool = False) -> str:
    if words < 3:
        raise ValueError("use at least 3 words; below that entropy is too low")
    chosen = [secrets.choice(WORDS) for _ in range(words)]
    if capitalise:
        chosen = [w.capitalize() for w in chosen]
    return separator.join(chosen)


def generate_pin(digits: int = 6) -> str:
    if digits < 4:
        raise ValueError("a PIN shorter than 4 digits is not acceptable")
    return "".join(secrets.choice(DIGITS) for _ in range(digits))


@dataclass(slots=True)
class Policy:
    min_length: int = 12
    require_lower: bool = True
    require_upper: bool = True
    require_digit: bool = True
    require_symbol: bool = False
    forbid_ambiguous: bool = False

    def violations(self, password: str) -> list[str]:
        problems: list[str] = []
        if len(password) < self.min_length:
            problems.append(f"shorter than {self.min_length} characters")
        if self.require_lower and not any(c.islower() for c in password):
            problems.append("missing a lowercase letter")
        if self.require_upper and not any(c.isupper() for c in password):
            problems.append("missing an uppercase letter")
        if self.require_digit and not any(c.isdigit() for c in password):
            problems.append("missing a digit")
        if self.require_symbol and not any(c in SYMBOLS for c in password):
            problems.append("missing a symbol")
        if self.forbid_ambiguous and any(c in AMBIGUOUS for c in password):
            problems.append("contains an ambiguous character")
        return problems

    def complies(self, password: str) -> bool:
        return not self.violations(password)


def generate_for_policy(policy: Policy, *, attempts: int = 50) -> str:
    """Regenerate until the policy is met - the pools guarantee it is reachable."""
    length = max(policy.min_length, 12)
    for _ in range(attempts):
        candidate = generate(
            length,
            Charset(
                lower=True,
                upper=policy.require_upper,
                digits=policy.require_digit,
                symbols=policy.require_symbol,
                exclude_ambiguous=policy.forbid_ambiguous,
            ),
        )
        if policy.complies(candidate):
            return candidate
    raise RuntimeError("could not satisfy the policy; relax it")
