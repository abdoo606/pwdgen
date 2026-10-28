from __future__ import annotations

import string

import pytest

from pwdgen.generator import (
    AMBIGUOUS,
    Charset,
    Policy,
    generate,
    generate_for_policy,
    generate_passphrase,
    generate_pin,
)
from pwdgen.strength import audit, crack_time_seconds, keyspace_bits, score, shannon_entropy
from pwdgen.wordlist import WORDS


# -------------------------------------------------------------- generator
def test_length_is_exactly_respected():
    for length in (8, 16, 33, 64):
        assert len(generate(length)) == length


def test_every_enabled_class_appears():
    for _ in range(30):
        pwd = generate(12)
        assert any(c.islower() for c in pwd)
        assert any(c.isupper() for c in pwd)
        assert any(c.isdigit() for c in pwd)
        assert any(c in string.punctuation or c in "!@#$%^&*()-_=+[]{};:,.?" for c in pwd)


def test_disabled_classes_are_absent():
    pwd = generate(20, Charset(lower=True, upper=False, digits=False, symbols=False))
    assert pwd.islower()


def test_ambiguous_characters_can_be_removed():
    pwd = generate(40, Charset(exclude_ambiguous=True))
    assert not (set(pwd) & set(AMBIGUOUS))


def test_rejects_impossible_lengths():
    with pytest.raises(ValueError, match="at least 4"):
        generate(3)
    with pytest.raises(ValueError, match="at least one character class"):
        generate(10, Charset(lower=False, upper=False, digits=False, symbols=False))


def test_minimum_length_still_guarantees_all_classes():
    pwd = generate(4, Charset())
    assert len(pwd) == 4
    assert any(c.isupper() for c in pwd) and any(c.isdigit() for c in pwd)


def test_passwords_are_not_repeated():
    """Sanity check that we are not accidentally using a seeded PRNG."""
    assert len({generate(16) for _ in range(200)}) == 200


def test_passphrase_shape():
    phrase = generate_passphrase(4, "_")
    parts = phrase.split("_")
    assert len(parts) == 4
    assert all(p in WORDS for p in parts)


def test_passphrase_rejects_short_input():
    with pytest.raises(ValueError, match="at least 3"):
        generate_passphrase(2)


def test_passphrase_capitalisation():
    assert all(p[0].isupper() for p in generate_passphrase(3, "-", capitalise=True).split("-"))


def test_pin():
    pin = generate_pin(8)
    assert pin.isdigit() and len(pin) == 8
    with pytest.raises(ValueError):
        generate_pin(3)


# ----------------------------------------------------------------- policy
def test_policy_flags_each_violation():
    policy = Policy(min_length=10, require_symbol=True)
    problems = policy.violations("abc")
    assert any("shorter" in p for p in problems)
    assert any("uppercase" in p for p in problems)
    assert any("symbol" in p for p in problems)


def test_policy_accepts_compliant_password():
    assert Policy().complies("Tr0ub4dor&3xyz")


def test_generated_password_always_satisfies_policy():
    policy = Policy(min_length=14, require_symbol=True, forbid_ambiguous=True)
    for _ in range(20):
        assert policy.complies(generate_for_policy(policy))


# --------------------------------------------------------------- strength
def test_keyspace_grows_with_classes():
    assert keyspace_bits("aaaaaaaa") < keyspace_bits("aA1!aA1!")


def test_empty_input_is_safe():
    assert keyspace_bits("") == 0
    assert shannon_entropy("") == 0.0


def test_common_passwords_score_zero():
    assert score("password")[0] == 0
    assert score("111111")[0] == 0
    assert audit("qwerty")["is_common"] is True


def test_strong_password_scores_four():
    assert score("kR7#mQ2$xL9!vB4@")[0] == 4


def test_sequence_penalty():
    assert score("abcdefghijkl")[0] < 4


def test_crack_time_monotonic():
    assert crack_time_seconds(20) < crack_time_seconds(60)


def test_audit_fields():
    result = audit("kR7#mQ2$xL9!vB4@")
    assert result["length"] == 16
    assert result["classes"] == 4
    assert result["score"] == 4
    assert isinstance(result["crack_time"], str)


def test_wordlist_is_clean():
    assert len(WORDS) > 100
    assert len(set(WORDS)) == len(WORDS)
    assert all(w.isalpha() and w.islower() for w in WORDS)


def test_wordlist_entropy_is_documented_behaviour():
    import math

    assert math.log2(len(WORDS)) > 6
