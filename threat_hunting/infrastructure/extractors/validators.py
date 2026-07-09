"""Indicator validators.

Responsibility
--------------
Provide algorithmic validators that raw regex cannot express, drastically
reducing false-positive indicators:

* :func:`luhn_valid` -- credit-card checksum.
* :func:`cpf_valid` / :func:`cnpj_valid` -- Brazilian document check digits.

These are pure functions with no I/O, kept separate from the extractor so they
can be unit-tested in isolation and reused by the detection engine.
"""

from __future__ import annotations


def _digits(value: str) -> list[int]:
    """Return the numeric digits of ``value`` as integers."""
    return [int(ch) for ch in value if ch.isdigit()]


def ipv4_valid(address: str) -> bool:
    """Return whether ``address`` is a dotted-quad IPv4 with octets in 0-255."""
    parts = address.split(".")
    if len(parts) != 4:
        return False
    for part in parts:
        if not part.isdigit() or not 0 <= int(part) <= 255:
            return False
    return True


def luhn_valid(number: str) -> bool:
    """Return whether ``number`` passes the Luhn checksum (credit cards)."""
    digits = _digits(number)
    if len(digits) < 13:
        return False
    total = 0
    parity = len(digits) % 2
    for index, digit in enumerate(digits):
        if index % 2 == parity:
            digit *= 2
            if digit > 9:
                digit -= 9
        total += digit
    return total % 10 == 0


def cpf_valid(cpf: str) -> bool:
    """Return whether ``cpf`` is a valid Brazilian CPF (11 digits + check)."""
    digits = _digits(cpf)
    if len(digits) != 11 or len(set(digits)) == 1:
        return False
    for check_len in (9, 10):
        weights = range(check_len + 1, 1, -1)
        total = sum(d * w for d, w in zip(digits[:check_len], weights))
        remainder = (total * 10) % 11
        expected = 0 if remainder == 10 else remainder
        if expected != digits[check_len]:
            return False
    return True


def cnpj_valid(cnpj: str) -> bool:
    """Return whether ``cnpj`` is a valid Brazilian CNPJ (14 digits + check)."""
    digits = _digits(cnpj)
    if len(digits) != 14 or len(set(digits)) == 1:
        return False
    first_weights = [5, 4, 3, 2, 9, 8, 7, 6, 5, 4, 3, 2]
    second_weights = [6, 5, 4, 3, 2, 9, 8, 7, 6, 5, 4, 3, 2]
    for weights, position in ((first_weights, 12), (second_weights, 13)):
        total = sum(d * w for d, w in zip(digits, weights))
        remainder = total % 11
        expected = 0 if remainder < 2 else 11 - remainder
        if expected != digits[position]:
            return False
    return True
