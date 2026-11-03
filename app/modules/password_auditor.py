"""Local password strength auditor. Never stores or transmits passwords."""
from __future__ import annotations

import math
import re
from dataclasses import asdict, dataclass


COMMON = {
    "password", "password1", "123456", "12345678", "qwerty", "abc123",
    "letmein", "admin", "welcome", "monkey", "dragon", "master", "login",
    "passw0rd", "iloveyou", "sunshine", "princess", "football", "baseball",
}


@dataclass
class PasswordReport:
    length: int
    score: int  # 0-100
    label: str
    entropy_bits_est: float
    has_lower: bool
    has_upper: bool
    has_digit: bool
    has_symbol: bool
    is_common: bool
    suggestions: list[str]

    def to_dict(self) -> dict:
        return asdict(self)


def audit_password(password: str) -> PasswordReport:
    # Work only on the provided string in-memory; caller must not log it.
    length = len(password)
    has_lower = bool(re.search(r"[a-z]", password))
    has_upper = bool(re.search(r"[A-Z]", password))
    has_digit = bool(re.search(r"\d", password))
    has_symbol = bool(re.search(r"[^A-Za-z0-9]", password))
    is_common = password.lower() in COMMON

    charset = 0
    if has_lower:
        charset += 26
    if has_upper:
        charset += 26
    if has_digit:
        charset += 10
    if has_symbol:
        charset += 33
    entropy = length * math.log2(charset) if charset and length else 0.0

    score = 0
    if length >= 8:
        score += 15
    if length >= 12:
        score += 15
    if length >= 16:
        score += 10
    if has_lower:
        score += 10
    if has_upper:
        score += 10
    if has_digit:
        score += 10
    if has_symbol:
        score += 15
    if entropy >= 50:
        score += 10
    if entropy >= 80:
        score += 5
    if is_common:
        score = min(score, 15)
    if length < 6:
        score = min(score, 20)
    score = max(0, min(100, score))

    if score < 30:
        label = "Very weak"
    elif score < 50:
        label = "Weak"
    elif score < 70:
        label = "Fair"
    elif score < 85:
        label = "Strong"
    else:
        label = "Very strong"

    suggestions: list[str] = []
    if length < 12:
        suggestions.append("Use at least 12 characters.")
    if not has_upper:
        suggestions.append("Add uppercase letters.")
    if not has_lower:
        suggestions.append("Add lowercase letters.")
    if not has_digit:
        suggestions.append("Add digits.")
    if not has_symbol:
        suggestions.append("Add symbols (e.g. !@#).")
    if is_common:
        suggestions.append("Avoid common passwords and dictionary words.")
    if re.search(r"(.)\1{2,}", password):
        suggestions.append("Avoid long repeated characters.")
    if not suggestions and score < 85:
        suggestions.append("Consider a longer passphrase of random words.")

    return PasswordReport(
        length=length,
        score=score,
        label=label,
        entropy_bits_est=round(entropy, 1),
        has_lower=has_lower,
        has_upper=has_upper,
        has_digit=has_digit,
        has_symbol=has_symbol,
        is_common=is_common,
        suggestions=suggestions,
    )
