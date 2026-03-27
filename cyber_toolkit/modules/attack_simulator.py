import math
from dataclasses import dataclass


@dataclass
class AttackEstimate:
    entropy_bits: float
    combinations: int
    attempts_per_second: int
    estimated_seconds: float
    success_probability_24h: float


class AttackSimulator:
    """Ethical estimator: computes brute-force feasibility without attacking targets."""

    @staticmethod
    def estimate(length: int, charset_size: int, attempts_per_second: int = 100_000) -> AttackEstimate:
        if length <= 0 or charset_size <= 1 or attempts_per_second <= 0:
            raise ValueError("Invalid simulation parameters")
        combinations = charset_size ** length
        entropy_bits = length * math.log2(charset_size)
        estimated_seconds = combinations / attempts_per_second
        attempts_day = attempts_per_second * 86_400
        success_probability_24h = min(1.0, attempts_day / combinations)
        return AttackEstimate(
            entropy_bits=entropy_bits,
            combinations=combinations,
            attempts_per_second=attempts_per_second,
            estimated_seconds=estimated_seconds,
            success_probability_24h=success_probability_24h,
        )

    @staticmethod
    def password_strength(password: str) -> dict:
        if not password:
            return {"score": 0, "label": "Very weak", "entropy_bits": 0.0}

        pools = 0
        if any(c.islower() for c in password):
            pools += 26
        if any(c.isupper() for c in password):
            pools += 26
        if any(c.isdigit() for c in password):
            pools += 10
        if any(not c.isalnum() for c in password):
            pools += 32

        pools = max(pools, 1)
        entropy = len(password) * math.log2(pools)
        if entropy < 35:
            score, label = 1, "Weak"
        elif entropy < 59:
            score, label = 2, "Medium"
        elif entropy < 80:
            score, label = 3, "Strong"
        else:
            score, label = 4, "Very strong"

        return {"score": score, "label": label, "entropy_bits": round(entropy, 2)}

