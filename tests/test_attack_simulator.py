import unittest

from cyber_toolkit.modules.attack_simulator import AttackSimulator


class TestAttackSimulator(unittest.TestCase):
    def test_estimate(self):
        result = AttackSimulator.estimate(length=8, charset_size=10, attempts_per_second=100)
        self.assertEqual(result.combinations, 100000000)
        self.assertGreater(result.estimated_seconds, 0)

    def test_strength(self):
        strength = AttackSimulator.password_strength("Abc123!xyz")
        self.assertIn(strength["label"], {"Medium", "Strong", "Very strong"})


if __name__ == "__main__":
    unittest.main()

