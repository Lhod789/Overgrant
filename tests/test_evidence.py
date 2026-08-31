import unittest

from overgrant.evidence import Claim, Evidence


class TestClaim(unittest.TestCase):
    def test_inferred_without_caveat_raises(self):
        with self.assertRaises(ValueError):
            Claim("scope is unused", Evidence.INFERRED, "manifest.json")

    def test_inferred_with_empty_caveat_raises(self):
        with self.assertRaises(ValueError):
            Claim("scope is unused", Evidence.INFERRED, "manifest.json", caveat="")

    def test_inferred_with_real_caveat_constructs(self):
        claim = Claim(
            "scope is unused",
            Evidence.INFERRED,
            "manifest.json",
            caveat="No references to scope were observed.",
        )
        self.assertEqual(claim.caveat, "No references to scope were observed.")


if __name__ == "__main__":
    unittest.main()
