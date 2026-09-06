import os
import tempfile
import unittest

from overgrant.catalogue import Combination, load_combinations, load_scopes
from overgrant.evidence import Evidence
from overgrant.findings import Tier
from overgrant.scoring import find_redundant, match_combinations
from tests.test_scoring import make_scope

TWO_SCOPES = """
[[scopes]]
id = "a:one"
short = "A"
grants = "Does a thing"
breadth = "workspace"
mutability = "write"
sensitivity = "none"
source = "https://example.com/one"

[[scopes]]
id = "a:two"
short = "B"
grants = "Does another thing"
breadth = "workspace"
mutability = "read"
sensitivity = "none"
source = "https://example.com/two"
"""

VALID_COMBINATION = """
[[combinations]]
id = "a-pair"
requires = ["a:one", "a:two"]
tier = "high"
rationale = "Together they reach further than either does alone."
caveat = "Capability, not behaviour."
"""


def load_text(toml_text):
    with tempfile.NamedTemporaryFile("wb", suffix=".toml", delete=False) as f:
        f.write(toml_text.encode("utf-8"))
        path = f.name
    try:
        scopes = load_scopes(path)
        return scopes, load_combinations(path, scopes)
    finally:
        os.unlink(path)


class TestCombinationMatching(unittest.TestCase):
    def test_fires_when_both_required_scopes_are_held(self):
        scopes, combinations = load_text(TWO_SCOPES + VALID_COMBINATION)
        findings = match_combinations({"a:one", "a:two"}, scopes, combinations)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].rule, "combination:a-pair")
        self.assertEqual(findings[0].tier, Tier.HIGH)

    def test_does_not_fire_when_only_one_scope_is_held(self):
        scopes, combinations = load_text(TWO_SCOPES + VALID_COMBINATION)
        self.assertEqual(match_combinations({"a:one"}, scopes, combinations), [])
        self.assertEqual(match_combinations({"a:two"}, scopes, combinations), [])

    def test_a_held_scope_satisfies_a_requirement_it_supersedes(self):
        scopes = {
            "a:one": make_scope(id="a:one"),
            "a:two": make_scope(id="a:two"),
            "a:broad": make_scope(id="a:broad", supersedes=["a:two"]),
        }
        combinations = {
            "a-pair": Combination(
                id="a-pair",
                requires=["a:one", "a:two"],
                tier=Tier.HIGH,
                rationale="r",
                caveat="c",
            )
        }
        self.assertEqual(
            len(match_combinations({"a:one", "a:broad"}, scopes, combinations)), 1
        )

        needs_broad = {
            "a-pair": Combination(
                id="a-pair",
                requires=["a:one", "a:broad"],
                tier=Tier.HIGH,
                rationale="r",
                caveat="c",
            )
        }
        self.assertEqual(
            match_combinations({"a:one", "a:two"}, scopes, needs_broad), []
        )

    def test_finding_is_inferred_and_carries_the_caveat(self):
        scopes, combinations = load_text(TWO_SCOPES + VALID_COMBINATION)
        claim = match_combinations({"a:one", "a:two"}, scopes, combinations)[0].claim
        self.assertIs(claim.evidence, Evidence.INFERRED)
        self.assertTrue(claim.caveat.strip())


class TestCombinationLoading(unittest.TestCase):
    def test_missing_or_blank_caveat_raises(self):
        missing = VALID_COMBINATION.replace(
            'caveat = "Capability, not behaviour."\n', ""
        )
        with self.assertRaises(ValueError) as cm:
            load_text(TWO_SCOPES + missing)
        self.assertIn("a-pair", str(cm.exception))

        blank = VALID_COMBINATION.replace('"Capability, not behaviour."', '"   "')
        with self.assertRaises(ValueError) as cm:
            load_text(TWO_SCOPES + blank)
        self.assertIn("caveat", str(cm.exception))

    def test_single_scope_requires_raises(self):
        one = VALID_COMBINATION.replace('["a:one", "a:two"]', '["a:one"]')
        with self.assertRaises(ValueError) as cm:
            load_text(TWO_SCOPES + one)
        self.assertIn("a-pair", str(cm.exception))

    def test_requires_naming_an_unknown_scope_raises(self):
        ghost = VALID_COMBINATION.replace('"a:two"', '"a:ghost"')
        with self.assertRaises(ValueError) as cm:
            load_text(TWO_SCOPES + ghost)
        self.assertIn("unknown scope 'a:ghost'", str(cm.exception))


class TestRedundancy(unittest.TestCase):
    def test_fires_for_a_superseded_scope_held_alongside_its_broader_one(self):
        scopes = {
            "drive": make_scope(id="drive", supersedes=["drive.readonly"]),
            "drive.readonly": make_scope(id="drive.readonly"),
        }
        findings = find_redundant({"drive", "drive.readonly"}, scopes)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].tier, Tier.LOW)
        self.assertEqual(findings[0].scopes, ["drive.readonly", "drive"])

    def test_does_not_fire_for_two_unrelated_scopes(self):
        scopes = {
            "a:one": make_scope(id="a:one"),
            "a:two": make_scope(id="a:two"),
        }
        self.assertEqual(find_redundant({"a:one", "a:two"}, scopes), [])


if __name__ == "__main__":
    unittest.main()
