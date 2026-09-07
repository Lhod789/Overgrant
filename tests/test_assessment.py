import unittest
from pathlib import Path

from overgrant import catalogue
from overgrant.assessment import assess
from overgrant.catalogue import load_combinations, load_scopes

GOOGLE = Path(catalogue.__file__).parent / "data" / "google.toml"


class TestAssessmentLabel(unittest.TestCase):
    def test_label_reaches_the_assessment(self):
        scopes = load_scopes(GOOGLE)
        combinations = load_combinations(GOOGLE, scopes)
        assessment = assess(set(scopes), scopes, combinations, "google", label="bot")
        self.assertEqual(assessment.label, "bot")


if __name__ == "__main__":
    unittest.main()
