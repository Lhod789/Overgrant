import unittest
from pathlib import Path

from overgrant import catalogue
from overgrant.assessment import assess
from overgrant.catalogue import load_combinations, load_scopes
from overgrant.evidence import Evidence
from overgrant.report import WIDTH, render_text

GOOGLE = Path(catalogue.__file__).parent / "data" / "google.toml"
UNKNOWN_SCOPE = "https://www.googleapis.com/auth/nonsense"


def normalise(text):
    return " ".join(text.split())


class TestTextReport(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        scopes = load_scopes(GOOGLE)
        combinations = load_combinations(GOOGLE, scopes)
        cls.assessment = assess(
            set(scopes) | {UNKNOWN_SCOPE}, scopes, combinations, "google"
        )
        cls.output = render_text([cls.assessment])
        cls.lines = cls.output.splitlines()

    def test_every_granted_scope_id_survives_on_one_line(self):
        for scope_id in self.assessment.granted:
            with self.subTest(scope=scope_id):
                self.assertTrue(
                    any(scope_id in line for line in self.lines),
                    f"{scope_id} does not appear unbroken on any line",
                )

    def test_no_line_exceeds_the_report_width(self):
        too_long = [line for line in self.lines if len(line) > WIDTH]
        self.assertEqual(
            too_long, [], f"{len(too_long)} line(s) longer than {WIDTH} columns"
        )

    def test_every_inferred_caveat_appears_in_full(self):
        flat = normalise(self.output)
        inferred = [
            f for f in self.assessment.findings if f.claim.evidence is Evidence.INFERRED
        ]
        self.assertTrue(inferred, "fixture produced no INFERRED findings to check")
        for finding in inferred:
            with self.subTest(rule=finding.rule):
                self.assertIn(normalise(finding.claim.caveat), flat)

    def test_unrecognised_scopes_appear_as_unassessed(self):
        self.assertIn("Unassessed scopes", self.output)
        self.assertIn(UNKNOWN_SCOPE, self.output)

    def test_limitations_footer_is_present(self):
        self.assertIn("Limitations", self.output)
        self.assertIn(
            "describes what the integration is permitted to do, not what it has done",
            normalise(self.output),
        )


class TestMultipleGrantSets(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        scopes = load_scopes(GOOGLE)
        combinations = load_combinations(GOOGLE, scopes)
        cls.assessments = [
            assess(set(scopes), scopes, combinations, "google", label="bot"),
            assess(
                set(sorted(scopes)[:2]), scopes, combinations, "google", label="user"
            ),
        ]
        cls.output = render_text(cls.assessments)
        cls.lines = cls.output.splitlines()

    def test_both_grant_sets_appear_as_section_headings(self):
        for assessment in self.assessments:
            with self.subTest(label=assessment.label):
                self.assertIn(f"Grant set: {assessment.label}", self.lines)

    def test_limitations_footer_appears_exactly_once(self):
        boilerplate = "describes what the integration is permitted to do"
        self.assertEqual(normalise(self.output).count(boilerplate), 1)
