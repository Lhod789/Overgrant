import json
import unittest
from pathlib import Path

from overgrant import catalogue
from overgrant.assessment import assess
from overgrant.catalogue import load_combinations, load_scopes
from overgrant.egress import build_map, capture_window, load_har
from overgrant.report import render_egress_json, render_json

SLACK = Path(catalogue.__file__).parent / "data" / "slack.toml"

TOP_LEVEL_KEYS = {"tool", "version", "provider", "source", "grant_sets"}
GRANT_SET_KEYS = {"label", "granted", "unrecognised", "worst", "counts", "findings"}
FINDING_KEYS = {"tier", "rule", "title", "detail", "scopes", "evidence", "caveat"}


class TestJsonSchemaIsStable(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        scopes = load_scopes(SLACK)
        combinations = load_combinations(SLACK, scopes)
        cls.document = json.loads(
            render_json(
                [
                    assess(set(scopes), scopes, combinations, "slack", label="bot"),
                    assess(
                        {"channels:history"},
                        scopes,
                        combinations,
                        "slack",
                        label="user",
                    ),
                ],
                source="tests",
            )
        )

    def test_top_level_keys_are_exactly_the_contract(self):
        self.assertEqual(set(self.document), TOP_LEVEL_KEYS)

    def test_each_grant_set_carries_the_contract_keys(self):
        self.assertEqual(len(self.document["grant_sets"]), 2)
        for grant_set in self.document["grant_sets"]:
            with self.subTest(label=grant_set["label"]):
                self.assertEqual(set(grant_set), GRANT_SET_KEYS)

    def test_each_finding_carries_the_contract_keys(self):
        findings = [f for s in self.document["grant_sets"] for f in s["findings"]]
        self.assertTrue(findings, "fixture produced no findings to check")
        for finding in findings:
            with self.subTest(rule=finding["rule"]):
                self.assertEqual(set(finding), FINDING_KEYS)

    def test_every_tier_value_is_lowercase(self):
        for grant_set in self.document["grant_sets"]:
            with self.subTest(label=grant_set["label"]):
                worst = grant_set["worst"]
                if worst is not None:
                    self.assertIn(worst, grant_set["counts"])
                for finding in grant_set["findings"]:
                    self.assertEqual(finding["tier"], finding["tier"].lower())


EGRESS_TOP_LEVEL_KEYS = {"tool", "version", "source", "window", "vendors"}
EGRESS_WINDOW_KEYS = {"start", "end", "duration_seconds"}
EGRESS_VENDOR_KEYS = {"vendor", "hosts", "paths", "requests", "detections"}

HAR = Path(catalogue.__file__).parent.parent / "examples" / "notes-bot.synthetic.har"


class TestEgressJsonSchemaIsStable(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.document = json.loads(
            render_egress_json(
                build_map(load_har(HAR)),
                source="tests",
                window=capture_window(load_har(HAR)),
            )
        )

    def test_top_level_keys_are_exactly_the_contract(self):
        self.assertEqual(set(self.document), EGRESS_TOP_LEVEL_KEYS)

    def test_the_window_carries_the_contract_keys(self):
        self.assertEqual(set(self.document["window"]), EGRESS_WINDOW_KEYS)
        self.assertIsNotNone(self.document["window"]["start"])

    def test_each_vendor_carries_the_contract_keys(self):
        self.assertEqual(len(self.document["vendors"]), 2)
        for vendor in self.document["vendors"]:
            with self.subTest(vendor=vendor["vendor"]):
                self.assertEqual(set(vendor), EGRESS_VENDOR_KEYS)


if __name__ == "__main__":
    unittest.main()
