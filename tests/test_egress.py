import json
import tempfile
import unittest
from pathlib import Path

from overgrant.egress import (
    UNKNOWN_VENDOR,
    Confidence,
    Detection,
    detect,
    load_har,
    normalise_path,
    resolve_vendor,
    scrub_har,
    build_map,
)

FIXTURE = (
    Path(__file__).resolve().parent.parent / "examples" / "notes-bot.synthetic.har"
)
FAKE_TOKEN = "xoxb-0000-FAKE-TOKEN-FOR-TESTS"


class TestScrub(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.raw = json.loads(FIXTURE.read_text(encoding="utf-8"))
        cls.scrubbed = scrub_har(cls.raw)

    def test_the_token_survives_nowhere_in_the_output(self):
        self.assertIn(FAKE_TOKEN, json.dumps(self.raw))
        self.assertNotIn(FAKE_TOKEN, json.dumps(self.scrubbed))

    def test_the_scrubbed_file_still_loads(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "scrubbed.har"
            path.write_text(json.dumps(self.scrubbed), encoding="utf-8")
            self.assertEqual(len(load_har(path)), len(load_har(FIXTURE)))


class TestNormalisePath(unittest.TestCase):
    def test_a_uuid_segment_collapses(self):
        self.assertEqual(
            normalise_path("/v1/users/8f2c9a1b-4d3e-4f21-9c8a-1b2c3d4e5f60/notes"),
            "/v1/users/:id/notes",
        )

    def test_a_numeric_segment_collapses(self):
        self.assertEqual(normalise_path("/v1/notes/12345"), "/v1/notes/:id")

    def test_a_long_hex_segment_collapses(self):
        self.assertEqual(
            normalise_path("/files/9f86d081884c7d659a2feaa0c55ad015"), "/files/:id"
        )

    def test_several_ids_in_one_path_all_collapse(self):
        self.assertEqual(
            normalise_path("/v1/teams/42/users/7/notes"),
            "/v1/teams/:id/users/:id/notes",
        )

    def test_a_dotted_method_path_is_untouched(self):
        self.assertEqual(
            normalise_path("/api/conversations.history"), "/api/conversations.history"
        )

    def test_an_unrecognised_id_shape_is_left_alone(self):
        self.assertEqual(
            normalise_path("/v2/teams/T0FAKE/channels"), "/v2/teams/T0FAKE/channels"
        )


class TestResolveVendor(unittest.TestCase):
    def test_a_known_host_resolves(self):
        self.assertEqual(resolve_vendor("slack.com"), "Slack")

    def test_a_subdomain_resolves_to_the_same_vendor(self):
        self.assertEqual(resolve_vendor("api.slack.com"), "Slack")

    def test_an_unknown_host_is_never_guessed(self):
        self.assertEqual(resolve_vendor("telemetry.notesbot.example"), UNKNOWN_VENDOR)


class TestDetectors(unittest.TestCase):
    def test_an_email_address_in_a_body_is_detected(self):
        found = detect({}, '{"user": "dana.olsen@notesbot.example"}')
        self.assertEqual([d.kind for d in found], ["email_address"])
        self.assertEqual(found[0].count, 1)

    def test_a_bearer_token_in_a_header_is_detected(self):
        found = detect({"authorization": "Bearer xoxb-0000-FAKE-TOKEN-FOR-TESTS"})
        self.assertEqual([d.kind for d in found], ["credential"])

    def test_clean_traffic_detects_nothing(self):
        self.assertEqual(
            detect({"content-type": "application/json"}, '{"ok": true}'), []
        )

    def test_a_detection_cannot_record_zero_matches(self):
        with self.assertRaises(ValueError):
            Detection("email_address", Confidence.HIGH, 0)


class TestEgressMap(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.rows = build_map(load_har(FIXTURE))
        cls.by_vendor = {row["vendor"]: row for row in cls.rows}

    def test_hosts_collapse_to_vendors(self):
        self.assertEqual(len(self.by_vendor["Slack"]["paths"]), 2)
        self.assertEqual(
            self.by_vendor[UNKNOWN_VENDOR]["hosts"], ["telemetry.notesbot.example"]
        )

    def test_the_unknown_vendor_carries_its_detection_kinds(self):
        self.assertEqual(
            sorted(self.by_vendor[UNKNOWN_VENDOR]["detections"]),
            ["credential", "email_address"],
        )

    def test_the_map_cannot_carry_the_matched_value(self):
        self.assertNotIn(FAKE_TOKEN, json.dumps(self.rows))


if __name__ == "__main__":
    unittest.main()
