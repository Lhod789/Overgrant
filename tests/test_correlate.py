import contextlib
import io
import json
import tempfile
import unittest
from pathlib import Path

from overgrant.catalogue import load_provider
from overgrant.cli import main
from overgrant.correlate import OVER_GRANT, UNDECLARED, correlate
from overgrant.evidence import Evidence

WINDOW = {
    "start": "2026-01-01T00:00:00+00:00",
    "end": "2026-01-01T06:12:00+00:00",
    "duration_seconds": 22320.0,
}

REPO = Path(__file__).resolve().parent.parent
LOCKFILE = REPO / "examples" / "notes-bot.lock.json"
HAR = REPO / "examples" / "notes-bot.synthetic.har"


def vendor(name, paths):
    return {
        "vendor": name,
        "hosts": [],
        "paths": list(paths),
        "requests": len(paths),
        "detections": {},
    }


class TestCorrelate(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.scopes, _ = load_provider("slack")

    def run_correlate(self, granted, paths, vendor_name="Slack"):
        return correlate(
            {"bot": list(granted)},
            [vendor(vendor_name, paths)],
            self.scopes,
            "slack",
            WINDOW,
        )

    def test_an_unused_scope_produces_an_over_grant(self):
        findings = self.run_correlate(
            ["channels:join", "files:read"], ["/api/conversations.join"]
        )
        self.assertEqual([f.rule for f in findings], [OVER_GRANT])
        self.assertEqual(findings[0].scopes, ["files:read"])

    def test_an_exercised_scope_produces_nothing(self):
        findings = self.run_correlate(["channels:join"], ["/api/conversations.join"])
        self.assertEqual(findings, [])

    def test_an_unmatched_path_is_an_undeclared_capability(self):
        findings = self.run_correlate(
            ["channels:join"], ["/api/conversations.join", "/api/chat.postMessage"]
        )
        self.assertEqual([f.rule for f in findings], [UNDECLARED])

    def test_a_third_party_host_is_not_an_undeclared_capability(self):
        findings = correlate(
            {"bot": ["channels:join"]},
            [
                vendor("Slack", ["/api/conversations.join"]),
                vendor("UNKNOWN", ["/v1/events"]),
            ],
            self.scopes,
            "slack",
            WINDOW,
        )
        self.assertEqual(findings, [])

    def test_the_over_grant_claim_is_inferred_and_names_the_window(self):
        finding = self.run_correlate(
            ["channels:join", "files:read"], ["/api/conversations.join"]
        )[0]
        self.assertIs(finding.claim.evidence, Evidence.INFERRED)
        self.assertIn("6h12m", finding.claim.caveat)


class TestCorrelateCommand(unittest.TestCase):
    def test_the_cli_exits_zero_and_emits_parseable_json(self):
        with tempfile.TemporaryDirectory() as tmp:
            egress = Path(tmp) / "egress.json"
            buffer = io.StringIO()
            with contextlib.redirect_stdout(buffer):
                self.assertEqual(
                    main(["egress", "map", str(HAR), "--format", "json"]), 0
                )
            egress.write_text(buffer.getvalue(), encoding="utf-8")

            buffer = io.StringIO()
            with contextlib.redirect_stdout(buffer):
                code = main(
                    [
                        "correlate",
                        "--scopes",
                        str(LOCKFILE),
                        "--egress",
                        str(egress),
                        "--format",
                        "json",
                    ]
                )
            self.assertEqual(code, 0)
            document = json.loads(buffer.getvalue())
            self.assertEqual(document["provider"], "slack")


if __name__ == "__main__":
    unittest.main()
