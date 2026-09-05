import os
import tempfile
import unittest
from pathlib import Path

from overgrant import catalogue
from overgrant.catalogue import load_scopes
from overgrant.risk import Breadth, Mutability, Sensitivity

SLACK_TOML = Path(catalogue.__file__).parent / "data" / "slack.toml"

VALID_ENTRY = """
[[scopes]]
id = "a:one"
short = "A"
grants = "Does a thing"
breadth = "workspace"
mutability = "read"
sensitivity = "none"
source = "https://example.com/a"
"""


def load_text(toml_text):
    with tempfile.NamedTemporaryFile(
        "w", suffix=".toml", delete=False, encoding="utf-8"
    ) as f:
        f.write(toml_text)
        path = f.name
    try:
        return load_scopes(path)
    finally:
        os.unlink(path)


class TestLoadsRealCatalogue(unittest.TestCase):
    def test_slack_catalogue_loads_with_real_enum_members(self):
        scopes = load_scopes(SLACK_TOML)

        self.assertEqual(len(scopes), 3)
        self.assertEqual(
            set(scopes), {"channels:join", "channels:history", "files:read"}
        )

        join = scopes["channels:join"]
        self.assertIs(join.breadth, Breadth.WORKSPACE)
        self.assertIs(join.mutability, Mutability.WRITE)
        self.assertIs(join.sensitivity, Sensitivity.NONE)


class TestRejectsMalformedCatalogue(unittest.TestCase):
    def test_duplicate_id_raises(self):
        with self.assertRaisesRegex(ValueError, "a:one: duplicate scope id"):
            load_text(VALID_ENTRY + VALID_ENTRY)

    def test_self_referential_supersedes_raises(self):
        with self.assertRaisesRegex(ValueError, "supersedes itself"):
            load_text(VALID_ENTRY + 'supersedes = ["a:one"]\n')

    def test_dangling_supersedes_raises(self):
        with self.assertRaisesRegex(ValueError, "supersedes unknown scope .a:ghost."):
            load_text(VALID_ENTRY + 'supersedes = ["a:ghost"]\n')

    def test_non_https_source_raises(self):
        with self.assertRaisesRegex(ValueError, "source must be an https:// URL"):
            load_text(
                VALID_ENTRY.replace("https://example.com/a", "http://example.com/a")
            )

    def test_unknown_data_class_raises(self):
        with self.assertRaises(ValueError) as cm:
            load_text(VALID_ENTRY + 'data_classes = ["messsages"]\n')
        self.assertIn("unknown data class 'messsages'", str(cm.exception))

    def test_content_sensitivity_without_data_classes_raises(self):
        with self.assertRaises(ValueError) as cm:
            load_text(
                VALID_ENTRY.replace('sensitivity = "none"', 'sensitivity = "content"')
            )
        self.assertIn(
            "sensitivity is content but data_classes is empty", str(cm.exception)
        )


if __name__ == "__main__":
    unittest.main()
