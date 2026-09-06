import unittest
from pathlib import Path

from overgrant import catalogue
from overgrant.catalogue import load_combinations, load_scopes
from overgrant.evidence import Evidence
from overgrant.findings import Tier
from overgrant.scoring import find_redundant, match_combinations, score

DATA_DIR = Path(catalogue.__file__).parent / "data"

DRIVE = "https://www.googleapis.com/auth/drive"
DRIVE_READONLY = "https://www.googleapis.com/auth/drive.readonly"
GMAIL_SEND = "https://www.googleapis.com/auth/gmail.send"
ADMIN_DIRECTORY = "https://www.googleapis.com/auth/admin.directory.user.readonly"


class TestCatalogueFilesLoad(unittest.TestCase):
    def test_every_catalogue_file_loads_and_validates(self):
        paths = sorted(DATA_DIR.glob("*.toml"))
        self.assertTrue(paths, f"no catalogue files found in {DATA_DIR}")

        for path in paths:
            with self.subTest(catalogue=path.name):
                scopes = load_scopes(path)
                self.assertTrue(scopes, f"{path.name} defines no scopes")
                load_combinations(path, scopes)


class TestGoogleCatalogue(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.path = DATA_DIR / "google.toml"
        cls.scopes = load_scopes(cls.path)
        cls.combinations = load_combinations(cls.path, cls.scopes)

    def test_admin_directory_scores_org_admin_critical(self):
        finding = score(self.scopes[ADMIN_DIRECTORY])
        self.assertEqual(finding.rule, "R2-org-admin")
        self.assertEqual(finding.tier, Tier.CRITICAL)

    def test_read_all_send_as_user_fires_critical_and_inferred(self):
        findings = match_combinations(
            {DRIVE_READONLY, GMAIL_SEND}, self.scopes, self.combinations
        )
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].rule, "combination:read-all-send-as-user")
        self.assertEqual(findings[0].tier, Tier.CRITICAL)
        self.assertIs(findings[0].claim.evidence, Evidence.INFERRED)
        self.assertTrue(findings[0].claim.caveat.strip())

    def test_combination_fires_via_the_broader_drive_scope(self):

        findings = match_combinations(
            {DRIVE, GMAIL_SEND}, self.scopes, self.combinations
        )
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].tier, Tier.CRITICAL)

    def test_drive_readonly_is_redundant_alongside_full_drive(self):
        findings = find_redundant({DRIVE, DRIVE_READONLY}, self.scopes)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].tier, Tier.LOW)
        self.assertEqual(findings[0].scopes, [DRIVE_READONLY, DRIVE])


if __name__ == "__main__":
    unittest.main()
