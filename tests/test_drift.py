import unittest

from overgrant.catalogue import load_provider
from overgrant.drift import Drift, classify

D = "https://www.googleapis.com/auth/"

DRIVE = D + "drive"
DRIVE_READONLY = D + "drive.readonly"
GMAIL_SEND = D + "gmail.send"
DIRECTORY = D + "admin.directory.user.readonly"


class TestClassify(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.scopes, _ = load_provider("google")

    def classify(self, before, after):
        return classify(before, after, self.scopes)

    def test_wider_replacement_is_broadened(self):
        changes = self.classify({DRIVE_READONLY}, {DRIVE})
        self.assertEqual([c.kind for c in changes], [Drift.BROADENED])
        self.assertEqual(changes[0].scope, DRIVE)
        self.assertEqual(changes[0].previous, DRIVE_READONLY)

    def test_narrower_replacement_is_narrowed(self):
        changes = self.classify({DRIVE}, {DRIVE_READONLY})
        self.assertEqual([c.kind for c in changes], [Drift.NARROWED])
        self.assertEqual(changes[0].previous, DRIVE)

    def test_a_swap_is_one_change_not_two(self):
        changes = self.classify({DRIVE_READONLY}, {DRIVE})
        self.assertEqual(len(changes), 1)
        kinds = {c.kind for c in changes}
        self.assertNotIn(Drift.REMOVED, kinds)
        self.assertNotIn(Drift.ADDED_ESCALATION, kinds)
        self.assertNotIn(Drift.ADDED_LATERAL, kinds)

    def test_severe_addition_is_an_escalation(self):
        changes = self.classify(set(), {DIRECTORY})
        self.assertEqual([c.kind for c in changes], [Drift.ADDED_ESCALATION])

    def test_mild_addition_is_lateral(self):
        changes = self.classify(set(), {GMAIL_SEND})
        self.assertEqual([c.kind for c in changes], [Drift.ADDED_LATERAL])

    def test_unpaired_removal_is_reported(self):
        changes = self.classify({GMAIL_SEND}, set())
        self.assertEqual([c.kind for c in changes], [Drift.REMOVED])
        self.assertEqual(changes[0].scope, GMAIL_SEND)

    def test_identical_sets_produce_no_changes(self):
        self.assertEqual(self.classify({DRIVE, GMAIL_SEND}, {DRIVE, GMAIL_SEND}), [])

    def test_uncatalogued_addition_is_an_escalation(self):
        changes = self.classify(set(), {D + "not.curated.yet"})
        self.assertEqual([c.kind for c in changes], [Drift.ADDED_ESCALATION])


if __name__ == "__main__":
    unittest.main()
