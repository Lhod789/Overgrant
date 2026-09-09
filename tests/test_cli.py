import contextlib
import io
import json
import tempfile
import unittest
from pathlib import Path

from overgrant.cli import main

D = "https://www.googleapis.com/auth/"

DRIVE = D + "drive"
DRIVE_READONLY = D + "drive.readonly"
GMAIL_SEND = D + "gmail.send"


def run(argv) -> int:
    with contextlib.redirect_stdout(io.StringIO()):
        with contextlib.redirect_stderr(io.StringIO()):
            return main(argv)


class TestSnapshotAndDiff(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.dir = Path(self.tmp.name)

    def scope_file(self, name, scopes) -> str:
        path = self.dir / name
        path.write_text("\n".join(scopes) + "\n", encoding="utf-8")
        return str(path)

    def snapshot(self, scopes, name="in.txt", lock="lock.json") -> str:
        source = self.scope_file(name, scopes)
        lockfile = str(self.dir / lock)
        self.assertEqual(run(["scopes", "snapshot", source, "-o", lockfile]), 0)
        return lockfile

    def test_snapshot_is_byte_identical_across_runs(self):
        source = self.scope_file("in.txt", [DRIVE_READONLY, GMAIL_SEND])
        first = self.dir / "first.json"
        second = self.dir / "second.json"
        run(["scopes", "snapshot", source, "-o", str(first)])
        run(["scopes", "snapshot", source, "-o", str(second)])
        self.assertEqual(first.read_bytes(), second.read_bytes())

    def test_lockfile_carries_no_derived_or_volatile_fields(self):
        lockfile = self.snapshot([DRIVE_READONLY])
        document = json.loads(Path(lockfile).read_text(encoding="utf-8"))
        self.assertEqual(set(document), {"provider", "grant_sets"})

    def test_unchanged_input_returns_0(self):
        lockfile = self.snapshot([DRIVE_READONLY, GMAIL_SEND])
        source = str(self.dir / "in.txt")
        self.assertEqual(run(["scopes", "diff", source, "--against", lockfile]), 0)

    def test_broadening_returns_1(self):
        lockfile = self.snapshot([DRIVE_READONLY])
        wider = self.scope_file("wider.txt", [DRIVE])
        self.assertEqual(run(["scopes", "diff", wider, "--against", lockfile]), 1)

    def test_lateral_addition_returns_0(self):
        lockfile = self.snapshot([DRIVE_READONLY])
        wider = self.scope_file("wider.txt", [DRIVE_READONLY, GMAIL_SEND])
        self.assertEqual(run(["scopes", "diff", wider, "--against", lockfile]), 0)

    def test_missing_lockfile_returns_2(self):
        source = self.scope_file("in.txt", [DRIVE_READONLY])
        absent = str(self.dir / "nope.json")
        self.assertEqual(run(["scopes", "diff", source, "--against", absent]), 2)


if __name__ == "__main__":
    unittest.main()
