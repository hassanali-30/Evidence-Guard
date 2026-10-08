import contextlib
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

import evidenceguard as eg


class IntegrityTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)
        self.root = self.base / "evidence"
        self.root.mkdir()
        (self.root / "config.txt").write_text("trusted\n")
        self.baseline = self.base / "baseline.json"

    def call(self, *args):
        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            return eg.main(list(map(str, args)))

    def create(self):
        self.assertEqual(self.call("baseline", self.root, "--output", self.baseline), 0)
        return json.loads(self.baseline.read_text())

    def test_clean_round_trip(self):
        self.create()
        self.assertEqual(self.call("check", self.baseline), 0)

    def test_known_sha256(self):
        (self.root / "config.txt").write_bytes(b"abc")
        self.assertEqual(self.create()["files"]["config.txt"]["sha256"],
                         "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")

    def test_added_modified_deleted(self):
        (self.root / "delete.txt").write_text("gone")
        old = self.create()
        (self.root / "delete.txt").unlink()
        (self.root / "config.txt").write_text("changed")
        (self.root / "new.txt").write_text("new")
        report = eg.compare(old, eg.scan(self.root, old["excludes"]))
        self.assertEqual({c["change"] for c in report["changes"]}, {"added", "modified", "deleted"})
        self.assertEqual(self.call("check", self.baseline), 1)

    @unittest.skipIf(os.name == "nt", "POSIX mode semantics")
    def test_permission_change(self):
        os.chmod(self.root / "config.txt", 0o600)
        old = self.create()
        os.chmod(self.root / "config.txt", 0o644)
        self.assertEqual(eg.compare(old, eg.scan(self.root, []))["changes"][0]["change"], "permissions_changed")

    def test_content_change_with_preserved_size_and_mtime(self):
        old = self.create()
        path = self.root / "config.txt"
        s = path.stat()
        path.write_text("altered\n")
        os.utime(path, ns=(s.st_atime_ns, s.st_mtime_ns))
        self.assertEqual(eg.compare(old, eg.scan(self.root, []))["status"], "changed")

    def test_exclusions_persist(self):
        (self.root / "cache").mkdir()
        (self.root / "cache" / "temp").write_text("one")
        self.assertEqual(self.call("baseline", self.root, "--output", self.baseline, "--exclude", "cache"), 0)
        (self.root / "cache" / "temp").write_text("two")
        self.assertEqual(self.call("check", self.baseline), 0)

    @unittest.skipIf(os.name == "nt", "symlink privileges vary on Windows")
    def test_symlink_replacement_is_unverified(self):
        old = self.create()
        path = self.root / "config.txt"
        path.unlink()
        path.symlink_to(self.base / "outside")
        report = eg.compare(old, eg.scan(self.root, []))
        self.assertEqual(report["status"], "incomplete")
        self.assertEqual(report["changes"][0]["change"], "unverified")

    def test_scan_error_is_not_deletion(self):
        old = self.create()
        with patch.object(eg, "fingerprint", side_effect=PermissionError("denied")):
            report = eg.compare(old, eg.scan(self.root, []))
        self.assertEqual(report["status"], "incomplete")
        self.assertEqual(report["changes"][0]["change"], "unverified")

    def test_failed_baseline_not_written(self):
        with patch.object(eg, "fingerprint", side_effect=PermissionError("denied")):
            self.assertEqual(self.call("baseline", self.root, "--output", self.baseline), 2)
        self.assertFalse(self.baseline.exists())

    def test_baseline_overwrite_requires_force(self):
        self.create()
        original = self.baseline.read_bytes()
        self.assertEqual(self.call("baseline", self.root, "--output", self.baseline), 2)
        self.assertEqual(original, self.baseline.read_bytes())
        self.assertEqual(self.call("baseline", self.root, "--output", self.baseline, "--force"), 0)

    def test_baseline_tampering(self):
        self.create()
        digest = eg.sha256(self.baseline.read_bytes())
        self.assertEqual(self.call("check", self.baseline, "--expected-digest", digest), 0)
        self.baseline.write_bytes(self.baseline.read_bytes() + b" ")
        self.assertEqual(self.call("check", self.baseline, "--expected-digest", digest), 2)

    def test_invalid_json(self):
        self.baseline.write_text("{broken")
        self.assertEqual(self.call("check", self.baseline), 2)

    def test_invalid_records(self):
        old = self.create()
        for invalid in [None, {"sha256": 10}, {"sha256": "x", "size": -1, "mode": 1}]:
            old["files"]["config.txt"] = invalid
            self.baseline.write_bytes(eg.encode(old))
            self.assertEqual(self.call("check", self.baseline), 2)

    def test_traversal_in_baseline(self):
        old = self.create()
        old["files"]["../escape"] = old["files"].pop("config.txt")
        self.baseline.write_bytes(eg.encode(old))
        self.assertEqual(self.call("check", self.baseline), 2)

    def test_output_inside_root_rejected(self):
        self.assertEqual(self.call("baseline", self.root, "--output", self.root / "baseline.json"), 2)

    def test_output_cannot_overwrite_baseline(self):
        self.create()
        self.assertEqual(self.call("check", self.baseline, "--json", self.baseline), 2)

    def test_html_escapes_untrusted_names(self):
        report = {"changes": [{"change": "added", "path": "<script>alert(1)</script>"}],
                  "skipped": [], "errors": [], "status": "changed", "checked_at": "now",
                  "root": "<root>", "files_checked": 1}
        document = eg.render_html(report)
        self.assertNotIn("<script>", document)
        self.assertIn("&lt;script&gt;", document)

    def test_relocated_evidence(self):
        self.create()
        moved = self.base / "moved"
        self.root.rename(moved)
        self.assertEqual(self.call("check", self.baseline, "--root", moved), 0)

    def test_missing_root(self):
        self.assertEqual(self.call("baseline", self.base / "missing", "--output", self.baseline), 2)

    def test_real_cli_reports(self):
        self.create()
        (self.root / "config.txt").write_text("changed")
        output = self.base / "report.json"
        html = self.base / "report.html"
        run = subprocess.run([sys.executable, str(Path(eg.__file__)), "check", str(self.baseline),
                              "--json", str(output), "--html", str(html)], capture_output=True, text=True)
        self.assertEqual(run.returncode, 1, run.stderr)
        self.assertEqual(json.loads(output.read_text())["status"], "changed")
        self.assertIn("EvidenceGuard", html.read_text())


    def test_tamper_evident_ledger(self):
        self.create()
        report = eg.compare(json.loads(self.baseline.read_text()), eg.scan(self.root, []))
        ledger = self.base / "ledger.jsonl"
        first = eg.append_ledger(ledger, report)
        report["status"] = "changed"
        second = eg.append_ledger(ledger, report)
        verified = eg.verify_ledger(ledger, second)
        self.assertEqual(verified, {"records": 2, "last_sha256": second})
        with self.assertRaises(ValueError):
            eg.verify_ledger(ledger, "0" * 64)
        self.assertNotEqual(first, second)
        lines = ledger.read_text().splitlines()
        tampered = json.loads(lines[0])
        tampered["status"] = "changed"
        lines[0] = json.dumps(tampered)
        ledger.write_text("\n".join(lines) + "\n")
        with self.assertRaises(ValueError):
            eg.verify_ledger(ledger)

    def test_ledger_cli(self):
        report = self.base / "report.json"
        ledger = self.base / "ledger.jsonl"
        report.write_text(json.dumps({"status": "clean", "root": str(self.root)}))
        append = subprocess.run(
            [sys.executable, str(Path(eg.__file__)), "ledger", "append",
             str(report), "--output", str(ledger)],
            capture_output=True, text=True,
        )
        self.assertEqual(append.returncode, 0, append.stderr)
        verify = subprocess.run(
            [sys.executable, str(Path(eg.__file__)), "ledger", "verify", str(ledger)],
            capture_output=True, text=True,
        )
        self.assertEqual(verify.returncode, 0, verify.stderr)
        append_result = json.loads(append.stdout)
        anchored = subprocess.run(
            [sys.executable, str(Path(eg.__file__)), "ledger", "verify", str(ledger),
             "--expected-digest", append_result["record_sha256"]],
            capture_output=True, text=True,
        )
        self.assertEqual(anchored.returncode, 0, anchored.stderr)
        self.assertEqual(json.loads(verify.stdout)["records"], 1)

    def test_append_repairs_missing_trailing_newline(self):
        ledger = self.base / "ledger.jsonl"
        report = {"status": "clean", "root": str(self.root)}
        eg.append_ledger(ledger, report)
        ledger.write_bytes(ledger.read_bytes().rstrip(b"\n"))
        last = eg.append_ledger(ledger, report)
        self.assertEqual(eg.verify_ledger(ledger, last)["records"], 2)


if __name__ == "__main__":
    unittest.main()
