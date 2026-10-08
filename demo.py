"""Run a deterministic demo in a temporary directory; leave JSON/HTML reports."""
import argparse
from pathlib import Path
import tempfile
import evidenceguard as eg


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-dir", default="demo-output")
    args = parser.parse_args()
    output = Path(args.output_dir).resolve()
    output.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="evidenceguard-demo-") as folder:
        root = Path(folder)
        (root / "app.conf").write_text("debug=false\n")
        (root / "audit.log").write_text("example synthetic audit entry\n")
        saved = eg.scan(root, [])
        (root / "app.conf").write_text("debug=true\n")
        (root / "audit.log").unlink()
        (root / "unexpected.txt").write_text("synthetic added file\n")
        report = eg.compare(saved, eg.scan(root, []))
        eg.atomic_write(output / "report.json", eg.encode(report))
        eg.atomic_write(output / "report.html", eg.render_html(report).encode())
        record_sha256 = eg.append_ledger(output / "ledger.jsonl", report)
        ledger = eg.verify_ledger(output / "ledger.jsonl")
        print(
            f"Demo complete: {len(report['changes'])} changes. "
            f"Ledger records: {ledger['records']}. Open {output / 'report.html'}"
        )
        valid = len(report["changes"]) == 3 and ledger["last_sha256"] == record_sha256
        return 0 if valid else 2


if __name__ == "__main__":
    raise SystemExit(main())
