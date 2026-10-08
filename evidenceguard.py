#!/usr/bin/env python3
"""Offline file integrity checks. Python 3.10+, standard library only."""
from __future__ import annotations

import argparse
import fnmatch
import hashlib
import html
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import sys
import tempfile
from datetime import datetime, timezone

VERSION = 1
DEFAULT_EXCLUDES = [".git", "__pycache__"]


def utc_now():
    return datetime.now(timezone.utc).isoformat()


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def atomic_write(path, data):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(prefix=".evidenceguard-", dir=path.parent)
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def encode(value):
    return (json.dumps(value, indent=2, sort_keys=True) + "\n").encode("utf-8")


def fingerprint(path):
    before = path.lstat()
    if not stat.S_ISREG(before.st_mode):
        raise ValueError("not a regular file")
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
    fd = os.open(path, flags)
    with os.fdopen(fd, "rb") as handle:
        opened = os.fstat(handle.fileno())
        if not stat.S_ISREG(opened.st_mode) or (before.st_dev, before.st_ino) != (opened.st_dev, opened.st_ino):
            raise ValueError("file replaced while opening")
        digest = hashlib.sha256()
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
        after = os.fstat(handle.fileno())
    current = path.lstat()
    def identity(s):
        # Windows can report different ctime/mode values for path and handle
        # stat calls even when the file is unchanged. Size and mtime are
        # portable; device/inode add replacement detection on POSIX.
        portable = (s.st_size, s.st_mtime_ns)
        return portable if os.name == "nt" else (s.st_dev, s.st_ino, *portable)
    if identity(before) != identity(after) or identity(after) != identity(current):
        raise ValueError("file changed during scan; retry on a stable copy")
    return {"sha256": digest.hexdigest(), "size": after.st_size,
            "mode": stat.S_IMODE(after.st_mode)}


def scan(root, excludes):
    root = Path(root).resolve(strict=True)
    if not root.is_dir():
        raise ValueError("scan root must be a directory")
    files, skipped, errors = {}, [], []

    def visit(directory):
        try:
            with os.scandir(directory) as entries:
                children = sorted(entries, key=lambda e: e.name)
        except OSError as exc:
            errors.append({"path": str(directory.relative_to(root)), "error": str(exc)})
            return
        for entry in children:
            path = directory / entry.name
            relative = path.relative_to(root).as_posix()
            if any(fnmatch.fnmatchcase(relative, p) or fnmatch.fnmatchcase(entry.name, p) for p in excludes):
                skipped.append({"path": relative, "reason": "excluded"})
                continue
            try:
                if entry.is_symlink():
                    skipped.append({"path": relative, "reason": "symbolic link"})
                elif entry.is_dir(follow_symlinks=False):
                    visit(path)
                elif entry.is_file(follow_symlinks=False):
                    files[relative] = fingerprint(path)
                else:
                    skipped.append({"path": relative, "reason": "special file"})
            except (OSError, ValueError) as exc:
                errors.append({"path": relative, "error": str(exc)})
    visit(root)
    return {"schema_version": VERSION, "algorithm": "sha256", "root": str(root),
            "created_at": utc_now(), "excludes": list(excludes), "files": files,
            "skipped": skipped, "errors": errors}


def _ledger_payload(report, previous_sha256):
    return {
        "schema_version": 1,
        "created_at": utc_now(),
        "previous_sha256": previous_sha256,
        "report_sha256": sha256(encode(report)),
        "status": report.get("status"),
        "root": report.get("root"),
    }


def append_ledger(path, report):
    """Append a chained, tamper-evident summary of a verification report."""
    ledger_path = Path(path)
    records = []
    if ledger_path.exists():
        for line in ledger_path.read_text(encoding="utf-8").splitlines():
            if line.strip():
                records.append(json.loads(line))
        verify_ledger(ledger_path)
    previous_sha256 = records[-1]["record_sha256"] if records else ""
    payload = _ledger_payload(report, previous_sha256)
    record = {**payload, "record_sha256": sha256(encode(payload))}
    existing = ledger_path.read_bytes() if ledger_path.exists() else b""
    line = (json.dumps(record, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")
    atomic_write(ledger_path, existing + line)
    return record["record_sha256"]


def verify_ledger(path):
    """Verify record hashes and links in a ledger."""
    records = []
    for line in Path(path).read_text(encoding="utf-8").splitlines():
        if line.strip():
            record = json.loads(line)
            if not isinstance(record, dict) or not isinstance(record.get("record_sha256"), str):
                raise ValueError("invalid ledger record")
            records.append(record)
    previous_sha256 = ""
    for record in records:
        actual = record["record_sha256"]
        payload = dict(record)
        payload.pop("record_sha256", None)
        if record.get("previous_sha256") != previous_sha256 or sha256(encode(payload)) != actual:
            raise ValueError("ledger integrity check failed")
        previous_sha256 = actual
    return {"records": len(records), "last_sha256": previous_sha256}


def load_baseline(path, expected_digest=None):
    data = Path(path).read_bytes()
    if expected_digest and sha256(data) != expected_digest.lower():
        raise ValueError("baseline digest does not match the trusted digest")
    result = json.loads(data)
    if not isinstance(result, dict) or result.get("schema_version") != VERSION or result.get("algorithm") != "sha256":
        raise ValueError("unsupported baseline format")
    if not isinstance(result.get("files"), dict) or not isinstance(result.get("root"), str):
        raise ValueError("invalid baseline fields")
    if not isinstance(result.get("excludes"), list) or not all(isinstance(p, str) for p in result["excludes"]):
        raise ValueError("invalid exclusion list")
    if result.get("errors") != []:
        raise ValueError("baseline is incomplete")
    for name, record in result["files"].items():
        if not name or PurePosixPath(name).is_absolute() or ".." in PurePosixPath(name).parts or "\\" in name:
            raise ValueError("invalid baseline path")
        if (not isinstance(record, dict) or not isinstance(record.get("sha256"), str)
                or not re.fullmatch(r"[0-9a-f]{64}", record["sha256"])
                or type(record.get("size")) is not int or record["size"] < 0
                or type(record.get("mode")) is not int):
            raise ValueError("invalid file record")
    return result, sha256(data)


def compare(baseline, current):
    changes = []
    old, new = baseline["files"], current["files"]
    skipped = {entry["path"]: entry["reason"] for entry in current["skipped"]}
    for path in sorted(old.keys() | new.keys()):
        before, after = old.get(path), new.get(path)
        kind = None
        if before is None:
            kind = "added"
        elif after is None:
            # A scan error makes absence uncertain; never report it as deletion.
            kind = "unverified" if current["errors"] else "deleted"
            if any(path == p or path.startswith(p + "/") for p in skipped):
                kind = "unverified"
        elif before["sha256"] != after["sha256"] or before["size"] != after["size"]:
            kind = "modified"
        elif before["mode"] != after["mode"]:
            kind = "permissions_changed"
        if kind:
            changes.append({"path": path, "change": kind, "before": before, "after": after})
    incomplete = bool(current["errors"]) or any(c["change"] == "unverified" for c in changes)
    return {"checked_at": utc_now(), "root": current["root"],
            "status": "incomplete" if incomplete else "changed" if changes else "clean",
            "files_checked": len(new), "changes": changes,
            "skipped": current["skipped"], "errors": current["errors"]}


def render_html(report):
    escape = lambda value: html.escape(str(value), quote=True)
    rows = "".join("<tr><td>" + escape(c["change"]) + "</td><td>" + escape(c["path"]) + "</td></tr>" for c in report["changes"])
    details = escape(json.dumps({"skipped": report["skipped"], "errors": report["errors"]}, indent=2))
    return ("<!doctype html><html lang='en'><meta charset='utf-8'>"
            "<meta name='viewport' content='width=device-width,initial-scale=1'>"
            "<title>EvidenceGuard report</title><style>body{font:16px system-ui;margin:3rem auto;max-width:960px;padding:1rem;background:#101827;color:#e5edf7}"
            "h1{color:#53d6bf}td,th{padding:.8rem;text-align:left;border-bottom:1px solid #415066}table{width:100%}pre{white-space:pre-wrap;overflow-wrap:anywhere}"
            "</style><h1>EvidenceGuard</h1><p>File integrity verification</p>"
            f"<h2>Status: {escape(report['status'])}</h2><p>{escape(report['checked_at'])}</p>"
            f"<p>Root: {escape(report['root'])} | Files checked: {report['files_checked']}</p>"
            f"<table><thead><tr><th>Change</th><th>Path</th></tr></thead><tbody>{rows}</tbody></table>"
            f"<h2>Skipped paths and errors</h2><pre>{details}</pre></html>")


def ensure_outside(root, outputs):
    root = Path(root).resolve()
    resolved = [Path(p).resolve() for p in outputs if p]
    if len(set(resolved)) != len(resolved):
        raise ValueError("baseline and report paths must be distinct")
    for path in resolved:
        if path == root or root in path.parents:
            raise ValueError("store baselines and reports outside the scanned directory")


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    baseline = sub.add_parser("baseline", help="record a known-good directory")
    baseline.add_argument("root")
    baseline.add_argument("--output", required=True)
    baseline.add_argument("--exclude", action="append", default=[])
    baseline.add_argument("--force", action="store_true", help="replace an existing baseline deliberately")
    ledger = sub.add_parser("ledger", help="append or verify chained report records")
    ledger_sub = ledger.add_subparsers(dest="ledger_command", required=True)
    append = ledger_sub.add_parser("append", help="append a report summary")
    append.add_argument("report")
    append.add_argument("--output", required=True)
    verify = ledger_sub.add_parser("verify", help="verify ledger hashes and links")
    verify.add_argument("path")
    check = sub.add_parser("check", help="compare a directory against a baseline")
    check.add_argument("baseline")
    check.add_argument("--root", help="explicitly check a relocated copy")
    check.add_argument("--expected-digest", help="SHA-256 of baseline from trusted separate storage")
    check.add_argument("--json", dest="json_output")
    check.add_argument("--html", dest="html_output")
    args = parser.parse_args(argv)
    try:
        if args.command == "ledger":
            if args.ledger_command == "append":
                report = json.loads(Path(args.report).read_text(encoding="utf-8"))
                if not isinstance(report, dict):
                    raise ValueError("report must be a JSON object")
                record_sha256 = append_ledger(args.output, report)
                print(json.dumps({"ledger": args.output, "record_sha256": record_sha256}))
                return 0
            print(json.dumps(verify_ledger(args.path)))
            return 0
        if args.command == "baseline":
            ensure_outside(args.root, [args.output])
            if Path(args.output).exists() and not args.force:
                raise ValueError("baseline already exists; use --force only after reviewing changes")
            result = scan(args.root, DEFAULT_EXCLUDES + args.exclude)
            if result["errors"]:
                print(json.dumps(result, indent=2))
                return 2
            data = encode(result)
            atomic_write(args.output, data)
            print(json.dumps({"baseline": args.output, "files": len(result["files"]),
                              "skipped": result["skipped"], "baseline_sha256": sha256(data)}, indent=2))
            return 0
        saved, digest = load_baseline(args.baseline, args.expected_digest)
        root = args.root or saved["root"]
        ensure_outside(root, [args.baseline, args.json_output, args.html_output])
        report = compare(saved, scan(root, saved["excludes"]))
        report["baseline_sha256"] = digest
        if args.json_output:
            atomic_write(args.json_output, encode(report))
        if args.html_output:
            atomic_write(args.html_output, render_html(report).encode("utf-8"))
        print(json.dumps(report, indent=2))
        return {"clean": 0, "changed": 1, "incomplete": 2}[report["status"]]
    except (OSError, ValueError, RecursionError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
