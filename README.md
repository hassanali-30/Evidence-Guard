# EvidenceGuard

**Offline file integrity checks for SOC analysts and incident-response labs.**

EvidenceGuard records a SHA-256 baseline of a known-good directory and compares later copies against it. It helps an analyst identify changed configuration files, missing logs, unexpected additions, and permission changes without uploading file contents to a service.

Built with Python 3.10+ and the standard library. No installation, API key, administrator access, or external dependencies are required.

## Quick start

From the project directory, run the synthetic demo:

```sh
python demo.py
```

Open `demo-output/report.html` in a browser. The demo creates its own temporary evidence, makes three intentional changes, and generates both HTML and JSON reports. It does not alter your files.

To check your own directory:

```sh
python evidenceguard.py baseline ./evidence --output ./baseline.json
python evidenceguard.py check ./baseline.json --json ./report.json --html ./report.html
```

Create `./evidence` and put the authorized files you want to monitor inside it first. Store the baseline and reports **outside** that directory. On systems where Python is named `python3`, use that command instead.

## Features

| Capability | Behavior |
| --- | --- |
| Content verification | Chunked SHA-256 hashing, including same-size edits with preserved timestamps |
| Change detection | Added, modified, deleted, and permission-changed regular files |
| Incomplete scans | Read failures and unverified paths are reported explicitly |
| Reports | Machine-readable JSON and an offline HTML summary with escaped filenames |
| Baseline protection | Explicit overwrite flag and optional verification against a separately stored digest |
| Exclusions | Repeatable shell-style patterns saved in the baseline |
| Automation | Exit codes for clean, changed, or incomplete scans |
| Portability | Standard-library implementation; Windows and Linux CI configuration |

## Baseline trust

Create a baseline only from a state you already trust. The baseline command prints `baseline_sha256`. Keep that digest separately in trusted storage, and pass it when verifying:

```sh
python evidenceguard.py check baseline.json --expected-digest YOUR_TRUSTED_SHA256
```

Replace `YOUR_TRUSTED_SHA256` with the printed 64-character digest. A digest stored beside an editable baseline is not protection against an attacker who can replace both. The tool does not digitally sign evidence or provide a legally certified chain of custody.

## Exclusions and relocated copies

```sh
python evidenceguard.py baseline ./evidence --output baseline.json --exclude '*.tmp' --exclude cache
python evidenceguard.py check baseline.json --root ./evidence-copy
```

Patterns are case-sensitive and match either the root-relative POSIX-style path or a single entry name. An excluded directory prunes its subtree. `.git` and `__pycache__` are excluded by default. Check commands reuse the baseline's exclusions so scope does not silently change between runs.

Review an existing baseline before deliberately replacing it with `baseline --force`.

## Results

| Exit code | Meaning |
| --- | --- |
| 0 | Baseline created successfully, or included files are unchanged |
| 1 | File or permission changes detected |
| 2 | Invalid input, scan error, unverified previously tracked paths, or report-write failure |

Reports include the scan root, UTC time, file count, before/after hashes, sizes, modes, skipped paths, and errors. HTML summarizes changes; JSON retains complete records. A content change is not automatically malicious: software updates and routine administration can also change files.

## Scope and limitations

- This is an on-demand scanner, not a background agent or real-time EDR.
- Baselines cover regular files only. Symbolic links, special files, and excluded paths are listed but not hashed. Empty directory changes are not tracked.
- A `clean` result applies only to included files; review skipped paths as part of an investigation.
- Permission checks use basic mode bits. Windows ACLs, ownership, extended attributes, alternate data streams, and filesystem timestamps are outside scope.
- File replacement and changes during hashing are checked where possible. This is not a filesystem snapshot: concurrent directory changes or hostile filesystem races can still produce an inconsistent view. Use a stable offline copy or filesystem snapshot for evidence work.
- Scanning reads file contents and can update access times. It does not copy evidence, acquire a forensic disk image, or preserve forensic metadata.
- JSON/HTML reports expose file names, paths, and hashes. Use synthetic data for public demonstrations.

## Development

```sh
python -m unittest discover -s tests -v
python demo.py
```

The test suite covers content and permission changes, tampering, exclusions, symlink replacement, error reporting, invalid baselines, report escaping, relocation, and CLI exit codes. GitHub Actions is configured to run it on Ubuntu and Windows across Python 3.10, 3.12, and 3.13. POSIX-only tests are skipped on Windows.

## Project files

- `evidenceguard.py`: scanner, baseline validation, comparison, reports, and CLI.
- `demo.py`: self-contained synthetic demonstration.
- `tests/test_evidenceguard.py`: automated regression tests.
- `.github/workflows/tests.yml`: CI configuration.

Author: Hassan Ali. Licensed under the MIT License.
