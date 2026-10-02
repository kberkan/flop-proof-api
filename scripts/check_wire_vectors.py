"""Check embedded test vectors against the pinned upstream wire-format corpus.

Downloads flop-labs/yellowpaper evidence/wire-format-v1.json at the commit
pinned in tests/fixtures/flop-yellowpaper/SOURCE.json into a temporary
directory, verifies its size and sha256, and compares every value listed in
_embedded_wire_vectors.py with the corpus. The corpus is not kept on disk.

It also scans every string constant in the root test_*.py files for hex values
of at least 64 characters. Trivial input patterns (one repeated byte, or the
byte sequence 00 01 02 ...) are ignored and listed. The rest are reported as
UNREGISTERED when found in the current corpus but not registered in
_embedded_wire_vectors.py, as STALE when found only in a previous revision
listed in SOURCE.json "previous_commits", and otherwise counted as test-local.
A previous revision that cannot be downloaded is skipped with a warning; one
that downloads with a different size or sha256 is an integrity failure.

Exit codes (highest priority first):
  2  download or integrity failure of the current corpus, or integrity
     failure of a previous revision
  1  a registered value does not match the current corpus
  3  UNREGISTERED or STALE findings
  0  everything matches
"""

import ast
import hashlib
import json
import re
import sys
import tempfile
import time
import urllib.request
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
SOURCE_PATH = REPO_ROOT / "tests" / "fixtures" / "flop-yellowpaper" / "SOURCE.json"

# Only the download is retried; integrity and value mismatches fail at once.
DOWNLOAD_ATTEMPTS = 3
RETRY_DELAY_SECONDS = 5

sys.path.insert(0, str(REPO_ROOT))

from _embedded_wire_vectors import EMBEDDED_WIRE_VECTORS, KNOWN_DIVERGENCES  # noqa: E402


def _download(url: str) -> bytes:
    with tempfile.TemporaryDirectory() as tmp:
        target = Path(tmp) / "wire-format-v1.json"
        with urllib.request.urlopen(url, timeout=30) as response:
            target.write_bytes(response.read())
        return target.read_bytes()


def _download_with_retry(url: str) -> bytes:
    for attempt in range(1, DOWNLOAD_ATTEMPTS + 1):
        try:
            return _download(url)
        except OSError as exc:
            print(f"download attempt {attempt}/{DOWNLOAD_ATTEMPTS} failed: {exc}")
            if attempt == DOWNLOAD_ATTEMPTS:
                raise
            time.sleep(RETRY_DELAY_SECONDS)


class IntegrityError(Exception):
    pass


def _raw_url(source: dict, commit: str) -> str:
    return (
        "https://raw.githubusercontent.com/"
        f"{source['repository']}/{commit}/{source['path']}"
    )


def _fetch_verified(url: str, size_bytes: int, sha256: str) -> bytes:
    """Download with retry, then check size and sha256 (not retried)."""
    data = _download_with_retry(url)
    digest = hashlib.sha256(data).hexdigest()
    if len(data) != size_bytes or digest != sha256:
        raise IntegrityError(
            f"  url    {url}\n"
            f"  size   expected {size_bytes}, got {len(data)}\n"
            f"  sha256 expected {sha256}\n"
            f"         got      {digest}"
        )
    return data


HEX_LITERAL = re.compile(r"[0-9a-f]{64,}")


def _test_hex_literals() -> list[tuple[str, int, str]]:
    """(file, line, lower-case hex) for every hex string constant of at least
    64 characters in the root test_*.py files. Implicitly concatenated
    literals arrive as a single constant from the AST."""
    found = []
    for path in sorted(REPO_ROOT.glob("test_*.py")):
        for node in ast.walk(ast.parse(path.read_text(), filename=str(path))):
            if isinstance(node, ast.Constant) and isinstance(node.value, str):
                value = node.value.lower()
                if HEX_LITERAL.fullmatch(value):
                    found.append((path.name, node.lineno, value))
    return sorted(found)


def _corpus_strings(node, path: str = "") -> list[tuple[str, str]]:
    """(dotted JSON path, lower-case value) for every string in the corpus."""
    if isinstance(node, dict):
        return [
            item
            for key, value in node.items()
            for item in _corpus_strings(value, f"{path}.{key}" if path else key)
        ]
    if isinstance(node, list):
        items = []
        for index, value in enumerate(node):
            label = index
            if isinstance(value, dict):
                label = value.get("id", value.get("version", index))
            items.extend(_corpus_strings(value, f"{path}.{label}"))
        return items
    if isinstance(node, str):
        return [(path, node.lower())]
    return []


def _paths_containing(value: str, strings: list[tuple[str, str]]) -> list[str]:
    return [path for path, text in strings if value in text]


def _is_trivial_pattern(value: str) -> bool:
    """One repeated byte (e.g. "11" * 32) or bytes(range(n))."""
    if len(value) % 2:
        return False
    data = bytes.fromhex(value)
    return len(set(data)) == 1 or (
        len(data) <= 256 and data == bytes(range(len(data)))
    )


def _scan_test_literals(current, previous: dict) -> int:
    """Print UNREGISTERED/STALE findings and summaries; return finding count."""
    registered = {embedded_hex for embedded_hex, _ in EMBEDDED_WIRE_VECTORS.values()}
    current_strings = _corpus_strings(current)
    previous_strings = {
        commit: _corpus_strings(corpus) for commit, corpus in previous.items()
    }
    findings = 0
    ignored = []
    test_local = 0
    for test_file, line, value in sorted(set(_test_hex_literals())):
        if _is_trivial_pattern(value):
            ignored.append(f"{test_file}:{line}")
            continue

        current_paths = _paths_containing(value, current_strings)
        if current_paths:
            if value not in registered:
                print(f"UNREGISTERED {test_file}:{line} {value[:16]}… "
                      f"-> {', '.join(current_paths)}")
                findings += 1
            continue

        for commit, strings in previous_strings.items():
            stale_paths = _paths_containing(value, strings)
            if stale_paths:
                print(f"STALE {test_file}:{line} {value[:16]}… "
                      f"-> {commit[:10]}: {', '.join(stale_paths)}")
                findings += 1
                break
        else:
            test_local += 1

    print(f"ignored trivial input patterns: {len(ignored)}"
          + (f" ({', '.join(ignored)})" if ignored else ""))
    print(f"test-local hex values: {test_local}")
    return findings


def _resolve(corpus, dotted_path: str):
    node = corpus
    for segment in dotted_path.split("."):
        if isinstance(node, list):
            if segment.isdigit():
                node = node[int(segment)]
            else:
                node = next(
                    item
                    for item in node
                    if isinstance(item, dict)
                    and segment in (item.get("id"), item.get("version"))
                )
        else:
            node = node[segment]
    return node


def main() -> int:
    source = json.loads(SOURCE_PATH.read_text())
    print(f"source: {source['repository']}@{source['commit']} {source['path']}")

    try:
        data = _fetch_verified(source["url"], source["size_bytes"], source["sha256"])
    except OSError as exc:
        print(f"FAIL download: {exc}")
        return 2
    except IntegrityError as exc:
        print(f"FAIL integrity:\n{exc}")
        return 2
    print(f"integrity: OK ({len(data)} bytes, sha256 {source['sha256']})")

    previous = {}
    for entry in source.get("previous_commits", []):
        commit = entry["commit"]
        try:
            previous[commit] = json.loads(
                _fetch_verified(
                    _raw_url(source, commit), entry["size_bytes"], entry["sha256"]
                )
            )
        except OSError:
            print(f"WARN: could not fetch previous revision {commit}; "
                  "STALE check skipped for it")
        except IntegrityError as exc:
            print(f"FAIL integrity (previous revision {commit}):\n{exc}")
            return 2
    print(f"previous revisions verified: {len(previous)}/"
          f"{len(source.get('previous_commits', []))}")

    corpus = json.loads(data)
    mismatches = 0
    for path, (embedded_hex, test_file) in EMBEDDED_WIRE_VECTORS.items():
        try:
            upstream_hex = _resolve(corpus, path)
        except (KeyError, IndexError, StopIteration):
            print(f"MISSING  {path} (embedded in {test_file})")
            mismatches += 1
            continue
        if upstream_hex != embedded_hex:
            print(f"MISMATCH {path} (embedded in {test_file})")
            print(f"  embedded {embedded_hex}")
            print(f"  upstream {upstream_hex}")
            mismatches += 1
        else:
            print(f"ok       {path}")

    for path, divergence in KNOWN_DIVERGENCES.items():
        upstream = _resolve(corpus, path)
        print(f"known divergence: {path} (in {divergence['file']}, "
              f"from upstream {divergence['source_commit']})")
        for field in ("public_key_hex", "signature_hex"):
            print(f"  {field}: embedded {divergence[field][:16]}… "
                  f"upstream {upstream[field][:16]}…")

    print(f"{len(EMBEDDED_WIRE_VECTORS) - mismatches}/{len(EMBEDDED_WIRE_VECTORS)} "
          f"embedded values match; {len(KNOWN_DIVERGENCES)} known divergence(s)")

    findings = _scan_test_literals(corpus, previous)
    print(f"UNREGISTERED/STALE findings: {findings}")
    if mismatches:
        return 1
    return 3 if findings else 0


if __name__ == "__main__":
    sys.exit(main())
