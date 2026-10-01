"""Check embedded test vectors against the pinned upstream wire-format corpus.

Downloads flop-labs/yellowpaper evidence/wire-format-v1.json at the commit
pinned in tests/fixtures/flop-yellowpaper/SOURCE.json into a temporary
directory, verifies its size and sha256, and compares every value listed in
_embedded_wire_vectors.py with the corpus. The corpus is not kept on disk.

Exit codes: 0 all match, 1 value mismatch, 2 download/integrity failure.
"""

import hashlib
import json
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
        data = _download_with_retry(source["url"])
    except OSError as exc:
        print(f"FAIL download: {exc}")
        return 2

    digest = hashlib.sha256(data).hexdigest()
    if len(data) != source["size_bytes"] or digest != source["sha256"]:
        print("FAIL integrity:")
        print(f"  size   expected {source['size_bytes']}, got {len(data)}")
        print(f"  sha256 expected {source['sha256']}")
        print(f"         got      {digest}")
        return 2
    print(f"integrity: OK ({len(data)} bytes, sha256 {digest})")

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
    return 1 if mismatches else 0


if __name__ == "__main__":
    sys.exit(main())
