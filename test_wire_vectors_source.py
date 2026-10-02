import json
import re
from pathlib import Path

from _embedded_wire_vectors import EMBEDDED_WIRE_VECTORS, KNOWN_DIVERGENCES


REPO_ROOT = Path(__file__).resolve().parent
SOURCE_PATH = REPO_ROOT / "tests" / "fixtures" / "flop-yellowpaper" / "SOURCE.json"


def _normalized_text(test_file: str) -> str:
    """Test file text with whitespace and quotes removed, so hex literals split
    across adjacent string lines compare as one value."""
    return re.sub(r'[\s"]', "", (REPO_ROOT / test_file).read_text()).lower()


def test_source_json_fields_and_formats():
    source = json.loads(SOURCE_PATH.read_text())

    assert source["repository"] == "flop-labs/yellowpaper"
    assert re.fullmatch(r"[0-9a-f]{40}", source["commit"])
    assert source["path"] == "evidence/wire-format-v1.json"
    assert source["url"] == (
        "https://raw.githubusercontent.com/"
        f"{source['repository']}/{source['commit']}/{source['path']}"
    )
    assert re.fullmatch(r"[0-9a-f]{64}", source["sha256"])
    assert isinstance(source["size_bytes"], int) and source["size_bytes"] > 0
    assert source["license_note"]
    assert re.fullmatch(
        rf"https://github\.com/{re.escape(source['repository'])}/issues/[0-9]+",
        source["license_issue"],
    )

    previous = source["previous_commits"]
    assert isinstance(previous, list)
    for entry in previous:
        assert set(entry) == {"commit", "sha256", "size_bytes"}
        assert re.fullmatch(r"[0-9a-f]{40}", entry["commit"])
        assert re.fullmatch(r"[0-9a-f]{64}", entry["sha256"])
        assert isinstance(entry["size_bytes"], int) and entry["size_bytes"] > 0
        assert entry["commit"] != source["commit"]
    assert len({entry["commit"] for entry in previous}) == len(previous)


def test_corpus_is_not_vendored():
    assert not (SOURCE_PATH.parent / "wire-format-v1.json").exists()


def test_embedded_wire_vectors_appear_verbatim_in_tests():
    missing = [
        f"{path} -> {test_file}"
        for path, (embedded_hex, test_file) in EMBEDDED_WIRE_VECTORS.items()
        if embedded_hex not in _normalized_text(test_file)
    ]

    assert not missing, "embedded values not found in their test files: " + ", ".join(
        missing
    )


def test_known_divergences_appear_verbatim_in_tests():
    for path, divergence in KNOWN_DIVERGENCES.items():
        text = _normalized_text(divergence["file"])
        assert divergence["public_key_hex"] in text, path
        assert divergence["signature_hex"] in text, path
