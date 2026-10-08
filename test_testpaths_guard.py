import tomllib
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parent

# Files intentionally left out of pytest testpaths. (The live-server E2E
# script that used to be listed here is now scripts/e2e_client.py.)
EXCLUDED_TEST_FILES: set[str] = set()


def _configured_testpaths() -> set[str]:
    with (REPO_ROOT / "pyproject.toml").open("rb") as f:
        config = tomllib.load(f)

    return set(config["tool"]["pytest"]["ini_options"]["testpaths"])


def _root_test_files() -> set[str]:
    return {path.name for path in REPO_ROOT.glob("test_*.py")}


def test_every_root_test_file_is_in_testpaths():
    missing = sorted(
        _root_test_files() - EXCLUDED_TEST_FILES - _configured_testpaths()
    )

    assert not missing, (
        "test files missing from [tool.pytest.ini_options] testpaths: "
        + ", ".join(missing)
    )


def test_every_testpath_exists_on_disk():
    nonexistent = sorted(
        path for path in _configured_testpaths() if not (REPO_ROOT / path).exists()
    )

    assert not nonexistent, (
        "testpaths entries with no file on disk: " + ", ".join(nonexistent)
    )
