"""dashboard/src/lib/fixtures/verify-samples.json must be what the API
produces today (scripts/generate_dashboard_verify_samples.py). The dashboard
tests check their display rules against it, so a change in the API's /verify
output fails here, in the Python suite, until the file is regenerated."""

import importlib.util
import json
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent
SAMPLES_PATH = REPO_ROOT / "dashboard" / "src" / "lib" / "fixtures" / "verify-samples.json"


def _generator():
    spec = importlib.util.spec_from_file_location(
        "generate_dashboard_verify_samples",
        REPO_ROOT / "scripts" / "generate_dashboard_verify_samples.py",
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_dashboard_verify_samples_are_up_to_date():
    assert SAMPLES_PATH.read_text(encoding="utf-8") == _generator().render(), (
        "run: python scripts/generate_dashboard_verify_samples.py"
    )


def test_generation_is_deterministic():
    generator = _generator()
    assert generator.render() == generator.render()


def test_samples_cover_the_six_scenarios():
    samples = json.loads(SAMPLES_PATH.read_text(encoding="utf-8"))
    verdicts = {name: samples[name]["verify"]["verdict"] for name in ("valid", "m9", "m13", "truncated", "v3", "v2")}
    assert verdicts == {
        "valid": "valid", "m9": "invalid", "m13": "invalid",
        "truncated": "valid", "v3": "valid", "v2": "valid",
    }
