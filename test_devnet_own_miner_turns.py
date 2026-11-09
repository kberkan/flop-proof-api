"""Offline tests of the logic of scripts/check_devnet_own_miner_turns.py.

The script needs the live devnet and is not part of pytest. These tests use real
records saved from a run of it (tests/fixtures/flop-devnet/own-miner-records.json:
the two-turn session and a one-turn session, with only the metadata types they
need) and the public inputs file. Nothing here touches the network.
"""

import copy
import hashlib
import importlib.util
import json
import random
from pathlib import Path

import httpx
import pytest

REPO_ROOT = Path(__file__).resolve().parent
FIXTURE = REPO_ROOT / "tests" / "fixtures" / "flop-devnet" / "own-miner-records.json"
INPUTS = REPO_ROOT / "docs" / "evidence" / "devnet-own-miner-turns-2026-11-09.inputs.json"
TWO_TURNS = "0x6eaa86e1c784"
ONE_TURN = "0x097a294cb4c5"

_spec = importlib.util.spec_from_file_location(
    "check_devnet_own_miner_turns", REPO_ROOT / "scripts" / "check_devnet_own_miner_turns.py"
)
script = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(script)


@pytest.fixture(scope="module")
def saved():
    data = json.loads(FIXTURE.read_text())
    data["types"] = {int(k): v for k, v in data["types"].items()}
    return data


def _pair(saved, prefix):
    pair = next(p for p in saved["records"] if p["session"]["channel_id"].startswith(prefix))
    return copy.deepcopy(pair["session"]), copy.deepcopy(pair["record"])


def _check(saved, session, record, **input_overrides):
    inputs = dict(saved["inputs"], **input_overrides)
    return script.check_session(session, record, inputs, saved["schema"], saved["types"])


def _replace_in_settle(session, record, old: bytes, new: bytes):
    """Change bytes of the settle extrinsic and keep the tx hash consistent with it."""
    raw = bytes.fromhex(record["settle_extrinsic"][2:])
    assert raw.count(old) == 1
    raw = raw.replace(old, new)
    record["settle_extrinsic"] = "0x" + raw.hex()
    session["settle_tx"] = "0x" + hashlib.blake2b(raw, digest_size=32).hexdigest()


def _settle_args(saved, record):
    raw = bytes.fromhex(record["settle_extrinsic"][2:])
    return script.decode_extrinsic(saved["types"], saved["schema"], raw)[3]


def _flip(data: bytes) -> bytes:
    return bytes([data[0] ^ 1]) + data[1:]


@pytest.mark.parametrize("prefix", [TWO_TURNS, ONE_TURN])
def test_real_settled_sessions_pass_every_check(saved, prefix):
    session, record = _pair(saved, prefix)
    result = _check(saved, session, record)
    assert "error" not in result
    assert result["ok"], result["checks"]
    assert result["aggregate_gn"] == session["gn"]
    assert all(t["leaf_version"] == "V3" and t["signature_ok"] for t in result["turns"])


def test_two_turn_session_has_merkle_paths_and_a_root_that_is_no_leaf(saved):
    session, record = _pair(saved, TWO_TURNS)
    result = _check(saved, session, record)
    assert [t["turn_index"] for t in result["turns"]] == [0, 1]
    assert [t["g_n"] for t in result["turns"]] == [74, 305]
    assert all(t["path_length"] == 1 and t["path_ok"] for t in result["turns"])
    assert result["final_root"] not in [t["leaf"] for t in result["turns"]]
    assert "single_turn_leaf_is_root" not in result["checks"]


def test_one_turn_session_leaf_is_the_root(saved):
    session, record = _pair(saved, ONE_TURN)
    result = _check(saved, session, record)
    assert len(result["turns"]) == 1
    assert result["turns"][0]["path_length"] == 0
    assert result["turns"][0]["leaf"] == result["final_root"]
    assert result["checks"]["single_turn_leaf_is_root"] is True


def test_turns_committed_is_reported_not_judged(saved):
    session, record = _pair(saved, TWO_TURNS)
    result = _check(saved, session, record)
    assert result["observations"]["turns_committed"] == 1  # with 2 turns: not interpreted
    assert "turns_committed" not in result["checks"]


@pytest.mark.parametrize("prefix", [TWO_TURNS, ONE_TURN])
def test_changed_enclave_signature_fails_only_the_signature_check(saved, prefix):
    session, record = _pair(saved, prefix)
    args = _settle_args(saved, record)
    signature = args["verified_turns"][0]["enclave_sig"]
    _replace_in_settle(session, record, signature, _flip(signature))
    result = _check(saved, session, record)
    assert not result["ok"]
    assert [k for k, ok in result["checks"].items() if not ok] == ["all_enclave_signatures"]


def test_changed_turn_field_breaks_leaf_signature_and_merkle_root(saved):
    session, record = _pair(saved, TWO_TURNS)
    args = _settle_args(saved, record)
    h_in = args["verified_turns"][1]["h_in"]
    _replace_in_settle(session, record, h_in, _flip(h_in))
    failed = [k for k, ok in _check(saved, session, record)["checks"].items() if not ok]
    assert "all_enclave_signatures" in failed
    assert "all_merkle_paths" in failed
    assert "merkle_root_of_leaves" in failed


def test_changed_final_root_fails_root_and_receipt(saved):
    session, record = _pair(saved, ONE_TURN)
    root = _settle_args(saved, record)["final_root"]
    _replace_in_settle(session, record, root, _flip(root))
    failed = [k for k, ok in _check(saved, session, record)["checks"].items() if not ok]
    for name in ("merkle_root_of_leaves", "single_turn_leaf_is_root",
                 "agent_receipt_payable_escrow", "all_merkle_paths"):
        assert name in failed


def test_changed_receipt_signature_fails_only_the_receipt_check(saved):
    session, record = _pair(saved, TWO_TURNS)
    signature = _settle_args(saved, record)["agent_receipt_sig"]
    _replace_in_settle(session, record, signature, _flip(signature))
    failed = [k for k, ok in _check(saved, session, record)["checks"].items() if not ok]
    assert failed == ["agent_receipt_payable_escrow"]


@pytest.mark.parametrize(
    ("change", "expected"),
    [
        (dict(settle_tx="0x" + "11" * 32), "settle_tx_found_in_block"),
        (dict(gn=1), "gn"),
        (dict(miner_paid="1"), "settled_event"),
    ],
)
def test_wrong_session_inputs_fail(saved, change, expected):
    session, record = _pair(saved, ONE_TURN)
    session.update(change)
    result = _check(saved, session, record)
    assert not result["ok"]
    assert result["checks"][expected] is False


@pytest.mark.parametrize(
    ("override", "expected"),
    [
        ("genesis_hash", "channel_id_v1"),
        ("miner_account", "signed_by_miner"),
        ("enclave_public_key", "channel_enclave_key"),
    ],
)
def test_wrong_network_inputs_fail(saved, override, expected):
    session, record = _pair(saved, ONE_TURN)
    result = _check(saved, session, record, **{override: "0x" + "22" * 32})
    assert not result["ok"]
    assert result["checks"][expected] is False


def test_tx_not_in_block_is_a_failure_not_a_crash(saved):
    session, record = _pair(saved, ONE_TURN)
    record.update(settle_extrinsic=None, settle_extrinsic_index=None)
    result = _check(saved, session, record)
    assert not result["ok"]
    assert result["checks"] == {"settle_tx_found_in_block": False}


def test_channel_not_closed_at_the_pinned_block_fails(saved):
    session, record = _pair(saved, ONE_TURN)
    record["channel_at_pin"] = record["channel_before"]
    result = _check(saved, session, record)
    assert not result["ok"]
    assert result["checks"]["channel_closed_at_pinned_block"] is False


def test_missing_evidence_entries_fail(saved):
    session, record = _pair(saved, ONE_TURN)
    record.update(toploc_evidence=None, registrations=None)
    checks = _check(saved, session, record)["checks"]
    assert checks["toploc_evidence_present"] is False
    assert checks["session_registrations_present"] is False


def test_events_of_another_extrinsic_do_not_count(saved):
    session, record = _pair(saved, ONE_TURN)
    record["settle_extrinsic_index"] += 1
    checks = _check(saved, session, record)["checks"]
    assert checks["settled_event"] is False


@pytest.mark.parametrize("change", ["truncated", "padded"])
def test_extrinsic_that_is_not_exactly_consumed_is_an_error(saved, change):
    session, record = _pair(saved, ONE_TURN)
    raw = record["settle_extrinsic"]
    record["settle_extrinsic"] = raw[:-2] if change == "truncated" else raw + "00"
    session["settle_tx"] = "0x" + hashlib.blake2b(
        bytes.fromhex(record["settle_extrinsic"][2:]), digest_size=32
    ).hexdigest()
    result = _check(saved, session, record)
    assert not result["ok"]
    assert "error" in result


def test_fixture_holds_only_the_types_it_needs(saved):
    assert FIXTURE.stat().st_size < 200_000
    assert len(saved["records"]) == 2


# -- the inputs file ---------------------------------------------------------


@pytest.fixture(scope="module")
def inputs():
    return json.loads(INPUTS.read_text())


def test_random_sessions_follow_from_the_seed(inputs):
    selection = inputs["random_selection"]
    expected = random.Random(selection["seed"]).sample(
        sorted(tx[2:] for tx in selection["population_settle_txs"]), 3
    )
    picked = [s["settle_tx"][2:] for s in inputs["sessions"] if s["selection"] == "random"]
    assert sorted(picked) == sorted(expected)


def test_chosen_sessions_are_not_in_the_random_population(inputs):
    population = set(inputs["random_selection"]["population_settle_txs"])
    chosen = [s for s in inputs["sessions"] if s["selection"] == "chosen"]
    assert len(chosen) == 3
    assert len(population) == 34
    assert not population & {s["settle_tx"] for s in chosen}


def test_inputs_hold_only_public_chain_values(inputs):
    assert set(inputs) == {"note", "network", "genesis_hash", "miner_account",
                           "enclave_public_key", "random_selection", "sessions"}
    assert len(inputs["sessions"]) == 6
    for session in inputs["sessions"]:
        assert set(session) == {"channel_id", "settle_tx", "settle_block", "gn",
                                "miner_paid", "selection"}
        assert isinstance(session["settle_block"], int)
    text = INPUTS.read_text()
    for marker in ("worker-1", "ghost", "trycloudflare", "mailbox", "/data/"):
        assert marker not in text


# -- RPC: a limit, and nothing is retried ------------------------------------


def _rpc(handler, limit):
    rpc = script.LimitedRpc("https://rpc.invalid", limit)
    rpc.delay = 0
    rpc._client = httpx.Client(transport=httpx.MockTransport(handler))
    return rpc


def test_request_limit_stops_before_sending():
    calls = []

    def handler(request):
        calls.append(request)
        return httpx.Response(200, json={"jsonrpc": "2.0", "id": 1, "result": "0x00"})

    rpc = _rpc(handler, 2)
    rpc.call("chain_getFinalizedHead", [])
    rpc.call("chain_getFinalizedHead", [])
    with pytest.raises(script.devnet.DevnetError, match="request limit"):
        rpc.call("chain_getFinalizedHead", [])
    assert len(calls) == 2


def test_block_hashes_are_fetched_once_in_one_request():
    calls = []

    def handler(request):
        numbers = json.loads(request.content)["params"][0]
        calls.append(numbers)
        return httpx.Response(200, json={"jsonrpc": "2.0", "id": 1,
                                         "result": [f"0x{n:x}" for n in numbers]})

    rpc = _rpc(handler, 5)
    rpc.block_hashes([3, 1, 2])
    rpc.block_hashes([2, 3])
    assert calls == [[1, 2, 3]]
    assert rpc.hashes[2] == "0x2"


@pytest.mark.parametrize("status", [403, 503])
def test_http_errors_are_reported_and_not_retried(status):
    calls = []

    def handler(request):
        calls.append(request)
        return httpx.Response(status, text="no")

    rpc = _rpc(handler, 5)
    with pytest.raises(script.devnet.DevnetError, match=f"HTTP {status}"):
        rpc.call("chain_getFinalizedHead", [])
    assert len(calls) == 1
