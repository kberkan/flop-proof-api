"""Offline tests of the decoding logic of scripts/check_devnet_channel_ids.py.

The script itself needs the live devnet and is not part of pytest. These tests
use a few real ComputeChannel.Channels records (key + value hex) and the
sub-registry of metadata types they need, saved from a run of the script into
tests/fixtures/flop-devnet/channels-sample.json (see its "source" field), and
a small hand-built metadata blob for the metadata parser.
"""

import hashlib
import importlib.util
import json
from pathlib import Path

import httpx
import pytest

REPO_ROOT = Path(__file__).resolve().parent
FIXTURE = REPO_ROOT / "tests" / "fixtures" / "flop-devnet" / "channels-sample.json"

_spec = importlib.util.spec_from_file_location(
    "check_devnet_channel_ids", REPO_ROOT / "scripts" / "check_devnet_channel_ids.py"
)
script = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(script)


@pytest.fixture(scope="module")
def fixture():
    data = json.loads(FIXTURE.read_text())
    data["types"] = {int(k): v for k, v in data["types"].items()}
    return data


def _check(fixture, sample, genesis=None):
    genesis = genesis or fixture["genesis_hash"]
    return script.check_channel(
        fixture["types"], fixture["entry"], bytes.fromhex(genesis[2:]),
        bytes.fromhex(fixture["prefix"][2:]), sample["key"], sample["value"],
    )


def test_storage_prefix_matches_known_values(fixture):
    # twox128("System") is a well-known constant of every Substrate chain.
    assert script.twox128("System").hex() == "26aa394eea5630e07c48ae0c9558cef7"
    assert "0x" + script.storage_prefix("ComputeChannel", "Channels").hex() == fixture["prefix"]


def test_real_channel_records_decode_and_match(fixture):
    assert len(fixture["samples"]) >= 3
    for sample in fixture["samples"]:
        result = _check(fixture, sample)
        assert result["status"] == "match", result
        assert result["nonce"] == sample["nonce"]
        assert result["computed_channel_id"] == sample["key"][-64:]


def test_wrong_genesis_is_a_mismatch(fixture):
    other = "0x" + "11" * 32
    for sample in fixture["samples"]:
        assert _check(fixture, sample, genesis=other)["status"] == "mismatch"


def test_changed_channel_id_in_key_is_an_error(fixture):
    sample = dict(fixture["samples"][0])
    key = sample["key"]
    sample["key"] = key[:-2] + ("00" if key[-2:] != "00" else "01")
    result = _check(fixture, sample)
    assert result["status"] == "error"
    assert "blake2_128" in result["error"]


def test_key_with_consistent_hash_but_other_channel_id_is_a_mismatch(fixture):
    sample = dict(fixture["samples"][0])
    prefix = bytes.fromhex(fixture["prefix"][2:])
    other_id = hashlib.blake2b(b"another channel", digest_size=32).digest()
    key_hash = hashlib.blake2b(other_id, digest_size=16).digest()
    sample["key"] = "0x" + (prefix + key_hash + other_id).hex()
    assert _check(fixture, sample)["status"] == "mismatch"


def test_truncated_and_padded_values_are_errors(fixture):
    sample = fixture["samples"][0]
    short = dict(sample, value=sample["value"][:-2])
    padded = dict(sample, value=sample["value"] + "00")
    assert _check(fixture, short)["status"] == "error"
    result = _check(fixture, padded)
    assert result["status"] == "error"
    assert "trailing" in result["error"]


def test_describe_decoding_names_the_fields_used(fixture):
    text = "\n".join(script.describe_decoding(fixture["types"], fixture["entry"]))
    for name in ("agent", "miner", "nonce"):
        assert f"{name}:" in text
    assert "u64 little-endian" in text


# -- metadata parser and field-name lookup, on a hand-built v14 blob --------


def _compact(n):
    assert n < 64
    return bytes([n << 2])


def _string(s):
    return _compact(len(s)) + s.encode()


def _type(type_id, path, definition):
    return _compact(type_id) + _compact(len(path)) + b"".join(_string(p) for p in path) \
        + _compact(0) + definition + _compact(0)


def _fields(named):
    out = _compact(len(named))
    for name, ty in named:
        out += (b"\x01" + _string(name) if name else b"\x00") + _compact(ty) + b"\x00" + _compact(0)
    return out


def _tiny_metadata(field_order):
    """Metadata with ComputeChannel.Channels: map Blake2_128Concat H256 -> Channel."""
    types = [
        _type(0, [], b"\x05\x03"),  # u8
        _type(1, [], b"\x03" + (32).to_bytes(4, "little") + _compact(0)),  # [u8; 32]
        _type(2, ["sp_core", "crypto", "AccountId32"], b"\x00" + _fields([(None, 1)])),
        _type(3, [], b"\x05\x06"),  # u64
        _type(4, ["Channel"], b"\x00" + _fields([(n, {"nonce": 3}.get(n, 2)) for n in field_order])),
    ]
    entry = _string("Channels") + b"\x01" + b"\x01" + _compact(1) + b"\x02" + _compact(1) \
        + _compact(4) + _compact(0) + _compact(0)
    pallet = _string("ComputeChannel") + b"\x01" + _string("ComputeChannel") + _compact(1) + entry \
        + b"\x00" + b"\x00" + _compact(0) + b"\x00" + b"\x67"
    return b"meta" + b"\x0e" + _compact(len(types)) + b"".join(types) + _compact(1) + pallet


@pytest.mark.parametrize("order", [["agent", "miner", "nonce"], ["nonce", "miner", "agent"]])
def test_tiny_metadata_end_to_end_is_independent_of_field_order(order):
    meta = script.parse_metadata(_tiny_metadata(order))
    entry = script.channels_entry(meta)
    assert [f["name"] for f in meta["types"][entry["value"]]["fields"]] == order

    genesis, agent, miner, nonce = bytes(range(32)), b"\xaa" * 32, b"\xbb" * 32, 2**64 - 5
    parts = {"agent": agent, "miner": miner, "nonce": nonce.to_bytes(8, "little")}
    value = b"".join(parts[n] for n in order)
    channel_id = bytes.fromhex(script.compute_channel_id_v1(genesis, agent, miner, nonce))
    prefix = script.storage_prefix("ComputeChannel", "Channels")
    key = prefix + hashlib.blake2b(channel_id, digest_size=16).digest() + channel_id

    result = script.check_channel(
        meta["types"], entry, genesis, prefix, "0x" + key.hex(), "0x" + value.hex()
    )
    assert result["status"] == "match"
    assert (result["nonce"], result["agent"], result["miner"]) == (nonce, agent.hex(), miner.hex())


def test_metadata_with_unexpected_shape_is_refused():
    meta = script.parse_metadata(_tiny_metadata(["agent", "miner", "nonce"]))
    meta["storage"]["ComputeChannel"]["Channels"]["hashers"] = [5]  # Twox64Concat
    with pytest.raises(script.DevnetError):
        script.channels_entry(meta)
    with pytest.raises(script.DevnetError):
        script.channels_entry(script.parse_metadata(_tiny_metadata(["agent", "miner"])))
    with pytest.raises(script.DevnetError):
        script.parse_metadata(b"meta" + b"\x0f")
    with pytest.raises(script.DevnetError):
        script.parse_metadata(b"nope")


# -- RPC client: a 403 stops the run, nothing is retried --------------------


def test_http_403_is_reported_and_not_retried():
    calls = []

    def handler(request):
        calls.append(request)
        return httpx.Response(403, text="error code: 1010")

    rpc = script.Rpc(delay=0)
    rpc._client = httpx.Client(transport=httpx.MockTransport(handler))
    with pytest.raises(script.DevnetError, match="HTTP 403"):
        rpc.call("chain_getBlockHash", [0])
    assert len(calls) == 1
    assert rpc.requests == 1
