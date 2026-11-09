"""Check sessions settled by our own devnet miner with this repository's primitives.

Read-only. Talks only to the public devnet RPC and uses only read methods:
chain_getBlockHash, chain_getFinalizedHead, chain_getHeader, chain_getBlock,
state_getMetadata, state_getRuntimeVersion, state_getStorage and
state_queryStorageAt. No key, faucet or transaction.

Input is a small JSON file of public values, never a raw miner log
(docs/evidence/devnet-own-miner-turns-2026-11-09.inputs.json): channel ids,
settle tx hashes, settle block numbers, `gn`, `miner_paid` and the enclave public
key. With settle blocks known, each session costs about 5 requests, and the run
6 more.

For each session (see check_session, which does not touch the network):
  - blake2_256 of the extrinsic in the settle block equals the settle tx hash,
    and the extrinsic decodes completely from the metadata types as
    ComputeChannel.settle, signed by the miner account, for that channel;
  - channel_id_v1 recomputed from the channel record equals the channel id, and
    the record's miner and enclave key are the expected ones;
  - for every VerifiedTurn: the leaf hash from our function, enclave_sig under the
    enclave key, the Merkle path against final_root;
  - our Merkle root over the leaves equals final_root (one turn: leaf = root);
  - aggregate_gn = sum of g_n = the input gn;
  - System.Events of that extrinsic: ExtrinsicSuccess and Settled (cooperative,
    same aggregate_gn, miner_paid equal to the input);
  - agent_receipt_sig verifies with payable = the channel's escrow. That payable
    rule comes from a comment in @flop-labs/sdk ("Cooperative: payable = escrow"),
    not from a check against the runtime source;
  - the channel's TOPLOC evidence and session registrations exist in the block
    before the settle, and the submit_toploc_evidence extrinsic is in the block
    the record names.

Reported, not judged: turns_committed, and whether toploc_commitment_hash is zero
(zero is valid, see PARITY.md).

Channel records are also read at one pinned finalized block (state must be
Closed). Locating and checking a settle has to read earlier finalized blocks too,
because a closed channel's evidence entries are gone.

A session with no settle_block is located first: the RPC has no lookup from a tx
hash to a block, so this is a binary search on the channel's state between its
opened_at and the session's search_upper_block (about 10 requests per session).
The result is written back to the inputs file.

It needs the network and the devnet can be reset, so it is not part of pytest or
CI. check_session and the decoding are tested offline in
test_devnet_own_miner_turns.py with real records saved by --write-fixture.

Exit codes: 0 every check of every session passed, 1 a check failed, 2 the RPC could
not be read, the request limit was reached, or the chain is not the expected one.
A 403 or 503 from the RPC stops the run; nothing is retried.
"""

import argparse
import hashlib
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import check_devnet_channel_ids as devnet  # noqa: E402
from app import crypto  # noqa: E402

DEFAULT_INPUTS = (
    devnet.REPO_ROOT / "docs" / "evidence" / "devnet-own-miner-turns-2026-11-09.inputs.json"
)
PALLET = "ComputeChannel"
DEFAULT_MAX_REQUESTS = 60
ZERO32 = bytes(32)


def from_hex(value: str) -> bytes:
    return bytes.fromhex(value[2:] if value.startswith("0x") else value)


def blake2_256(data: bytes) -> bytes:
    return hashlib.blake2b(data, digest_size=32).digest()


# --------------------------------------------------------------------------
# Metadata: what check_devnet_channel_ids.parse_metadata does not keep
# --------------------------------------------------------------------------


def _skip_pallets(r: devnet.Reader) -> None:
    for _ in range(r.compact()):
        r.string()
        if r.u8():
            r.string()
            for _ in range(r.compact()):
                r.string()
                r.u8()
                if r.u8() == 0:
                    r.compact()
                else:
                    r.vec(r.u8)
                    r.compact()
                    r.compact()
                r.vec(r.u8)
                r.vec(r.string)
        r.option(r.compact)
        r.option(r.compact)
        for _ in range(r.compact()):
            r.string()
            r.compact()
            r.vec(r.u8)
            r.vec(r.string)
        r.option(r.compact)
        r.u8()


def build_schema(raw_metadata: bytes, meta: dict) -> dict:
    """Type ids this script decodes with, all taken from the metadata."""
    r = devnet.Reader(raw_metadata, 5)
    params = {}
    for _ in range(r.compact()):
        type_id = r.compact()
        r.vec(r.string)
        params[type_id] = dict(r.vec(lambda: (r.string(), r.option(r.compact))))
        devnet._read_type_def(r)
        r.vec(r.string)
    _skip_pallets(r)
    extrinsic_type = r.compact()
    extrinsic_version = r.u8()
    extrinsic_params = params[extrinsic_type]
    records = [i for i, t in meta["types"].items() if t["path"][-1:] == ["EventRecord"]]
    if len(records) != 1:
        raise devnet.DevnetError("metadata does not have exactly one EventRecord type")
    entries = meta["storage"][PALLET]
    for item in ("Channels", "ChannelToplocEvidence", "SessionEvidenceRegistrations"):
        if entries[item]["hashers"] != [devnet.BLAKE2_128_CONCAT]:
            raise devnet.DevnetError(f"{PALLET}.{item} is not a Blake2_128Concat map")
    return {
        "extrinsic_version": extrinsic_version,
        "address": extrinsic_params["Address"],
        "signature": extrinsic_params["Signature"],
        "extra": extrinsic_params["Extra"],
        "call": extrinsic_params["Call"],
        "event_record": records[0],
        "channel": entries["Channels"]["value"],
        "toploc_evidence": entries["ChannelToplocEvidence"]["value"],
        "registrations": entries["SessionEvidenceRegistrations"]["value"],
    }


# --------------------------------------------------------------------------
# Decoding
# --------------------------------------------------------------------------


def decode_extrinsic(types: dict, schema: dict, raw: bytes):
    """Return (signer or None, pallet, call name, args). Every byte must be used."""
    r = devnet.Reader(raw)
    length = r.compact()
    if r.pos + length != len(raw):
        raise ValueError("extrinsic length prefix does not match its size")
    version = r.u8()
    if version & 0x7F != schema["extrinsic_version"]:
        raise ValueError(f"unexpected extrinsic version byte {version}")
    signer = None
    if version & 0x80:
        address = devnet.decode_value(types, schema["address"], r)
        if address[0] != "Id":
            raise ValueError(f"unexpected address kind {address[0]}")
        signer = address[1]
        devnet.decode_value(types, schema["signature"], r)
        devnet.decode_value(types, schema["extra"], r)
    pallet, (name, args) = devnet.decode_value(types, schema["call"], r)
    if r.pos != len(raw):
        raise ValueError(f"{len(raw) - r.pos} trailing bytes after the extrinsic")
    return signer, pallet, name, args


def decode_events(types: dict, schema: dict, raw: bytes, extrinsic_index: int) -> list:
    """Return [(pallet, name, fields)] of one extrinsic from a System.Events value."""
    r = devnet.Reader(raw)
    events = []
    for _ in range(r.compact()):
        record = devnet.decode_value(types, schema["event_record"], r)
        if record["phase"] == ("ApplyExtrinsic", extrinsic_index):
            pallet, (name, fields) = record["event"]
            events.append((pallet, name, fields))
    if r.pos != len(raw):
        raise ValueError(f"{len(raw) - r.pos} trailing bytes after the events")
    return events


# --------------------------------------------------------------------------
# The checks (no network)
# --------------------------------------------------------------------------


def _check_turns(cid: bytes, enclave_key: bytes, args: dict) -> dict:
    root = args["final_root"]
    turns, leaves = [], []
    for turn in args["verified_turns"]:
        leaf = bytes.fromhex(
            crypto.compute_verified_turn_leaf_v0_v1_v2_v3(
                int(turn["leaf_version"][0][1:]), cid, turn["turn_index"],
                turn["h_in"], turn["h_out"], turn["g_n"], turn["decode_policy_hash"],
                turn["h_ids"], turn["toploc_commitment_hash"], turn["miner_recv_ms"],
                turn["miner_done_ms"], turn["latency_ms"],
            )
        )
        leaves.append(leaf)
        path = [(sibling, is_left) for sibling, is_left in turn["merkle_path"]]
        turns.append({
            "turn_index": turn["turn_index"],
            "leaf_version": turn["leaf_version"][0],
            "g_n": turn["g_n"],
            "leaf": leaf.hex(),
            "signature_ok": crypto.verify_verified_turn_leaf_signature(
                enclave_key, turn["enclave_sig"], leaf
            ),
            "path_length": len(path),
            "path_ok": crypto.verify_merkle_path(leaf, turn["turn_index"], path, root),
            "toploc_commitment_hash": turn["toploc_commitment_hash"].hex(),
            "toploc_nonzero": turn["toploc_commitment_hash"] != ZERO32,
            "h_ids_nonzero": turn["h_ids"] != ZERO32,
            "decode_policy_nonzero": turn["decode_policy_hash"] != ZERO32,
        })
    return {"turns": turns, "leaves": leaves}


def check_session(session: dict, record: dict, inputs: dict, schema: dict, types: dict) -> dict:
    """Run every check on one session's saved chain data. Touches no network.

    record: settle_extrinsic and settle_extrinsic_index (the extrinsic whose hash
    matched, None if none did), events, channel_before, channel_at_pin,
    toploc_evidence, registrations, toploc_extrinsics (hex values from the chain).
    """
    result = {"channel_id": session["channel_id"], "settle_block": session["settle_block"],
              "checks": {}, "turns": [], "observations": {}}
    checks = result["checks"]
    try:
        cid = from_hex(session["channel_id"])
        miner = from_hex(inputs["miner_account"])
        enclave_key = from_hex(inputs["enclave_public_key"])
        genesis = from_hex(inputs["genesis_hash"])

        raw = record["settle_extrinsic"]
        checks["settle_tx_found_in_block"] = raw is not None and (
            "0x" + blake2_256(from_hex(raw)).hex() == session["settle_tx"]
        )
        if raw is None:
            return _finish(result)
        signer, pallet, name, args = decode_extrinsic(types, schema, from_hex(raw))
        checks["signed_by_miner"] = signer == miner
        checks["call_is_settle"] = (pallet, name) == (PALLET, "settle")
        checks["call_is_for_channel"] = args["channel_id"] == cid

        channel = devnet.decode_exact(types, schema["channel"], from_hex(record["channel_before"]))
        checks["channel_miner"] = channel["miner"] == miner
        checks["channel_enclave_key"] = channel["enclave_key"] == enclave_key
        checks["channel_id_v1"] = (
            crypto.compute_channel_id_v1(
                genesis, channel["agent"], channel["miner"], channel["nonce"]
            ) == cid.hex()
        )
        pinned = devnet.decode_exact(types, schema["channel"], from_hex(record["channel_at_pin"]))
        checks["channel_closed_at_pinned_block"] = pinned["state"][0] == "Closed"

        checked = _check_turns(cid, enclave_key, args)
        turns, leaves = checked["turns"], checked["leaves"]
        result["turns"] = turns
        checks["has_turns"] = bool(turns)
        checks["all_enclave_signatures"] = all(t["signature_ok"] for t in turns)
        checks["all_merkle_paths"] = all(t["path_ok"] for t in turns)
        final_root = args["final_root"]
        checks["merkle_root_of_leaves"] = crypto.compute_merkle_root(leaves) == final_root.hex()
        if len(leaves) == 1:
            checks["single_turn_leaf_is_root"] = leaves[0] == final_root
        checks["gn"] = args["aggregate_gn"] == sum(t["g_n"] for t in turns) == session["gn"]
        result["final_root"] = final_root.hex()
        result["aggregate_gn"] = args["aggregate_gn"]

        events = decode_events(types, schema, from_hex(record["events"]),
                               record["settle_extrinsic_index"])
        checks["extrinsic_success_event"] = any(
            (p, n) == ("System", "ExtrinsicSuccess") for p, n, _ in events
        )
        checks["settled_event"] = any(
            (p, n) == (PALLET, "Settled") and f["channel_id"] == cid
            and f["cooperative"] is True and f["aggregate_gn"] == session["gn"]
            and f["miner_paid"] == int(session["miner_paid"])
            for p, n, f in events
        )

        # payable = escrow is the rule stated in a @flop-labs/sdk comment.
        checks["agent_receipt_payable_escrow"] = crypto.verify_agent_receipt_v1(
            channel["agent_key"], args["agent_receipt_sig"], cid, final_root,
            args["aggregate_gn"], channel["escrow"],
        )

        checks["toploc_evidence_present"] = record["toploc_evidence"] is not None
        checks["session_registrations_present"] = record["registrations"] is not None
        if record["toploc_evidence"] is not None:
            evidence = devnet.decode_exact(
                types, schema["toploc_evidence"], from_hex(record["toploc_evidence"])
            )
            result["observations"].update(
                turns_committed=evidence["turns_committed"],
                toploc_evidence_block=evidence["last_submitted"],
            )
            calls = [decode_extrinsic(types, schema, from_hex(e))
                     for e in record["toploc_extrinsics"]]
            checks["submit_toploc_evidence_extrinsic"] = any(
                signer_ == miner and (p, n) == (PALLET, "submit_toploc_evidence")
                and a["channel_id"] == cid
                for signer_, p, n, a in calls
            )
    except (ValueError, KeyError, TypeError, IndexError) as e:
        result["error"] = f"{type(e).__name__}: {e}"
    return _finish(result)


def _finish(result: dict) -> dict:
    result["ok"] = "error" not in result and bool(result["checks"]) and all(
        result["checks"].values()
    )
    return result


# --------------------------------------------------------------------------
# RPC
# --------------------------------------------------------------------------


class LimitedRpc(devnet.Rpc):
    """The devnet RPC client with a hard request limit and a block-hash cache."""

    def __init__(self, url: str, max_requests: int):
        super().__init__(url)
        self.max_requests = max_requests
        self.hashes = {}

    def call(self, method: str, params: list):
        if self.requests >= self.max_requests:
            raise devnet.DevnetError(
                f"request limit reached ({self.max_requests}) before {method}"
            )
        return super().call(method, params)

    def block_hashes(self, numbers) -> None:
        """Fetch the hashes of many blocks in one request."""
        missing = sorted({n for n in numbers if n not in self.hashes})
        if missing:
            self.hashes.update(zip(missing, self.call("chain_getBlockHash", [missing])))


def _map_key(item: str, cid: bytes) -> str:
    prefix = devnet.storage_prefix(PALLET, item)
    return "0x" + (prefix + hashlib.blake2b(cid, digest_size=16).digest() + cid).hex()


def _read_at(rpc: LimitedRpc, keys: list, block_hash: str) -> dict:
    values = {}
    for block in rpc.call("state_queryStorageAt", [keys, block_hash]):
        values.update(dict(block["changes"]))
    return values


def locate_settle_block(rpc, session, types, schema, pinned_channel_hex) -> int:
    """Binary search for the first block at which the channel is Closed."""
    cid = from_hex(session["channel_id"])
    channel = devnet.decode_exact(types, schema["channel"], from_hex(pinned_channel_hex))
    low, high = channel["opened_at"], session["search_upper_block"]
    rpc.block_hashes(range(low, high + 1))
    key = _map_key("Channels", cid)
    while high - low > 1:
        middle = (low + high) // 2
        value = rpc.call("state_getStorage", [key, rpc.hashes[middle]])
        state = devnet.decode_exact(types, schema["channel"], from_hex(value))["state"]
        if state[0] == "Closed":
            high = middle
        else:
            low = middle
    return high


def read_record(rpc, session, schema, types, pinned_channel_hex) -> dict:
    """Read one session's chain data. About 5 requests."""
    cid = from_hex(session["channel_id"])
    number = session["settle_block"]
    # In one request: the evidence block has been a few blocks before the settle.
    rpc.block_hashes(range(number - 12, number + 1))
    block_hash = rpc.hashes[number]
    extrinsics = rpc.call("chain_getBlock", [block_hash])["block"]["extrinsics"]
    settle, index = None, None
    for i, extrinsic in enumerate(extrinsics):
        if "0x" + blake2_256(from_hex(extrinsic)).hex() == session["settle_tx"]:
            settle, index = extrinsic, i
    events_key = "0x" + (devnet.twox128("System") + devnet.twox128("Events")).hex()
    events = rpc.call("state_getStorage", [events_key, block_hash])
    keys = {item: _map_key(item, cid)
            for item in ("Channels", "ChannelToplocEvidence", "SessionEvidenceRegistrations")}
    before = _read_at(rpc, list(keys.values()), rpc.hashes[number - 1])
    evidence_hex = before.get(keys["ChannelToplocEvidence"])
    toploc_extrinsics = []
    if evidence_hex:
        evidence = devnet.decode_exact(types, schema["toploc_evidence"], from_hex(evidence_hex))
        evidence_block = evidence["last_submitted"]
        rpc.block_hashes([evidence_block])
        block = rpc.call("chain_getBlock", [rpc.hashes[evidence_block]])["block"]
        toploc_extrinsics = [e for e in block["extrinsics"] if cid in from_hex(e)]
    return {
        "settle_extrinsic": settle,
        "settle_extrinsic_index": index,
        "events": events,
        "channel_before": before.get(keys["Channels"]),
        "channel_at_pin": pinned_channel_hex,
        "toploc_evidence": evidence_hex,
        "registrations": before.get(keys["SessionEvidenceRegistrations"]),
        "toploc_extrinsics": toploc_extrinsics,
    }


# --------------------------------------------------------------------------
# Fixture for the offline tests
# --------------------------------------------------------------------------


class _TracingTypes(dict):
    """Records which type ids a decode touches."""

    def __init__(self, types):
        super().__init__(types)
        self.used = set()

    def __getitem__(self, key):
        self.used.add(key)
        return super().__getitem__(key)


def write_fixture(path, pairs, inputs, schema, types, source) -> None:
    """Save real records and only the types they need (the full set is ~1 MB)."""
    tracing = _TracingTypes(types)
    for session, record in pairs:
        check_session(session, record, inputs, schema, tracing)
    kept = {}
    for type_id in sorted(tracing.used):
        t = dict(types[type_id])
        if t["kind"] == "variant":
            t["variants"] = [v for v in t["variants"]
                             if all(f["ty"] in tracing.used for f in v["fields"])]
        kept[str(type_id)] = t
    fixture = {
        "source": source,
        "inputs": {k: inputs[k] for k in ("genesis_hash", "miner_account", "enclave_public_key")},
        "schema": schema,
        "types": kept,
        "records": [{"session": s, "record": r} for s, r in pairs],
    }
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(fixture, indent=1, sort_keys=True) + "\n")


# --------------------------------------------------------------------------
# Main
# --------------------------------------------------------------------------


def _report(result: dict) -> None:
    status = "PASS" if result["ok"] else "FAIL"
    print(f"{status} {result['channel_id']} settle #{result['settle_block']} "
          f"aggregate_gn {result.get('aggregate_gn')} root {result.get('final_root')}")
    for turn in result["turns"]:
        print(f"  turn {turn['turn_index']} {turn['leaf_version']} g_n {turn['g_n']} "
              f"leaf {turn['leaf']} sig {turn['signature_ok']} "
              f"path[{turn['path_length']}] {turn['path_ok']} "
              f"toploc_nonzero {turn['toploc_nonzero']}")
    print(f"  observations (not judged): {result['observations']}")
    failed = [name for name, ok in result["checks"].items() if not ok]
    print(f"  checks: {len(result['checks']) - len(failed)}/{len(result['checks'])} passed"
          + (f"; failed: {failed}" if failed else ""))
    if "error" in result:
        print(f"  error: {result['error']}")


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--inputs", default=str(DEFAULT_INPUTS))
    ap.add_argument("--url", default=devnet.RPC_URL)
    ap.add_argument("--only", action="append", default=[],
                    help="channel id prefix (0x...); repeat for several; default every session")
    ap.add_argument("--max-requests", type=int, default=DEFAULT_MAX_REQUESTS)
    ap.add_argument("--write-fixture", metavar="PATH",
                    help="save the records of the sessions in --fixture-session for the tests")
    ap.add_argument("--fixture-session", action="append", default=[],
                    help="channel id prefix to save with --write-fixture")
    args = ap.parse_args(argv)

    inputs_path = Path(args.inputs)
    inputs = json.loads(inputs_path.read_text())
    sessions = [s for s in inputs["sessions"]
                if not args.only or any(s["channel_id"].startswith(p) for p in args.only)]
    rpc = LimitedRpc(args.url, args.max_requests)
    results, pairs = [], []
    try:
        genesis = rpc.call("chain_getBlockHash", [0])
        if genesis != inputs["genesis_hash"]:
            raise devnet.DevnetError(
                f"genesis {genesis} is not {inputs['genesis_hash']}: another or a reset chain"
            )
        pinned = rpc.call("chain_getFinalizedHead", [])
        number = int(rpc.call("chain_getHeader", [pinned])["number"], 16)
        runtime = rpc.call("state_getRuntimeVersion", [pinned])
        raw_metadata = from_hex(rpc.call("state_getMetadata", [pinned]))
        meta = devnet.parse_metadata(raw_metadata)
        schema = build_schema(raw_metadata, meta)
        types = meta["types"]
        print(f"genesis {genesis}\npinned block #{number} {pinned}, "
              f"runtime {runtime['specName']} {runtime['specVersion']}")
        print(f"sessions: {len(sessions)}, request limit {args.max_requests}")

        keys = [_map_key("Channels", from_hex(s["channel_id"])) for s in sessions]
        at_pin = _read_at(rpc, keys, pinned)

        to_locate = [(s, k) for s, k in zip(sessions, keys) if s["settle_block"] is None]
        ranges = []
        for session, key in to_locate:
            channel = devnet.decode_exact(types, schema["channel"], from_hex(at_pin[key]))
            ranges.extend(range(channel["opened_at"], session["search_upper_block"] + 1))
        rpc.block_hashes(ranges)
        for session, key in to_locate:
            session["settle_block"] = locate_settle_block(rpc, session, types, schema, at_pin[key])
            del session["search_upper_block"]
            inputs_path.write_text(json.dumps(inputs, indent=1) + "\n")
            print(f"located {session['channel_id']} at #{session['settle_block']}")

        for session, key in zip(sessions, keys):
            record = read_record(rpc, session, schema, types, at_pin[key])
            result = check_session(session, record, inputs, schema, types)
            results.append(result)
            _report(result)
            if any(session["channel_id"].startswith(p) for p in args.fixture_session):
                pairs.append((session, record))
    except devnet.DevnetError as e:
        print(f"ERROR: {e}", file=sys.stderr)
        print(f"requests sent: {rpc.requests}", file=sys.stderr)
        return 2
    finally:
        rpc.close()

    if args.write_fixture:
        write_fixture(args.write_fixture, pairs, inputs, schema, types,
                      f"{args.url}, read with pinned block #{number} {pinned}")
        print(f"fixture written: {args.write_fixture} ({len(pairs)} sessions)")
    passed = sum(r["ok"] for r in results)
    print(f"requests sent: {rpc.requests}")
    print(f"RESULT: {passed}/{len(results)} sessions passed every check")
    return 0 if passed == len(results) else 1


if __name__ == "__main__":
    sys.exit(main())
