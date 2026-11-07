"""Check channel_id_v1 against every compute channel on the live FLOP Devnet.

Read-only. Talks only to the public devnet RPC (rpc.devnet.flop.network) and
uses only read methods: chain_getBlockHash, chain_getFinalizedHead,
chain_getHeader, state_getMetadata, state_getRuntimeVersion,
state_getKeysPaged and state_queryStorageAt. No key, faucet or transaction.

Every storage read is pinned to ONE block (the finalized head when the run
starts), so a run can be repeated on the same block while the node keeps it.

What it does:
  1. reads the genesis hash and the pinned block;
  2. reads the metadata at that block (v14) and finds the storage entry
     ComputeChannel.Channels: its key hasher, key type and value type;
  3. reads every key and value of that entry at the pinned block;
  4. decodes each value from the SCALE type definition in the metadata, with
     no byte offset written out here: agent, miner and nonce are taken by
     field name from the decoded Channel;
  5. recomputes channel_id with app.crypto.compute_channel_id_v1 and compares
     it with the last 32 bytes of the storage key (the key is
     Blake2_128Concat(channel_id), so the 16 bytes before it are also
     checked).

It needs the network and the devnet can be reset, so it is not part of pytest
or CI. The decoding code is tested offline in test_devnet_channel_decoding.py
with a few channel records saved from a real run (--write-fixture).

Exit codes: 0 every channel matched, 1 a mismatch or undecodable record,
2 the RPC could not be read, or the metadata does not have the expected shape.

Standard httpx client, default settings and default headers. A 403 from the
RPC stops the run (nothing is retried or worked around).
"""

import argparse
import hashlib
import json
import struct
import sys
import time
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

from app.crypto import compute_channel_id_v1  # noqa: E402

RPC_URL = "https://rpc.devnet.flop.network"
PALLET = "ComputeChannel"
STORAGE_ITEM = "Channels"
KEYS_PAGE_SIZE = 1000
VALUES_CHUNK = 100
REQUEST_DELAY_SECONDS = 0.5
REQUEST_TIMEOUT_SECONDS = 30

# The SDK 0.4.0 CHANGELOG pins the devnet genesis only in abbreviated form.
SDK_PIN_PREFIX = "0x99c172c0"
SDK_PIN_SUFFIX = "8be2d631"
SDK_PIN_SOURCE = "@flop-labs/sdk 0.4.0 CHANGELOG.md (genesis `0x99c172c0…8be2d631`)"

BLAKE2_128_CONCAT = 2  # StorageHasher::Blake2_128Concat in metadata v14
PRIMITIVES = (
    "bool", "char", "str", "u8", "u16", "u32", "u64", "u128", "u256",
    "i8", "i16", "i32", "i64", "i128", "i256",
)


class DevnetError(Exception):
    """RPC or metadata problem (exit code 2)."""


# --------------------------------------------------------------------------
# Storage key prefix: twox128(pallet) ++ twox128(item)
# --------------------------------------------------------------------------

_M64 = (1 << 64) - 1
_P1 = 11400714785074694791
_P2 = 14029467366897019727
_P3 = 1609587929392839161
_P4 = 9650029242287828579
_P5 = 2870177450012600261


def _rol(x, r):
    return ((x << r) | (x >> (64 - r))) & _M64


def _round(acc, value):
    return (_rol((acc + value * _P2) & _M64, 31) * _P1) & _M64


def _merge(acc, value):
    return (((acc ^ _round(0, value)) * _P1) + _P4) & _M64


def xxh64(data: bytes, seed: int = 0) -> int:
    n = len(data)
    p = 0
    if n >= 32:
        v = [(seed + _P1 + _P2) & _M64, (seed + _P2) & _M64, seed, (seed - _P1) & _M64]
        while p <= n - 32:
            for k in range(4):
                v[k] = _round(v[k], struct.unpack_from("<Q", data, p + 8 * k)[0])
            p += 32
        h = (_rol(v[0], 1) + _rol(v[1], 7) + _rol(v[2], 12) + _rol(v[3], 18)) & _M64
        for k in range(4):
            h = _merge(h, v[k])
    else:
        h = (seed + _P5) & _M64
    h = (h + n) & _M64
    while p <= n - 8:
        h ^= _round(0, struct.unpack_from("<Q", data, p)[0])
        h = (_rol(h, 27) * _P1 + _P4) & _M64
        p += 8
    if p <= n - 4:
        h ^= (struct.unpack_from("<I", data, p)[0] * _P1) & _M64
        h = (_rol(h, 23) * _P2 + _P3) & _M64
        p += 4
    while p < n:
        h ^= (data[p] * _P5) & _M64
        h = (_rol(h, 11) * _P1) & _M64
        p += 1
    h ^= h >> 33
    h = (h * _P2) & _M64
    h ^= h >> 29
    h = (h * _P3) & _M64
    h ^= h >> 32
    return h


def twox128(text: str) -> bytes:
    data = text.encode()
    return struct.pack("<QQ", xxh64(data, 0), xxh64(data, 1))


def storage_prefix(pallet: str, item: str) -> bytes:
    return twox128(pallet) + twox128(item)


# --------------------------------------------------------------------------
# Metadata v14 parsing. Types are kept as plain dicts (JSON-friendly).
# --------------------------------------------------------------------------


class Reader:
    def __init__(self, data: bytes, pos: int = 0):
        self.data = data
        self.pos = pos

    def take(self, n: int) -> bytes:
        if n < 0 or self.pos + n > len(self.data):
            raise ValueError("unexpected end of data")
        out = self.data[self.pos:self.pos + n]
        self.pos += n
        return out

    def u8(self) -> int:
        return self.take(1)[0]

    def compact(self) -> int:
        first = self.data[self.pos] if self.pos < len(self.data) else None
        if first is None:
            raise ValueError("unexpected end of data")
        mode = first & 3
        if mode == 0:
            return self.take(1)[0] >> 2
        if mode == 1:
            return int.from_bytes(self.take(2), "little") >> 2
        if mode == 2:
            return int.from_bytes(self.take(4), "little") >> 2
        length = (first >> 2) + 4
        self.take(1)
        return int.from_bytes(self.take(length), "little")

    def string(self) -> str:
        return self.take(self.compact()).decode("utf-8", "replace")

    def option(self, read):
        flag = self.u8()
        if flag == 0:
            return None
        if flag != 1:
            raise ValueError("invalid Option byte")
        return read()

    def vec(self, read):
        return [read() for _ in range(self.compact())]


def _read_fields(r: Reader) -> list:
    def one():
        name = r.option(r.string)
        ty = r.compact()
        r.option(r.string)  # type name
        r.vec(r.string)  # docs
        return {"name": name, "ty": ty}

    return r.vec(one)


def _read_type_def(r: Reader) -> dict:
    kind = r.u8()
    if kind == 0:
        return {"kind": "composite", "fields": _read_fields(r)}
    if kind == 1:
        def variant():
            name = r.string()
            fields = _read_fields(r)
            idx = r.u8()
            r.vec(r.string)
            return {"name": name, "idx": idx, "fields": fields}

        return {"kind": "variant", "variants": r.vec(variant)}
    if kind == 2:
        return {"kind": "sequence", "ty": r.compact()}
    if kind == 3:
        length = int.from_bytes(r.take(4), "little")
        return {"kind": "array", "len": length, "ty": r.compact()}
    if kind == 4:
        return {"kind": "tuple", "tys": r.vec(r.compact)}
    if kind == 5:
        code = r.u8()
        if code >= len(PRIMITIVES):
            raise ValueError("unknown primitive type code")
        return {"kind": "primitive", "name": PRIMITIVES[code]}
    if kind == 6:
        return {"kind": "compact", "ty": r.compact()}
    if kind == 7:
        r.compact()
        r.compact()
        return {"kind": "bitsequence"}
    raise ValueError(f"unknown type definition kind {kind}")


def parse_metadata(raw: bytes) -> dict:
    """Return {"version", "types": {id: {...}}, "storage": {pallet: {item: {...}}}}.

    Only metadata v14 is supported. Pallet calls, events, constants and errors
    are read over (they have to be, to reach the next pallet) but not kept.
    """
    if raw[:4] != b"meta":
        raise DevnetError("metadata does not start with the 'meta' magic number")
    r = Reader(raw, 4)
    version = r.u8()
    if version != 14:
        raise DevnetError(f"unsupported metadata version {version} (only v14)")
    types = {}
    for _ in range(r.compact()):
        type_id = r.compact()
        path = r.vec(r.string)
        r.vec(lambda: (r.string(), r.option(r.compact)))  # type parameters
        definition = _read_type_def(r)
        r.vec(r.string)  # docs
        definition["path"] = path
        types[type_id] = definition
    storage = {}
    for _ in range(r.compact()):
        pallet = r.string()
        entries = {}
        if r.u8():
            r.string()  # storage prefix
            for _ in range(r.compact()):
                name = r.string()
                r.u8()  # modifier
                if r.u8() == 0:
                    entry = {"kind": "plain", "value": r.compact()}
                else:
                    hashers = r.vec(r.u8)
                    key = r.compact()
                    entry = {"kind": "map", "hashers": hashers, "key": key, "value": r.compact()}
                r.vec(r.u8)  # default value
                r.vec(r.string)  # docs
                entries[name] = entry
        r.option(r.compact)  # calls
        r.option(r.compact)  # events
        for _ in range(r.compact()):  # constants
            r.string()
            r.compact()
            r.vec(r.u8)
            r.vec(r.string)
        r.option(r.compact)  # errors
        r.u8()  # pallet index
        storage[pallet] = entries
    return {"version": version, "types": types, "storage": storage}


def type_name(types: dict, type_id: int) -> str:
    t = types[type_id]
    kind = t["kind"]
    if t["path"]:
        return "::".join(t["path"])
    if kind == "primitive":
        return t["name"]
    if kind == "sequence":
        return f"Vec<{type_name(types, t['ty'])}>"
    if kind == "array":
        return f"[{type_name(types, t['ty'])}; {t['len']}]"
    if kind == "tuple":
        return "(" + ", ".join(type_name(types, x) for x in t["tys"]) + ")"
    if kind == "compact":
        return f"Compact<{type_name(types, t['ty'])}>"
    return kind


def reachable_types(types: dict, root_ids) -> dict:
    """The sub-registry of the types reachable from root_ids."""
    keep = {}
    stack = list(root_ids)
    while stack:
        type_id = stack.pop()
        if type_id in keep:
            continue
        t = types[type_id]
        keep[type_id] = t
        kind = t["kind"]
        if kind == "composite":
            stack.extend(f["ty"] for f in t["fields"])
        elif kind == "variant":
            stack.extend(f["ty"] for v in t["variants"] for f in v["fields"])
        elif kind in ("sequence", "array", "compact"):
            stack.append(t["ty"])
        elif kind == "tuple":
            stack.extend(t["tys"])
    return keep


# --------------------------------------------------------------------------
# SCALE decoding from a type definition
# --------------------------------------------------------------------------


def decode_value(types: dict, type_id: int, r: Reader):
    """Decode one value of type type_id.

    composite -> dict by field name (a single unnamed field is unwrapped);
    variant -> (name, value) with value None for a unit variant, and Option
    -> None or the inner value; arrays and sequences of u8 -> bytes; other
    arrays/sequences -> list; integers -> int.
    """
    t = types[type_id]
    kind = t["kind"]
    if kind == "primitive":
        name = t["name"]
        if name == "bool":
            b = r.u8()
            if b > 1:
                raise ValueError("invalid bool byte")
            return bool(b)
        if name == "str":
            return r.string()
        if name == "char":
            raise ValueError("char is not supported")
        width = {"8": 1, "16": 2, "32": 4, "64": 8, "128": 16, "256": 32}[name[1:]]
        return int.from_bytes(r.take(width), "little", signed=name[0] == "i")
    if kind == "compact":
        return r.compact()
    if kind == "composite":
        fields = t["fields"]
        if not fields:
            return {}
        if len(fields) == 1 and fields[0]["name"] is None:
            return decode_value(types, fields[0]["ty"], r)
        if all(f["name"] is None for f in fields):
            return [decode_value(types, f["ty"], r) for f in fields]
        return {f["name"]: decode_value(types, f["ty"], r) for f in fields}
    if kind == "variant":
        idx = r.u8()
        variant = next((v for v in t["variants"] if v["idx"] == idx), None)
        if variant is None:
            raise ValueError(f"unknown variant index {idx} in {type_name(types, type_id)}")
        if t["path"] == ["Option"]:
            return None if variant["name"] == "None" else decode_value(types, variant["fields"][0]["ty"], r)
        fields = variant["fields"]
        if not fields:
            return (variant["name"], None)
        if len(fields) == 1 and fields[0]["name"] is None:
            return (variant["name"], decode_value(types, fields[0]["ty"], r))
        if all(f["name"] is None for f in fields):
            return (variant["name"], [decode_value(types, f["ty"], r) for f in fields])
        return (variant["name"], {f["name"]: decode_value(types, f["ty"], r) for f in fields})
    if kind in ("array", "sequence"):
        length = t["len"] if kind == "array" else r.compact()
        inner = types[t["ty"]]
        if inner["kind"] == "primitive" and inner["name"] == "u8":
            return r.take(length)
        return [decode_value(types, t["ty"], r) for _ in range(length)]
    if kind == "tuple":
        return [decode_value(types, x, r) for x in t["tys"]]
    raise ValueError(f"cannot decode type kind {kind}")


def decode_exact(types: dict, type_id: int, data: bytes):
    """Decode data as type_id; the whole of data must be used."""
    r = Reader(data)
    value = decode_value(types, type_id, r)
    if r.pos != len(data):
        raise ValueError(f"{len(data) - r.pos} trailing bytes after decoding")
    return value


# --------------------------------------------------------------------------
# The check itself (no network)
# --------------------------------------------------------------------------


def channels_entry(meta: dict) -> dict:
    """Locate ComputeChannel.Channels and check the shape this script relies on."""
    try:
        entry = meta["storage"][PALLET][STORAGE_ITEM]
    except KeyError as e:
        raise DevnetError(f"metadata has no storage entry {PALLET}.{STORAGE_ITEM}") from e
    if entry["kind"] != "map" or entry["hashers"] != [BLAKE2_128_CONCAT]:
        raise DevnetError(
            f"{PALLET}.{STORAGE_ITEM} is not a single-key Blake2_128Concat map: {entry}"
        )
    types = meta["types"]
    key_type = types[entry["key"]]
    while key_type["kind"] == "composite" and len(key_type["fields"]) == 1:  # H256(..)
        key_type = types[key_type["fields"][0]["ty"]]
    if not (
        key_type["kind"] == "array"
        and key_type["len"] == 32
        and types[key_type["ty"]] == {"kind": "primitive", "name": "u8", "path": []}
    ):
        raise DevnetError(f"{PALLET}.{STORAGE_ITEM} key is not a 32-byte array")
    value_type = types[entry["value"]]
    if value_type["kind"] != "composite":
        raise DevnetError(f"{PALLET}.{STORAGE_ITEM} value is not a struct")
    names = {f["name"] for f in value_type["fields"]}
    missing = {"agent", "miner", "nonce"} - names
    if missing:
        raise DevnetError(f"Channel has no field(s) {sorted(missing)}")
    return entry


def check_channel(types: dict, entry: dict, genesis_hash: bytes, prefix: bytes,
                  key_hex: str, value_hex: str) -> dict:
    """Decode one record and compare channel_id. Returns a result dict.

    result["status"] is "match", "mismatch" or "error"; the other fields are
    for reporting.
    """
    result = {"key": key_hex, "status": "error"}
    try:
        key = bytes.fromhex(key_hex[2:])
        value = bytes.fromhex(value_hex[2:])
        if not key.startswith(prefix) or len(key) != len(prefix) + 16 + 32:
            raise ValueError("key is not prefix + blake2_128 + 32 bytes")
        key_hash, key_id = key[len(prefix):len(prefix) + 16], key[-32:]
        result["key_channel_id"] = key_id.hex()
        if hashlib.blake2b(key_id, digest_size=16).digest() != key_hash:
            raise ValueError("blake2_128 part of the key does not match its channel_id part")
        channel = decode_exact(types, entry["value"], value)
        agent, miner, nonce = channel["agent"], channel["miner"], channel["nonce"]
        if not (isinstance(agent, bytes) and len(agent) == 32
                and isinstance(miner, bytes) and len(miner) == 32
                and isinstance(nonce, int)):
            raise ValueError("agent/miner/nonce do not have the expected types")
        result.update(agent=agent.hex(), miner=miner.hex(), nonce=nonce)
        computed = compute_channel_id_v1(genesis_hash, agent, miner, nonce)
        result["computed_channel_id"] = computed
        result["status"] = "match" if computed == key_id.hex() else "mismatch"
    except (ValueError, KeyError, TypeError) as e:
        result["error"] = f"{type(e).__name__}: {e}"
    return result


def describe_decoding(types: dict, entry: dict) -> list:
    """Lines saying how the Channel value is decoded."""
    lines = [
        f"value type: {type_name(types, entry['value'])} (type id {entry['value']}), "
        f"key type: {type_name(types, entry['key'])}, hasher: Blake2_128Concat",
        "fields, in SCALE order (decoded from the metadata type, not by offset):",
    ]
    used = {
        "agent": "AccountId32 -> 32 bytes, channel_id_v1 'agent'",
        "miner": "AccountId32 -> 32 bytes, channel_id_v1 'miner'",
        "nonce": "u64 little-endian, channel_id_v1 'nonce'",
    }
    for f in types[entry["value"]]["fields"]:
        note = f"  <- {used[f['name']]}" if f["name"] in used else ""
        lines.append(f"  {f['name']}: {type_name(types, f['ty'])}{note}")
    lines.append("every value must be consumed exactly (no trailing bytes)")
    return lines


# --------------------------------------------------------------------------
# RPC
# --------------------------------------------------------------------------


class Rpc:
    def __init__(self, url: str = RPC_URL, delay: float = REQUEST_DELAY_SECONDS):
        import httpx  # default client, default headers, default TLS settings

        self._httpx = httpx
        self.url = url
        self.delay = delay
        self.requests = 0
        self._client = httpx.Client(timeout=REQUEST_TIMEOUT_SECONDS)

    def call(self, method: str, params: list):
        if self.requests:
            time.sleep(self.delay)
        self.requests += 1
        try:
            response = self._client.post(
                self.url, json={"jsonrpc": "2.0", "id": self.requests, "method": method, "params": params}
            )
        except self._httpx.HTTPError as e:
            raise DevnetError(f"{method}: {type(e).__name__}: {e}") from e
        if response.status_code != 200:
            raise DevnetError(
                f"{method}: HTTP {response.status_code} {response.text[:200]!r} "
                "(not retried, no workaround attempted)"
            )
        body = response.json()
        if "error" in body:
            raise DevnetError(f"{method}: RPC error {body['error']}")
        return body["result"]

    def close(self):
        self._client.close()


def read_chain(rpc: Rpc) -> dict:
    """Read everything for the check at one pinned block."""
    genesis = rpc.call("chain_getBlockHash", [0])
    block_hash = rpc.call("chain_getFinalizedHead", [])
    header = rpc.call("chain_getHeader", [block_hash])
    runtime = rpc.call("state_getRuntimeVersion", [block_hash])
    metadata_hex = rpc.call("state_getMetadata", [block_hash])
    meta = parse_metadata(bytes.fromhex(metadata_hex[2:]))
    entry = channels_entry(meta)
    prefix = storage_prefix(PALLET, STORAGE_ITEM)
    keys, start = [], "0x" + prefix.hex()
    while True:
        page = rpc.call("state_getKeysPaged", ["0x" + prefix.hex(), KEYS_PAGE_SIZE, start, block_hash])
        keys.extend(page)
        if len(page) < KEYS_PAGE_SIZE:
            break
        start = page[-1]
    values = {}
    for i in range(0, len(keys), VALUES_CHUNK):
        chunk = keys[i:i + VALUES_CHUNK]
        for block in rpc.call("state_queryStorageAt", [chunk, block_hash]):
            if block["block"] != block_hash:
                raise DevnetError("state_queryStorageAt answered for a different block")
            for key, value in block["changes"]:
                values[key] = value
    return {
        "genesis": genesis,
        "block_hash": block_hash,
        "block_number": int(header["number"], 16),
        "spec_name": runtime["specName"],
        "spec_version": runtime["specVersion"],
        "meta": meta,
        "entry": entry,
        "prefix": prefix,
        "keys": keys,
        "values": values,
    }


def write_fixture(path: Path, data: dict, results: list, count: int) -> None:
    """Save the type sub-registry and a few real records for the offline test."""
    entry, types = data["entry"], data["meta"]["types"]
    picked = [r for r in results if r["status"] == "match"][:count]
    sub = reachable_types(types, [entry["key"], entry["value"]])
    fixture = {
        "source": f"{RPC_URL}, state at block {data['block_hash']} (#{data['block_number']})",
        "spec": f"{data['spec_name']} {data['spec_version']}",
        "genesis_hash": data["genesis"],
        "prefix": "0x" + data["prefix"].hex(),
        "entry": entry,
        "types": {str(k): v for k, v in sorted(sub.items())},
        "samples": [
            {"key": r["key"], "value": data["values"][r["key"]], "nonce": r["nonce"]}
            for r in picked
        ],
    }
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(fixture, indent=1, sort_keys=True) + "\n")


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--url", default=RPC_URL)
    ap.add_argument("--write-fixture", metavar="PATH", help="save the type registry and a few records as an offline test fixture")
    ap.add_argument("--fixture-samples", type=int, default=3)
    args = ap.parse_args(argv)

    rpc = Rpc(args.url)
    try:
        data = read_chain(rpc)
    except DevnetError as e:
        print(f"ERROR: {e}", file=sys.stderr)
        print(f"requests sent: {rpc.requests}", file=sys.stderr)
        return 2
    finally:
        rpc.close()

    genesis_hex = data["genesis"]
    genesis = bytes.fromhex(genesis_hex[2:])
    pin_ok = genesis_hex.startswith(SDK_PIN_PREFIX) and genesis_hex.endswith(SDK_PIN_SUFFIX)
    print(f"network: {args.url}  runtime {data['spec_name']} {data['spec_version']}")
    print(f"genesis hash: {genesis_hex}")
    print(f"  SDK pin {SDK_PIN_PREFIX}…{SDK_PIN_SUFFIX} ({SDK_PIN_SOURCE}): "
          f"{'consistent' if pin_ok else 'DIFFERENT'} (abbreviated pin only)")
    print("  flop.finance/official: publishes no genesis hash (checked by hand; not tested here)")
    print(f"pinned block: #{data['block_number']} {data['block_hash']} (finalized head at start)")
    print(f"storage item: {PALLET}.{STORAGE_ITEM}, prefix 0x{data['prefix'].hex()}")
    for line in describe_decoding(data["meta"]["types"], data["entry"]):
        print(line)

    keys, values = data["keys"], data["values"]
    results = []
    for key in keys:
        if key not in values:
            results.append({"key": key, "status": "error", "error": "no value returned for key"})
        else:
            results.append(check_channel(data["meta"]["types"], data["entry"], genesis,
                                         data["prefix"], key, values[key]))
    matched = [r for r in results if r["status"] == "match"]
    bad = [r for r in results if r["status"] != "match"]
    print(f"channels read: {len(keys)} (distinct keys: {len(set(keys))})")
    print(f"matching channel_id_v1: {len(matched)}")
    print(f"not matching or undecodable: {len(bad)}")
    for r in bad[:5]:
        print("  " + json.dumps(r, sort_keys=True))
    print(f"requests sent: {rpc.requests}")
    if args.write_fixture:
        write_fixture(Path(args.write_fixture), data, results, args.fixture_samples)
        print(f"fixture written: {args.write_fixture}")
    ok = bool(keys) and not bad and pin_ok
    print(f"RESULT: {len(matched)}/{len(keys)} channels match at block #{data['block_number']}"
          f"{'' if ok else ' (FAILED)'}")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
