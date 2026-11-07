"""Our primitives vs the official @flop-labs/sdk, byte for byte.

  parity.py run                               install the SDK in a temporary
                                              directory, compare, report
  parity.py gen CASES.json CORPUS.json        fixed-seed cases + corpus vectors
  parity.py compare CASES.json SDK_OUT.json CORPUS.json REPORT.json

`run` is the normal entry point (see README.md). It needs the network twice:
`npm install` of one pinned package, and the download of the pinned wire-format
corpus. The SDK side runs in sdk_run.mjs (Node) and calls only the pure
transcript functions. Our side is app.crypto from this repository (imported,
not modified). Not part of pytest or CI.

Exit codes: 0 no byte difference, corpus vectors and signatures all fine;
1 a difference; 2 the SDK install or the corpus did not check out.
"""
import hashlib, json, random, shutil, struct, subprocess, sys, tempfile, urllib.request
from collections import Counter, defaultdict
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(REPO))
from app import crypto as ours  # noqa: E402
import sr25519  # noqa: E402

SDK_NAME, SDK_VERSION = "@flop-labs/sdk", "0.4.0"
SDK_RESOLVED = "https://registry.npmjs.org/@flop-labs/sdk/-/sdk-0.4.0.tgz"
SDK_INTEGRITY = "sha512-qC31W4f08qXKpONZDXx2fn9rnaiouBbKrcf5zyzIaFiXk+sD/PT14iko3OJ9LtD398hUBG4tZ/2/Wd9/rss/5A=="
SOURCE_JSON = REPO / "tests" / "fixtures" / "flop-yellowpaper" / "SOURCE.json"
EXPECTED_CASES = 31614

SEED = 20261107
U32, U64, U128 = 2**32 - 1, 2**64 - 1, 2**128 - 1
EDGE = {
    32: [0, 1, 2, 255, 256, 2**31 - 1, 2**31, U32],
    64: [0, 1, 2, U32, U32 + 1, 2**53 - 1, 2**63, U64 - 1, U64],
    128: [0, 1, U64, U64 + 1, 2**127, U128 - 1, U128],
}
h = lambda b: b.hex()
blake = lambda d: hashlib.blake2b(d, digest_size=32).digest()

def bytes32(r, nonzero=False):
    k = r.random()
    if not nonzero and k < 0.08: return b"\x00" * 32
    if k < 0.16: return b"\xff" * 32
    v = r.randbytes(32)
    return v if any(v) else b"\x01" * 32

def integer(r, bits):
    return r.choice(EDGE[bits]) if r.random() < 0.4 else r.getrandbits(bits)


def gen(cases_path, corpus_path):
    r = random.Random(SEED)
    cases = []
    def add(op, kind, args, **extra):
        cases.append(dict(id=len(cases), op=op, kind=kind, args=args, **extra))
    N = 2000
    for _ in range(N):
        add("channel_id", "valid", dict(genesis=h(bytes32(r)), agent=h(bytes32(r)), miner=h(bytes32(r)), nonce=str(integer(r, 64))))
    for nonce in (str(2**64), "-1", str(2**64 + 7)):
        add("channel_id", "invalid", dict(genesis=h(bytes32(r)), agent=h(bytes32(r)), miner=h(bytes32(r)), nonce=nonce))
    for field in ("genesis", "agent", "miner"):
        for ln in (0, 31, 33):
            a = dict(genesis=h(bytes32(r)), agent=h(bytes32(r)), miner=h(bytes32(r)), nonce="5"); a[field] = h(r.randbytes(ln)); add("channel_id", "invalid", a)
    for _ in range(N):
        add("task_hash", "valid", dict(genesis=h(bytes32(r)), agent=h(bytes32(r)), nonce=str(integer(r, 64)), model=h(bytes32(r)), payload=h(bytes32(r)), commit=h(bytes32(r))))
    for nonce in (str(2**64), "-1"):
        add("task_hash", "invalid", dict(genesis=h(bytes32(r)), agent=h(bytes32(r)), nonce=nonce, model=h(bytes32(r)), payload=h(bytes32(r)), commit=h(bytes32(r))))
    for field in ("genesis", "agent", "model", "payload", "commit"):
        for ln in (0, 31, 33):
            a = dict(genesis=h(bytes32(r)), agent=h(bytes32(r)), nonce="5", model=h(bytes32(r)), payload=h(bytes32(r)), commit=h(bytes32(r))); a[field] = h(r.randbytes(ln)); add("task_hash", "invalid", a)

    Z = h(b"\x00" * 32)
    def leaf_args(version, **o):
        a = dict(version=version, channel=h(bytes32(r)), turn_index=str(integer(r, 32)), h_in=h(bytes32(r)), h_out=h(bytes32(r)),
                 g_n=str(integer(r, 128)), dph=Z, hids=Z, toploc=Z, recv="0", done="0", lat="0")
        if version >= 1: a.update(recv=str(integer(r, 64)), done=str(integer(r, 64)), lat=str(integer(r, 64)))
        if version == 2: a["dph"] = h(bytes32(r))
        if version == 3: a.update(dph=h(bytes32(r, True)), hids=h(bytes32(r, True)), toploc=h(bytes32(r, True)))
        a.update(o); return a
    for version in range(4):
        for _ in range(1500): add("leaf", "valid", leaf_args(version))
        for o in (dict(turn_index=str(2**32)), dict(turn_index="-1"), dict(g_n=str(2**128)), dict(g_n="-1"),
                  dict(recv=str(2**64)), dict(done="-1"), dict(lat=str(2**64)),
                  dict(channel=h(r.randbytes(31))), dict(h_in=h(r.randbytes(33))), dict(h_out=h(b""))):
            if version == 0 and any(k in o for k in ("recv", "done", "lat")): continue  # V0 has no timing fields
            add("leaf", "invalid", leaf_args(version, **o))
    # consistency rules: every zero / non-zero combination, repeated with fresh values
    for version in range(4):
        for rep in range(130):
            for dz in (0, 1):
                for iz in (0, 1):
                    for tz in (0, 1):
                        for tm in (0, 1):
                            nzv = lambda z: Z if z else h(bytes32(r, True))
                            add("leaf_consistency", "rule", dict(version=version, dph=nzv(dz), hids=nzv(iz), toploc=nzv(tz),
                                timing=tm, channel=h(bytes32(r)), turn_index="3", h_in=h(bytes32(r)), h_out=h(bytes32(r)), g_n="9",
                                recv=str(5 * tm), done=str(7 * tm), lat=str(2 * tm)))
    for _ in range(N):
        add("receipt", "valid", dict(channel=h(bytes32(r)), root=h(bytes32(r)), gn=str(integer(r, 128)), payable=str(integer(r, 128))))
    for o in (dict(gn=str(2**128)), dict(gn="-1"), dict(payable=str(2**128)), dict(payable="-1"), dict(channel=h(r.randbytes(31))), dict(root=h(r.randbytes(33)))):
        a = dict(channel=h(bytes32(r)), root=h(bytes32(r)), gn="1", payable="1"); a.update(o); add("receipt", "invalid", a)
    for _ in range(N):
        add("legacy_receipt", "sdk_only", dict(channel=h(bytes32(r)), root=h(bytes32(r)), gn=str(integer(r, 128)), payable=str(integer(r, 128))))
    for _ in range(N):
        add("ack", "valid", dict(channel=h(bytes32(r)), turn_index=str(integer(r, 32)), leaf=h(bytes32(r)), send=str(integer(r, 64)), recv=str(integer(r, 64))))
    for o in (dict(turn_index=str(2**32)), dict(turn_index="-1"), dict(send=str(2**64)), dict(recv="-1"), dict(channel=h(r.randbytes(31))), dict(leaf=h(r.randbytes(33)))):
        a = dict(channel=h(bytes32(r)), turn_index="1", leaf=h(bytes32(r)), send="1", recv="1"); a.update(o); add("ack", "invalid", a)
    for _ in range(N):
        add("h_ids", "sdk_only", dict(prompt=[str(integer(r, 32)) for _ in range(r.choice([0, 0, 1, 2, 5, 40]))],
                                      generated=[str(integer(r, 32)) for _ in range(r.choice([0, 0, 1, 2, 5, 40]))]))
    sizes = list(range(0, 41)) + [63, 64, 65, 127, 128, 129, 255, 256, 300]
    for i in range(1600):
        n = sizes[i] if i < len(sizes) else r.randint(1, 70)
        add("merkle_root", "valid", dict(leaves=[h(bytes32(r)) for _ in range(n)]))
    for i in range(1600):
        n = r.randint(1, 70) if i % 4 else r.choice([1, 2, 3, 64, 65, 128, 129])
        add("merkle_proof", "valid", dict(leaves=[h(bytes32(r)) for _ in range(n)], index=r.randrange(n) if i % 3 else n - 1))
    for i in range(2000):
        canonical = i % 2 == 0
        length = r.choice([0, 1, 2, 3, 5, 10, 32, 63, 64]) if r.random() < .5 else r.randint(0, 64)
        index = r.getrandbits(length) if length else 0
        if canonical:
            path = [[h(bytes32(r)), bool((index >> k) & 1)] for k in range(length)]
        else:
            path = [[h(bytes32(r)), r.random() < .5] for _ in range(length)]
        add("merkle_path_root", "valid", dict(leaf=h(bytes32(r)), path=path, index=index, canonical=canonical))
    for length in (65, 70, 100):
        add("merkle_path_root", "invalid", dict(leaf=h(bytes32(r)), path=[[h(bytes32(r)), False] for _ in range(length)], index=0, canonical=False))

    # --- wire-format corpus vectors, fed to the SDK
    c = json.load(open(corpus_path)); cc = c["compute_channel_v1"]; dr = c["direct_rail_v1"]
    ci = cc["channel_id"]["inputs"]
    add("channel_id", "corpus", dict(genesis=ci["genesis_hash_hex"], agent=ci["agent_account_id32_hex"], miner=ci["miner_account_id32_hex"], nonce=str(ci["nonce"])), expect=cc["channel_id"]["hash_hex"], name="compute_channel_v1.channel_id")
    ti = dr["task_hash"]["inputs"]
    add("task_hash", "corpus", dict(genesis=ti["genesis_hash_hex"], agent=ti["agent_account_id32_hex"], nonce=str(ti["nonce"]), model=ti["model_hash_hex"], payload=ti["payload_hash_hex"], commit=ti["commit_hash_hex"]), expect=dr["task_hash"]["hash_hex"], name="direct_rail_v1.task_hash")
    li = cc["leaf_inputs"]
    for ver, ent in enumerate(cc["leaf_versions"]):
        assert ent["version"] == "V%d" % ver
        add("leaf", "corpus", dict(version=ver, channel=li["channel_id_hex"], turn_index=str(li["turn_index"]), h_in=li["h_in_hex"], h_out=li["h_out_hex"], g_n=str(li["g_n"]),
            dph=li["decode_policy_hash_hex"] if ver >= 2 else Z, hids=li["h_ids_hex"] if ver == 3 else Z, toploc=li["toploc_commitment_hash_hex"] if ver == 3 else Z,
            recv=str(li["miner_recv_ms"]) if ver else "0", done=str(li["miner_done_ms"]) if ver else "0", lat=str(li["latency_ms"]) if ver else "0"),
            expect=ent["hash_hex"] + "|" + ent["hash_hex"], name="compute_channel_v1.leaf_versions." + ent["version"])
    ri = cc["receipt"]["inputs"]
    add("receipt", "corpus", dict(channel=ri["channel_id_hex"], root=ri["final_root_hex"], gn=str(ri["aggregate_gn"]), payable=str(ri["payable"])), expect=cc["receipt"]["preimage_hex"], name="compute_channel_v1.receipt.preimage")
    leg = [n for n in c["negative_cases"] if n["id"] == "legacy_receipt_current_channel"][0]["bytes_hex"]
    add("legacy_receipt", "corpus", dict(channel=ri["channel_id_hex"], root=ri["final_root_hex"], gn=str(ri["aggregate_gn"]), payable=str(ri["payable"])), expect=leg[:-128], name="negative_cases.legacy_receipt_current_channel (message part)")
    ak = cc["fcc4_transcript_with_ack"]
    add("ack", "corpus", dict(channel=li["channel_id_hex"], turn_index=str(li["turn_index"]), leaf=cc["v3_leaf_signature"]["leaf_hash_hex"], send=str(ak["agent_send_ms"]), recv=str(ak["agent_recv_ms"])), expect=ak["ack_preimage_hex"], name="compute_channel_v1.fcc4_transcript_with_ack.ack_preimage")
    mk = cc["merkle"]
    lv = {e["version"]: e["hash_hex"] for e in cc["leaf_versions"]}
    leaves = [lv[n] for n in mk["leaf_order"]]  # leaf_order names the leaf versions in the tree
    add("merkle_root", "corpus", dict(leaves=leaves), expect=mk["root_hex"], name="compute_channel_v1.merkle.root")
    add("merkle_proof", "corpus", dict(leaves=leaves, index=2), expect=json.dumps([[p["sibling_hex"], p["sibling_is_left"]] for p in mk["path_for_index_2"]]), name="compute_channel_v1.merkle.path_for_index_2")
    for v in c["h_ids_v1"]["vectors"]:
        add("h_ids", "corpus", dict(prompt=[str(i) for i in v["prompt_ids"]], generated=[str(i) for i in v["generated_ids"]]), expect=v["hash_hex"], name="h_ids_v1." + v["id"])
    json.dump(cases, open(cases_path, "w"))
    print("cases:", len(cases), dict(Counter(c_["op"] for c_ in cases)))


def run(fn):
    try:
        return "ok", fn()
    except Exception as e:  # noqa: BLE001 - classification of rejections is the point
        return "err", f"{type(e).__name__}: {str(e)[:70]}"

B = bytes.fromhex
def ref_h_ids(p, g):
    f = lambda xs: struct.pack("<I", len(xs)) + b"".join(struct.pack("<I", int(i)) for i in xs)
    return h(blake(f(p) + f(g)))
def ref_legacy(a): return B(a["channel"]) + B(a["root"]) + int(a["gn"]).to_bytes(16, "little") + int(a["payable"]).to_bytes(16, "little")

def ref_proof(leaves, index):
    level = [B(x) for x in leaves]; idx = index; path = []
    while len(level) > 1:
        if len(level) % 2: level.append(level[-1])
        path.append([h(level[idx ^ 1]), bool(idx & 1)])
        level = [blake(level[i] + level[i + 1]) for i in range(0, len(level), 2)]; idx //= 2
    return h(level[0]), path

def ours_fold(leaf, path):
    node = B(leaf)
    for s, left in path:
        node = B(ours.compute_merkle_node(B(s), node) if left else ours.compute_merkle_node(node, B(s)))
    return h(node)

def ours_out(c):
    a, op = c["args"], c["op"]
    if op == "channel_id": return run(lambda: ours.compute_channel_id_v1(B(a["genesis"]), B(a["agent"]), B(a["miner"]), int(a["nonce"])))
    if op == "task_hash": return run(lambda: ours.compute_task_hash_v1(B(a["genesis"]), B(a["agent"]), int(a["nonce"]), B(a["model"]), B(a["payload"]), B(a["commit"])))
    if op == "leaf":
        s, o = run(lambda: ours.compute_verified_turn_leaf_v0_v1_v2_v3(a["version"], B(a["channel"]), int(a["turn_index"]), B(a["h_in"]), B(a["h_out"]), int(a["g_n"]),
            B(a["dph"]), B(a["hids"]), B(a["toploc"]), int(a["recv"]), int(a["done"]), int(a["lat"])))
        return s, (o + "|" + o if s == "ok" else o)
    if op == "leaf_consistency":
        s, o = run(lambda: ours.compute_verified_turn_leaf_v0_v1_v2_v3(a["version"], B(a["channel"]), int(a["turn_index"]), B(a["h_in"]), B(a["h_out"]), int(a["g_n"]),
            B(a["dph"]), B(a["hids"]), B(a["toploc"]), int(a["recv"]), int(a["done"]), int(a["lat"])))
        return "ok", str(s == "ok").lower()
    if op == "receipt": return run(lambda: h(ours.compute_agent_receipt_v1_signable_payload(B(a["channel"]), B(a["root"]), int(a["gn"]), int(a["payable"]))))
    if op == "legacy_receipt": return "ok", h(ref_legacy(a))
    if op == "ack": return run(lambda: h(ours.turn_ack_message(B(a["channel"]), int(a["turn_index"]), B(a["leaf"]), int(a["send"]), int(a["recv"]))))
    if op == "h_ids": return "ok", ref_h_ids(a["prompt"], a["generated"])
    if op == "merkle_root": return run(lambda: ours.compute_merkle_root([B(x) for x in a["leaves"]]))
    if op == "merkle_proof":
        def f():
            root, path = ref_proof(a["leaves"], a["index"])
            assert ours.compute_merkle_root([B(x) for x in a["leaves"]]) == root
            ok = ours.verify_merkle_path(B(a["leaves"][a["index"]]), a["index"], [(B(s), l) for s, l in path], B(root))
            return json.dumps(dict(root=root, rebuilt=root, path=path, ours_verify_merkle_path=ok), sort_keys=True)
        return run(f)
    if op == "merkle_path_root": return run(lambda: ours_fold(a["leaf"], a["path"]))


def compare(cases_path, sdk_path, corpus_path, report_path):
    cases = json.load(open(cases_path)); sdk = {o["id"]: o for o in json.load(open(sdk_path))}
    stats = defaultdict(Counter); problems = defaultdict(list)
    def note(op, key, c, **d):
        stats[op][key] += 1
        if key.endswith(("MISMATCH", "ACCEPT_DIFF", "CORPUS_FAIL", "RULE_DIFF")) and len(problems[op + ":" + key]) < 5:
            problems[op + ":" + key].append(dict(id=c["id"], args=c["args"], **d))
    for c in cases:
        op, kind, s = c["op"], c["kind"], sdk[c["id"]]
        sdk_res = ("err", s["err"]) if "err" in s else ("ok", s["out"])
        if kind == "corpus":
            if sdk_res[0] == "ok" and op == "merkle_proof":
                got = json.dumps(json.loads(sdk_res[1])["path"])
                ok = got == c["expect"] and json.loads(sdk_res[1])["root"] == json.loads(sdk_res[1])["rebuilt"]
            else: ok = sdk_res == ("ok", c["expect"])
            note(op, "corpus_ok" if ok else "CORPUS_FAIL", c, name=c["name"], sdk=sdk_res)
            continue
        o = ours_out(c)
        if op == "merkle_proof":
            if sdk_res[0] == "ok" and o[0] == "ok":
                sj, oj = json.loads(sdk_res[1]), json.loads(o[1])
                same = sj["root"] == oj["root"] and sj["rebuilt"] == sj["root"] and sj["path"] == oj["path"] and oj["ours_verify_merkle_path"] is True
                note(op, "match" if same else "MISMATCH", c, sdk=sj, ours=oj)
            else: note(op, "MISMATCH", c, sdk=sdk_res, ours=o)
            continue
        if kind == "sdk_only":
            note(op, "match_reference" if sdk_res == o else "MISMATCH", c, sdk=sdk_res, reference=o); continue
        if kind == "rule":
            if sdk_res[0] == "ok" and o[0] == "ok":
                note(op, f"V{c['args']['version']}:agree" if sdk_res[1] == o[1] else f"V{c['args']['version']}:RULE_DIFF", c, sdk=sdk_res[1], ours=o[1], flags={k: c['args'][k] == Z_ for k in ("dph", "hids", "toploc")} | {"timing": bool(c['args']['timing'])});
            else: note(op, "MISMATCH", c, sdk=sdk_res, ours=o)
            continue
        if sdk_res[0] == "ok" and o[0] == "ok":
            if op == "leaf":
                sa, sb = sdk_res[1].split("|")
                good = sa == sb == o[1].split("|")[0]
            else: good = sdk_res[1] == o[1]
            if kind == "valid": note(op, "match" if good else "MISMATCH", c, sdk=sdk_res, ours=o)
            else: note(op, "both_accept" if good else "ACCEPT_DIFF", c, sdk=sdk_res, ours=o)
        elif sdk_res[0] == "err" and o[0] == "err": note(op, "both_reject" if kind == "invalid" else "MISMATCH", c, sdk=sdk_res, ours=o)
        elif kind == "valid": note(op, "MISMATCH", c, sdk=sdk_res, ours=o)
        else: note(op, "ours_rejects_sdk_accepts" if o[0] == "err" else "sdk_rejects_ours_accepts", c, sdk=sdk_res, ours=o)
    # signatures: SDK-produced messages for corpus vectors verified with sr25519
    c_ = json.load(open(corpus_path))["compute_channel_v1"]
    corpus_sdk = {c["name"]: sdk[c["id"]]["out"] for c in cases if c["kind"] == "corpus" and "out" in sdk[c["id"]]}
    sigs = {}
    msg = B(corpus_sdk["compute_channel_v1.receipt.preimage"])
    sigs["receipt: SDK receiptMessage verifies the corpus agent signature"] = sr25519.verify(B(c_["receipt"]["signature_hex"]), msg, B(c_["receipt"]["public_key_hex"]))
    lm = B(corpus_sdk["negative_cases.legacy_receipt_current_channel (message part)"])
    sigs["receipt: SDK legacyReceiptMessage does NOT verify the receipt signature"] = not sr25519.verify(B(c_["receipt"]["signature_hex"]), lm, B(c_["receipt"]["public_key_hex"]))
    ak = c_["fcc4_transcript_with_ack"]
    am = B(corpus_sdk["compute_channel_v1.fcc4_transcript_with_ack.ack_preimage"])
    sigs["ack: SDK turnAckMessage verifies the corpus agent ack signature"] = sr25519.verify(B(ak["agent_signature_hex"]), am, B(ak["agent_public_key_hex"]))
    out = dict(stats={k: dict(v) for k, v in stats.items()}, problems=problems, signatures=sigs)
    json.dump(out, open(report_path, "w"), indent=1, default=str)
    for op, cnt in stats.items(): print(f"{op:18s}", dict(cnt))
    for k, v in sigs.items(): print("SIG", v, k)
    # RULE_DIFF and the *_accepts rows are known, reported differences (README);
    # byte mismatches, corpus failures and signature failures are not.
    failing = {k: len(v) for k, v in problems.items() if not k.endswith("RULE_DIFF")}
    rule = {k: v for k, v in stats["leaf_consistency"].items() if k.endswith("RULE_DIFF")}
    print("problem kinds:", failing or "none", "| reported rule differences (not byte differences):", rule or "none")
    return 1 if failing or not all(sigs.values()) else 0


def _check_lockfile(tmp):
    lock = json.load(open(Path(tmp) / "package-lock.json"))
    pkg = lock["packages"]["node_modules/" + SDK_NAME]
    if (pkg["version"], pkg["resolved"], pkg["integrity"]) != (SDK_VERSION, SDK_RESOLVED, SDK_INTEGRITY):
        raise SystemExit(f"SDK does not match the pinned version/integrity: {pkg['version']} {pkg['integrity']}")
    scripted = [k for k, v in lock["packages"].items() if v.get("hasInstallScript")]
    if scripted:
        raise SystemExit(f"packages with install scripts: {scripted}")
    print(f"sdk: {SDK_NAME}@{SDK_VERSION} integrity {SDK_INTEGRITY} (matches the pin); no package has install scripts")


def _fetch_corpus(dest):
    src = json.load(open(SOURCE_JSON))
    data = urllib.request.urlopen(src["url"], timeout=30).read()
    if len(data) != src["size_bytes"] or hashlib.sha256(data).hexdigest() != src["sha256"]:
        raise SystemExit("downloaded corpus does not match SOURCE.json")
    Path(dest).write_bytes(data)
    print(f"corpus: yellowpaper@{src['commit'][:10]} {len(data)} bytes sha256 {src['sha256']}")


def run_all(keep=False):
    tmp = Path(tempfile.mkdtemp(prefix="flop-sdk-parity-"))
    try:
        (tmp / "package.json").write_text('{"name":"flop-sdk-parity-tmp","private":true,"type":"module"}\n')
        subprocess.run(["npm", "install", f"{SDK_NAME}@{SDK_VERSION}", "--ignore-scripts", "--legacy-peer-deps",
                        "--no-audit", "--no-fund", "--loglevel=error"], cwd=tmp, check=True)
        _check_lockfile(tmp)
        _fetch_corpus(tmp / "wire-format-v1.json")
        gen(str(tmp / "cases.json"), str(tmp / "wire-format-v1.json"))
        n = len(json.load(open(tmp / "cases.json")))
        if n != EXPECTED_CASES:
            raise SystemExit(f"{n} cases, expected {EXPECTED_CASES} (generator or seed changed)")
        subprocess.run(["node", str(HERE / "sdk_run.mjs"), str(tmp / "cases.json"), str(tmp / "sdk_out.json"),
                        str(tmp / "node_modules" / SDK_NAME)], check=True, cwd=tmp)
        status = compare(str(tmp / "cases.json"), str(tmp / "sdk_out.json"), str(tmp / "wire-format-v1.json"), str(tmp / "report.json"))
        print(f"RESULT: {n} cases, " + ("no byte difference" if status == 0 else "DIFFERENCES FOUND") + f" (work dir {tmp if keep else 'removed'})")
        return status
    finally:
        if not keep:
            shutil.rmtree(tmp, ignore_errors=True)

Z_ = "00" * 32
if __name__ == "__main__":
    mode = sys.argv[1] if len(sys.argv) > 1 else "run"
    if mode == "run": sys.exit(run_all("--keep" in sys.argv))
    if mode == "gen": gen(sys.argv[2], sys.argv[3])
    else: sys.exit(compare(*sys.argv[2:6]))
