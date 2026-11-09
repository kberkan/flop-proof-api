# Our own devnet miner's settled sessions, checked with our primitives

Run date: 2026-11-09. Read-only; no key, faucet or transaction. The miner log is
not in this repository. The values taken from it are public chain data and are in
[devnet-own-miner-turns-2026-11-09.inputs.json](devnet-own-miner-turns-2026-11-09.inputs.json).

| Item | Value |
|---|---|
| Network | FLOP Devnet, `https://rpc.devnet.flop.network`, runtime `tzkv-runtime` 1014014 |
| Genesis hash | `0x99c172c095340ace980631f9123544c6bebd4839f3437e463533422d8be2d631` |
| Pinned blocks | first run #3303069 `0x3d5083a31c2a40b9e12c80955069ea5f7918c6d145fd19211224c3ac3446eaca`; second run #3304057 `0x9b8ed890a6f7c2d532434d592d5f5b7ca34757131096658cb4e620b0dfe0b1ae`; third run #3320256 `0x994b0a8111033defc32442970f31327fa91f24ef9bbb6aa07ce3c9af905cc36b` (finalized head at each start) |
| Miner account | `0x44beeb4354bdd0aa52a2b8cc8c3b626c67eb1dec3785658425ce7115ac885e46` |
| Session signing key | `0xc89633cb3190c5c391c2fa9aaa660582a73874c01a66c6fe8f7cd7c0bb650059` |
| In the log | 77 sessions opened, 37 settled cooperatively, 49 turns (one session has 2 turns) |
| Requests | **159**: 91 in the first run (ad hoc scripts; one a 503, repeated once after 45 s), 52 in the second and 16 in the third (repository script) |

## Coverage: 6 of 37 settled sessions

**6 of the 37 settled sessions were checked end to end. The other 31 were not.**
The RPC has no lookup from a tx hash to a block, and `state_queryStorage` is
refused by the node (`4003 RPC call is unsafe to be called externally`), so
locating a settle takes about 10 requests (binary search on the channel's state
at past blocks).

- **Chosen by hand (3):** the first session, a 16-G_n one, the only two-turn one.
- **Random (3):** from the other 34 settled sessions, seed `20261109`,
  `random.Random(seed).sample(sorted(population), 3)`, over the tx hashes listed in the inputs file. Picked:
  `0xd62ce5f1af0cbb1c3237b5907660acf4be83fa34b9e66847e534a749455876ee`, `0x12e602fd7e8f8992600df1a6b26435772f2ff882d6ffe8ecf42ffdf22459fd74`, `0x4df3a0fd1da4f18ef9301ef1e7297b5b59eafd7ee0f772eac9572cac4adf5f3e`.
  All three passed. Three random sessions are a small sample: this is not a
  statistical claim about the other 31.

All 77 channels of the log, first run at #3303069: the 6-byte prefix from the
log matches exactly one channel, state `Closed`, `miner` = our account,
`enclave_key` = the session signing key, and **`channel_id_v1` recomputed with
`app.crypto` matches for 77 / 77**.

## Sessions checked

| Selection | Channel | Settle block | Turns | `gn` (log = `aggregate_gn` = sum of `g_n`) | `final_root` | Root | Checked with |
|---|---|---|---:|---:|---|---|---|
| chosen | `0x1be6e56d5064bd16dc8f2af9357b79a002d45112cfad2b5a9f0e86a777ebb69b` | #3232613 | 1 | 127 | `14c3714f98e69121e39299b06ae0d3b2dd17f8c7c5331456ebd582fa511d948d` | leaf = root | repository script, third run |
| chosen | `0x005d1fa1c8cbc36b89d24d2dce5c2ede3411e15cdc96523c484b52e9e4e6676e` | #3236362 | 1 | 16 | `1f6f6339b3c459db41f379c7ca308ad3c9e769754dc513a170c90be6c42b93f1` | leaf = root | repository script, third run |
| chosen | `0x6eaa86e1c78465545ee31a33fe491a04fde4663fa6c91123ae43863836f5cd1f` | #3283590 | 2 | 379 | `aa9d13affafc0536abe61d9da60553fe5e6a26e07c8de498a8aefd05a3d2c715` | Merkle root of 2 leaves | repository script, second run |
| random | `0x097a294cb4c5462e94f292433def23e6a0535e05731cc780ee8b516767d1d00a` | #3245287 | 1 | 120 | `323e9c5959b60c7f9248d1478071b2bb7f309b564383480aba07f883b57170fa` | leaf = root | repository script, second run |
| random | `0x0431c1e06f150179529117ce35c717bf66065f6ffde205aaf49f93bed8e9c8dd` | #3267292 | 1 | 21 | `add7a7ea0cbbae1233c95f4c230aa86a8294a1fcff3644576c2a42c00c36dc5e` | leaf = root | repository script, second run |
| random | `0xfc196747a1a97be6ad16c265d0579df335cd0a5e5a3c1d5d045c24dbbe65b0ec` | #3280521 | 1 | 72 | `04cee202a8df9d02a2e16c5bec155c99acb3d63e06e8f4fdfd11e045d8b3273f` | leaf = root | repository script, second run |

All turns are V3. In all of them `enclave_sig` is valid under the session signing
key, the Merkle path verifies against `final_root`, and `decode_policy_hash`,
`h_ids` and `toploc_commitment_hash` are non-zero.

| Session | Turn | `g_n` | Leaf hash (`compute_verified_turn_leaf_v0_v1_v2_v3`) | Path length |
|---|---:|---:|---|---:|
| `1be6e56d5064…` | 0 | 127 | `14c3714f98e69121e39299b06ae0d3b2dd17f8c7c5331456ebd582fa511d948d` | 0 |
| `005d1fa1c8cb…` | 0 | 16 | `1f6f6339b3c459db41f379c7ca308ad3c9e769754dc513a170c90be6c42b93f1` | 0 |
| `6eaa86e1c784…` | 0 | 74 | `7b37d05cffff1281a35182cc73e69a8c034780652248d82e5e66fcc0ae01f3ff` | 1 |
| `6eaa86e1c784…` | 1 | 305 | `f4a3956e007ec61bb1a0edd70b3cee8e6027349143dc4eea60bf162bb194a96f` | 1 |
| `097a294cb4c5…` | 0 | 120 | `323e9c5959b60c7f9248d1478071b2bb7f309b564383480aba07f883b57170fa` | 0 |
| `0431c1e06f15…` | 0 | 21 | `add7a7ea0cbbae1233c95f4c230aa86a8294a1fcff3644576c2a42c00c36dc5e` | 0 |
| `fc196747a1a9…` | 0 | 72 | `04cee202a8df9d02a2e16c5bec155c99acb3d63e06e8f4fdfd11e045d8b3273f` | 0 |

For each of the six:

- `blake2_256` of the extrinsic in that block equals the settle tx hash, and it
  decodes completely from the metadata types as `ComputeChannel.settle`, signed
  by the miner account, for that channel.
- `channel_id_v1` matches, and `compute_merkle_root` over the leaves = `final_root`.
- `System.Events` of that extrinsic has `Settled` with `cooperative: true`, the
  same `aggregate_gn`, and `miner_paid` equal to the log's `minerPaid`, and
  `ExtrinsicSuccess`.
- **`agent_receipt_sig`:** `verify_agent_receipt_v1` accepts it under the channel's
  `agent_key` with `payable` = the channel's `escrow`, read one block before the
  settle. **That `payable` rule rests on a comment in `@flop-labs/sdk` ("Cooperative:
  `payable = escrow`")**, not on the runtime source. It held in all six.

## Evidence transactions

| Session | `settle` tx | `submit_toploc_evidence` found in block |
|---|---|---:|
| `1be6e56d5064…` | `0x29e2e758a15cd4cfd390bf0b1bbd72bbfe1648e9c40c697b4d56ada6495b16a0` | #3232606 |
| `005d1fa1c8cb…` | `0x8318fb2e5627f06d252673e823fa030e8ea68c3d51548e8027affa82769040d9` | #3236356 |
| `6eaa86e1c784…` | `0x914cef96cc8b04ae6fb4d323dfc5d99df6dbacc9299f4cb37565b036937f36ef` | #3283583 |
| `097a294cb4c5…` | `0xd62ce5f1af0cbb1c3237b5907660acf4be83fa34b9e66847e534a749455876ee` | #3245280 |
| `0431c1e06f15…` | `0x12e602fd7e8f8992600df1a6b26435772f2ff882d6ffe8ecf42ffdf22459fd74` | #3267285 |
| `fc196747a1a9…` | `0x4df3a0fd1da4f18ef9301ef1e7297b5b59eafd7ee0f772eac9572cac4adf5f3e` | #3280514 |

`register_session_evidence` was located for one session only: `005d1fa1c8cb…`,
`0x4bcbfecc0f29cd7f565179645bfcaf0161eef7989b425f2a467d2f73636f37a5` (#3236319, slot Activation 0, commitment
`0d478ab96b92ff3d86d110096abae4f4c84cd4c0b7483d21cee9129609586a75`, 133 bytes, signed by the miner). For the other five,
`SessionEvidenceRegistrations` one block before the settle shows registrations, but
their transactions were not located. Both evidence maps are empty once a channel
is closed, so they are read at the block before the settle.

## Not interpreted

- **`turns_committed`** in `ChannelToplocEvidence` is 1 in all six sessions, the
  two-turn one included. What it means for R3.1 is not known without the runtime
  source; it is reported, not judged.
- **The 40 channels closed without a settle line in the log** (77 opened, 37
  settled) were not looked at beyond the checks on all 77 above.
- The commitment values in the evidence records differ from the per-turn
  `toploc_commitment_hash`. Their relationship was not checked.

## Departures from a single pinned block

Channel records are read at the pinned block. To locate and check a settle,
channel state, evidence maps and `System.Events` are read at earlier blocks (all
older than the pinned finalized block). Types come from the metadata at the pinned
block; the runtime version at the earlier blocks was not read, but every decoded
value consumed its bytes exactly.

## Reproduce

Script: `scripts/check_devnet_own_miner_turns.py`, sha256 `d2080f29f83528a8a0734793c984ad874b71af6b5ee9ce8238a3f089016a6769`, not
committed when this was written (repository HEAD `d3e5710`). It needs the network and
is not part of pytest or CI; it reads no log, only the inputs file.

```
.venv/bin/python scripts/check_devnet_own_miner_turns.py
```

All six: about 36 requests, under its default limit of 60. **All six sessions were
checked with this script, at the sha256 above, with every check including
`ExtrinsicSuccess`:** the three random ones and the two-turn one in the second run
(4/4 passed, 52 requests, three of them located by binary search first), and
`1be6e56d5064…` and `005d1fa1c8cb…` in the third run (2/2 passed, 20/20 checks each,
16 requests, `--only 0x1be6 --only 0x005d`). The first run's ad hoc scripts found the
sessions; their results are superseded by these runs.

`test_devnet_own_miner_turns.py` runs the decoding and the checks without a network on
real records of two sessions (two-turn and one-turn) in
`tests/fixtures/flop-devnet/own-miner-records.json`, and on changed copies of them.

## What this shows and does not show

Our leaf, signature, Merkle, receipt and `channel_id_v1` functions agree with what the
devnet runtime accepted and settled, for real V3 turns our own miner produced, on the
sessions above. All of them have a non-zero TOPLOC commitment, so this says nothing
about zero values. It is not a check against the runtime source (not public), and
the miner software that produced the turns comes from the same vendor as the runtime,
so it is not independent of it. The devnet can be reset.
