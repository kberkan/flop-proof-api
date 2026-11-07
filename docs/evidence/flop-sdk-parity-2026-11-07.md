# Primitive parity with the official `@flop-labs/sdk`

Run date: 2026-11-07. Read-only comparison of our primitives (`app/crypto.py`)
with the transcript primitives of the npm package, on fixed-seed inputs. No
network call was made by any SDK function.

## The SDK that was used

| Item | Value |
|---|---|
| Package | `@flop-labs/sdk` **0.4.0** (npm `latest`; published 2026-10-29) |
| Tarball | `https://registry.npmjs.org/@flop-labs/sdk/-/sdk-0.4.0.tgz` |
| Integrity | `sha512-qC31W4f08qXKpONZDXx2fn9rnaiouBbKrcf5zyzIaFiXk+sD/PT14iko3OJ9LtD398hUBG4tZ/2/Wd9/rss/5A==` (the `package-lock.json` integrity equals the registry's `dist.integrity`) |
| Install scripts | none: the package has no `preinstall`/`install`/`postinstall`/`prepare`, and no package in the lockfile has `hasInstallScript`. Installed anyway with `--ignore-scripts --legacy-peer-deps` in a temporary directory outside the repository. |
| Not added to | this repository, `dashboard/` or any lockfile |
| Source file used | `dist/compute-channel/transcript.js` (imports only `@polkadot/util` and `@polkadot/util-crypto`: blake2 and byte concatenation) |
| Repository the package names | `flop-labs/flop-core` (`sdk/typescript`), not public. The file header says the primitives are "byte-identical to the on-chain verifier (`pallets/pallets/compute-channel/src/lib.rs`) and the Rust SDK". The SDK is built from flop-core, but it is not the runtime source. |

## Function mapping

| SDK function (`transcript.js`) | Ours | Inputs |
|---|---|---|
| `channelIdV1(genesis, agent, miner, nonce)` | `compute_channel_id_v1` | 3 × 32 B, `nonce` u64 |
| `taskHashV1(genesis, agent, nonce, model, payload, commit)` | `compute_task_hash_v1` | 5 × 32 B, `nonce` u64 |
| `reconstructLeafVersioned(V0..V3, …)`, `transcriptLeaf` (V1), `transcriptLeafV2`, `transcriptLeafV3` | `compute_verified_turn_leaf_v0_v1_v2_v3` | channel, `turn_index` u32, `h_in`, `h_out`, `g_n` u128, `decode_policy_hash`, `h_ids`, `toploc_commitment_hash`, 3 × u64 timing |
| `receiptMessage(channel, root, aggregateGn, payable)` | `compute_agent_receipt_v1_signable_payload` | 2 × 32 B, 2 × u128 |
| `legacyReceiptMessage(…)` | none (we only reject the legacy form) | same |
| `turnAckMessage(channel, turnIndex, leaf, sendMs, recvMs)` | `turn_ack_message` | 32 B, u32, 32 B, 2 × u64 |
| `MerkleAccumulator.root()` | `compute_merkle_root` | list of 32 B leaves |
| `MerkleAccumulator.proof(i)` | none (we only verify) | |
| `merkleRootFromPath(leaf, path)` | folding with `compute_merkle_node`; `verify_merkle_path` for the checked form | leaf, `[(sibling, sibling_is_left)]` |
| `hIds(prompt, generated)` | none (`h_ids` is an input for us) | `u32` lists |
| `leafFieldsConsistent(version, dph, hIds, toploc)` | the `LeafFieldsInconsistent` checks inside the leaf function | |
| validator attestation (direct-rail) encoding | **not in the SDK**: it has `AttestClaim` helpers (`attestation.js`, a different object) | not compared |

## Method

`parity.py gen` writes 31 614 cases from `random.Random(20261107)`: random
32-byte values mixed with all-zero and all-0xFF, and integers drawn 40 % of the
time from boundary sets (u32: 0, 1, 2, 255, 256, 2³¹−1, 2³¹, 2³²−1; u64: 0, 1,
2³²−1, 2³², 2⁵³−1, 2⁶³, 2⁶⁴−2, 2⁶⁴−1; u128: 0, 1, 2⁶⁴−1, 2⁶⁴, 2¹²⁷, 2¹²⁸−2,
2¹²⁸−1). It adds rejection cases (value one past the range, −1, byte lengths
0, 31, 33) and the wire-format corpus vectors. `sdk_run.mjs` runs the SDK on the
same file; `parity.py compare` runs ours and compares byte for byte. The
corpus is `evidence/wire-format-v1.json` at yellowpaper `2a2cc82180` (sha256
`53440d85…e5011de`, the pinned one).

Scripts: `scripts/flop_sdk_parity/parity.py` sha256
`04489857a2681a3a0cacf6604daadb2d70b939f502e0f5e6cd314747e5c20ccc` and
`scripts/flop_sdk_parity/sdk_run.mjs` sha256
`5e3621689e8107ea9dede299cb0f5f7fffb348658c585f769b1498054078de0e`; cases file
sha256 `88c7dab4bf9ca34deef0851f5c5a70c31e002f50dfafe053f5b76fe1c115bcb4`.
The results above were first obtained with an earlier, standalone copy of
`parity.py` (sha256 `8ad3f0e1…ba2`; same generator, same seed, same cases file
hash, same comparison). The repository version adds the `run` driver (pinned
install and corpus checks, cleanup); its first version (sha256 `6e6dc9b6…f4de`)
gave the same result as the standalone copy. The hash above is the file after
the formatting clean-up (same random draws, same cases file) and the V3 rule
change, and is the one that produced the results in this file: 31 614 cases, no
byte difference. Not part of pytest or CI (it needs
`npm install` and the network); see `scripts/flop_sdk_parity/README.md`.

## Result: no byte difference

| Primitive | Byte-identical, valid inputs | Corpus vectors through the SDK | Rejections |
|---|---:|---:|---|
| channel_id v1 | 2000 | 1 / 1 | 12 rejected by both |
| task_hash v1 | 2000 | 1 / 1 | 17 rejected by both |
| leaf V0, V1, V2, V3 (1500 each) | 5880 (V0 1500, V1 1500, V2 1380, V3 1500; both SDK entry points agree with ours) | 4 / 4 (`leaf_versions` V0–V3) | 25 rejected by both |
| receipt v1 | 2000 | 1 / 1 | 4 rejected by both |
| turn ack | 2000 | 1 / 1 | 4 rejected by both |
| Merkle root | 1600 (0 to 300 leaves, including 0, 1, 63–65, 127–129, 255, 256) | 1 / 1 | |
| Merkle path (`proof(i)`) | 1600: SDK path = independent reference path, SDK root = rebuilt root, our `verify_merkle_path` accepts it | 1 / 1 | |
| `merkleRootFromPath` | 2000 (half with orientation from the index bits, half arbitrary) = our fold | | 3 over-long paths (65, 70, 100): SDK and our fold accept |
| legacy receipt (SDK only) | 2000 = `channel ‖ root ‖ gn:u128LE ‖ payable:u128LE` | 1 / 1 | |
| `hIds` (SDK only) | 2000 = `blake2_256(u32LE count ‖ u32LE ids ‖ u32LE count ‖ u32LE ids)` | 2 / 2 (`h_ids_v1`) | |

Signatures on SDK-produced messages (sr25519, corpus keys): the SDK's
`receiptMessage` verifies the corpus agent receipt signature; its
`legacyReceiptMessage` does not; its `turnAckMessage` verifies the corpus agent
ack signature.

## Differences that are not byte differences

These are input validation and rules, found on inputs where one side rejects.

1. **Byte lengths.** The SDK checks lengths only in `channelIdV1` and
   `taskHashV1`. `transcriptLeaf*`, `receiptMessage`, `turnAckMessage` and the
   Merkle functions concatenate whatever they get (12 leaf, 2 receipt and 2 ack
   cases with a 0-, 31- or 33-byte field: SDK hashes, we raise). Ours is
   stricter; no valid input differs.
2. **Merkle path length.** `merkleRootFromPath` has no cap; `verify_merkle_path`
   rejects more than 64 items (`MaxMerklePathLen` = 64 in the devnet runtime).
3. **Leaf field consistency** (8320 combinations of zero / non-zero
   `decode_policy_hash`, `h_ids`, `toploc_commitment_hash` and timing, per
   version, against the SDK's `leafFieldsConsistent`):
   Result after the V3 rule change of 2026-11-07 (see below); the first run
   of this comparison is kept under "Result before the V3 rule change".
   - V1: same answer in all 2080.
   - V0, 130 differences: all with non-zero timing fields. We reject (V0 has no
     timing fields); the SDK ignores timing. Consistent with the spec (V0 is V1
     without the timing fields).
   - V2, 260 differences: all with a zero `decode_policy_hash` (and zero
     `h_ids` and TOPLOC). We reject it in every path on purpose (a zero hash
     is "no policy"); the SDK only needs the policy to be present. The 120 V2
     leaf inputs with a zero `decode_policy_hash` among the random "valid"
     cases are the same difference: the SDK hashes them, we raise
     (`rule_v2_zero_decode_policy_hash` in the output).
   - V3, 520 differences: all with a zero `decode_policy_hash` (4 of the 8
     combinations in which `h_ids` is non-zero). A zero `toploc_commitment_hash`
     now gives the same answer as the SDK.
   The remaining differences are one deliberate rule: **`decode_policy_hash`
   must be non-zero for V2 and V3, in every path.** `yellowpaper.md` (F.3) and
   the SDK ask only that a policy is present.
4. **Not comparable:** the direct-rail `ValidatorAttestation` signable payload
   and SCALE encoding have no SDK counterpart.

## The V3 rule change (2026-11-07) and the result before it

The first run (before the change) found that our V3 check also required a
non-zero `toploc_commitment_hash` and `decode_policy_hash`, while the SDK, the
upstream reference (`evidence/compute-channel.py`) and the specification text
(F.3: "V3 has a policy and non-zero `h_ids`") require neither. The
`toploc_commitment_hash` rule was removed and the `decode_policy_hash` rule was
made the same in all three of our paths (leaf function, FCC4 decoder,
`verify_turn_proof`) for V2 and V3. In that first run: 6000 valid leaf cases
byte-identical; `leaf_consistency` V1 and V2 same answer in all 4160, V0 130
differences, V3 780 differences (the SDK accepts any V3 with a non-zero
`h_ids`; we also required the other two to be non-zero). On the devnet, 18 V3
turns read from three `force_settle` extrinsics (blocks #2893845, #2886961,
#2773600) all have non-zero values in all three fields, so the chain data
neither shows nor excludes zero values.

## Reproduce

```
.venv/bin/python scripts/flop_sdk_parity/parity.py run
```

It installs `@flop-labs/sdk@0.4.0` with `--ignore-scripts` in a temporary
directory, checks the lockfile integrity above and that no package has install
scripts, downloads the pinned corpus (size and sha256 from `SOURCE.json`),
runs both sides and removes the directory.

## What this shows and does not show

Our primitives produce the same bytes as the vendor's published TypeScript code
for these inputs. The SDK is a second implementation from the same vendor, built
from flop-core; this is not a check against the runtime source (not public), and
agreement of two implementations is not proof that either follows the runtime.
The live-chain check of `channel_id_v1` is in
[devnet-channel-id-2026-11-07.md](devnet-channel-id-2026-11-07.md).
