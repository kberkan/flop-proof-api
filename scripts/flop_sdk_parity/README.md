# Parity with the official `@flop-labs/sdk`

Compares our compute-channel primitives (`app/crypto.py`) with the TypeScript
SDK's `transcript.js`, byte for byte, on 31 614 fixed-seed cases and the pinned
wire-format corpus vectors. Evidence and the function mapping:
[docs/evidence/flop-sdk-parity-2026-11-07.md](../../docs/evidence/flop-sdk-parity-2026-11-07.md).

```
.venv/bin/python scripts/flop_sdk_parity/parity.py run
```

Needs Node, npm and the network. It does, in a temporary directory outside the
repository (removed afterwards; `--keep` keeps it):

1. `npm install @flop-labs/sdk@0.4.0 --ignore-scripts --legacy-peer-deps`, then
   checks the lockfile entry against the version, tarball URL and integrity
   pinned in `parity.py` and that no package has an install script;
2. downloads `evidence/wire-format-v1.json` as pinned in
   `tests/fixtures/flop-yellowpaper/SOURCE.json` and checks size and sha256;
3. generates the cases (seed `20261107`), runs `sdk_run.mjs` on them (pure
   functions only: blake2 and byte concatenation, no network) and compares.

Exit 0: no byte difference, all corpus vectors and signatures fine. Exit 1: a
difference. Exit 2 (or an error): the install or the corpus did not check out.

Not part of pytest, `testpaths` or CI: it needs `npm install` and the network.
The SDK is not a dependency of this repository or of `dashboard/`.

## Known differences it reports (not byte differences)

- the SDK does not check byte lengths outside `channelIdV1` and `taskHashV1`;
- `decode_policy_hash` must be non-zero for V2 and V3 in our code (a zero hash
  is "no policy"; a deliberately stricter rule than the specification and the
  SDK, which only need a policy to be present): `leaf_consistency`
  `V2:RULE_DIFF` 260 and `V3:RULE_DIFF` 520 combinations, and 120 random V2
  leaf inputs (`rule_v2_zero_decode_policy_hash`);
- V0 with non-zero timing fields is rejected by us and ignored by the SDK
  (`V0:RULE_DIFF`, 130).

A zero `toploc_commitment_hash` in a V3 turn is accepted by us and by the SDK
(since 2026-11-07; before, V3 showed 780 differences, see the evidence file).

## Changing the pinned SDK version

Edit `SDK_VERSION`, `SDK_RESOLVED` and `SDK_INTEGRITY` in `parity.py` after
reading the new version's install scripts, run, and write a new evidence file.
Agreement of two implementations from the same vendor is not a check against
the runtime source (`flop-core` is not public).
