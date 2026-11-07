# channel_id_v1 against live FLOP Devnet data

Run date: 2026-11-07. Read-only; no key, faucet or transaction.

| Item | Value |
|---|---|
| Network | FLOP Devnet, `https://rpc.devnet.flop.network` (`system_chain`: "FLOP Devnet") |
| Runtime | `tzkv-runtime` spec 1014014 (node reports itself as `zkVerify` 1.1.0) |
| Genesis hash | `0x99c172c095340ace980631f9123544c6bebd4839f3437e463533422d8be2d631` |
| Genesis cross-check | Consistent with the abbreviated pin `0x99c172c0…8be2d631` in the `@flop-labs/sdk` 0.4.0 CHANGELOG. `flop.finance/official/` and `docs.flop.network/docs/network-devnet` publish no genesis hash (checked by hand), so there is no official full value to compare with. |
| Pinned block | #3133177, `0x575c6e8fb06d7ccc2c75a816224752d88ed7472dedf54b384b058c30330d4a5a` (finalized head when the run started; every storage read used this block) |
| Storage item | `ComputeChannel.Channels`, prefix `0x130ba67ef498736437f36679a246a7547759ccc18de172078306ca5973251a7b`, key `Blake2_128Concat(H256)`, value `pallet_compute_channel::pallet::Channel` |
| Channels read | 1020 (1020 distinct keys) |
| channel_id_v1 match | **1020 / 1020**; 0 mismatches, 0 undecodable |
| Requests sent | 18 in the run below. An earlier attempt of the same script stopped after 5 requests, before reading any channel, on a script bug (it did not accept the `H256` wrapper as a 32-byte key type); fixed, then this run. 23 requests in total. |

## What was compared

For each channel the script decodes the value from the SCALE type definition
in the metadata read at the same block (no byte offsets in the script; the
fields are taken by name), takes `agent`, `miner` (both `AccountId32`) and
`nonce` (`u64`), recomputes `app.crypto.compute_channel_id_v1(genesis, agent,
miner, nonce)` and compares it with the last 32 bytes of the storage key. The
16 bytes before them (the `Blake2_128Concat` part) are checked too, and each
value must be consumed exactly.

Decoded `Channel` fields in SCALE order: `agent`, `miner`, `model_hash`,
`measured_root`, `precision`, `enclave_key`, `agent_key`, `escrow`, `sla`,
`nonce`, `opened_at`, `last_attested_at`, `state`, `transcript_ref`,
`weights_pin`, `locked_compute_consumed`.

## How to reproduce

Script as run: `scripts/check_devnet_channel_ids.py`, sha256
`1e1d50e513b64dd8b0b29a1d1f8c0001f0d4eeec3f138d1bfe7b8da9c8e551a8`. It was
not committed when run (repository HEAD `c5a7086`); the commit that adds it
is the one to cite.

```
.venv/bin/python scripts/check_devnet_channel_ids.py \
    --write-fixture tests/fixtures/flop-devnet/channels-sample.json
```

Exit 0 only if every channel matches. A later run reads a later block (the
finalized head), so the block and channel count will differ.

## Output of the run

```
network: https://rpc.devnet.flop.network  runtime tzkv-runtime 1014014
genesis hash: 0x99c172c095340ace980631f9123544c6bebd4839f3437e463533422d8be2d631
  SDK pin 0x99c172c0…8be2d631 (...): consistent (abbreviated pin only)
pinned block: #3133177 0x575c6e8fb06d7ccc2c75a816224752d88ed7472dedf54b384b058c30330d4a5a (finalized head at start)
channels read: 1020 (distinct keys: 1020)
matching channel_id_v1: 1020
not matching or undecodable: 0
requests sent: 18
RESULT: 1020/1020 channels match at block #3133177
```

## Offline test data

`tests/fixtures/flop-devnet/channels-sample.json` holds three real records
(key and value hex) from this run, the genesis hash and the 15 metadata types
needed to decode them. `test_devnet_channel_decoding.py` runs the decoding and
the comparison on them without a network. The other 1017 records are not
copied.

## What this does and does not show

- It shows that the channel IDs the devnet runtime stored equal what our
  `channel_id_v1` computes from the stored agent, miner and nonce, for every
  channel present at that block. That is a check against data the runtime
  produced, not against the runtime source (`flop-core` is not public).
- It says nothing about `task_hash`, VerifiedTurn leaves, receipts or
  attestations (`FlopPoui.ProcessedTasks` and `Attest.Profiles` were empty
  when read on 2026-11-07).
- The devnet can be reset. The result is a dated observation; the genesis
  hash above identifies the chain it was made on.
