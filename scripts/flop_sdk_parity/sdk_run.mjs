// Runs the @flop-labs/sdk compute-channel transcript primitives on a cases file.
// Reads only the local file node_modules/@flop-labs/sdk/dist/compute-channel/transcript.js
// (pure functions: blake2 + byte concatenation). Nothing here touches the network.
import { readFileSync, writeFileSync } from "node:fs";
import { pathToFileURL } from "node:url";
import path from "node:path";

const [, , casesPath, outPath, sdkDir] = process.argv;
const sdk = await import(pathToFileURL(path.join(sdkDir, "dist/compute-channel/transcript.js")).href);
const hex = (u8) => Buffer.from(u8).toString("hex");
const b = (h) => new Uint8Array(Buffer.from(h, "hex"));
const big = (s) => BigInt(s);
const num = (s) => Number(s);
const V = ["V0", "V1", "V2", "V3"];

const ops = {
  channel_id: (a) => hex(sdk.channelIdV1(b(a.genesis), b(a.agent), b(a.miner), big(a.nonce))),
  task_hash: (a) => hex(sdk.taskHashV1(b(a.genesis), b(a.agent), big(a.nonce), b(a.model), b(a.payload), b(a.commit))),
  leaf: (a) => {
    const v = V[a.version];
    const args = [b(a.channel), num(a.turn_index), b(a.h_in), b(a.h_out), big(a.g_n)];
    const viaVersioned = hex(sdk.reconstructLeafVersioned(v, ...args, b(a.dph), b(a.hids), b(a.toploc),
      big(a.recv), big(a.done), big(a.lat)));
    let direct;
    if (a.version === 0) direct = viaVersioned; // no dedicated V0 function in the SDK
    else if (a.version === 1) direct = hex(sdk.transcriptLeaf(...args, big(a.recv), big(a.done), big(a.lat)));
    else if (a.version === 2) direct = hex(sdk.transcriptLeafV2(...args, b(a.dph), big(a.recv), big(a.done), big(a.lat)));
    else direct = hex(sdk.transcriptLeafV3(...args, b(a.dph), b(a.hids), b(a.toploc), big(a.recv), big(a.done), big(a.lat)));
    return viaVersioned + "|" + direct;
  },
  leaf_consistency: (a) => {
    const nz = (h) => b(h).some((x) => x !== 0);
    // SDK models "no decode policy" as undefined; map an all-zero hash to that for V0/V1.
    const dph = (a.version <= 1 && !nz(a.dph)) ? undefined : b(a.dph);
    return String(sdk.leafFieldsConsistent(V[a.version], dph, b(a.hids), b(a.toploc)));
  },
  receipt: (a) => hex(sdk.receiptMessage(b(a.channel), b(a.root), big(a.gn), big(a.payable))),
  legacy_receipt: (a) => hex(sdk.legacyReceiptMessage(b(a.channel), b(a.root), big(a.gn), big(a.payable))),
  ack: (a) => hex(sdk.turnAckMessage(b(a.channel), num(a.turn_index), b(a.leaf), big(a.send), big(a.recv))),
  h_ids: (a) => hex(sdk.hIds(a.prompt.map(num), a.generated.map(num))),
  merkle_root: (a) => {
    const acc = new sdk.MerkleAccumulator();
    a.leaves.forEach((l) => acc.push(b(l)));
    return hex(acc.root());
  },
  merkle_proof: (a) => {
    const acc = new sdk.MerkleAccumulator();
    a.leaves.forEach((l) => acc.push(b(l)));
    const proof = acc.proof(a.index);
    const root = acc.root();
    const rebuilt = sdk.merkleRootFromPath(b(a.leaves[a.index]), proof);
    return JSON.stringify({ root: hex(root), rebuilt: hex(rebuilt), path: proof.map(([s, left]) => [hex(s), left]) });
  },
  merkle_path_root: (a) => hex(sdk.merkleRootFromPath(b(a.leaf), a.path.map(([s, left]) => [b(s), left]))),
};

const cases = JSON.parse(readFileSync(casesPath, "utf8"));
const out = cases.map((c) => {
  try {
    return { id: c.id, out: ops[c.op](c.args) };
  } catch (e) {
    return { id: c.id, err: `${e.constructor.name}: ${String(e.message).slice(0, 80)}` };
  }
});
writeFileSync(outPath, JSON.stringify(out));
console.log(`sdk_run: ${cases.length} cases, ${out.filter((o) => o.err).length} threw`);
