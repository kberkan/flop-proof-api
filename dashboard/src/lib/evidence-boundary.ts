// What each API boundary does and does not establish. Moved verbatim from
// src/app/developer/page.tsx so the proof pages reuse the same wording
// instead of writing new claims.

export type EvidenceBoundary = {
  endpoint: string;
  proves: string;
  doesNotProve: string;
};

export const evidenceBoundary: EvidenceBoundary[] = [
  {
    endpoint: "/proofs/{proof_id}/verify",
    proves: "The stored proof event chain and its cryptographic integrity.",
    doesNotProve:
      "Real model execution, TEE attestation, STARK verification, runtime settlement, or FLOP reward credit.",
  },
  {
    endpoint: "/validator-attestations/accept",
    proves: "Validator-attestation structure, signatures, field agreement and API-side acceptance.",
    doesNotProve:
      "Underlying TEE/DCAP verification, execution verification, runtime settlement, or reward credit.",
  },
  {
    endpoint: "/proofs/{proof_id}/validator-attestations/accept",
    proves: "Validator evidence bound to the specified stored proof and accepted at the API boundary.",
    doesNotProve:
      "Underlying hardware attestation, execution verification, runtime settlement, or reward credit.",
  },
  {
    endpoint: "/stark-batches",
    proves: "STARK evidence was accepted into a pending API-side verification record.",
    doesNotProve:
      "That the STARK proof was cryptographically verified, execution was verified, or runtime settlement occurred.",
  },
];

export const verifyBoundary: EvidenceBoundary = evidenceBoundary[0];
