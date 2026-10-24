from typing import Any

import httpx

import base64
import hashlib
import json

import base58
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from .canonical import build_event_canonical_v4, build_request_canonical_v4, chain_head


ED25519_PUB_MULTICODEC = bytes([0xed, 0x01])


def sha256_json(value: Any) -> str:
    raw = json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")
    return hashlib.sha256(raw).hexdigest()


def public_key_to_test_did(public_key: Any) -> str:
    public_key_bytes = public_key.public_bytes_raw()
    multicodec_key = ED25519_PUB_MULTICODEC + public_key_bytes
    return "did:key:z" + base58.b58encode(multicodec_key).decode("ascii")


def sign_message(
    private_key: Ed25519PrivateKey,
    message: bytes,
) -> str:
    signature = private_key.sign(message)
    return base64.urlsafe_b64encode(signature).rstrip(b"=").decode("ascii")


class FlopProofError(Exception):
    """Base exception for FLOP Proof SDK errors."""


class FlopProofHTTPError(FlopProofError):
    """Raised when the FLOP Proof API returns an HTTP error."""

    def __init__(self, status_code: int, detail: Any):
        self.status_code = status_code
        self.detail = detail

        message = f"FLOP API error {status_code}: {detail}"
        super().__init__(message)


# The API's 409 detail for a stale prior_head (app/authorization.py REASONS).
HEAD_MISMATCH_DETAIL = "Event prior_head does not match the current chain"

# Never re-signed automatically (docs/design/proof-closure.md D-C4).
CLOSING_EVENT_TYPES = frozenset({"proof.completed", "proof.failed"})


class HeadMismatchError(FlopProofHTTPError):
    """409 head_mismatch: the event signed `signed_head`, but the chain moved
    on (another writer appended first). `current_head` is the head the SDK
    read and checked after the rejection (D-C4)."""

    def __init__(self, detail: Any, signed_head: str, current_head: str):
        super().__init__(409, detail)
        self.signed_head = signed_head
        self.current_head = current_head


class FlopProofChainError(FlopProofError):
    """The API's chain_head does not match the head the SDK computes from the
    exported events, or the export has no events. Nothing is signed.

    This catches an inconsistent answer only. A server that consistently
    serves a shortened chain is not detected here; compare chain_head with a
    record of your own for that (README, "What it does not verify")."""


class FlopProofClient:
    def __init__(
        self,
        base_url: str,
        timeout: float = 10.0,
        api_key: str | None = None,
        http_client: httpx.Client | None = None,
    ):
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout
        self.api_key = api_key
        # Optional httpx.Client used for every request (connection reuse, or
        # an in-process test client); its own timeout setting applies. Without
        # it each call uses httpx.request with `timeout`.
        self.http_client = http_client

    def _request(
        self,
        method: str,
        path: str,
        **kwargs: Any,
    ) -> dict[str, Any]:
        try:
            headers = dict(kwargs.pop("headers", {}) or {})

            if self.api_key:
                headers["X-API-Key"] = self.api_key

            if self.http_client is not None:
                response = self.http_client.request(
                    method,
                    f"{self.base_url}{path}",
                    headers=headers,
                    **kwargs,
                )
            else:
                response = httpx.request(
                    method,
                    f"{self.base_url}{path}",
                    timeout=self.timeout,
                    headers=headers,
                    **kwargs,
                )
        except httpx.HTTPError as exc:
            raise FlopProofError(
                f"FLOP API connection error: {exc}"
            ) from exc

        if response.is_error:
            try:
                detail = response.json().get("detail")
            except (ValueError, TypeError):
                detail = response.text

            raise FlopProofHTTPError(
                status_code=response.status_code,
                detail=detail,
            )

        try:
            return response.json()
        except ValueError as exc:
            raise FlopProofError(
                "FLOP API returned invalid JSON."
            ) from exc

    def health(self) -> dict[str, Any]:
        return self._request(
            "GET",
            "/health",
        )

    def create_proof(
        self,
        request: dict[str, Any],
    ) -> dict[str, Any]:
        return self._request(
            "POST",
            "/proofs",
            json={"request": request},
        )

    def create_signed_proof(
        self,
        private_key: Any,
        did: str,
        text: str,
        room: str,
        nonce: str,
        request_id: str,
        created_at: str,
    ) -> dict[str, Any]:
        # Version-4 request format; raises ValueError for an invalid field.
        canonical = build_request_canonical_v4(room, nonce, text)
        signature = sign_message(
            private_key,
            canonical.encode("utf-8"),
        )

        request = {
            "request_id": request_id,
            "from_did": did,
            "text": text,
            "created_at": created_at,
            "signature": {
                "nonce": nonce,
                "sig": signature,
                "canonical": canonical,
            },
        }

        return self.create_proof(request)

    def current_head(self, proof_id: str) -> str:
        """The head a new event must sign: read from GET /proofs/{id}, computed
        from the exported events (created_at as exported text, D-C12) and
        compared with the export's chain_head. Raises FlopProofChainError if
        they differ, before anything is signed."""
        exported = self.get_proof(proof_id)
        try:
            computed = chain_head(exported.get("events"), proof_id=proof_id)
        except ValueError as exc:
            raise FlopProofChainError(f"Cannot compute the chain head: {exc}") from exc
        if computed is None:
            raise FlopProofChainError("The exported proof has no events.")
        if computed != exported.get("chain_head"):
            raise FlopProofChainError(
                "The API's chain_head does not match its exported events; not signing."
            )
        return computed

    def append_signed_event(
        self,
        proof_id: str,
        private_key: Any,
        did: str,
        event_type: str,
        payload: dict[str, Any],
        nonce: str,
        prior_head: str | None = None,
        *,
        retries: int = 0,
    ) -> dict[str, Any]:
        """Sign and append a version-4 event (FLOP/EVENT/v4, D-C1).

        prior_head: the chain head to sign; if None, current_head() reads and
        checks it. On 409 head_mismatch a HeadMismatchError is raised with the
        current head (D-C4). With retries=N the event is re-signed on the new
        head up to N times, with the same nonce (a rejected event is not
        stored); proof.completed and proof.failed are never re-signed, because
        a re-signed event states its signer saw a chain the caller has not
        looked at. Version-4 proofs only: the API rejects prior_head on
        v1/v2/v3 proofs (400).
        """
        if not isinstance(retries, int) or retries < 0:
            raise ValueError("retries: must be a non-negative integer")

        payload_hash = sha256_json(payload)
        head = prior_head
        attempt = 0

        while True:
            if head is None:
                head = self.current_head(proof_id)
            canonical = build_event_canonical_v4(
                proof_id, event_type, payload_hash, nonce, head
            )
            event = {
                "type": event_type,
                "actor_did": did,
                "payload": payload,
                "signature": {
                    "nonce": nonce,
                    "sig": sign_message(private_key, canonical.encode("utf-8")),
                    "canonical": canonical,
                    "prior_head": head,
                },
            }

            try:
                return self.append_event(proof_id, event)
            except FlopProofHTTPError as exc:
                if exc.status_code != 409 or exc.detail != HEAD_MISMATCH_DETAIL:
                    raise
                current = self.current_head(proof_id)
                if attempt >= retries or event_type in CLOSING_EVENT_TYPES:
                    raise HeadMismatchError(exc.detail, head, current) from exc
                attempt += 1
                head = current

    def append_event(
        self,
        proof_id: str,
        event: dict[str, Any],
    ) -> dict[str, Any]:
        return self._request(
            "POST",
            f"/proofs/{proof_id}/events",
            json=event,
        )

    def get_proof(
        self,
        proof_id: str,
    ) -> dict[str, Any]:
        return self._request(
            "GET",
            f"/proofs/{proof_id}",
        )


    def accept_proof_validator_attestations(
        self,
        proof_id: str,
        report_data: str,
        attestations: list[dict[str, Any]],
    ) -> dict[str, Any]:
        return self._request(
            "POST",
            f"/proofs/{proof_id}/validator-attestations/accept",
            json={
                "report_data": report_data,
                "attestations": attestations,
            },
        )

    def accept_validator_attestation(
        self,
        report_data: str,
        attestations: list[dict[str, Any]],
        *,
        result: dict[str, Any],
    ) -> dict[str, Any]:
        """Accept validator-attestation evidence at the API boundary.

        `result` is the result metadata the attestations are bound to; the API
        requires its task_hash, model_hash, output_hash and decode_policy_hash
        (64-hex strings) and gn_weight, latency_ms and tee_type (integers).
        This method exposes API-side attestation validation and acceptance.
        It does not imply real execution verification or runtime settlement.
        The response evidence fields are returned unchanged.
        """
        return self._request(
            "POST",
            "/validator-attestations/accept",
            json={
                "result": result,
                "report_data": report_data,
                "attestations": attestations,
            },
        )

    def submit_stark_evidence(
        self,
        proofs: list[dict[str, Any]],
        *,
        task_hash: str,
        gn_weight: int,
        latency_ms: int,
        model_hash: str,
        output_hash: str,
    ) -> dict[str, Any]:
        """Submit STARK evidence for pending API-side verification.

        task_hash, model_hash and output_hash are 64-character hex strings;
        gn_weight and latency_ms are integers (u64). The API rejects any other
        JSON type for them, including booleans, numeric strings and floats.

        This method performs evidence intake only. The current API response
        uses proof_verified=false and verification_status="pending".
        It does not imply STARK verification, execution verification,
        runtime settlement, or reward credit.
        The response evidence fields are returned unchanged.
        """
        return self._request(
            "POST",
            "/stark-batches",
            json={
                "proofs": proofs,
                "task_hash": task_hash,
                "gn_weight": gn_weight,
                "latency_ms": latency_ms,
                "model_hash": model_hash,
                "output_hash": output_hash,
            },
        )

    def verify_proof(
        self,
        proof_id: str,
    ) -> dict[str, Any]:
        return self._request(
            "GET",
            f"/proofs/{proof_id}/verify",
        )
