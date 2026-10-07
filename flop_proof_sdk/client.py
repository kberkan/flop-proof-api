from typing import Any

import httpx

import base64
import hashlib
import json

import base58
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from .canonical import build_event_canonical_v3, build_request_canonical_v3


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
        # Version-3 request format; raises ValueError for an invalid field.
        canonical = build_request_canonical_v3(room, nonce, text)
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

    def append_signed_event(
        self,
        proof_id: str,
        private_key: Any,
        did: str,
        event_type: str,
        payload: dict[str, Any],
        nonce: str,
    ) -> dict[str, Any]:
        payload_hash = sha256_json(payload)
        # Version-3 event format: the nonce is signed. Version-3 proofs only;
        # the API rejects new events in this format on v1/v2 proofs (D-R12).
        canonical = build_event_canonical_v3(proof_id, event_type, payload_hash, nonce)

        signature = sign_message(
            private_key,
            canonical.encode("utf-8"),
        )

        event = {
            "type": event_type,
            "actor_did": did,
            "payload": payload,
            "signature": {
                "nonce": nonce,
                "sig": signature,
                "canonical": canonical,
            },
        }

        return self.append_event(proof_id, event)

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
