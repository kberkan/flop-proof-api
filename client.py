from typing import Any

import httpx

import base64
import hashlib
import json

import base58
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


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
    def __init__(self, base_url: str, timeout: float = 10.0):
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout

    def _request(
        self,
        method: str,
        path: str,
        **kwargs: Any,
    ) -> dict[str, Any]:
        try:
            response = httpx.request(
                method,
                f"{self.base_url}{path}",
                timeout=self.timeout,
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
        canonical = f"{room}|{nonce}|{text}"
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
        canonical = f"{proof_id}|{event_type}|{payload_hash}"

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

    def verify_proof(
        self,
        proof_id: str,
    ) -> dict[str, Any]:
        return self._request(
            "GET",
            f"/proofs/{proof_id}/verify",
        )
