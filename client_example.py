import base64
import hashlib
import json
import secrets
import threading
import time
from urllib.parse import urlparse
import httpx
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives import serialization

from app.domain.crypto_core import (
    build_canonical_payload,
    build_sync_canonical_payload,
    build_registration_challenge
)
from app.domain.anti_replay import normalize_host, normalize_path

BASE_URL = "http://localhost:8000"


class QuantumResistantAuthClient:
    """Reference Client demonstrating registration, signed requests, and auto-sync on 409 Conflict."""

    def __init__(self, base_url: str = BASE_URL):
        self.base_url = base_url
        self.parsed_url = urlparse(base_url)
        self.host = normalize_host(self.parsed_url.netloc or "localhost:8000")
        
        self.private_key = ed25519.Ed25519PrivateKey.generate()
        self.public_key = self.private_key.public_key()
        self.public_pem = self.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode("utf-8")
        self.raw_public_bytes = self.public_key.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        )
        
        self.user_id = None
        self._counter = 1
        self._lock = threading.Lock()

    def allocate_counter(self) -> int:
        with self._lock:
            counter = self._counter
            self._counter += 1
            return counter

    def set_counter(self, new_counter: int) -> None:
        with self._lock:
            self._counter = new_counter

    def generate_proof_of_possession(self, timestamp: int, client_nonce: str) -> str:
        challenge = build_registration_challenge(
            "Ed25519", self.raw_public_bytes, timestamp, client_nonce
        )
        sig = self.private_key.sign(challenge.encode("utf-8"))
        return base64.b64encode(sig).decode("utf-8")

    def sign_request(
        self, method: str, path: str, query: str, body_bytes: bytes, counter: int, content_type: str = "application/json"
    ) -> dict:
        timestamp = int(time.time())
        body_hash = hashlib.sha256(body_bytes).hexdigest()
        norm_path = normalize_path(path)
        payload = build_canonical_payload(
            self.host, method, norm_path, query, timestamp, counter, body_hash, content_type
        )
        signature = self.private_key.sign(payload.encode("utf-8"))

        return {
            "X-User-Id": self.user_id,
            "X-Timestamp": str(timestamp),
            "X-Nonce-Counter": str(counter),
            "X-Signature": base64.b64encode(signature).decode("utf-8"),
            "Content-Type": content_type
        }

    def sign_sync_request(self, path: str, query: str, sync_nonce: str, content_type: str = "") -> dict:
        timestamp = int(time.time())
        body_hash = hashlib.sha256(b"").hexdigest()
        norm_path = normalize_path(path)
        payload = build_sync_canonical_payload(
            self.host, "GET", norm_path, query, timestamp, sync_nonce, body_hash, content_type
        )
        signature = self.private_key.sign(payload.encode("utf-8"))

        return {
            "X-User-Id": self.user_id,
            "X-Timestamp": str(timestamp),
            "X-Sync-Nonce": sync_nonce,
            "X-Signature": base64.b64encode(signature).decode("utf-8")
        }

    def register(self):
        print("1. [REGISTRATION] Registering Identity with Timestamped Proof of Possession...")
        reg_timestamp = int(time.time())
        client_nonce = secrets.token_hex(16)
        proof_signature = self.generate_proof_of_possession(reg_timestamp, client_nonce)
        
        reg_resp = httpx.post(f"{self.base_url}/auth/register", json={
            "public_key": self.public_pem,
            "key_algorithm": "Ed25519",
            "timestamp": reg_timestamp,
            "client_nonce": client_nonce,
            "proof_signature": proof_signature
        })
        reg_resp.raise_for_status()
        self.user_id = reg_resp.json().get("user_id")
        print(f"   Registered User ID: {self.user_id}")

    def sync_nonce(self) -> int:
        print("   [SYNCHRONIZATION] Initiating out-of-band nonce recovery...")
        path = "/api/v1/security/nonce"
        sync_nonce = secrets.token_hex(16)
        headers = self.sign_sync_request(path, "", sync_nonce)
        resp = httpx.get(f"{self.base_url}{path}", headers=headers)
        resp.raise_for_status()
        next_expected = resp.json().get("next_expected_nonce", 1)
        self.set_counter(next_expected)
        print(f"   Synced Server Nonce: Next Expected = {next_expected}")
        return next_expected

    def call_protected(self, message: str = "Quantum Resistance Verified"):
        path = "/protected/do-something"
        body_bytes = json.dumps({"secret_message": message}).encode("utf-8")

        counter = self.allocate_counter()
        print(f"\n2. [REQUEST] Calling Protected Route with Nonce: {counter}...")
        headers = self.sign_request("POST", path, "", body_bytes, counter)
        resp = httpx.post(f"{self.base_url}{path}", content=body_bytes, headers=headers)

        if resp.status_code == 409:
            print("   [409 CONFLICT] Stale/Replayed Nonce detected! Triggering background sync...")
            self.sync_nonce()
            retry_counter = self.allocate_counter()
            print(f"   [RETRY] Retrying request with fresh Nonce: {retry_counter}...")
            headers = self.sign_request("POST", path, "", body_bytes, retry_counter)
            resp = httpx.post(f"{self.base_url}{path}", content=body_bytes, headers=headers)

        print("   Response Status:", resp.status_code)
        print("   Response Body:", resp.json())


if __name__ == "__main__":
    client = QuantumResistantAuthClient()
    client.register()
    client.call_protected("Initial Transaction")
    client.call_protected("Subsequent Monotonic Transaction")
    
    print("\n3. [REPLAY ATTACK SIMULATION] Attempting to replay old counter (Counter: 1)...")
    path = "/protected/do-something"
    body_bytes = json.dumps({"secret_message": "Replay Attempt"}).encode("utf-8")
    replayed_headers = client.sign_request("POST", path, "", body_bytes, counter=1)
    replay_resp = httpx.post(f"{BASE_URL}{path}", content=body_bytes, headers=replayed_headers)
    print("   Replay Server Response (Expected 409 Conflict):", replay_resp.status_code, replay_resp.json())