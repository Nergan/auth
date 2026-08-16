import base64
import hashlib
import json
import secrets
import threading
import time
from urllib.parse import urlparse
import httpx
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
from app.domain.crypto_core import (
    build_canonical_payload,
    build_sync_canonical_payload,
    build_registration_challenge
)
from app.domain.anti_replay import normalize_host, normalize_path

BASE_URL = "http://localhost:8000"


class AuthClient:
    def __init__(self, base_url: str = BASE_URL):
        self.base_url = base_url
        self.parsed_url = urlparse(base_url)
        self.host = normalize_host(self.parsed_url.netloc or "localhost:8000")
        self.private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        self.public_pem = self.private_key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode("utf-8")
        self.der_bytes = self.private_key.public_key().public_bytes(
            encoding=serialization.Encoding.DER, format=serialization.PublicFormat.SubjectPublicKeyInfo
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
        challenge = build_registration_challenge("RSA-PSS-SHA256", self.der_bytes, timestamp, client_nonce)
        signature = self.private_key.sign(
            challenge.encode("utf-8"),
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=32),
            hashes.SHA256()
        )
        return base64.b64encode(signature).decode("utf-8")

    def sign_request(self, method: str, path: str, query: str, body_bytes: bytes, counter: int) -> dict:
        timestamp = int(time.time())
        body_hash = hashlib.sha256(body_bytes).hexdigest()
        norm_path = normalize_path(path)
        payload = build_canonical_payload(self.host, method, norm_path, query, timestamp, counter, body_hash)

        signature = self.private_key.sign(
            payload.encode("utf-8"),
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=32),
            hashes.SHA256()
        )

        return {
            "X-User-Id": self.user_id,
            "X-Timestamp": str(timestamp),
            "X-Nonce-Counter": str(counter),
            "X-Signature": base64.b64encode(signature).decode("utf-8")
        }

    def sign_sync_request(self, path: str, query: str, sync_nonce: str) -> dict:
        timestamp = int(time.time())
        body_hash = hashlib.sha256(b"").hexdigest()
        norm_path = normalize_path(path)
        payload = build_sync_canonical_payload(self.host, "GET", norm_path, query, timestamp, sync_nonce, body_hash)

        signature = self.private_key.sign(
            payload.encode("utf-8"),
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=32),
            hashes.SHA256()
        )

        return {
            "X-User-Id": self.user_id,
            "X-Timestamp": str(timestamp),
            "X-Sync-Nonce": sync_nonce,
            "X-Signature": base64.b64encode(signature).decode("utf-8")
        }

    def register(self):
        print("1. Registering Identity with Timestamped Proof of Possession...")
        reg_timestamp = int(time.time())
        client_nonce = secrets.token_hex(16)
        proof_signature = self.generate_proof_of_possession(reg_timestamp, client_nonce)
        reg_resp = httpx.post(f"{self.base_url}/auth/register", json={
            "public_key": self.public_pem,
            "key_algorithm": "RSA-PSS-SHA256",
            "timestamp": reg_timestamp,
            "client_nonce": client_nonce,
            "proof_signature": proof_signature
        })
        self.user_id = reg_resp.json().get("user_id")
        print(f"Registered User ID: {self.user_id}")

    def sync_nonce(self):
        path = "/api/v1/security/nonce"
        sync_nonce = secrets.token_hex(16)
        headers = self.sign_sync_request(path, "", sync_nonce)
        resp = httpx.get(f"{self.base_url}{path}", headers=headers)
        if resp.status_code == 200:
            expected = resp.json().get("nonce_counter", 1)
            self.set_counter(expected)
            print(f"Synced Counter from Server: {expected}")

    def call_protected(self):
        counter = self.allocate_counter()
        print(f"\n2. Calling Protected Route (Allocated Counter: {counter})...")
        path = "/protected/do-something"
        body_bytes = json.dumps({"secret_message": "Attack at dawn"}).encode("utf-8")

        headers = self.sign_request("POST", path, "", body_bytes, counter)
        headers["Content-Type"] = "application/json"

        resp = httpx.post(f"{self.base_url}{path}", content=body_bytes, headers=headers)

        if resp.status_code == 409:
            error_data = resp.json()
            expected = error_data.get("detail", {}).get("expected")
            if expected is not None:
                print(f"Received 409 Conflict. Resyncing counter to {expected}...")
                self.set_counter(expected)
                retry_counter = self.allocate_counter()
                headers = self.sign_request("POST", path, "", body_bytes, retry_counter)
                headers["Content-Type"] = "application/json"
                resp = httpx.post(f"{self.base_url}{path}", content=body_bytes, headers=headers)

        print("Protected Response:", resp.json() if resp.status_code == 200 else resp.text)


if __name__ == "__main__":
    client = AuthClient()
    client.register()
    client.call_protected()
    client.call_protected()
    client.sync_nonce()