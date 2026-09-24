import base64
import hashlib
import secrets
import time
from unittest.mock import AsyncMock, patch
import pytest
from fastapi.testclient import TestClient
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives import serialization
from pymongo.errors import DuplicateKeyError

from app.main import app
from app.infrastructure.database import db_instance
from app.infrastructure.crypto_service import crypto_service
from app.infrastructure.rate_limiter import reset_rate_limiters, resolve_client_ip
from app.infrastructure.verifiers import Ed25519Verifier, MLDSAVerifier
from app.domain.exceptions import KeyValidationError, UnsupportedAlgorithmError
from app.domain.crypto_core import (
    build_canonical_payload,
    build_sync_canonical_payload,
    build_registration_challenge
)
from app.domain.anti_replay import normalize_path, normalize_content_type, is_host_trusted


class MockAsyncCursor:
    def __init__(self, items):
        self.items = items

    async def to_list(self, length=100):
        return list(self.items)


class MockAsyncCollection:
    def __init__(self, name="mock_coll"):
        self.name = name
        self.store = []
        self.indexes = []

    def list_indexes(self):
        return MockAsyncCursor(self.indexes)

    async def create_index(self, keys, name=None, **kwargs):
        target_keys = dict(keys if isinstance(keys, list) else [(keys, 1)] if isinstance(keys, str) else [keys])
        idx_name = name or "_".join(f"{k}_{v}" for k, v in target_keys.items())
        idx_def = {"name": idx_name, "key": target_keys}
        idx_def.update(kwargs)
        self.indexes.append(idx_def)
        return idx_name

    async def drop_index(self, index_name):
        self.indexes = [idx for idx in self.indexes if idx["name"] != index_name]

    async def find_one(self, query, projection=None, *args, **kwargs):
        for doc in self.store:
            if self._matches(doc, query):
                if projection:
                    return {k: doc.get(k) for k in projection if k in doc}
                return dict(doc)
        return None

    async def find_one_and_update(self, query, update, *args, **kwargs):
        for doc in self.store:
            if self._matches(doc, query):
                if "$set" in update:
                    for k, val in update["$set"].items():
                        doc[k] = val
                return dict(doc)
        return None

    async def insert_one(self, document):
        if "sync_nonce" in document:
            for doc in self.store:
                if doc.get("user_id") == document.get("user_id") and doc.get("sync_nonce") == document.get("sync_nonce"):
                    raise DuplicateKeyError("E11000 duplicate sync nonce")
        elif "client_nonce" in document:
            for doc in self.store:
                if doc.get("user_id") == document.get("user_id") and doc.get("client_nonce") == document.get("client_nonce"):
                    raise DuplicateKeyError("E11000 duplicate registration nonce")
        else:
            for doc in self.store:
                if doc.get("user_id") == document.get("user_id"):
                    raise DuplicateKeyError("E11000 duplicate user key")

        self.store.append(dict(document))

        class InsertResult:
            inserted_id = "mock_id"

        return InsertResult()

    async def delete_one(self, query):
        for idx, doc in enumerate(self.store):
            if self._matches(doc, query):
                del self.store[idx]
                break

    def _matches(self, doc, query):
        for k, v in query.items():
            if isinstance(v, dict):
                val = doc.get(k, 0)
                if "$lt" in v and not (val < v["$lt"]):
                    return False
                if "$gte" in v and not (val >= v["$gte"]):
                    return False
            elif doc.get(k) != v:
                return False
        return True


@pytest.fixture(autouse=True)
def mock_db():
    crypto_service.key_cache._cache.clear()
    reset_rate_limiters()
    with patch("app.main.connect_to_mongo", new_callable=AsyncMock), \
         patch("app.main.close_mongo_connection", new_callable=AsyncMock):
        db_instance.users_collection = MockAsyncCollection("users")
        db_instance.used_sync_nonces_collection = MockAsyncCollection("used_sync_nonces")
        db_instance.used_registration_nonces_collection = MockAsyncCollection("used_registration_nonces")
        crypto_service.start()
        yield
        crypto_service.shutdown()
        reset_rate_limiters()


def generate_ed25519_keypair():
    priv = ed25519.Ed25519PrivateKey.generate()
    pem = priv.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode("utf-8")
    return priv, pem


def generate_proof_signature(private_key, client_nonce: str, algorithm: str = "Ed25519", timestamp: int = None) -> str:
    timestamp = timestamp if timestamp is not None else int(time.time())
    raw_pub = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw
    )
    challenge = build_registration_challenge(algorithm, raw_pub, timestamp, client_nonce)
    sig = private_key.sign(challenge.encode("utf-8"))
    return base64.b64encode(sig).decode("utf-8")


def generate_headers(
    private_key,
    user_id,
    method,
    path,
    query,
    body_bytes,
    host="testserver",
    timestamp=None,
    counter=1,
    content_type="application/json"
):
    timestamp = timestamp or int(time.time())
    body_hash = hashlib.sha256(body_bytes).hexdigest()
    norm_path = normalize_path(path)
    payload = build_canonical_payload(host, method, norm_path, query, timestamp, counter, body_hash, content_type)
    sig = private_key.sign(payload.encode("utf-8"))

    return {
        "X-User-Id": user_id,
        "X-Timestamp": str(timestamp),
        "X-Nonce-Counter": str(counter),
        "X-Signature": base64.b64encode(sig).decode("utf-8"),
        "Content-Type": content_type
    }


def generate_sync_headers(
    private_key,
    user_id,
    path,
    query,
    sync_nonce,
    host="testserver",
    timestamp=None,
    corrupt_signature=False
):
    timestamp = timestamp or int(time.time())
    body_hash = hashlib.sha256(b"").hexdigest()
    norm_path = normalize_path(path)
    payload = build_sync_canonical_payload(host, "GET", norm_path, query, timestamp, sync_nonce, body_hash, "")

    if corrupt_signature:
        sig_b64 = base64.b64encode(b"A" * 64).decode("utf-8")
    else:
        sig = private_key.sign(payload.encode("utf-8"))
        sig_b64 = base64.b64encode(sig).decode("utf-8")

    return {
        "X-User-Id": user_id,
        "X-Timestamp": str(timestamp),
        "X-Sync-Nonce": sync_nonce,
        "X-Signature": sig_b64
    }


client = TestClient(app, raise_server_exceptions=False)


def test_ip_resolution_right_to_left_traversal():
    trusted = ["127.0.0.1", "10.0.0.1"]
    headers = [(b"x-forwarded-for", b"203.0.113.195, 198.51.100.1, 10.0.0.1")]
    client_ip = resolve_client_ip(headers, "127.0.0.1", True, trusted)
    assert client_ip == "198.51.100.1"


def test_content_type_normalization():
    assert normalize_content_type("application/json; charset=utf-8") == "application/json;charset=utf-8"
    assert normalize_content_type("application/json ; b=2 ; a=1") == "application/json;a=1;b=2"
    assert normalize_content_type("") == ""


def test_host_header_trust_with_and_without_ports():
    trusted = ["localhost", "testserver"]
    assert is_host_trusted("localhost:8000", trusted) is True
    assert is_host_trusted("localhost", trusted) is True
    assert is_host_trusted("evil.com", trusted) is False


def test_proof_of_possession_verified_before_uniqueness():
    _, pem = generate_ed25519_keypair()
    now = int(time.time())
    client_nonce = secrets.token_hex(16)
    bad_sig = base64.b64encode(b"Z" * 64).decode("utf-8")

    resp = client.post("/auth/register", json={
        "public_key": pem,
        "key_algorithm": "Ed25519",
        "timestamp": now,
        "client_nonce": client_nonce,
        "proof_signature": bad_sig
    })
    # Must fail signature verification (401) without querying user existence
    assert resp.status_code == 401
    assert resp.json()["detail"]["code"] == "signature_verification_error"


def test_sliding_window_out_of_order_success_and_replay_rejection():
    priv, pem = generate_ed25519_keypair()
    now = int(time.time())
    client_nonce = secrets.token_hex(16)
    proof_sig = generate_proof_signature(priv, client_nonce=client_nonce, timestamp=now)

    reg_resp = client.post("/auth/register", json={
        "public_key": pem,
        "key_algorithm": "Ed25519",
        "timestamp": now,
        "client_nonce": client_nonce,
        "proof_signature": proof_sig
    })
    assert reg_resp.status_code == 201
    user_id = reg_resp.json()["user_id"]

    body = b'{"secret_message":"test"}'

    # Step 1: Counter 3 arrives first (N_max becomes 3) -> 200 OK
    headers_3 = generate_headers(priv, user_id, "POST", "/protected/do-something", "", body, counter=3)
    resp_3 = client.post("/protected/do-something", content=body, headers=headers_3)
    assert resp_3.status_code == 200

    # Step 2: Out-of-order Counter 1 arrives (falls within sliding window) -> 200 OK
    headers_1 = generate_headers(priv, user_id, "POST", "/protected/do-something", "", body, counter=1)
    resp_1 = client.post("/protected/do-something", content=body, headers=headers_1)
    assert resp_1.status_code == 200

    # Step 3: Counter 1 replayed -> 409 Conflict (Replay detected in window)
    resp_replay = client.post("/protected/do-something", content=body, headers=headers_1)
    assert resp_replay.status_code == 409
    assert resp_replay.json()["detail"]["code"] == "nonce_conflict"


def test_deferred_counter_advancement_on_handler_error():
    priv, pem = generate_ed25519_keypair()
    now = int(time.time())
    client_nonce = secrets.token_hex(16)
    proof_sig = generate_proof_signature(priv, client_nonce=client_nonce, timestamp=now)

    reg_resp = client.post("/auth/register", json={
        "public_key": pem,
        "key_algorithm": "Ed25519",
        "timestamp": now,
        "client_nonce": client_nonce,
        "proof_signature": proof_sig
    })
    user_id = reg_resp.json()["user_id"]

    # Invalid payload body triggers validation error (422) in route handler
    bad_body = b'{"invalid_field":123}'
    headers_1 = generate_headers(priv, user_id, "POST", "/protected/do-something", "", bad_body, counter=1)
    resp_bad = client.post("/protected/do-something", content=bad_body, headers=headers_1)
    assert resp_bad.status_code == 422

    # Retrying with the SAME counter and valid body must succeed because counter was not burned
    good_body = b'{"secret_message":"retry_succeeded"}'
    headers_retry = generate_headers(priv, user_id, "POST", "/protected/do-something", "", good_body, counter=1)
    resp_retry = client.post("/protected/do-something", content=good_body, headers=headers_retry)
    assert resp_retry.status_code == 200


def test_ed25519_verifier_key_formats():
    verifier = Ed25519Verifier()
    priv, pem = generate_ed25519_keypair()
    raw_pub = priv.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw
    )
    # PEM format
    key_pem = verifier.parse_public_key(pem)
    assert verifier.get_canonical_key_bytes(key_pem) == raw_pub

    # Hex format
    key_hex = verifier.parse_public_key(raw_pub.hex())
    assert verifier.get_canonical_key_bytes(key_hex) == raw_pub

    # Base64 format with whitespace
    b64_str = base64.b64encode(raw_pub).decode("utf-8")
    key_b64 = verifier.parse_public_key(f"  {b64_str}\n  ")
    assert verifier.get_canonical_key_bytes(key_b64) == raw_pub

    # Invalid length
    with pytest.raises(KeyValidationError):
        verifier.parse_public_key(base64.b64encode(b"short").decode("utf-8"))