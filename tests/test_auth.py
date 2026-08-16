import asyncio
import base64
from datetime import datetime, timezone
import hashlib
import secrets
import time
from unittest.mock import AsyncMock, patch
import pytest
from fastapi.testclient import TestClient
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
from pymongo.errors import DuplicateKeyError, ConnectionFailure, OperationFailure

from app.main import app
from app.config import settings
from app.infrastructure.database import db_instance, _reconcile_index
from app.infrastructure.crypto_service import crypto_service
from app.infrastructure.repositories import MongoNonceManager, mask_to_hex
from app.infrastructure.rate_limiter import reset_rate_limiters, SlidingWindowRateLimiter
from app.infrastructure.verifiers import RSAPSSVerifier
from app.domain.exceptions import KeyValidationError
from app.domain.crypto_core import (
    build_canonical_payload,
    build_sync_canonical_payload,
    build_registration_challenge
)
from app.domain.anti_replay import (
    normalize_path,
    is_host_trusted
)


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
                if "$unset" in update:
                    for k in update["$unset"]:
                        doc.pop(k, None)
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
            if k == "$or":
                if not any(self._matches(doc, branch) for branch in v):
                    return False
            elif isinstance(v, dict):
                if "$exists" in v:
                    exists = k in doc and doc[k] is not None
                    if v["$exists"] != exists:
                        return False
                if "$in" in v:
                    val = doc.get(k)
                    if val is None:
                        if None not in v["$in"]:
                            return False
                    elif val not in v["$in"]:
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


def generate_test_keypair(key_size=2048, public_exponent=65537):
    private_key = rsa.generate_private_key(public_exponent=public_exponent, key_size=key_size)
    public_pem = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode("utf-8")
    return private_key, public_pem


def generate_proof_signature(private_key, client_nonce: str, algorithm: str = "RSA-PSS-SHA256", timestamp: int = None) -> str:
    timestamp = timestamp if timestamp is not None else int(time.time())
    der_bytes = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.DER, format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    challenge = build_registration_challenge(algorithm, der_bytes, timestamp, client_nonce)
    sig = private_key.sign(
        challenge.encode("utf-8"),
        padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=32),
        hashes.SHA256()
    )
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
    salt_length=32
):
    timestamp = timestamp or int(time.time())
    body_hash = hashlib.sha256(body_bytes).hexdigest()
    norm_path = normalize_path(path)
    payload = build_canonical_payload(host, method, norm_path, query, timestamp, counter, body_hash)

    signature = private_key.sign(
        payload.encode("utf-8"),
        padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=salt_length),
        hashes.SHA256()
    )

    return {
        "X-User-Id": user_id,
        "X-Timestamp": str(timestamp),
        "X-Nonce-Counter": str(counter),
        "X-Signature": base64.b64encode(signature).decode("utf-8"),
        "Content-Type": "application/json"
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
    payload = build_sync_canonical_payload(host, "GET", norm_path, query, timestamp, sync_nonce, body_hash)

    if corrupt_signature:
        sig_b64 = base64.b64encode(b"A" * 256).decode("utf-8")
    else:
        signature = private_key.sign(
            payload.encode("utf-8"),
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=32),
            hashes.SHA256()
        )
        sig_b64 = base64.b64encode(signature).decode("utf-8")

    return {
        "X-User-Id": user_id,
        "X-Timestamp": str(timestamp),
        "X-Sync-Nonce": sync_nonce,
        "X-Signature": sig_b64
    }


client = TestClient(app, raise_server_exceptions=False)


def test_path_normalization_encoded_dot_segments():
    """Verify normalize_path decodes unreserved characters first and collapses traversal segments."""
    assert normalize_path("/protected/%2e%2e/admin") == "/admin"
    assert normalize_path("/a/b/%2E%2E/c") == "/a/c"
    assert normalize_path("/foo/bar/./baz") == "/foo/bar/baz"
    assert normalize_path("/foo/%2e/bar") == "/foo/bar"
    assert normalize_path("///foo///bar//") == "/foo/bar/"


def test_rsa_key_size_strictly_enforces_2048_bits():
    """Verify keys of non-2048 bit size are rejected to guarantee constant-time side-channel protection."""
    verifier = RSAPSSVerifier()

    priv_3072, pem_3072 = generate_test_keypair(key_size=3072)
    with pytest.raises(KeyValidationError) as exc:
        verifier.parse_public_key(pem_3072)
    assert "must be exactly 2048 bits" in str(exc.value)

    priv_2048, pem_2048 = generate_test_keypair(key_size=2048)
    assert verifier.parse_public_key(pem_2048) is not None


def test_rsa_public_exponent_strictly_65537():
    """Verify keys with non-65537 exponents (e.g. e=3) are rejected to prevent complexity attacks."""
    verifier = RSAPSSVerifier()
    priv_e3, pem_e3 = generate_test_keypair(key_size=2048, public_exponent=3)
    with pytest.raises(KeyValidationError) as exc:
        verifier.parse_public_key(pem_e3)
    assert "must be strictly 65537" in str(exc.value)


def test_rate_limiter_throttles_excessive_registration_requests():
    """Verify rate limiter blocks bursts on /auth/register with HTTP 429 and Retry-After header."""
    private_key, public_pem = generate_test_keypair()
    now = int(time.time())

    last_resp = None
    for i in range(settings.auth_rate_limit_requests + 2):
        nonce = secrets.token_hex(16)
        proof = generate_proof_signature(private_key, client_nonce=nonce, timestamp=now)
        last_resp = client.post("/auth/register", json={
            "public_key": public_pem,
            "key_algorithm": "RSA-PSS-SHA256",
            "timestamp": now,
            "client_nonce": nonce,
            "proof_signature": proof
        })

    assert last_resp.status_code == 429
    assert last_resp.json()["detail"]["code"] == "rate_limit_exceeded"
    assert "Retry-After" in last_resp.headers


def test_database_connection_failure_returns_503():
    """Verify database exceptions return HTTP 503 Service Unavailable with Retry-After header."""
    with patch.object(db_instance.users_collection, "find_one", side_effect=ConnectionFailure("Connection refused")):
        resp = client.post(
            "/protected/do-something",
            json={"secret_message": "test"},
            headers={
                "X-User-Id": "nonexistent_user",
                "X-Timestamp": str(int(time.time())),
                "X-Nonce-Counter": "1",
                "X-Signature": base64.b64encode(b"A" * 256).decode("utf-8"),
                "Content-Type": "application/json"
            }
        )
        assert resp.status_code == 503
        assert resp.json()["detail"]["code"] == "service_unavailable"
        assert resp.headers.get("Retry-After") == "5"


def test_registration_nonce_retained_on_signature_failure_mitigates_dos():
    """Verify challenge nonces remain consumed after verification failure to prevent amplification DoS."""
    private_key, public_pem = generate_test_keypair()
    now = int(time.time())
    client_nonce = secrets.token_hex(16)
    bad_signature = base64.b64encode(b"A" * 256).decode("utf-8")

    bad_payload = {
        "public_key": public_pem,
        "key_algorithm": "RSA-PSS-SHA256",
        "timestamp": now,
        "client_nonce": client_nonce,
        "proof_signature": bad_signature
    }

    resp_bad = client.post("/auth/register", json=bad_payload)
    assert resp_bad.status_code == 401
    assert len(db_instance.used_registration_nonces_collection.store) == 1

    good_sig = generate_proof_signature(private_key, client_nonce=client_nonce, timestamp=now)
    good_payload = {
        "public_key": public_pem,
        "key_algorithm": "RSA-PSS-SHA256",
        "timestamp": now,
        "client_nonce": client_nonce,
        "proof_signature": good_sig
    }
    resp_replayed = client.post("/auth/register", json=good_payload)
    assert resp_replayed.status_code == 401
    assert resp_replayed.json()["detail"]["code"] == "registration_nonce_reused"


def test_sync_nonce_not_burned_on_invalid_signature():
    """Verify invalid signature does not consume sync nonce, preventing sync DoS."""
    private_key, public_pem = generate_test_keypair()
    now = int(time.time())
    client_nonce = secrets.token_hex(16)
    proof_sig = generate_proof_signature(private_key, client_nonce=client_nonce, timestamp=now)

    reg_resp = client.post("/auth/register", json={
        "public_key": public_pem,
        "key_algorithm": "RSA-PSS-SHA256",
        "timestamp": now,
        "client_nonce": client_nonce,
        "proof_signature": proof_sig
    })
    user_id = reg_resp.json()["user_id"]

    sync_nonce = secrets.token_hex(16)
    bad_headers = generate_sync_headers(
        private_key, user_id, "/api/v1/security/nonce", "", sync_nonce, corrupt_signature=True
    )

    resp_bad = client.get("/api/v1/security/nonce", headers=bad_headers)
    assert resp_bad.status_code == 401
    assert len(db_instance.used_sync_nonces_collection.store) == 0

    good_headers = generate_sync_headers(
        private_key, user_id, "/api/v1/security/nonce", "", sync_nonce, corrupt_signature=False
    )
    resp_good = client.get("/api/v1/security/nonce", headers=good_headers)
    assert resp_good.status_code == 200
    assert resp_good.json()["nonce_counter"] == 1


def test_user_enumeration_side_channel_eliminated():
    """Verify non-existent user and invalid signature return identical 401 code and message."""
    private_key, public_pem = generate_test_keypair()
    now = int(time.time())
    client_nonce = secrets.token_hex(16)
    proof_sig = generate_proof_signature(private_key, client_nonce=client_nonce, timestamp=now)

    reg_resp = client.post("/auth/register", json={
        "public_key": public_pem,
        "key_algorithm": "RSA-PSS-SHA256",
        "timestamp": now,
        "client_nonce": client_nonce,
        "proof_signature": proof_sig
    })
    real_user_id = reg_resp.json()["user_id"]

    # Probe 1: Non-existent user
    resp_fake = client.post(
        "/protected/do-something",
        json={"secret_message": "test"},
        headers={
            "X-User-Id": "fake_user_id_12345",
            "X-Timestamp": str(now),
            "X-Nonce-Counter": "1",
            "X-Signature": base64.b64encode(b"A" * 256).decode("utf-8"),
            "Content-Type": "application/json"
        }
    )

    # Probe 2: Real user with invalid signature
    resp_real_bad_sig = client.post(
        "/protected/do-something",
        json={"secret_message": "test"},
        headers={
            "X-User-Id": real_user_id,
            "X-Timestamp": str(now),
            "X-Nonce-Counter": "1",
            "X-Signature": base64.b64encode(b"A" * 256).decode("utf-8"),
            "Content-Type": "application/json"
        }
    )

    assert resp_fake.status_code == 401
    assert resp_real_bad_sig.status_code == 401
    assert resp_fake.json() == resp_real_bad_sig.json()
    assert resp_fake.json()["detail"]["code"] == "signature_verification_error"
    assert resp_fake.json()["detail"]["message"] == "Invalid authentication credentials"


def test_legacy_integer_bitmask_cas_matches_first_attempt():
    """Verify CAS filter matches legacy integer nonce_mask on the first attempt without extra roundtrips."""
    coll = MockAsyncCollection()
    coll.store.append({
        "user_id": "usr_legacy",
        "public_key": "dummy",
        "key_algorithm": "RSA-PSS-SHA256",
        "nonce_base": 5,
        "nonce_mask": 1,
        "created_at": datetime.now(timezone.utc)
    })
    manager = MongoNonceManager(users_collection=coll)
    loop = asyncio.new_event_loop()
    try:
        success, next_expected, err = loop.run_until_complete(manager.validate_and_advance("usr_legacy", 6))
        assert success is True
        assert next_expected == 7
        assert err == ""
        assert coll.store[0]["nonce_base"] == 6
        assert coll.store[0]["nonce_mask"] == mask_to_hex(3)
    finally:
        loop.close()


def test_request_validation_error_returns_422_envelope():
    """Verify Pydantic validation errors return HTTP 422 in the unified error envelope."""
    resp = client.post("/auth/register", json={"invalid_field": "test"})
    assert resp.status_code == 422
    assert resp.json()["detail"]["code"] == "validation_error"
    assert "errors" in resp.json()["detail"]["meta"]


def test_http_exception_returns_404_envelope():
    """Verify unmapped routes return HTTP 404 in the unified error envelope instead of 500."""
    resp = client.get("/non-existent-route")
    assert resp.status_code == 404
    assert resp.json()["detail"]["code"] == "http_404"


def test_host_trust_with_non_standard_port():
    """Verify host trust validator strictly matches host with non-standard ports."""
    assert is_host_trusted("localhost", ["localhost"]) is True
    assert is_host_trusted("localhost:80", ["localhost"]) is True
    assert is_host_trusted("localhost:9999", ["localhost"]) is False
    assert is_host_trusted("localhost:9999", ["localhost:9999"]) is True


def test_rate_limiter_memory_cleanup_and_thread_safety():
    """Verify sliding window rate limiter cleans up empty keys and functions under concurrent access."""
    limiter = SlidingWindowRateLimiter(limit=5, window_seconds=1)
    limiter.is_allowed("test_key")
    assert "test_key" in limiter._history

    time.sleep(1.05)
    limiter.is_allowed("test_key")
    assert len(limiter._history["test_key"]) == 1


def test_cors_headers_present_on_rate_limit_and_error_responses():
    """Verify outermost CORS middleware handles preflight and attaches CORS headers to early error responses."""
    # 1. Preflight OPTIONS request check
    preflight_resp = client.options(
        "/protected/do-something",
        headers={
            "Origin": "http://localhost:3000",
            "Access-Control-Request-Method": "POST",
            "Access-Control-Request-Headers": "X-User-Id, Content-Type"
        }
    )
    assert preflight_resp.status_code == 200
    assert preflight_resp.headers.get("access-control-allow-origin") == "http://localhost:3000"

    # 2. Actual request with Origin triggering early error (HTTP 400 Invalid Host)
    error_resp = client.post(
        "/protected/do-something",
        headers={
            "Origin": "http://localhost:3000",
            "Host": "untrusted-attacker.com",
            "Content-Type": "application/json"
        }
    )
    assert error_resp.status_code == 400
    assert error_resp.headers.get("access-control-allow-origin") == "http://localhost:3000"
    expose_headers = error_resp.headers.get("access-control-expose-headers", "")
    assert "Retry-After" in expose_headers or "retry-after" in expose_headers.lower()


def test_concurrency_contention_returns_503():
    """Verify CAS exhaustion returns 503 Service Unavailable with Retry-After header."""
    private_key, public_pem = generate_test_keypair()
    now = int(time.time())
    client_nonce = secrets.token_hex(16)
    proof_sig = generate_proof_signature(private_key, client_nonce=client_nonce, timestamp=now)

    reg_resp = client.post("/auth/register", json={
        "public_key": public_pem,
        "key_algorithm": "RSA-PSS-SHA256",
        "timestamp": now,
        "client_nonce": client_nonce,
        "proof_signature": proof_sig
    })
    user_id = reg_resp.json()["user_id"]

    body = b'{"secret_message":"contention_test"}'
    headers = generate_headers(
        private_key=private_key,
        user_id=user_id,
        method="POST",
        path="/protected/do-something",
        query="",
        body_bytes=body,
        counter=1
    )

    with patch.object(
        MongoNonceManager,
        "validate_and_advance",
        new_callable=AsyncMock,
        return_value=(False, 2, "concurrency_contention")
    ):
        resp = client.post("/protected/do-something", content=body, headers=headers)
        assert resp.status_code == 503
        assert resp.json()["detail"]["code"] == "concurrency_contention"
        assert resp.headers.get("Retry-After") == "1"


def test_index_reconciliation_failure_raises_exception():
    """Verify database index configuration failure is not swallowed silently."""
    coll = MockAsyncCollection("users")
    with patch.object(coll, "create_index", side_effect=OperationFailure("Index build failed")):
        loop = asyncio.new_event_loop()
        try:
            with pytest.raises(OperationFailure):
                loop.run_until_complete(_reconcile_index(coll, "user_id", unique=True))
        finally:
            loop.close()


def test_protected_route_successful_flow():
    """Verify end-to-end registration and authenticated request to protected route."""
    private_key, public_pem = generate_test_keypair()
    now = int(time.time())
    client_nonce = secrets.token_hex(16)
    proof_sig = generate_proof_signature(private_key, client_nonce=client_nonce, timestamp=now)

    reg_resp = client.post("/auth/register", json={
        "public_key": public_pem,
        "key_algorithm": "RSA-PSS-SHA256",
        "timestamp": now,
        "client_nonce": client_nonce,
        "proof_signature": proof_sig
    })
    assert reg_resp.status_code == 201
    user_id = reg_resp.json()["user_id"]

    body = b'{"secret_message":"classified"}'
    headers = generate_headers(
        private_key=private_key,
        user_id=user_id,
        method="POST",
        path="/protected/do-something",
        query="",
        body_bytes=body,
        counter=1
    )
    resp = client.post("/protected/do-something", content=body, headers=headers)
    assert resp.status_code == 200
    assert resp.json()["your_data_was"] == "classified"