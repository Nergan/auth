import pytest
from fastapi.testclient import TestClient
from unittest.mock import AsyncMock, patch
import time
import json
import base64
import secrets
import hashlib
from cryptography.hazmat.primitives.asymmetric import rsa, ec, padding
from cryptography.hazmat.primitives import hashes, serialization
from pymongo.errors import DuplicateKeyError

from app.main import app
from app.database import db_instance

# ==========================================
# 1. DATABASE MOCKING
# ==========================================
class MockAsyncCollection:
    def __init__(self):
        self.store =[]

    async def find_one(self, query, *args, **kwargs):
        for doc in self.store:
            if all(doc.get(k) == v for k, v in query.items()):
                return doc
        return None

    async def insert_one(self, document):
        # Simulate composite unique index (user_id, nonce)
        if "nonce" in document and "user_id" in document:
            for doc in self.store:
                if doc.get("nonce") == document["nonce"] and doc.get("user_id") == document["user_id"]:
                    raise DuplicateKeyError("E11000 duplicate key error")
        self.store.append(document)
        class InsertOneResult:
            inserted_id = "mock_id"
        return InsertOneResult()

    async def create_index(self, *args, **kwargs): pass

@pytest.fixture(autouse=True)
def mock_db():
    with patch("app.main.connect_to_mongo", new_callable=AsyncMock), \
         patch("app.main.close_mongo_connection", new_callable=AsyncMock):
        db_instance.users_collection = MockAsyncCollection()
        db_instance.used_nonces_collection = MockAsyncCollection()
        yield

# ==========================================
# 2. CRYPTOGRAPHY TEST HELPERS
# ==========================================
def generate_test_keypair():
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_pem = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode('utf-8')
    return private_key, public_pem

def generate_headers(private_key, user_id, method, path, query, body_bytes, timestamp=None, nonce=None):
    timestamp = timestamp or int(time.time())
    nonce = nonce or secrets.token_hex(16)
    
    body_hash = hashlib.sha256(body_bytes).hexdigest()
    payload = f"{method}\n{path}\n{query}\n{timestamp}\n{nonce}\n{body_hash}"
    
    signature = private_key.sign(
        payload.encode('utf-8'),
        padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
        hashes.SHA256()
    )
    
    return {
        "X-User-Id": user_id,
        "X-Timestamp": str(timestamp),
        "X-Nonce": nonce,
        "X-Signature": base64.b64encode(signature).decode('utf-8'),
        "Content-Type": "application/json"   # <--- ADD THIS LINE
    }

# ==========================================
# 3. TESTS
# ==========================================
client = TestClient(app)

def test_register_success():
    _, public_pem = generate_test_keypair()
    resp = client.post("/auth/register", json={"public_key": public_pem})
    assert resp.status_code == 201

def test_register_ec_key_rejected():
    ec_priv = ec.generate_private_key(ec.SECP256R1())
    ec_pem = ec_priv.public_key().public_bytes(
        encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode('utf-8')
    resp = client.post("/auth/register", json={"public_key": ec_pem})
    assert resp.status_code == 400
    assert "Only RSA" in resp.json()["detail"]

def test_protected_route_success():
    private_key, public_pem = generate_test_keypair()
    user_id = client.post("/auth/register", json={"public_key": public_pem}).json()["user_id"]
    
    body = {"secret_message": "Hello"}
    body_bytes = json.dumps(body).encode('utf-8')
    headers = generate_headers(private_key, user_id, "POST", "/protected/do-something", "", body_bytes)
    
    # FIX: Use content=body_bytes instead of json=body
    resp = client.post("/protected/do-something", content=body_bytes, headers=headers)
    assert resp.status_code == 200

def test_replay_attack_atomic_block():
    private_key, public_pem = generate_test_keypair()
    user_id = client.post("/auth/register", json={"public_key": public_pem}).json()["user_id"]
    
    body = {"secret_message": "Hello"}
    body_bytes = json.dumps(body).encode('utf-8')
    headers = generate_headers(private_key, user_id, "POST", "/protected/do-something", "", body_bytes)
    
    # FIX: Use content=body_bytes instead of json=body
    assert client.post("/protected/do-something", content=body_bytes, headers=headers).status_code == 200
    
    resp2 = client.post("/protected/do-something", content=body_bytes, headers=headers)
    assert resp2.status_code == 401
    assert resp2.json()["detail"] == "Invalid authentication credentials"

def test_invalid_base64_signature():
    private_key, public_pem = generate_test_keypair()
    user_id = client.post("/auth/register", json={"public_key": public_pem}).json()["user_id"]
    
    headers = generate_headers(private_key, user_id, "POST", "/protected/do-something", "", b'{}')
    headers["X-Signature"] = "NOT_VALID_BASE64_!@#"
    
    resp = client.post("/protected/do-something", json={}, headers=headers)
    assert resp.status_code == 401