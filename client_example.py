import httpx
import time
import secrets
import base64
import hashlib
import json
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization

private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
public_pem = private_key.public_key().public_bytes(
    encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo
).decode('utf-8')

BASE_URL = "http://localhost:8000"

def sign_request(method: str, path: str, query: str, body_bytes: bytes) -> dict:
    timestamp = int(time.time())
    nonce = secrets.token_hex(16)
    
    body_hash = hashlib.sha256(body_bytes).hexdigest()
    
    # Canonical payload
    payload = f"{method}\n{path}\n{query}\n{timestamp}\n{nonce}\n{body_hash}"
    
    # RSA-PSS Signature
    signature = private_key.sign(
        payload.encode('utf-8'),
        padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
        hashes.SHA256()
    )
    
    return {
        "X-Timestamp": str(timestamp),
        "X-Nonce": nonce,
        "X-Signature": base64.b64encode(signature).decode('utf-8')
    }

def run_test():
    print("1. Registering...")
    reg_resp = httpx.post(f"{BASE_URL}/auth/register", json={"public_key": public_pem})
    user_id = reg_resp.json().get("user_id")

    print("\n2. Calling Protected Route...")
    path = "/protected/do-something"
    body_dict = {"secret_message": "Attack at dawn"}
    
    # 1. Serialize exactly how we want it
    body_bytes = json.dumps(body_dict).encode('utf-8')
    
    # 2. Sign those exact bytes
    headers = sign_request("POST", path, "", body_bytes)
    headers["X-User-Id"] = user_id
    headers["Content-Type"] = "application/json" # Required by FastAPI
    
    # 3. Send those exact bytes over the wire
    protected_resp = httpx.post(f"{BASE_URL}{path}", content=body_bytes, headers=headers)
    print("Protected Response:", protected_resp.json())

if __name__ == "__main__":
    run_test()