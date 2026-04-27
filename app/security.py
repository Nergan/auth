import hashlib
import base64
import time
import logging
from datetime import datetime, timezone
from fastapi import Request, HTTPException, Header, Depends
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.serialization import load_pem_public_key
from cryptography.exceptions import InvalidSignature
from pymongo.errors import DuplicateKeyError
from app.database import db_instance

TIMESTAMP_TOLERANCE = 120 
AUTH_ERROR = HTTPException(status_code=401, detail="Invalid authentication credentials")

def get_canonical_key_bytes(public_key_pem: str) -> bytes:
    """Parses the PEM and returns canonical DER format bytes. Enforces RSA >= 2048."""
    key = load_pem_public_key(public_key_pem.encode('utf-8'))
    if not isinstance(key, rsa.RSAPublicKey):
        raise ValueError("Only RSA public keys are supported")
    if key.key_size < 2048:
        raise ValueError("RSA key size must be >= 2048 bits")
    
    return key.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

def generate_user_id(public_key_pem: str) -> str:
    """Hashes the strict DER bytes, not the raw fragile PEM string."""
    der_bytes = get_canonical_key_bytes(public_key_pem)
    return hashlib.sha256(der_bytes).hexdigest()

async def verify_request_signature(
    request: Request,
    x_user_id: str = Header(...),
    x_timestamp: int = Header(...),
    x_nonce: str = Header(...),
    x_signature: str = Header(...)
) -> dict:
    
    # 1. Validate Timestamp
    current_time = int(time.time())
    if abs(current_time - x_timestamp) > TIMESTAMP_TOLERANCE:
        logging.warning(f"Timestamp out of window for {x_user_id}")
        raise AUTH_ERROR

    # 2. Fetch User
    user = await db_instance.users_collection.find_one({"user_id": x_user_id})
    if not user:
        raise AUTH_ERROR

    # 3. Build Canonical Payload (Method \n Path \n Query \n Timestamp \n Nonce \n BodyHash)
    body_bytes = await request.body()
    body_hash = hashlib.sha256(body_bytes).hexdigest()
    query_string = request.url.query
    
    payload_to_verify = f"{request.method}\n{request.url.path}\n{query_string}\n{x_timestamp}\n{x_nonce}\n{body_hash}"
    
    # 4. Verify RSA-PSS Signature
    try:
        public_key = load_pem_public_key(user["public_key"].encode('utf-8'))
        signature_bytes = base64.b64decode(x_signature)
        
        public_key.verify(
            signature_bytes,
            payload_to_verify.encode('utf-8'),
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
    except (ValueError, TypeError, InvalidSignature) as e:
        logging.warning(f"Signature mismatch for user {x_user_id}")
        raise AUTH_ERROR
    except Exception as e:
        logging.error(f"Unexpected crypto error: {e}")
        raise AUTH_ERROR

    # 5. ATOMIC DB Insert to Prevent Replay Attacks
    try:
        await db_instance.used_nonces_collection.insert_one({
            "nonce": x_nonce,
            "user_id": x_user_id,
            "created_at": datetime.now(timezone.utc)
        })
    except DuplicateKeyError:
        logging.warning(f"Replay attack blocked for user {x_user_id} with nonce {x_nonce}")
        raise AUTH_ERROR

    return user