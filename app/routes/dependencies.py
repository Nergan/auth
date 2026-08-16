import base64
import hashlib
import time
from typing import Optional
from fastapi import Header, Request

from app.config import settings
from app.domain.anti_replay import resolve_host, is_host_trusted
from app.domain.crypto_core import build_canonical_payload, build_sync_canonical_payload
from app.domain.models import UserEntity
from app.domain.exceptions import (
    SignatureVerificationError,
    TimestampExpiredError,
    NonceConflictError,
    ConcurrencyContentionError,
    SyncNonceReusedError,
    InvalidHostError
)
from app.infrastructure.crypto_service import crypto_service
from app.infrastructure.repositories import user_repository, nonce_manager, MAX_INT64


def extract_and_validate_host(request: Request) -> str:
    """
    Resolves and verifies request host against configured trusted hosts,
    respecting trusted proxy headers and HTTP/2 authority when configured.
    """
    client_host = request.client.host if request.client else ""
    norm_host = resolve_host(
        headers=request.headers,
        client_ip=client_host,
        trust_proxy_headers=settings.trust_proxy_headers,
        trusted_proxies=settings.trusted_proxies
    )

    if not is_host_trusted(norm_host, settings.trusted_hosts):
        raise InvalidHostError(f"Untrusted or missing request host: {norm_host}")

    return norm_host


def safe_decode_signature(signature_str: str, expected_length: Optional[int] = 256) -> Optional[bytes]:
    """
    Safely decodes base64 signature returning None if malformed or byte length constraints fail.
    """
    try:
        decoded = base64.b64decode(signature_str, validate=True)
        if expected_length is not None and len(decoded) != expected_length:
            return None
        return decoded
    except Exception:
        return None


async def verify_request_signature(
    request: Request,
    x_user_id: str = Header(...),
    x_timestamp: int = Header(...),
    x_nonce_counter: int = Header(...),
    x_signature: str = Header(...)
) -> UserEntity:
    # 1. Monotonic counter range validation
    if not (1 <= x_nonce_counter <= MAX_INT64):
        raise NonceConflictError(1, reason="invalid_counter_bounds")

    # 2. Freshness Skew Check
    current_time = int(time.time())
    if abs(current_time - x_timestamp) > settings.timestamp_tolerance_seconds:
        raise TimestampExpiredError("Request timestamp expired or skewed")

    # 3. Host Resolution & Whitelist Verification
    host = extract_and_validate_host(request)

    # 4. Canonical Payload Construction
    body_bytes = await request.body()
    body_hash = hashlib.sha256(body_bytes).hexdigest()
    query_string = request.url.query
    payload = build_canonical_payload(
        host, request.method, request.url.path, query_string, x_timestamp, x_nonce_counter, body_hash
    )

    # 5. User Lookup with Constant-Time Side-Channel Protection
    user = await user_repository.get_user_by_id(x_user_id)
    sig_bytes = safe_decode_signature(x_signature)

    if not user:
        await crypto_service.verify_dummy_async(payload.encode("utf-8"), sig_bytes)
        raise SignatureVerificationError("Invalid authentication credentials")

    # 6. Signature Verification (Uniform error responses to prevent user enumeration)
    try:
        if not sig_bytes:
            raise SignatureVerificationError("Invalid authentication credentials")

        verifier = crypto_service.get_verifier(user.key_algorithm.value)
        public_key = await crypto_service.get_or_parse_public_key_async(user.user_id, user.public_key, user.key_algorithm.value)

        is_valid_sig = await crypto_service.verify_signature_async(
            verifier, public_key, payload.encode("utf-8"), sig_bytes
        )
        if not is_valid_sig:
            raise SignatureVerificationError("Invalid authentication credentials")
    except SignatureVerificationError:
        raise
    except Exception:
        raise SignatureVerificationError("Invalid authentication credentials")

    # 7. Atomic Anti-Replay State Advance (CAS Commit)
    success, expected, reason = await nonce_manager.validate_and_advance(
        x_user_id, x_nonce_counter, current_user=user
    )
    if not success:
        if reason == "concurrency_contention":
            raise ConcurrencyContentionError()
        raise NonceConflictError(expected_counter=expected, reason=reason)

    return user


async def verify_sync_signature(
    request: Request,
    x_user_id: str = Header(...),
    x_timestamp: int = Header(...),
    x_sync_nonce: str = Header(..., min_length=16, max_length=64, pattern=r"^[a-zA-Z0-9_-]+$"),
    x_signature: str = Header(...)
) -> UserEntity:
    # 1. Freshness Skew Check
    current_time = int(time.time())
    if abs(current_time - x_timestamp) > settings.timestamp_tolerance_seconds:
        raise TimestampExpiredError("Request timestamp expired or skewed")

    # 2. Host Resolution & Whitelist Verification
    host = extract_and_validate_host(request)

    # 3. Canonical Payload Construction
    body_bytes = await request.body()
    body_hash = hashlib.sha256(body_bytes).hexdigest()
    query_string = request.url.query
    payload = build_sync_canonical_payload(
        host, request.method, request.url.path, query_string, x_timestamp, x_sync_nonce, body_hash
    )

    # 4. User Lookup with Constant-Time Side-Channel Protection
    user = await user_repository.get_user_by_id(x_user_id)
    sig_bytes = safe_decode_signature(x_signature)

    if not user:
        await crypto_service.verify_dummy_async(payload.encode("utf-8"), sig_bytes)
        raise SignatureVerificationError("Invalid authentication credentials")

    # 5. Cryptographic Signature Verification BEFORE Nonce Reservation (Prevents Nonce Burning DoS)
    try:
        if not sig_bytes:
            raise SignatureVerificationError("Invalid authentication credentials")

        verifier = crypto_service.get_verifier(user.key_algorithm.value)
        public_key = await crypto_service.get_or_parse_public_key_async(user.user_id, user.public_key, user.key_algorithm.value)

        is_valid = await crypto_service.verify_signature_async(
            verifier, public_key, payload.encode("utf-8"), sig_bytes
        )
        if not is_valid:
            raise SignatureVerificationError("Invalid authentication credentials")
    except SignatureVerificationError:
        raise
    except Exception:
        raise SignatureVerificationError("Invalid authentication credentials")

    # 6. Reserve Ephemeral Sync Nonce ONLY After Signature Validity Is Established
    recorded = await nonce_manager.record_sync_nonce(x_user_id, x_sync_nonce)
    if not recorded:
        raise SyncNonceReusedError("Sync nonce has already been consumed")

    return user