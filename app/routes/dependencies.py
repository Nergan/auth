import base64
import hashlib
import time
from typing import Optional, AsyncGenerator
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


def safe_decode_signature(signature_str: str) -> Optional[bytes]:
    try:
        return base64.b64decode(signature_str, validate=True)
    except Exception:
        return None


async def verify_request_signature(
    request: Request,
    x_user_id: str = Header(...),
    x_timestamp: int = Header(...),
    x_nonce_counter: int = Header(...),
    x_signature: str = Header(...)
) -> AsyncGenerator[UserEntity, None]:
    """
    Generator dependency: Pre-validates signature and sequence window, yields identity to handler,
    and commits atomic state advance only after successful handler completion (HTTP 2xx).
    """
    if not (1 <= x_nonce_counter <= MAX_INT64):
        raise NonceConflictError(1, reason="invalid_counter_bounds")

    current_time = int(time.time())
    if abs(current_time - x_timestamp) > settings.timestamp_tolerance_seconds:
        raise TimestampExpiredError("Request timestamp expired or skewed")

    host = extract_and_validate_host(request)
    body_bytes = await request.body()
    body_hash = hashlib.sha256(body_bytes).hexdigest()
    query_string = request.url.query
    content_type = request.headers.get("content-type", "")

    payload = build_canonical_payload(
        host, request.method, request.url.path, query_string, x_timestamp, x_nonce_counter, body_hash, content_type
    )

    user = await user_repository.get_user_by_id(x_user_id)
    sig_bytes = safe_decode_signature(x_signature)

    if not user:
        await crypto_service.verify_dummy_async(payload.encode("utf-8"), sig_bytes)
        raise SignatureVerificationError("Invalid authentication credentials")

    try:
        if not sig_bytes:
            raise SignatureVerificationError("Invalid authentication credentials")

        verifier = crypto_service.get_verifier(user.key_algorithm.value)
        public_key = await crypto_service.get_or_parse_public_key_async(
            user.user_id, user.public_key, user.key_algorithm.value
        )

        is_valid_sig = await crypto_service.verify_signature_async(
            verifier, public_key, payload.encode("utf-8"), sig_bytes
        )
        if not is_valid_sig:
            raise SignatureVerificationError("Invalid authentication credentials")
    except SignatureVerificationError:
        raise
    except Exception:
        raise SignatureVerificationError("Invalid authentication credentials")

    # Step 2: Sliding Replay Window Pre-validation (Read-Only)
    valid_window, expected, reason = await nonce_manager.validate_counter(x_user_id, x_nonce_counter)
    if not valid_window:
        if reason == "concurrency_contention":
            raise ConcurrencyContentionError()
        raise NonceConflictError(expected_counter=expected, reason=reason)

    try:
        yield user
        # Executed post-handler on successful response: Atomic CAS commit
        success, expected_post, reason_post = await nonce_manager.advance_counter(x_user_id, x_nonce_counter)
        if not success:
            if reason_post == "concurrency_contention":
                raise ConcurrencyContentionError()
            raise NonceConflictError(expected_counter=expected_post, reason=reason_post)
    except Exception:
        # Route handler failed or threw an exception: Do not commit/burn counter
        raise


async def verify_sync_signature(
    request: Request,
    x_user_id: str = Header(...),
    x_timestamp: int = Header(...),
    x_sync_nonce: str = Header(..., min_length=16, max_length=64, pattern=r"^[a-zA-Z0-9_-]+$"),
    x_signature: str = Header(...)
) -> UserEntity:
    """Verifies out-of-band nonce synchronization requests using challenge signatures."""
    current_time = int(time.time())
    if abs(current_time - x_timestamp) > settings.timestamp_tolerance_seconds:
        raise TimestampExpiredError("Request timestamp expired or skewed")

    host = extract_and_validate_host(request)

    body_bytes = await request.body()
    body_hash = hashlib.sha256(body_bytes).hexdigest()
    query_string = request.url.query
    content_type = request.headers.get("content-type", "")
    payload = build_sync_canonical_payload(
        host, request.method, request.url.path, query_string, x_timestamp, x_sync_nonce, body_hash, content_type
    )

    user = await user_repository.get_user_by_id(x_user_id)
    sig_bytes = safe_decode_signature(x_signature)

    if not user:
        await crypto_service.verify_dummy_async(payload.encode("utf-8"), sig_bytes)
        raise SignatureVerificationError("Invalid authentication credentials")

    try:
        if not sig_bytes:
            raise SignatureVerificationError("Invalid authentication credentials")

        verifier = crypto_service.get_verifier(user.key_algorithm.value)
        public_key = await crypto_service.get_or_parse_public_key_async(
            user.user_id, user.public_key, user.key_algorithm.value
        )

        is_valid = await crypto_service.verify_signature_async(
            verifier, public_key, payload.encode("utf-8"), sig_bytes
        )
        if not is_valid:
            raise SignatureVerificationError("Invalid authentication credentials")
    except SignatureVerificationError:
        raise
    except Exception:
        raise SignatureVerificationError("Invalid authentication credentials")

    recorded = await nonce_manager.record_sync_nonce(x_user_id, x_sync_nonce)
    if not recorded:
        raise SyncNonceReusedError("Sync nonce has already been consumed")

    return user