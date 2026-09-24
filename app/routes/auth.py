import base64
import binascii
import time
from datetime import datetime, timezone
from fastapi import APIRouter, status

from app.config import settings
from app.domain.models import UserRegister, UserResponse, UserEntity
from app.domain.crypto_core import generate_user_id, build_registration_challenge
from app.domain.exceptions import (
    KeyValidationError,
    TimestampExpiredError,
    SignatureVerificationError,
    RegistrationNonceReusedError
)
from app.infrastructure.crypto_service import crypto_service
from app.infrastructure.repositories import user_repository, nonce_manager

router = APIRouter(prefix="/auth", tags=["Authentication"])


@router.post("/register", status_code=status.HTTP_201_CREATED, response_model=UserResponse)
async def register(user_data: UserRegister):
    """
    Registers an asymmetric / post-quantum identity.
    Enforces Proof-of-Possession signature verification BEFORE checking identity existence
    to prevent timing and enumeration oracles.
    """
    # 1. Freshness validation
    current_time = int(time.time())
    if abs(current_time - user_data.timestamp) > settings.timestamp_tolerance_seconds:
        raise TimestampExpiredError("Registration timestamp expired or skewed")

    # 2. Key parsing and canonical fingerprint ID derivation
    verifier = crypto_service.get_verifier(user_data.key_algorithm.value)

    try:
        parsed_key = await crypto_service.parse_public_key_async(user_data.key_algorithm.value, user_data.public_key)
        canonical_bytes = await crypto_service.get_canonical_key_bytes_async(verifier, parsed_key)
        user_id = generate_user_id(user_data.key_algorithm.value, canonical_bytes)
    except KeyValidationError:
        raise
    except (ValueError, binascii.Error, TypeError) as exc:
        raise KeyValidationError("Invalid public key format") from exc

    # 3. Proof-of-Possession Challenge Verification Executed FIRST
    challenge = build_registration_challenge(
        user_data.key_algorithm.value, canonical_bytes, user_data.timestamp, user_data.client_nonce
    )

    try:
        sig_bytes = base64.b64decode(user_data.proof_signature, validate=True)
    except Exception as exc:
        raise SignatureVerificationError("Invalid base64 signature encoding") from exc

    is_valid = await crypto_service.verify_signature_async(
        verifier, parsed_key, challenge.encode("utf-8"), sig_bytes
    )
    if not is_valid:
        raise SignatureVerificationError("Invalid proof of possession signature")

    # 4. Gating: Reserve ephemeral registration nonce
    nonce_recorded = await nonce_manager.record_registration_nonce(user_id, user_data.client_nonce)
    if not nonce_recorded:
        raise RegistrationNonceReusedError("Registration challenge nonce has already been used")

    # 5. Identity State Persistence (atomic insert handles collision without revealing existence to unauthenticated probes)
    persisted = False
    try:
        user = UserEntity(
            user_id=user_id,
            public_key=user_data.public_key,
            key_algorithm=user_data.key_algorithm,
            nonce_base=0,
            nonce_mask=0,
            created_at=datetime.now(timezone.utc)
        )

        await user_repository.create_user(user)
        crypto_service.key_cache.put(user_id, parsed_key)
        persisted = True
    finally:
        if not persisted:
            await nonce_manager.remove_registration_nonce(user_id, user_data.client_nonce)

    return UserResponse(user_id=user_id, message="Registration successful")