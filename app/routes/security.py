from fastapi import APIRouter, Depends
from app.domain.models import NonceSyncResponse, UserEntity
from app.domain.exceptions import SignatureVerificationError
from app.infrastructure.repositories import user_repository
from app.routes.dependencies import verify_sync_signature

router = APIRouter(prefix="/api/v1/security", tags=["Security"])


@router.get("/nonce", response_model=NonceSyncResponse)
async def get_nonce(user: UserEntity = Depends(verify_sync_signature)):
    """
    Returns the user's active monotonic state directly from the persistent state store.
    Bound to an ephemeral client challenge nonce and verified via post-quantum signature.
    """
    current_user = await user_repository.get_user_by_id(user.user_id)
    if not current_user:
        raise SignatureVerificationError("User record not found")

    last_nonce = current_user.nonce_base
    next_nonce = last_nonce + 1
    return NonceSyncResponse(
        user_id=current_user.user_id,
        last_successful_nonce=last_nonce,
        next_expected_nonce=next_nonce,
        nonce_counter=next_nonce
    )