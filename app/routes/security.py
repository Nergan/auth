from fastapi import APIRouter, Depends
from app.domain.models import NonceSyncResponse, UserEntity
from app.routes.dependencies import verify_sync_signature

router = APIRouter(prefix="/api/v1/security", tags=["Security"])


@router.get("/nonce", response_model=NonceSyncResponse)
async def get_nonce(user: UserEntity = Depends(verify_sync_signature)):
    """
    Returns the user's active expected nonce counter.
    Bound to an ephemeral client challenge nonce, verified via asymmetric signature,
    and computed with zero redundant database queries.
    """
    return NonceSyncResponse(
        user_id=user.user_id,
        nonce_counter=user.nonce_base + 1
    )