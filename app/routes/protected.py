from fastapi import APIRouter, Depends
from app.domain.models import ProtectedData, ProtectedResponse, UserEntity
from app.routes.dependencies import verify_request_signature

router = APIRouter(prefix="/protected", tags=["Protected"])


@router.post("/do-something", response_model=ProtectedResponse)
async def secure_action(data: ProtectedData, user: UserEntity = Depends(verify_request_signature)):
    return ProtectedResponse(
        message=f"Hello {user.user_id[:8]}... Signature verified successfully!",
        your_data_was=data.secret_message
    )