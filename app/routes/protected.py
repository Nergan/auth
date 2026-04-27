from fastapi import APIRouter, Depends
from app.models import ProtectedData, ProtectedResponse
from app.security import verify_request_signature

router = APIRouter(prefix="/protected", tags=["Protected"])

@router.post("/do-something", response_model=ProtectedResponse)
async def secure_action(data: ProtectedData, user: dict = Depends(verify_request_signature)):
    return {
        "message": f"Hello {user['user_id'][:8]}... Signature verified successfully!",
        "your_data_was": data.secret_message
    }