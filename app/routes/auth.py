from datetime import datetime, timezone
from fastapi import APIRouter, HTTPException, status
from app.models import UserRegister, UserResponse
from app.database import db_instance
from app.security import generate_user_id

router = APIRouter(prefix="/auth", tags=["Authentication"])

@router.post("/register", status_code=status.HTTP_201_CREATED, response_model=UserResponse)
async def register(user_data: UserRegister):
    try:
        user_id = generate_user_id(user_data.public_key)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid public key format")

    existing_user = await db_instance.users_collection.find_one({"user_id": user_id})
    if existing_user:
        raise HTTPException(status_code=400, detail="Public key already registered")
    
    await db_instance.users_collection.insert_one({
        "user_id": user_id,
        "public_key": user_data.public_key,
        "created_at": datetime.now(timezone.utc)
    })
    
    return UserResponse(user_id=user_id, message="Registration successful")