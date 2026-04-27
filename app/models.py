from pydantic import BaseModel, Field

class UserRegister(BaseModel):
    public_key: str = Field(..., max_length=4096, description="PEM encoded RSA public key (min 2048 bits)")

class UserResponse(BaseModel):
    user_id: str
    message: str

class ProtectedData(BaseModel):
    secret_message: str

class ProtectedResponse(BaseModel):
    message: str
    your_data_was: str