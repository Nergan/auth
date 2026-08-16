from datetime import datetime
from enum import Enum
from typing import Optional, Any, Dict
from pydantic import BaseModel, Field


class KeyAlgorithm(str, Enum):
    RSA_PSS_SHA256 = "RSA-PSS-SHA256"


class ErrorDetail(BaseModel):
    code: str
    message: str
    expected: Optional[int] = None
    reason: Optional[str] = None
    retry_after: Optional[int] = None
    meta: Dict[str, Any] = Field(default_factory=dict)


class ErrorResponse(BaseModel):
    detail: ErrorDetail


class UserRegister(BaseModel):
    public_key: str = Field(..., max_length=10000, description="PEM formatted RSA public key (2048 bits)")
    key_algorithm: KeyAlgorithm = Field(default=KeyAlgorithm.RSA_PSS_SHA256)
    timestamp: int = Field(..., description="Unix epoch timestamp in seconds for freshness validation")
    client_nonce: str = Field(
        ...,
        min_length=16,
        max_length=64,
        pattern=r"^[a-zA-Z0-9_-]+$",
        description="Unique random challenge token (alphanumeric/url-safe)"
    )
    proof_signature: str = Field(..., description="Base64 signature proving ownership of the private key")


class UserEntity(BaseModel):
    user_id: str
    public_key: str
    key_algorithm: KeyAlgorithm
    nonce_base: int = 0
    nonce_mask: int = 0
    created_at: datetime


class UserResponse(BaseModel):
    user_id: str
    message: str


class NonceSyncResponse(BaseModel):
    user_id: str
    nonce_counter: int


class ProtectedData(BaseModel):
    secret_message: str


class ProtectedResponse(BaseModel):
    message: str
    your_data_was: str