from datetime import datetime
from enum import Enum
from typing import Optional, Any, Dict
from pydantic import BaseModel, Field


class KeyAlgorithm(str, Enum):
    ED25519 = "Ed25519"
    ML_DSA_44 = "ML-DSA-44"  # NIST FIPS 204 (Category 2)
    ML_DSA_65 = "ML-DSA-65"  # NIST FIPS 204 (Category 3)
    ML_DSA_87 = "ML-DSA-87"  # NIST FIPS 204 (Category 5)


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
    public_key: str = Field(..., max_length=25000, description="PEM, Base64, or Hex encoded public key")
    key_algorithm: KeyAlgorithm = Field(default=KeyAlgorithm.ED25519)
    timestamp: int = Field(..., description="Unix epoch timestamp in seconds for freshness validation")
    client_nonce: str = Field(..., min_length=16, max_length=64, pattern=r"^[a-zA-Z0-9_-]+$")
    proof_signature: str = Field(..., description="Base64 deterministic signature proving key possession")


class UserEntity(BaseModel):
    user_id: str
    public_key: str
    key_algorithm: KeyAlgorithm
    nonce_base: int = 0  # Represents highest seen counter (N_max)
    nonce_mask: int = 0  # Sliding window bitmask
    created_at: datetime


class UserResponse(BaseModel):
    user_id: str
    message: str


class NonceSyncResponse(BaseModel):
    user_id: str
    last_successful_nonce: int
    next_expected_nonce: int
    nonce_counter: int  # Compatibility alias for next_expected_nonce


class ProtectedData(BaseModel):
    secret_message: str


class ProtectedResponse(BaseModel):
    message: str
    your_data_was: str