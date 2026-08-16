from typing import Optional, Any


class DomainError(Exception):
    """Base class for all domain errors."""
    code: str = "domain_error"

    def __init__(self, message: str = "Domain error occurred", meta: Optional[dict[str, Any]] = None):
        self.message = message
        self.meta = meta or {}
        super().__init__(self.message)


class KeyValidationError(DomainError):
    """Raised when a public key fails cryptographic structure or size constraints."""
    code: str = "key_validation_error"

    def __init__(self, message: str = "Invalid public key"):
        super().__init__(message)


class UnsupportedAlgorithmError(DomainError):
    """Raised when an unsupported cryptographic algorithm is specified."""
    code: str = "unsupported_algorithm"

    def __init__(self, algorithm: str):
        super().__init__(f"Unsupported cryptographic algorithm: {algorithm}", meta={"algorithm": algorithm})


class UserAlreadyExistsError(DomainError):
    """Raised when attempting to register an identity that is already registered."""
    code: str = "user_already_exists"

    def __init__(self, message: str = "Public key already registered"):
        super().__init__(message)


class SignatureVerificationError(DomainError):
    """Raised when asymmetric signature verification fails."""
    code: str = "signature_verification_error"

    def __init__(self, message: str = "Invalid authentication credentials"):
        super().__init__(message)


class NonceConflictError(DomainError):
    """Raised when a presented counter violates monotonic sliding window constraints."""
    code: str = "nonce_conflict"

    def __init__(self, expected_counter: int, reason: str = "nonce_conflict", message: str = "Nonce counter conflict"):
        self.expected_counter = expected_counter
        self.reason = reason
        super().__init__(message, meta={"expected": expected_counter, "reason": reason})


class ConcurrencyContentionError(DomainError):
    """Raised when atomic counter CAS updates exhaust retries due to internal lock contention."""
    code: str = "concurrency_contention"

    def __init__(self, message: str = "High request concurrency contention. Please retry.", retry_after: int = 1):
        self.retry_after = retry_after
        super().__init__(message, meta={"retry_after": retry_after})


class TimestampExpiredError(DomainError):
    """Raised when a request timestamp falls outside the acceptable skew tolerance."""
    code: str = "timestamp_expired"

    def __init__(self, message: str = "Timestamp expired or skewed"):
        super().__init__(message)


class SyncNonceReusedError(DomainError):
    """Raised when an ephemeral sync challenge nonce is replayed."""
    code: str = "sync_nonce_reused"

    def __init__(self, message: str = "Sync nonce has already been consumed"):
        super().__init__(message)


class RegistrationNonceReusedError(DomainError):
    """Raised when an ephemeral registration proof-of-possession challenge nonce is replayed."""
    code: str = "registration_nonce_reused"

    def __init__(self, message: str = "Registration challenge nonce has already been used"):
        super().__init__(message)


class InvalidHostError(DomainError):
    """Raised when request host header fails trust validation."""
    code: str = "invalid_host"

    def __init__(self, message: str = "Untrusted or invalid request host"):
        super().__init__(message)