from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.serialization import load_pem_public_key
from cryptography.exceptions import InvalidSignature
from app.domain.ports import SignatureVerifierPort
from app.domain.exceptions import KeyValidationError

REQUIRED_RSA_KEY_SIZE = 2048
REQUIRED_RSA_PUBLIC_EXPONENT = 65537

# Static dummy key and pre-generated valid 256-byte signature for constant-time side-channel mitigation
_DUMMY_PRIVATE_KEY = rsa.generate_private_key(public_exponent=REQUIRED_RSA_PUBLIC_EXPONENT, key_size=REQUIRED_RSA_KEY_SIZE)
DUMMY_PUBLIC_KEY: rsa.RSAPublicKey = _DUMMY_PRIVATE_KEY.public_key()
_DUMMY_PAYLOAD = b"dummy_constant_time_payload_for_timing_mitigation"
DUMMY_SIGNATURE: bytes = _DUMMY_PRIVATE_KEY.sign(
    _DUMMY_PAYLOAD,
    padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=32),
    hashes.SHA256()
)


class RSAPSSVerifier(SignatureVerifierPort):
    def verify(self, public_key: rsa.RSAPublicKey, payload: bytes, signature: bytes) -> bool:
        try:
            public_key.verify(
                signature,
                payload,
                padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.AUTO),
                hashes.SHA256()
            )
            return True
        except (ValueError, TypeError, InvalidSignature):
            return False

    def parse_public_key(self, public_key_pem: str) -> rsa.RSAPublicKey:
        try:
            key = load_pem_public_key(public_key_pem.encode("utf-8"))
        except Exception as exc:
            raise KeyValidationError("Invalid PEM public key format") from exc

        if not isinstance(key, rsa.RSAPublicKey):
            raise KeyValidationError("Public key is not a valid RSA key")

        if key.key_size != REQUIRED_RSA_KEY_SIZE:
            raise KeyValidationError(
                f"RSA key size must be exactly {REQUIRED_RSA_KEY_SIZE} bits for constant-time security. Received: {key.key_size}"
            )

        public_numbers = key.public_numbers()
        if public_numbers.e != REQUIRED_RSA_PUBLIC_EXPONENT:
            raise KeyValidationError(
                f"RSA public exponent must be strictly {REQUIRED_RSA_PUBLIC_EXPONENT}. Received: {public_numbers.e}"
            )

        return key

    def get_canonical_key_bytes(self, public_key: rsa.RSAPublicKey) -> bytes:
        return public_key.public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )