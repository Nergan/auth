import base64
import threading
from typing import Any, Dict, Optional
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives import serialization
from cryptography.exceptions import InvalidSignature

from app.domain.ports import SignatureVerifierPort
from app.domain.exceptions import KeyValidationError, UnsupportedAlgorithmError

try:
    import oqs
    OQS_AVAILABLE = True
except ImportError:
    OQS_AVAILABLE = False


_DUMMY_ED25519_KEY = ed25519.Ed25519PrivateKey.generate()
DUMMY_ED25519_PUB: ed25519.Ed25519PublicKey = _DUMMY_ED25519_KEY.public_key()
_DUMMY_PAYLOAD = b"constant_time_side_channel_mitigation_payload_pad"
DUMMY_ED25519_SIG: bytes = _DUMMY_ED25519_KEY.sign(_DUMMY_PAYLOAD)


class Ed25519Verifier(SignatureVerifierPort):
    """Deterministic Ed25519 Signature Verifier."""

    def verify(self, public_key: ed25519.Ed25519PublicKey, payload: bytes, signature: bytes) -> bool:
        if len(signature) != 64:
            return False
        try:
            public_key.verify(signature, payload)
            return True
        except (InvalidSignature, Exception):
            return False

    def parse_public_key(self, public_key_str: str) -> ed25519.Ed25519PublicKey:
        raw_input = public_key_str.strip()
        if "-----BEGIN PUBLIC KEY-----" in raw_input:
            try:
                key = serialization.load_pem_public_key(raw_input.encode("utf-8"))
                if not isinstance(key, ed25519.Ed25519PublicKey):
                    raise KeyValidationError("Key is not an Ed25519 public key instance")
                return key
            except KeyValidationError:
                raise
            except Exception as exc:
                raise KeyValidationError(f"Invalid PEM Ed25519 public key: {exc}") from exc

        try:
            lines = [line.strip() for line in raw_input.splitlines() if not line.startswith("-----")]
            clean_str = "".join(lines)
            if len(clean_str) == 64:
                try:
                    raw_bytes = bytes.fromhex(clean_str)
                except ValueError:
                    raw_bytes = base64.b64decode(clean_str, validate=True)
            else:
                raw_bytes = base64.b64decode(clean_str, validate=True)

            if len(raw_bytes) != 32:
                raise KeyValidationError(f"Ed25519 public key must be exactly 32 bytes (got {len(raw_bytes)})")
            return ed25519.Ed25519PublicKey.from_public_bytes(raw_bytes)
        except KeyValidationError:
            raise
        except Exception as exc:
            raise KeyValidationError(f"Invalid Ed25519 public key encoding: {exc}") from exc

    def get_canonical_key_bytes(self, public_key: ed25519.Ed25519PublicKey) -> bytes:
        return public_key.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        )


class MLDSAVerifier(SignatureVerifierPort):
    """
    NIST FIPS 204 Module-Lattice-Based Digital Signature Algorithm (ML-DSA).
    Supports ML-DSA-44, ML-DSA-65, and ML-DSA-87 parameter sets.
    """

    SPECIFICATIONS: Dict[str, Dict[str, Any]] = {
        "ML-DSA-44": {"pub_len": 1312, "sig_len": 2420, "oqs_names": ["ML-DSA-44", "Dilithium2"]},
        "ML-DSA-65": {"pub_len": 1952, "sig_len": 3309, "oqs_names": ["ML-DSA-65", "Dilithium3"]},
        "ML-DSA-87": {"pub_len": 2592, "sig_len": 4627, "oqs_names": ["ML-DSA-87", "Dilithium5"]},
    }

    def __init__(self, algorithm_name: str):
        if algorithm_name not in self.SPECIFICATIONS:
            raise UnsupportedAlgorithmError(algorithm_name)
        self.algorithm_name = algorithm_name
        self.pub_key_len = self.SPECIFICATIONS[algorithm_name]["pub_len"]
        self.sig_len = self.SPECIFICATIONS[algorithm_name]["sig_len"]
        self.oqs_names = self.SPECIFICATIONS[algorithm_name]["oqs_names"]
        self._cached_name: Optional[str] = None
        self._lock = threading.Lock()

    def verify(self, public_key: bytes, payload: bytes, signature: bytes) -> bool:
        if len(public_key) != self.pub_key_len or len(signature) != self.sig_len:
            return False

        if not OQS_AVAILABLE:
            raise UnsupportedAlgorithmError(
                f"{self.algorithm_name} backend unavailable. Install liboqs-python to enable PQC verification."
            )

        with self._lock:
            if self._cached_name:
                try:
                    with oqs.Signature(self._cached_name) as verifier:
                        return verifier.verify(payload, signature, public_key)
                except Exception:
                    self._cached_name = None

        for name in self.oqs_names:
            try:
                with oqs.Signature(name) as verifier:
                    res = verifier.verify(payload, signature, public_key)
                    with self._lock:
                        self._cached_name = name
                    return res
            except Exception:
                continue
        return False

    def parse_public_key(self, public_key_str: str) -> bytes:
        raw_input = public_key_str.strip()
        lines = [line.strip() for line in raw_input.splitlines() if not line.startswith("-----")]
        clean_str = "".join(lines)
        try:
            if len(clean_str) == self.pub_key_len * 2:
                raw_bytes = bytes.fromhex(clean_str)
            else:
                raw_bytes = base64.b64decode(clean_str, validate=True)

            if len(raw_bytes) != self.pub_key_len:
                raise KeyValidationError(
                    f"{self.algorithm_name} public key must be exactly {self.pub_key_len} bytes (got {len(raw_bytes)})"
                )
            return raw_bytes
        except Exception as exc:
            raise KeyValidationError(f"Invalid {self.algorithm_name} public key encoding: {exc}") from exc

    def get_canonical_key_bytes(self, public_key: bytes) -> bytes:
        return public_key