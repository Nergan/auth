import asyncio
import threading
from concurrent.futures import ThreadPoolExecutor
from typing import Optional, Any
from app.config import settings
from app.domain.models import KeyAlgorithm
from app.domain.ports import SignatureVerifierPort, KeyCachePort
from app.domain.exceptions import UnsupportedAlgorithmError, SignatureVerificationError
from app.infrastructure.key_cache import key_cache
from app.infrastructure.verifiers import (
    Ed25519Verifier,
    MLDSAVerifier,
    DUMMY_ED25519_PUB,
    DUMMY_ED25519_SIG,
    _DUMMY_PAYLOAD,
    OQS_AVAILABLE
)


class CryptoService:
    """Asynchronous worker pool executing CPU-bound cryptographic operations."""

    def __init__(self, key_cache_instance: KeyCachePort = key_cache):
        self.verifiers: dict[str, SignatureVerifierPort] = {
            KeyAlgorithm.ED25519.value: Ed25519Verifier(),
            KeyAlgorithm.ML_DSA_44.value: MLDSAVerifier("ML-DSA-44"),
            KeyAlgorithm.ML_DSA_65.value: MLDSAVerifier("ML-DSA-65"),
            KeyAlgorithm.ML_DSA_87.value: MLDSAVerifier("ML-DSA-87"),
        }
        self.key_cache = key_cache_instance
        self._executor: Optional[ThreadPoolExecutor] = None
        self._lock = threading.Lock()
        self._dummy_pqc_keys: dict[str, tuple[bytes, bytes]] = {}
        self._init_dummy_pqc_keys()

    def _init_dummy_pqc_keys(self) -> None:
        if not OQS_AVAILABLE:
            return
        import oqs
        for algo, name in [
            (KeyAlgorithm.ML_DSA_44.value, "ML-DSA-44"),
            (KeyAlgorithm.ML_DSA_65.value, "ML-DSA-65"),
            (KeyAlgorithm.ML_DSA_87.value, "ML-DSA-87")
        ]:
            try:
                with oqs.Signature(name) as signer:
                    pub = signer.generate_keypair()
                    sig = signer.sign(_DUMMY_PAYLOAD)
                    self._dummy_pqc_keys[algo] = (pub, sig)
            except Exception:
                pass

    def start(self) -> None:
        with self._lock:
            if self._executor is None:
                self._executor = ThreadPoolExecutor(
                    max_workers=settings.crypto_max_workers,
                    thread_name_prefix="crypto_worker"
                )

    def shutdown(self) -> None:
        with self._lock:
            if self._executor is not None:
                self._executor.shutdown(wait=True, cancel_futures=True)
                self._executor = None

    def get_verifier(self, algo_str: str) -> SignatureVerifierPort:
        verifier = self.verifiers.get(algo_str)
        if not verifier:
            raise UnsupportedAlgorithmError(algo_str)
        return verifier

    async def parse_public_key_async(self, algo_str: str, public_key_str: str) -> Any:
        if self._executor is None:
            self.start()

        verifier = self.get_verifier(algo_str)
        loop = asyncio.get_running_loop()
        try:
            return await asyncio.wait_for(
                loop.run_in_executor(self._executor, verifier.parse_public_key, public_key_str),
                timeout=settings.crypto_timeout_seconds
            )
        except asyncio.TimeoutError:
            raise SignatureVerificationError("Key parsing operation timed out")

    async def get_canonical_key_bytes_async(self, verifier: SignatureVerifierPort, public_key: Any) -> bytes:
        if self._executor is None:
            self.start()

        loop = asyncio.get_running_loop()
        try:
            return await asyncio.wait_for(
                loop.run_in_executor(self._executor, verifier.get_canonical_key_bytes, public_key),
                timeout=settings.crypto_timeout_seconds
            )
        except asyncio.TimeoutError:
            raise SignatureVerificationError("Key serialization operation timed out")

    async def get_or_parse_public_key_async(self, user_id: str, public_key_str: str, algo_str: str) -> Any:
        cached_key = self.key_cache.get(user_id)
        if cached_key is not None:
            return cached_key
        parsed_key = await self.parse_public_key_async(algo_str, public_key_str)
        self.key_cache.put(user_id, parsed_key)
        return parsed_key

    async def verify_signature_async(
        self, verifier: SignatureVerifierPort, public_key: Any, payload_bytes: bytes, signature_bytes: bytes
    ) -> bool:
        if self._executor is None:
            self.start()

        loop = asyncio.get_running_loop()
        try:
            return await asyncio.wait_for(
                loop.run_in_executor(
                    self._executor,
                    verifier.verify,
                    public_key,
                    payload_bytes,
                    signature_bytes
                ),
                timeout=settings.crypto_timeout_seconds
            )
        except asyncio.TimeoutError:
            raise SignatureVerificationError("Signature verification operation timed out")

    async def verify_dummy_async(self, payload_bytes: bytes = _DUMMY_PAYLOAD, signature_bytes: Optional[bytes] = None) -> None:
        """
        Executes constant-time dummy signature verification matched to the algorithm family
        inferred from signature length to prevent timing-based identity enumeration.
        """
        sig_len = len(signature_bytes) if signature_bytes else 64

        if sig_len == 2420 and KeyAlgorithm.ML_DSA_44.value in self._dummy_pqc_keys:
            pub, sig = self._dummy_pqc_keys[KeyAlgorithm.ML_DSA_44.value]
            verifier = self.verifiers[KeyAlgorithm.ML_DSA_44.value]
            target_pub, target_sig = pub, (signature_bytes or sig)
        elif sig_len == 3309 and KeyAlgorithm.ML_DSA_65.value in self._dummy_pqc_keys:
            pub, sig = self._dummy_pqc_keys[KeyAlgorithm.ML_DSA_65.value]
            verifier = self.verifiers[KeyAlgorithm.ML_DSA_65.value]
            target_pub, target_sig = pub, (signature_bytes or sig)
        elif sig_len == 4627 and KeyAlgorithm.ML_DSA_87.value in self._dummy_pqc_keys:
            pub, sig = self._dummy_pqc_keys[KeyAlgorithm.ML_DSA_87.value]
            verifier = self.verifiers[KeyAlgorithm.ML_DSA_87.value]
            target_pub, target_sig = pub, (signature_bytes or sig)
        else:
            verifier = self.verifiers[KeyAlgorithm.ED25519.value]
            target_pub = DUMMY_ED25519_PUB
            target_sig = signature_bytes if (signature_bytes and len(signature_bytes) == 64) else DUMMY_ED25519_SIG

        try:
            await self.verify_signature_async(verifier, target_pub, payload_bytes, target_sig)
        except Exception:
            pass


crypto_service = CryptoService()