import asyncio
import threading
from concurrent.futures import ThreadPoolExecutor
from typing import Optional
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey
from app.config import settings
from app.domain.models import KeyAlgorithm
from app.domain.ports import SignatureVerifierPort, KeyCachePort
from app.domain.exceptions import UnsupportedAlgorithmError, SignatureVerificationError
from app.infrastructure.key_cache import key_cache
from app.infrastructure.verifiers import RSAPSSVerifier, DUMMY_PUBLIC_KEY, DUMMY_SIGNATURE


class CryptoService:
    def __init__(self, key_cache_instance: KeyCachePort = key_cache):
        self.verifiers: dict[str, SignatureVerifierPort] = {
            KeyAlgorithm.RSA_PSS_SHA256.value: RSAPSSVerifier(),
        }
        self.key_cache = key_cache_instance
        self._executor: Optional[ThreadPoolExecutor] = None
        self._lock = threading.Lock()

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

    async def parse_public_key_async(self, algo_str: str, public_key_pem: str) -> RSAPublicKey:
        if self._executor is None:
            self.start()

        verifier = self.get_verifier(algo_str)
        loop = asyncio.get_running_loop()
        try:
            return await asyncio.wait_for(
                loop.run_in_executor(self._executor, verifier.parse_public_key, public_key_pem),
                timeout=settings.crypto_timeout_seconds
            )
        except asyncio.TimeoutError:
            raise SignatureVerificationError("Key parsing operation timed out")

    async def get_canonical_key_bytes_async(self, verifier: SignatureVerifierPort, public_key: RSAPublicKey) -> bytes:
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

    async def get_or_parse_public_key_async(self, user_id: str, public_key_pem: str, algo_str: str) -> RSAPublicKey:
        cached_key = self.key_cache.get(user_id)
        if cached_key:
            return cached_key
        parsed_key = await self.parse_public_key_async(algo_str, public_key_pem)
        self.key_cache.put(user_id, parsed_key)
        return parsed_key

    async def verify_signature_async(
        self, verifier: SignatureVerifierPort, public_key: RSAPublicKey, payload_bytes: bytes, signature_bytes: bytes
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

    async def verify_dummy_async(self, payload_bytes: bytes, signature_bytes: Optional[bytes] = None) -> None:
        """
        Executes full asymmetric modular exponentiation against a dummy RSA key
        using a canonical 256-byte signature buffer to equalize execution latency.
        """
        verifier = self.verifiers[KeyAlgorithm.RSA_PSS_SHA256.value]
        target_sig = signature_bytes if (signature_bytes and len(signature_bytes) == 256) else DUMMY_SIGNATURE
        try:
            await self.verify_signature_async(verifier, DUMMY_PUBLIC_KEY, payload_bytes, target_sig)
        except Exception:
            pass


crypto_service = CryptoService()