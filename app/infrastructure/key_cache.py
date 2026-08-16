from collections import OrderedDict
import threading
from typing import Optional
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey
from app.domain.ports import KeyCachePort


class InMemoryLRUKeyCache(KeyCachePort):
    def __init__(self, capacity: int = 10000):
        self.capacity = capacity
        self._cache: OrderedDict[str, RSAPublicKey] = OrderedDict()
        self._lock = threading.Lock()

    def get(self, user_id: str) -> Optional[RSAPublicKey]:
        with self._lock:
            if user_id not in self._cache:
                return None
            self._cache.move_to_end(user_id)
            return self._cache[user_id]

    def put(self, user_id: str, public_key: RSAPublicKey) -> None:
        with self._lock:
            if user_id in self._cache:
                self._cache.move_to_end(user_id)
            self._cache[user_id] = public_key
            if len(self._cache) > self.capacity:
                self._cache.popitem(last=False)

    def invalidate(self, user_id: str) -> None:
        with self._lock:
            self._cache.pop(user_id, None)


key_cache = InMemoryLRUKeyCache()