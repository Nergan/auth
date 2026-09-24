from collections import OrderedDict
import threading
from typing import Optional, Any
from app.domain.ports import KeyCachePort


class InMemoryLRUKeyCache(KeyCachePort):
    """Thread-safe LRU Key Cache for in-memory parsed asymmetric and post-quantum keys."""
    
    def __init__(self, capacity: int = 10000):
        self.capacity = capacity
        self._cache: OrderedDict[str, Any] = OrderedDict()
        self._lock = threading.Lock()

    def get(self, user_id: str) -> Optional[Any]:
        with self._lock:
            if user_id not in self._cache:
                return None
            self._cache.move_to_end(user_id)
            return self._cache[user_id]

    def put(self, user_id: str, public_key: Any) -> None:
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