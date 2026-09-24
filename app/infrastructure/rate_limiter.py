import threading
import time
from typing import Dict, List, Optional, Tuple, Sequence
from starlette.types import ASGIApp, Scope, Receive, Send
from app.config import settings


class SlidingWindowRateLimiter:
    """In-memory thread-safe sliding window rate limiter with bounded memory eviction."""
    def __init__(self, limit: int, window_seconds: int, max_keys: int = 50000):
        self.limit = limit
        self.window_seconds = window_seconds
        self.max_keys = max_keys
        self._history: Dict[str, List[float]] = {}
        self._lock = threading.Lock()

    def is_allowed(self, key: str) -> Tuple[bool, int]:
        now = time.monotonic()
        cutoff = now - self.window_seconds

        with self._lock:
            timestamps = self._history.get(key, [])
            valid_timestamps = [t for t in timestamps if t > cutoff]

            if not valid_timestamps:
                if key in self._history:
                    del self._history[key]
            else:
                self._history[key] = valid_timestamps

            if len(valid_timestamps) < self.limit:
                if key not in self._history and len(self._history) >= self.max_keys:
                    keys_to_delete = [k for k, v in self._history.items() if not v or v[-1] <= cutoff]
                    for k in keys_to_delete:
                        del self._history[k]

                if len(self._history) < self.max_keys or key in self._history:
                    valid_timestamps.append(now)
                    self._history[key] = valid_timestamps
                return True, 0

            oldest = valid_timestamps[0]
            retry_after = max(1, int(oldest + self.window_seconds - now))
            return False, retry_after

    def reset(self) -> None:
        with self._lock:
            self._history.clear()


default_general_limiter = SlidingWindowRateLimiter(
    settings.rate_limit_requests, settings.rate_limit_window_seconds
)
default_auth_limiter = SlidingWindowRateLimiter(
    settings.auth_rate_limit_requests, settings.auth_rate_limit_window_seconds
)


def reset_rate_limiters() -> None:
    default_general_limiter.reset()
    default_auth_limiter.reset()


def resolve_client_ip(
    headers: Sequence[Tuple[bytes, bytes]],
    direct_ip: str,
    trust_proxy_headers: bool,
    trusted_proxies: Sequence[str]
) -> str:
    """
    Extracts client IP by traversing the X-Forwarded-For chain from right to left,
    stripping configured trusted proxies to prevent header spoofing rate limiter bypasses.
    """
    if not trust_proxy_headers:
        return direct_ip

    if direct_ip not in trusted_proxies:
        return direct_ip

    xff_raw = None
    for name, value in headers:
        if name.lower() == b"x-forwarded-for":
            xff_raw = value.decode("latin-1", errors="ignore")
            break

    if not xff_raw:
        return direct_ip

    ips = [ip.strip() for ip in xff_raw.split(",") if ip.strip()]
    if not ips:
        return direct_ip

    # Traverse from right to left (most recently appended)
    for ip in reversed(ips):
        if ip not in trusted_proxies:
            return ip

    return ips[0]


class RateLimitMiddleware:
    """ASGI middleware providing DoS mitigation based on verified client IP."""
    def __init__(
        self,
        app: ASGIApp,
        general_limiter: Optional[SlidingWindowRateLimiter] = None,
        auth_limiter: Optional[SlidingWindowRateLimiter] = None,
        trust_proxy_headers: bool = False,
        trusted_proxies: Optional[Sequence[str]] = None
    ):
        self.app = app
        self.general_limiter = general_limiter or default_general_limiter
        self.auth_limiter = auth_limiter or default_auth_limiter
        self.trust_proxy_headers = trust_proxy_headers
        self.trusted_proxies = trusted_proxies or []

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        client_info = scope.get("client")
        direct_ip = client_info[0] if client_info else "127.0.0.1"
        headers = scope.get("headers", [])

        client_ip = resolve_client_ip(
            headers=headers,
            direct_ip=direct_ip,
            trust_proxy_headers=self.trust_proxy_headers,
            trusted_proxies=self.trusted_proxies
        )

        path = scope.get("path", "")
        if path == "/auth" or path.startswith("/auth/"):
            rate_key = f"auth:{client_ip}"
            allowed, retry_after = self.auth_limiter.is_allowed(rate_key)
        else:
            rate_key = f"ip:{client_ip}"
            allowed, retry_after = self.general_limiter.is_allowed(rate_key)

        if not allowed:
            body = (
                f'{{"detail":{{"code":"rate_limit_exceeded",'
                f'"message":"Too many requests. Please try again later.","retry_after":{retry_after}}}}}'
            ).encode("utf-8")
            await send({
                "type": "http.response.start",
                "status": 429,
                "headers": [
                    (b"content-type", b"application/json"),
                    (b"content-length", str(len(body)).encode("ascii")),
                    (b"retry-after", str(retry_after).encode("ascii")),
                ],
            })
            await send({
                "type": "http.response.body",
                "body": body,
            })
            return

        await self.app(scope, receive, send)