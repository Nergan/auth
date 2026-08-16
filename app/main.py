from contextlib import asynccontextmanager
import logging
from typing import Optional, Any
from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from pymongo.errors import PyMongoError, ServerSelectionTimeoutError, ConnectionFailure, AutoReconnect
from starlette.exceptions import HTTPException as StarletteHTTPException
from starlette.types import ASGIApp, Scope, Receive, Send

from app.config import settings
from app.domain.anti_replay import resolve_host, is_host_trusted
from app.domain.exceptions import (
    DomainError,
    KeyValidationError,
    UnsupportedAlgorithmError,
    UserAlreadyExistsError,
    SignatureVerificationError,
    NonceConflictError,
    ConcurrencyContentionError,
    TimestampExpiredError,
    SyncNonceReusedError,
    RegistrationNonceReusedError,
    InvalidHostError
)
from app.infrastructure.database import connect_to_mongo, close_mongo_connection
from app.infrastructure.crypto_service import crypto_service
from app.infrastructure.rate_limiter import (
    RateLimitMiddleware,
    default_general_limiter,
    default_auth_limiter
)
from app.routes import auth, protected, security

logger = logging.getLogger(__name__)

AUTH_CHALLENGE_HEADER = {
    "WWW-Authenticate": 'Signature realm="asymmetric-auth", headers="X-User-Id X-Timestamp X-Nonce-Counter X-Signature"'
}
SYNC_CHALLENGE_HEADER = {
    "WWW-Authenticate": 'Signature realm="asymmetric-auth-sync", headers="X-User-Id X-Timestamp X-Sync-Nonce X-Signature"'
}


def get_auth_challenge_header(request: Request) -> dict[str, str]:
    path = request.url.path
    if "/security/" in path or path.endswith("/nonce"):
        return SYNC_CHALLENGE_HEADER
    return AUTH_CHALLENGE_HEADER


def format_error_response(
    status_code: int,
    code: str,
    message: str,
    expected: Optional[int] = None,
    reason: Optional[str] = None,
    retry_after: Optional[int] = None,
    meta: Optional[dict[str, Any]] = None,
    headers: Optional[dict[str, str]] = None
) -> JSONResponse:
    detail: dict[str, Any] = {
        "code": code,
        "message": message,
    }
    if expected is not None:
        detail["expected"] = expected
    if reason is not None:
        detail["reason"] = reason
    if retry_after is not None:
        detail["retry_after"] = retry_after
    if meta:
        detail["meta"] = meta
    return JSONResponse(status_code=status_code, content={"detail": detail}, headers=headers)


class TrustedHostMiddleware:
    def __init__(
        self,
        app: ASGIApp,
        allowed_hosts: list[str],
        trust_proxy_headers: bool = False,
        trusted_proxies: Optional[list[str]] = None
    ):
        self.app = app
        self.allowed_hosts = allowed_hosts
        self.trust_proxy_headers = trust_proxy_headers
        self.trusted_proxies = trusted_proxies or []

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        client_info = scope.get("client")
        client_ip = client_info[0] if client_info else ""
        headers = scope.get("headers", [])

        resolved_host = resolve_host(
            headers=headers,
            client_ip=client_ip,
            trust_proxy_headers=self.trust_proxy_headers,
            trusted_proxies=self.trusted_proxies
        )

        if not is_host_trusted(resolved_host, self.allowed_hosts):
            response = format_error_response(status_code=400, code="invalid_host", message="Invalid host header")
            await response(scope, receive, send)
            return

        await self.app(scope, receive, send)


class ContentSizeLimitMiddleware:
    def __init__(self, app: ASGIApp, max_bytes: int):
        self.app = app
        self.max_bytes = max_bytes

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        for name, value in scope.get("headers", []):
            if name.lower() == b"content-length":
                try:
                    if int(value) > self.max_bytes:
                        await self._reject(send)
                        return
                except ValueError:
                    pass

        total_bytes = 0
        response_sent = False
        stream_closed = False

        async def streaming_receive() -> dict:
            nonlocal total_bytes, response_sent, stream_closed
            if stream_closed:
                return {"type": "http.disconnect"}

            message = await receive()
            msg_type = message.get("type")

            if msg_type == "http.request":
                chunk = message.get("body", b"")
                total_bytes += len(chunk)
                if total_bytes > self.max_bytes:
                    stream_closed = True
                    if not response_sent:
                        response_sent = True
                        await self._reject(send)
                    return {"type": "http.disconnect"}
            elif msg_type == "http.disconnect":
                stream_closed = True

            return message

        async def guarded_send(message: dict) -> None:
            nonlocal response_sent
            if response_sent:
                return
            await send(message)

        try:
            await self.app(scope, streaming_receive, guarded_send)
        except Exception:
            if not response_sent:
                raise

    async def _reject(self, send: Send) -> None:
        body = b'{"detail":{"code":"payload_too_large","message":"Payload too large"}}'
        await send({
            "type": "http.response.start",
            "status": 413,
            "headers": [
                (b"content-type", b"application/json"),
                (b"content-length", str(len(body)).encode("ascii")),
                (b"connection", b"close"),
            ],
        })
        await send({
            "type": "http.response.body",
            "body": body,
        })


@asynccontextmanager
async def lifespan(app: FastAPI):
    if not settings.mongo_tls and not any(h in settings.mongodb_uri for h in ("localhost", "127.0.0.1", "::1")):
        logger.warning("INSECURE CONFIGURATION: MongoDB TLS is disabled for non-loopback connection URI.")
    await connect_to_mongo()
    crypto_service.start()
    yield
    crypto_service.shutdown()
    await close_mongo_connection()


app = FastAPI(title="Per-Request Asymmetric Auth API", lifespan=lifespan)


# Standard Framework Exception Handlers
@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request: Request, exc: RequestValidationError):
    return format_error_response(
        status_code=422,
        code="validation_error",
        message="Request validation failed",
        meta={"errors": exc.errors()}
    )


@app.exception_handler(StarletteHTTPException)
async def http_exception_handler(request: Request, exc: StarletteHTTPException):
    return format_error_response(
        status_code=exc.status_code,
        code=f"http_{exc.status_code}",
        message=str(exc.detail) if exc.detail else "HTTP error occurred",
        headers=exc.headers
    )


# Infrastructure Exception Handlers
@app.exception_handler(ServerSelectionTimeoutError)
@app.exception_handler(ConnectionFailure)
@app.exception_handler(AutoReconnect)
@app.exception_handler(PyMongoError)
async def mongo_exception_handler(request: Request, exc: PyMongoError):
    logger.error("Database connection/operation failure: %s", exc, exc_info=True)
    return format_error_response(
        status_code=503,
        code="service_unavailable",
        message="Database service temporarily unavailable. Please retry later.",
        headers={"Retry-After": "5"}
    )


# Domain Exception Handlers
@app.exception_handler(SignatureVerificationError)
async def signature_error_handler(request: Request, exc: SignatureVerificationError):
    return format_error_response(
        status_code=401,
        code=exc.code,
        message=exc.message,
        meta=exc.meta,
        headers=get_auth_challenge_header(request)
    )


@app.exception_handler(TimestampExpiredError)
async def timestamp_error_handler(request: Request, exc: TimestampExpiredError):
    return format_error_response(
        status_code=401,
        code=exc.code,
        message=exc.message,
        meta=exc.meta,
        headers=get_auth_challenge_header(request)
    )


@app.exception_handler(SyncNonceReusedError)
async def sync_nonce_reused_handler(request: Request, exc: SyncNonceReusedError):
    return format_error_response(
        status_code=401,
        code=exc.code,
        message=exc.message,
        meta=exc.meta,
        headers=SYNC_CHALLENGE_HEADER
    )


@app.exception_handler(RegistrationNonceReusedError)
async def registration_nonce_reused_handler(request: Request, exc: RegistrationNonceReusedError):
    return format_error_response(
        status_code=401,
        code=exc.code,
        message=exc.message,
        meta=exc.meta,
        headers=AUTH_CHALLENGE_HEADER
    )


@app.exception_handler(KeyValidationError)
async def key_validation_handler(request: Request, exc: KeyValidationError):
    return format_error_response(status_code=400, code=exc.code, message=exc.message, meta=exc.meta)


@app.exception_handler(InvalidHostError)
async def invalid_host_handler(request: Request, exc: InvalidHostError):
    return format_error_response(status_code=400, code=exc.code, message=exc.message, meta=exc.meta)


@app.exception_handler(UnsupportedAlgorithmError)
async def unsupported_algo_handler(request: Request, exc: UnsupportedAlgorithmError):
    return format_error_response(status_code=400, code=exc.code, message=exc.message, meta=exc.meta)


@app.exception_handler(UserAlreadyExistsError)
async def user_exists_handler(request: Request, exc: UserAlreadyExistsError):
    return format_error_response(status_code=409, code=exc.code, message=exc.message, meta=exc.meta)


@app.exception_handler(NonceConflictError)
async def nonce_conflict_handler(request: Request, exc: NonceConflictError):
    return format_error_response(
        status_code=409,
        code=exc.code,
        message=exc.message,
        expected=exc.expected_counter,
        reason=exc.reason,
        meta=exc.meta
    )


@app.exception_handler(ConcurrencyContentionError)
async def concurrency_contention_handler(request: Request, exc: ConcurrencyContentionError):
    return format_error_response(
        status_code=503,
        code=exc.code,
        message=exc.message,
        retry_after=exc.retry_after,
        meta=exc.meta,
        headers={"Retry-After": str(exc.retry_after)}
    )


@app.exception_handler(DomainError)
async def generic_domain_error_handler(request: Request, exc: DomainError):
    return format_error_response(status_code=400, code=exc.code, message=exc.message, meta=exc.meta)


@app.exception_handler(Exception)
async def unhandled_exception_handler(request: Request, exc: Exception):
    logger.error("Unhandled server exception: %s", exc, exc_info=True)
    return format_error_response(
        status_code=500,
        code="internal_server_error",
        message="An internal server error occurred"
    )


# Middleware Registration Order (Starlette executes in reverse order):
# Registration Order: RateLimit (1st) -> ContentSize (2nd) -> TrustedHost (3rd) -> CORS (4th)
# Execution Order:    CORS (1st) -> TrustedHost (2nd) -> ContentSize (3rd) -> RateLimit (4th) -> Endpoints
app.add_middleware(
    RateLimitMiddleware,
    general_limiter=default_general_limiter,
    auth_limiter=default_auth_limiter,
    trust_proxy_headers=settings.trust_proxy_headers,
    trusted_proxies=settings.trusted_proxies
)
app.add_middleware(ContentSizeLimitMiddleware, max_bytes=settings.max_request_body_bytes)
app.add_middleware(
    TrustedHostMiddleware,
    allowed_hosts=settings.trusted_hosts,
    trust_proxy_headers=settings.trust_proxy_headers,
    trusted_proxies=settings.trusted_proxies
)
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.allowed_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=[
        "X-User-Id",
        "X-Timestamp",
        "X-Nonce-Counter",
        "X-Sync-Nonce",
        "X-Signature",
        "Content-Type",
        "Authorization"
    ],
    expose_headers=[
        "X-User-Id",
        "X-Nonce-Counter",
        "WWW-Authenticate",
        "Retry-After"
    ]
)

app.include_router(auth.router)
app.include_router(protected.router)
app.include_router(security.router)


@app.get("/")
def root():
    return {"status": "ok", "auth_type": "per-request-signature"}