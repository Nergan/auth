import os
from typing import List
from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    mongodb_uri: str = "mongodb://localhost:27017"
    mongodb_db_name: str = "asymmetric_auth_db"
    mongo_tls: bool = False
    mongo_server_selection_timeout_ms: int = 5000
    mongo_connect_timeout_ms: int = 5000
    mongo_max_pool_size: int = 100
    mongo_min_pool_size: int = 10
    mongo_max_idle_time_ms: int = 60000
    mongo_wait_queue_timeout_ms: int = 5000

    max_request_body_bytes: int = 5 * 1024 * 1024  # 5 MB limit
    timestamp_tolerance_seconds: int = 120
    max_counter_window: int = 100  # Bounds forward jumps to prevent counter exhaustion DoS
    replay_window_size: int = 64  # Sliding window bitmask size for out-of-order concurrent requests
    crypto_max_workers: int = Field(default_factory=lambda: max(4, os.cpu_count() or 4))
    crypto_timeout_seconds: float = 5.0
    sync_nonce_ttl_seconds: int = 300

    rate_limit_requests: int = 60
    rate_limit_window_seconds: int = 60
    auth_rate_limit_requests: int = 15
    auth_rate_limit_window_seconds: int = 60

    trust_proxy_headers: bool = False
    trusted_proxies: List[str] = ["127.0.0.1", "::1"]
    trusted_hosts: List[str] = ["localhost", "127.0.0.1", "testserver"]

    allowed_origins: List[str] = [
        "http://localhost:3000",
        "http://localhost:5173",
        "http://127.0.0.1:3000",
        "http://127.0.0.1:5173",
        "http://localhost:8000",
    ]

    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore")


settings = Settings()