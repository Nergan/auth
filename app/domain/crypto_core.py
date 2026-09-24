import hashlib
from app.domain.anti_replay import normalize_host, normalize_path, normalize_query, normalize_content_type


def build_canonical_payload(
    host: str,
    method: str,
    path: str,
    query: str,
    timestamp: int,
    nonce_counter: int,
    body_hash: str,
    content_type: str = ""
) -> str:
    """
    Constructs deterministic byte-length prefixed canonical string for request signature.
    Normalizes headers, query params, and Content-Type to prevent desync.
    """
    norm_host = normalize_host(host)
    norm_method = method.strip().upper()
    norm_path = normalize_path(path)
    norm_query = normalize_query(query)
    norm_ct = normalize_content_type(content_type)

    components = [
        norm_host,
        norm_method,
        norm_path,
        norm_query,
        str(timestamp),
        f"counter:{nonce_counter}",
        norm_ct,
        body_hash
    ]
    return "".join(f"{len(c.encode('utf-8'))}:{c}\n" for c in components)


def build_sync_canonical_payload(
    host: str,
    method: str,
    path: str,
    query: str,
    timestamp: int,
    sync_nonce: str,
    body_hash: str,
    content_type: str = ""
) -> str:
    """Constructs deterministic canonical string for out-of-band nonce synchronization requests."""
    norm_host = normalize_host(host)
    norm_method = method.strip().upper()
    norm_path = normalize_path(path)
    norm_query = normalize_query(query)
    norm_ct = normalize_content_type(content_type)

    components = [
        norm_host,
        norm_method,
        norm_path,
        norm_query,
        str(timestamp),
        f"sync:{sync_nonce}",
        norm_ct,
        body_hash
    ]
    return "".join(f"{len(c.encode('utf-8'))}:{c}\n" for c in components)


def build_registration_challenge(
    algorithm: str,
    canonical_key_bytes: bytes,
    timestamp: int,
    client_nonce: str
) -> str:
    """Constructs challenge payload proving private key ownership during identity registration."""
    key_hex = canonical_key_bytes.hex()
    components = ["register_pop", algorithm, key_hex, str(timestamp), client_nonce]
    return "".join(f"{len(c.encode('utf-8'))}:{c}\n" for c in components)


def generate_user_id(algorithm: str, canonical_key_bytes: bytes) -> str:
    """Generates immutable cryptographic fingerprint identifier (SHA-256) of identity public key."""
    hasher = hashlib.sha256()
    hasher.update(f"{len(algorithm)}:{algorithm}\n".encode("utf-8"))
    hasher.update(canonical_key_bytes)
    return hasher.hexdigest()