import hashlib
from app.domain.anti_replay import normalize_host, normalize_path, normalize_query


def build_canonical_payload(
    host: str,
    method: str,
    path: str,
    query: str,
    timestamp: int,
    nonce_counter: int,
    body_hash: str
) -> str:
    """Deterministic, normalized canonical payload construction with length framing."""
    norm_host = normalize_host(host)
    norm_method = method.strip().upper()
    norm_path = normalize_path(path)
    norm_query = normalize_query(query)

    components = [norm_host, norm_method, norm_path, norm_query, str(timestamp), f"counter:{nonce_counter}", body_hash]
    return "".join(f"{len(c.encode('utf-8'))}:{c}\n" for c in components)


def build_sync_canonical_payload(
    host: str,
    method: str,
    path: str,
    query: str,
    timestamp: int,
    sync_nonce: str,
    body_hash: str
) -> str:
    """Deterministic canonical payload construction for challenge-bound nonce synchronization."""
    norm_host = normalize_host(host)
    norm_method = method.strip().upper()
    norm_path = normalize_path(path)
    norm_query = normalize_query(query)

    components = [norm_host, norm_method, norm_path, norm_query, str(timestamp), f"sync:{sync_nonce}", body_hash]
    return "".join(f"{len(c.encode('utf-8'))}:{c}\n" for c in components)


def build_registration_challenge(
    algorithm: str,
    canonical_key_bytes: bytes,
    timestamp: int,
    client_nonce: str
) -> str:
    """Constructs a deterministic PoP challenge string bound to key, timestamp, and client challenge nonce."""
    key_hex = canonical_key_bytes.hex()
    components = ["register_pop", algorithm, key_hex, str(timestamp), client_nonce]
    return "".join(f"{len(c.encode('utf-8'))}:{c}\n" for c in components)


def generate_user_id(algorithm: str, canonical_key_bytes: bytes) -> str:
    """Hashes algorithm and canonical key bytes with length-framing to establish user identity."""
    hasher = hashlib.sha256()
    hasher.update(f"{len(algorithm)}:{algorithm}\n".encode("utf-8"))
    hasher.update(canonical_key_bytes)
    return hasher.hexdigest()