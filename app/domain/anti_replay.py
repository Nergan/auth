import re
from typing import Tuple, List, Sequence, Union, Mapping, Any
from urllib.parse import parse_qsl, quote

SLIDING_WINDOW_SIZE = 64  # 64-bit window
UNRESERVED_CHARS = set(b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_.~")


def evaluate_sliding_window(
    base: int,
    mask: int,
    presented: int,
    window_size: int = SLIDING_WINDOW_SIZE,
    max_forward_window: int = 100
) -> Tuple[bool, int, int, str]:
    """
    RFC 6479 bitmask sliding window anti-replay evaluation.
    Returns (is_valid, new_base, new_mask, error_reason).
    """
    if presented <= 0:
        return False, base, mask, "invalid_counter_range"

    if base == 0:
        if presented > max_forward_window:
            return False, base, mask, "forward_jump_too_large"
        return True, presented, 0, ""

    if presented > base:
        delta = presented - base
        if delta > max_forward_window:
            return False, base, mask, "forward_jump_too_large"

        if delta > window_size:
            new_mask = 0
        else:
            new_mask = ((mask << delta) | (1 << (delta - 1))) & ((1 << window_size) - 1)

        return True, presented, new_mask, ""

    if presented == base:
        return False, base, mask, "replay_detected"

    # presented < base
    delta = base - presented
    if delta > window_size:
        return False, base, mask, "counter_too_old"

    bit_index = delta - 1
    if (mask & (1 << bit_index)) != 0:
        return False, base, mask, "replay_detected"

    new_mask = mask | (1 << bit_index)
    return True, base, new_mask, ""


def normalize_host(host: str) -> str:
    """
    Standardizes host strings by stripping default ports (80/443) and lowercasing.
    Handles IPv6 bracketed literals and standard hostname/IPv4 formats.
    """
    if not host:
        return ""
    host_clean = host.strip().lower()
    if host_clean.startswith("["):
        if "]" in host_clean:
            ipv6_part, _, rest = host_clean.partition("]")
            bracketed = ipv6_part + "]"
            if rest.startswith(":"):
                port = rest[1:]
                if port in ("80", "443"):
                    return bracketed
                return bracketed + ":" + port
            return bracketed
    elif ":" in host_clean:
        if host_clean.count(":") == 1:
            hostname, port = host_clean.split(":", 1)
            if port in ("80", "443"):
                return hostname
    return host_clean


def resolve_host(
    headers: Union[Mapping[str, Any], Sequence[Tuple[bytes, bytes]], Any],
    client_ip: str = "",
    trust_proxy_headers: bool = False,
    trusted_proxies: Sequence[str] = ()
) -> str:
    """
    Resolves canonical request host taking into account HTTP/2 authority,
    Host header, and X-Forwarded-Host when proxy trust is established.
    Accepts Starlette Headers, Mapping/dict instances, or ASGI raw header sequences.
    """
    header_map: dict[str, str] = {}

    if hasattr(headers, "items"):
        for k, v in headers.items():
            k_str = k.decode("latin-1").lower() if isinstance(k, bytes) else str(k).lower()
            v_str = v.decode("latin-1") if isinstance(v, bytes) else str(v)
            header_map[k_str] = v_str
    elif isinstance(headers, (list, tuple)):
        for item in headers:
            if isinstance(item, (list, tuple)) and len(item) == 2:
                k, v = item
                k_str = k.decode("latin-1").lower() if isinstance(k, bytes) else str(k).lower()
                v_str = v.decode("latin-1") if isinstance(v, bytes) else str(v)
                header_map[k_str] = v_str

    raw_host = ""
    if trust_proxy_headers and client_ip in trusted_proxies:
        forwarded = header_map.get("x-forwarded-host")
        if forwarded:
            raw_host = forwarded.split(",")[0].strip()

    if not raw_host:
        raw_host = header_map.get(":authority") or header_map.get("host") or ""

    return normalize_host(raw_host)


def is_host_trusted(host: str, trusted_hosts: Sequence[str]) -> bool:
    """Validates whether normalized host matches configured trusted host patterns."""
    if "*" in trusted_hosts:
        return True
    if not host:
        return False
    clean_host = normalize_host(host)
    return clean_host in trusted_hosts


def remove_dot_segments(path: str) -> str:
    """Removes relative dot segments '.' and '..' according to RFC 3986 Section 5.2.4."""
    if not path:
        return "/"

    input_buffer = path
    output_segments: List[str] = []

    while input_buffer:
        if input_buffer.startswith("../"):
            input_buffer = input_buffer[3:]
        elif input_buffer.startswith("./"):
            input_buffer = input_buffer[2:]
        elif input_buffer.startswith("/./"):
            input_buffer = "/" + input_buffer[3:]
        elif input_buffer == "/.":
            input_buffer = "/"
        elif input_buffer.startswith("/../"):
            input_buffer = "/" + input_buffer[4:]
            if output_segments:
                output_segments.pop()
        elif input_buffer == "/..":
            input_buffer = "/"
            if output_segments:
                output_segments.pop()
        elif input_buffer in (".", ".."):
            input_buffer = ""
        else:
            if input_buffer.startswith("/"):
                next_slash = input_buffer.find("/", 1)
                if next_slash != -1:
                    segment = input_buffer[:next_slash]
                    input_buffer = input_buffer[next_slash:]
                else:
                    segment = input_buffer
                    input_buffer = ""
            else:
                next_slash = input_buffer.find("/")
                if next_slash != -1:
                    segment = input_buffer[:next_slash]
                    input_buffer = input_buffer[next_slash:]
                else:
                    segment = input_buffer
                    input_buffer = ""
            output_segments.append(segment)

    result = "".join(output_segments)
    if not result.startswith("/"):
        result = "/" + result
    return result


def normalize_percent_encoding(text: str) -> str:
    """
    Decodes RFC 3986 unreserved percent-encoded characters and uppercases remaining hex triplets.
    """
    def _replace_pct(match: re.Match) -> str:
        hex_val = match.group(1)
        byte_val = int(hex_val, 16)
        if byte_val in UNRESERVED_CHARS:
            return chr(byte_val)
        return f"%{hex_val.upper()}"

    return re.sub(r"%([0-9a-fA-F]{2})", _replace_pct, text)


def normalize_path(path: str) -> str:
    """
    Normalizes URL path by decoding unreserved characters first, resolving dot segments,
    collapsing duplicate slashes, ensuring a leading slash, and canonicalizing hex encodings.
    """
    if not path:
        return "/"
    clean_path = path.strip()
    # Step 1: Decode unreserved percent-encoded characters (including %2e -> '.')
    clean_path = normalize_percent_encoding(clean_path)
    # Step 2: Remove dot segments on decoded path
    clean_path = remove_dot_segments(clean_path)
    # Step 3: Collapse redundant duplicate slashes
    clean_path = re.sub(r"/+", "/", clean_path)
    if not clean_path.startswith("/"):
        clean_path = "/" + clean_path
    # Step 4: Uppercase remaining valid percent-encodings
    return normalize_percent_encoding(clean_path)


def normalize_query(query: str) -> str:
    """Sorts query parameters lexicographically by key and value using RFC 3986 percent-encoding."""
    if not query:
        return ""
    pairs: List[Tuple[str, str]] = parse_qsl(query, keep_blank_values=True)
    pairs.sort(key=lambda item: (item[0], item[1]))
    return "&".join(f"{quote(k, safe='-_.~')}={quote(v, safe='-_.~')}" for k, v in pairs)