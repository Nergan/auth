import re
from typing import Tuple, List, Sequence, Union, Mapping, Any
from urllib.parse import parse_qsl, quote

UNRESERVED_CHARS = set(b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_.~")


def evaluate_sliding_replay_window(
    current_base: int,
    current_mask: int,
    presented: int,
    max_forward_jump: int = 100,
    window_size: int = 64
) -> Tuple[bool, int, str, int, int]:
    """
    RFC 6479-compliant sliding replay window evaluation.
    Tracks received sequence numbers using a bitmask to support out-of-order execution.
    Returns (is_valid, expected_base, error_reason, new_base, new_mask).
    """
    if presented <= 0:
        return False, current_base + 1, "invalid_counter_range", current_base, current_mask

    if presented > current_base + max_forward_jump:
        return False, current_base + 1, "forward_jump_too_large", current_base, current_mask

    # Case 1: Sequence advances ahead of current max sequence
    if presented > current_base:
        diff = presented - current_base
        if diff >= window_size:
            new_mask = 1
        else:
            new_mask = ((current_mask << diff) | 1) & ((1 << window_size) - 1)
        return True, presented + 1, "", presented, new_mask

    # Case 2: Sequence falls inside the sliding window
    diff = current_base - presented
    if diff >= window_size:
        return False, current_base + 1, "replay_detected", current_base, current_mask

    if (current_mask >> diff) & 1:
        return False, current_base + 1, "replay_detected", current_base, current_mask

    # Out-of-order counter accepted within window
    new_mask = current_mask | (1 << diff)
    return True, current_base + 1, "", current_base, new_mask


def normalize_content_type(content_type: str) -> str:
    """
    Deterministic Content-Type normalization according to RFC 9110 media-type specs.
    Extracts essence and sorts media parameters alphabetically.
    """
    if not content_type:
        return ""
    parts = [p.strip() for p in content_type.split(";") if p.strip()]
    if not parts:
        return ""

    essence = parts[0].lower()
    params = []
    for p in parts[1:]:
        if "=" in p:
            k, v = p.split("=", 1)
            params.append((k.strip().lower(), v.strip().strip('"')))

    params.sort(key=lambda item: item[0])
    if not params:
        return essence

    param_str = ";".join(f"{k}={v}" for k, v in params)
    return f"{essence};{param_str}"


def normalize_host(host: str) -> str:
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


def is_host_trusted(host: str, trusted_hosts: Sequence[str]) -> bool:
    if "*" in trusted_hosts:
        return True
    if not host:
        return False

    norm_host = normalize_host(host)
    norm_hostname = norm_host
    if norm_host.startswith("["):
        if "]" in norm_host:
            norm_hostname = norm_host[:norm_host.index("]") + 1]
    elif ":" in norm_host:
        norm_hostname = norm_host.split(":", 1)[0]

    for th in trusted_hosts:
        th_norm = normalize_host(th)
        if norm_host == th_norm:
            return True
        if ":" not in th_norm and norm_hostname == th_norm:
            return True

    return False


def resolve_host(
    headers: Union[Mapping[str, Any], Sequence[Tuple[bytes, bytes]], Any],
    client_ip: str = "",
    trust_proxy_headers: bool = False,
    trusted_proxies: Sequence[str] = ()
) -> str:
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


def remove_dot_segments(path: str) -> str:
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
                    segment, input_buffer = input_buffer[:next_slash], input_buffer[next_slash:]
                else:
                    segment, input_buffer = input_buffer, ""
            else:
                next_slash = input_buffer.find("/")
                if next_slash != -1:
                    segment, input_buffer = input_buffer[:next_slash], input_buffer[next_slash:]
                else:
                    segment, input_buffer = input_buffer, ""
            output_segments.append(segment)
    result = "".join(output_segments)
    return result if result.startswith("/") else "/" + result


def normalize_percent_encoding(text: str) -> str:
    def _replace_pct(match: re.Match) -> str:
        byte_val = int(match.group(1), 16)
        return chr(byte_val) if byte_val in UNRESERVED_CHARS else f"%{match.group(1).upper()}"
    return re.sub(r"%([0-9a-fA-F]{2})", _replace_pct, text)


def normalize_path(path: str) -> str:
    if not path:
        return "/"
    clean_path = normalize_percent_encoding(path.strip())
    clean_path = remove_dot_segments(clean_path)
    clean_path = re.sub(r"/+", "/", clean_path)
    if not clean_path.startswith("/"):
        clean_path = "/" + clean_path
    return normalize_percent_encoding(clean_path)


def normalize_query(query: str) -> str:
    if not query:
        return ""
    pairs: List[Tuple[str, str]] = parse_qsl(query, keep_blank_values=True)
    pairs.sort(key=lambda item: (item[0], item[1]))
    return "&".join(f"{quote(k, safe='-_.~')}={quote(v, safe='-_.~')}" for k, v in pairs)