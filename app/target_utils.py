from urllib.parse import urlparse

ALLOWED_HOSTS = {"localhost", "127.0.0.1"}


def normalize_target(raw_target: str, raw_port=None) -> tuple[str, int, str]:
    """Normalize an operator-entered localhost URL/host into policy-safe host+port."""
    value = (raw_target or "").strip()
    if not value:
        raise ValueError("Target URL is required. Example: http://127.0.0.1:3000")
    candidate = value if "://" in value else f"http://{value}"
    parsed = urlparse(candidate)
    host = (parsed.hostname or "").lower()
    if host not in ALLOWED_HOSTS:
        raise ValueError("Only localhost and 127.0.0.1 targets are permitted by the POC.")
    port = int(raw_port or parsed.port or 3000)
    if not 1 <= port <= 65535:
        raise ValueError("Target port must be between 1 and 65535.")
    scheme = parsed.scheme if parsed.scheme in {"http", "https"} else "http"
    display = f"{scheme}://{host}:{port}"
    return host, port, display
