
from pathlib import Path
import shutil

app_file = Path("app.py")
backup_file = Path("app.py.before_fetcher_hardening.bak")

source = app_file.read_text(encoding="utf-8")

start_marker = "def fetch_page(url):\n"
end_marker = "def analyze(url):\n"

start = source.find(start_marker)
end = source.find(end_marker, start)

if start == -1 or end == -1:
    raise RuntimeError(
        "Could not locate fetch_page() and analyze(). "
        "No changes made."
    )

if "def validate_public_http_url(url):" in source:
    raise RuntimeError(
        "URL validation helper already exists. "
        "No changes made."
    )

replacement = '''def validate_public_http_url(url):
    """Best-effort checks before requesting a public HTTP(S) URL."""
    from urllib.parse import urlparse
    import ipaddress

    parsed = urlparse(url)
    scheme = parsed.scheme.lower()

    if scheme not in ("http", "https"):
        raise ValueError("Only HTTP and HTTPS URLs are supported.")

    if not parsed.hostname:
        raise ValueError("The URL has no hostname.")

    if parsed.username is not None or parsed.password is not None:
        raise ValueError("URLs containing embedded credentials are blocked.")

    try:
        port = parsed.port
    except ValueError as exc:
        raise ValueError("The URL has an invalid port.") from exc

    expected_port = 443 if scheme == "https" else 80
    if port is not None and port != expected_port:
        raise ValueError("Only standard HTTP and HTTPS ports are allowed.")

    host = parsed.hostname

    try:
        addresses = {ipaddress.ip_address(host)}
    except ValueError:
        try:
            records = socket.getaddrinfo(
                host, expected_port, type=socket.SOCK_STREAM
            )
        except socket.gaierror as exc:
            raise ValueError("The hostname could not be resolved.") from exc

        addresses = set()
        for record in records:
            raw_ip = record[4][0].split("%", 1)[0]
            try:
                addresses.add(ipaddress.ip_address(raw_ip))
            except ValueError:
                continue

    if not addresses:
        raise ValueError("The hostname did not resolve to an IP address.")

    if any(not address.is_global for address in addresses):
        raise ValueError(
            "A private, local, reserved, or otherwise non-public "
            "destination was blocked."
        )

    return parsed


def fetch_page(url):
    """Fetch HTML with redirect checks and bounded response consumption."""
    from urllib.parse import urljoin

    headers = {
        "User-Agent": "FakeGuard-Research-Demo/1.0",
        "Accept": "text/html,application/xhtml+xml",
    }

    max_bytes = 2_000_000
    max_redirects = 5
    redirect_codes = {301, 302, 303, 307, 308}
    current_url = url
    started_at = time.monotonic()
    max_elapsed_seconds = 30

    # Avoid inheriting proxy settings from the process environment.
    # DNS is checked before every request, but this does not fully
    # eliminate DNS-rebinding risks; use network-level egress controls
    # for deployments.
    with requests.Session() as session:
        session.trust_env = False

        for redirect_count in range(max_redirects + 1):
            validate_public_http_url(current_url)

            if time.monotonic() - started_at > max_elapsed_seconds:
                raise ValueError("The page fetch exceeded the time limit.")

            with session.get(
                current_url,
                headers=headers,
                timeout=(3, 5),
                allow_redirects=False,
                stream=True,
            ) as response:

                if response.status_code in redirect_codes:
                    location = response.headers.get("Location")
                    if not location:
                        raise ValueError(
                            "The redirect response has no Location header."
                        )

                    if redirect_count >= max_redirects:
                        raise ValueError("Too many redirects.")

                    # Validate the new URL at the beginning of the next loop.
                    current_url = urljoin(current_url, location)
                    continue

                content = bytearray()

                for chunk in response.iter_content(chunk_size=16384):
                    if time.monotonic() - started_at > max_elapsed_seconds:
                        raise ValueError(
                            "The page download exceeded the time limit."
                        )

                    if not chunk:
                        continue

                    remaining = max_bytes - len(content)
                    if remaining <= 0:
                        break

                    content.extend(chunk[:remaining])

                    if len(content) >= max_bytes:
                        break

                html = bytes(content).decode(
                    response.encoding or "utf-8",
                    errors="replace",
                )

                return response.url, html, response.status_code

    raise ValueError("The page could not be fetched.")


'''

# Back up the original before modifying it.
if not backup_file.exists():
    shutil.copy2(app_file, backup_file)

# Add standard-library imports if missing.
updated = source
if "import ipaddress" not in updated:
    updated = updated.replace(
        "import json, os, socket, time\n",
        "import json, os, socket, time\nimport ipaddress\n",
        1,
    )

if "from urllib.parse import urljoin, urlparse" not in updated:
    updated = updated.replace(
        "import requests\n",
        "import requests\nfrom urllib.parse import urljoin, urlparse\n",
        1,
    )

# Recalculate offsets after import changes.
start = updated.find(start_marker)
end = updated.find(end_marker, start)

if start == -1 or end == -1:
    raise RuntimeError(
        "Could not locate fetcher after import changes. "
        "Restore the backup if necessary."
    )

updated = updated[:start] + replacement + updated[end:]
app_file.write_text(updated, encoding="utf-8")

print("Fetcher update complete.")
print(f"Backup: {backup_file}")
print("Redirect checks: added")
print("Public-IP checks: added")
print("Response-size limit: 2,000,000 bytes")
print("Redirect limit: 5")
print("Fetch time limit: 30 seconds")
print("Original model and risk engine were not changed.")
