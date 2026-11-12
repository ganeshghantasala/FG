
import socket
from unittest.mock import MagicMock, patch

import app


def dns_answer(ip):
    family = socket.AF_INET6 if ":" in ip else socket.AF_INET
    return [
        (family, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", (ip, 443))
    ]


def make_response(status, url, headers=None, chunks=None):
    response = MagicMock()
    response.status_code = status
    response.url = url
    response.headers = headers or {}
    response.encoding = "utf-8"
    response.iter_content.return_value = iter(chunks or [])
    response.__enter__.return_value = response
    response.__exit__.return_value = False
    return response


def check(name, callback):
    try:
        callback()
        print(f"[PASS] {name}")
    except Exception as exc:
        print(f"[FAIL] {name}: {type(exc).__name__}: {exc}")
        raise


def test_public_hostname_allowed():
    with patch(
        "app.socket.getaddrinfo",
        return_value=dns_answer("93.184.216.34"),
    ):
        parsed = app.validate_public_http_url("https://example.com/")
        assert parsed.hostname == "example.com"


def test_private_ipv4_blocked():
    try:
        app.validate_public_http_url("http://127.0.0.1/")
    except ValueError:
        return
    raise AssertionError("Loopback IPv4 was not blocked")


def test_loopback_ipv6_blocked():
    try:
        app.validate_public_http_url("http://[::1]/")
    except ValueError:
        return
    raise AssertionError("Loopback IPv6 was not blocked")


def test_hostname_resolving_private_blocked():
    with patch(
        "app.socket.getaddrinfo",
        return_value=dns_answer("192.168.1.20"),
    ):
        try:
            app.validate_public_http_url("https://private.example/")
        except ValueError:
            return
    raise AssertionError("Private DNS result was not blocked")


def test_unsupported_scheme_blocked():
    try:
        app.validate_public_http_url("file:///C:/Windows/win.ini")
    except ValueError:
        return
    raise AssertionError("Unsupported URL scheme was not blocked")


def test_nonstandard_port_blocked():
    try:
        app.validate_public_http_url("http://example.com:8080/")
    except ValueError:
        return
    raise AssertionError("Nonstandard port was not blocked")


def test_redirect_to_loopback_blocked_before_second_request():
    redirect = make_response(
        302,
        "https://example.com/",
        headers={"Location": "http://127.0.0.1/admin"},
    )

    session = MagicMock()
    session.get.return_value = redirect

    session_context = MagicMock()
    session_context.__enter__.return_value = session
    session_context.__exit__.return_value = False

    with (
        patch("app.requests.Session", return_value=session_context),
        patch(
            "app.socket.getaddrinfo",
            return_value=dns_answer("93.184.216.34"),
        ),
    ):
        try:
            app.fetch_page("https://example.com/")
        except ValueError:
            pass
        else:
            raise AssertionError("Unsafe redirect was not blocked")

    assert session.get.call_count == 1, (
        "Fetcher made a request after the unsafe redirect"
    )


def test_response_body_limited_to_two_megabytes():
    limit = 2_000_000
    response = make_response(
        200,
        "https://example.com/",
        chunks=[b"a" * (limit + 100)],
    )

    session = MagicMock()
    session.get.return_value = response

    session_context = MagicMock()
    session_context.__enter__.return_value = session
    session_context.__exit__.return_value = False

    with (
        patch("app.requests.Session", return_value=session_context),
        patch(
            "app.socket.getaddrinfo",
            return_value=dns_answer("93.184.216.34"),
        ),
    ):
        _, html, status = app.fetch_page("https://example.com/")

    assert status == 200
    assert len(html.encode("utf-8")) == limit


if __name__ == "__main__":
    tests = [
        ("Public hostname allowed", test_public_hostname_allowed),
        ("Private IPv4 blocked", test_private_ipv4_blocked),
        ("Loopback IPv6 blocked", test_loopback_ipv6_blocked),
        ("Private DNS result blocked", test_hostname_resolving_private_blocked),
        ("Unsupported scheme blocked", test_unsupported_scheme_blocked),
        ("Nonstandard port blocked", test_nonstandard_port_blocked),
        ("Unsafe redirect blocked before request", test_redirect_to_loopback_blocked_before_second_request),
        ("Response limited to 2 MB", test_response_body_limited_to_two_megabytes),
    ]

    print("\n=== FakeGuard URL Fetcher Security Tests ===\n")
    for name, test in tests:
        check(name, test)
    print("\nAll fetcher security checks passed.")
