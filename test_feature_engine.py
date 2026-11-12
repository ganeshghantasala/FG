
from feature_engine import extract_features, feature_vector, UCI_FEATURES


def report(name, passed, details=""):
    status = "PASS" if passed else "CHECK"
    print(f"[{status}] {name}: {details}")


print("\n=== FakeGuard Feature Engine Tests ===\n")

# Test 1: HTTPS detection
features, meta = extract_features(
    "https://example.com/",
    "<html><head><title>Example</title></head><body>Welcome</body></html>"
)
report(
    "HTTPS detection",
    meta["https"] and features["sslfinal_state"] == 1,
    f"https={meta['https']}"
)

# Test 2: Long URL detection
long_url = "https://example.com/" + ("a" * 80)
features, meta = extract_features(long_url, "<html></html>")
report(
    "Long URL detection",
    features["URL_Length"] == -1,
    f"URL length={meta['url_length']}"
)

# Test 3: Password form and external form detection
html = """
<html><body>
<form action="https://collector.example.net/submit" method="post">
    <input type="password" name="password">
    <button type="submit">Sign in</button>
</form>
</body></html>
"""
features, meta = extract_features("https://example.com/", html)
report(
    "Password field detection",
    meta["password_fields"] == 1,
    f"password fields={meta['password_fields']}"
)
report(
    "External form detection",
    meta["external_form_actions"] == 1,
    f"external forms={meta['external_form_actions']}"
)

# Test 4: Check the domain-boundary comparison
# The destination is NOT a subdomain of paypal.com.
html = """
<html><body>
<form action="https://evilpaypal.com/submit">
    <input type="password">
</form>
</body></html>
"""
features, meta = extract_features("https://paypal.com/", html)

if meta["external_form_actions"] == 1:
    report("Domain boundary check", True, "Deceptive domain detected as external")
else:
    report(
        "Domain boundary check",
        False,
        "BUG FOUND: evilpaypal.com was not recognized as external"
    )

# Test 5: ML feature-vector size
features, meta = extract_features("https://example.com/", "<html></html>")
vector = feature_vector(features)
report(
    "ML feature vector",
    len(vector) == len(UCI_FEATURES) == 30,
    f"vector={len(vector)}, expected={len(UCI_FEATURES)}"
)

print("\n=== Tests completed ===")
