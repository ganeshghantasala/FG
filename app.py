import json, os, socket, time
import ipaddress
import joblib
import numpy as np
import pandas as pd
import requests
from urllib.parse import urljoin, urlparse
from flask import Flask, request, render_template_string, jsonify
from feature_engine import safe_url, private_or_local, extract_features, feature_vector,feature_vector_for_model
from risk_engine import calculate_fused_score, risk_label
app = Flask(__name__)
MODEL_FILE = "fakeguard_model_runtime.joblib"

PAGE = """
<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>FakeGuard | Website safety check</title>
<style>
:root {
    --ink: #172b3a;
    --muted: #617485;
    --line: #dce6e9;
    --paper: #ffffff;
    --background: #f3f7f8;
    --teal: #087e80;
    --teal-dark: #066568;
    --green: #19734d;
    --green-bg: #eaf7ef;
    --amber: #8a5700;
    --amber-bg: #fff5dd;
    --red: #a92c35;
    --red-bg: #fff0ef;
}
* { box-sizing: border-box; }
body {
    margin: 0;
    background: var(--background);
    color: var(--ink);
    font-family: "Segoe UI", Arial, sans-serif;
    line-height: 1.6;
}
button, input { font: inherit; }
button, input { min-height: 48px; }
a { color: var(--teal-dark); }
.wrap { max-width: 980px; width: calc(100% - 32px); margin: auto; }
header {
    background: var(--paper);
    border-bottom: 1px solid var(--line);
}
.nav {
    min-height: 74px;
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 18px;
}
.brand { display: flex; align-items: center; gap: 12px; font-weight: 800; font-size: 22px; }
.brand-mark {
    height: 40px; width: 40px; display: grid; place-items: center;
    background: #e1f5f2; color: var(--teal-dark);
    border-radius: 12px; font-weight: 900;
}
.nav-note { color: var(--muted); font-size: 14px; }
main { padding: 38px 0 56px; }
.hero { text-align: center; max-width: 700px; margin: 0 auto 26px; }
.eyebrow {
    text-transform: uppercase; letter-spacing: 1.3px;
    font-size: 12px; font-weight: 800; color: var(--teal);
}
h1 { font-size: clamp(30px, 5vw, 44px); line-height: 1.15; margin: 8px 0 14px; letter-spacing: -1px; }
h2 { line-height: 1.3; margin: 0 0 12px; font-size: 24px; }
h3 { margin: 0 0 12px; font-size: 18px; }
p { margin: 8px 0 14px; }
.lead { color: var(--muted); font-size: 18px; }
.card {
    background: var(--paper);
    border: 1px solid var(--line);
    border-radius: 20px;
    box-shadow: 0 8px 28px rgba(27, 58, 72, .05);
    padding: clamp(20px, 4vw, 32px);
    margin: 20px 0;
}
.form-label { display: block; font-weight: 750; margin-bottom: 8px; }
.input-row { display: flex; gap: 10px; }
input[name="url"] {
    flex: 1; min-width: 0; width: 100%;
    border: 1px solid #b7c8d0; border-radius: 11px;
    background: white; color: var(--ink); padding: 12px 14px;
}
input[name="url"]:focus { outline: 3px solid #b8e7e1; border-color: var(--teal); }
button {
    border: 0; border-radius: 11px; padding: 12px 20px;
    background: var(--teal); color: white; font-weight: 750;
    cursor: pointer; white-space: nowrap;
}
button:hover { background: var(--teal-dark); }
button:focus-visible { outline: 3px solid #8ad6ce; outline-offset: 3px; }
.help, .small { color: var(--muted); font-size: 14px; }
.notice {
    margin-top: 18px; padding: 13px 15px; border-radius: 10px;
    background: #f0f7f8; color: #385968; font-size: 14px;
}
.result-card { scroll-margin-top: 20px; }
.result-top { display: grid; grid-template-columns: 1fr auto; gap: 20px; align-items: start; }
.status-pill {
    display: inline-flex; align-items: center;
    border-radius: 999px; padding: 6px 12px; font-weight: 800; font-size: 14px;
}
.good { color: var(--green); background: var(--green-bg); }
.warn { color: var(--amber); background: var(--amber-bg); }
.bad { color: var(--red); background: var(--red-bg); }
.score-box { min-width: 115px; text-align: right; }
.score-number { font-size: 34px; font-weight: 850; line-height: 1.15; }
.score-caption { color: var(--muted); font-size: 13px; }
.progress { background: #e9eff0; height: 10px; border-radius: 99px; overflow: hidden; margin: 18px 0; }
.progress-fill { height: 100%; border-radius: 99px; }
.progress-fill.good { background: #2e9567; }
.progress-fill.warn { background: #d49420; }
.progress-fill.bad { background: #cf5157; }
.advice { border-radius: 12px; padding: 16px; margin: 18px 0 22px; }
.advice.good { background: var(--green-bg); }
.advice.warn { background: var(--amber-bg); }
.advice.bad { background: var(--red-bg); }
.advice strong { display: block; margin-bottom: 4px; }
.result-section { border-top: 1px solid var(--line); padding-top: 23px; margin-top: 24px; }
.reason-list { padding-left: 22px; margin-bottom: 0; }
.reason-list li { margin: 10px 0; padding-left: 3px; }
.evidence-grid, .signal-grid, .how-grid {
    display: grid; grid-template-columns: repeat(2, minmax(0, 1fr)); gap: 12px;
}
.evidence-item, .signal-item, .how-item {
    min-width: 0; padding: 14px; border: 1px solid var(--line);
    border-radius: 12px; background: #fbfdfd;
}
.evidence-label, .signal-label { display: block; color: var(--muted); font-size: 13px; margin-bottom: 4px; }
.evidence-value { display: block; overflow-wrap: anywhere; font-weight: 750; }
details { margin-top: 18px; border: 1px solid var(--line); border-radius: 12px; padding: 15px; }
summary { cursor: pointer; font-weight: 750; }
details[open] summary { margin-bottom: 14px; }
.signal-value { font-size: 21px; font-weight: 800; }
.actions { display: flex; flex-wrap: wrap; gap: 10px; margin-top: 22px; }
.button-secondary { background: white; border: 1px solid #b7c8d0; color: var(--ink); }
.button-secondary:hover { background: #f0f7f8; }
.how-section { margin-top: 34px; }
.how-grid { grid-template-columns: repeat(3, minmax(0, 1fr)); }
.how-item p { color: var(--muted); font-size: 14px; margin-bottom: 0; }
footer { padding: 24px 0 32px; border-top: 1px solid var(--line); color: var(--muted); font-size: 13px; }
footer p { margin: 6px 0; }
@media (max-width: 620px) {
    .nav { min-height: 64px; }
    .nav-note { display: none; }
    main { padding-top: 25px; }
    .input-row { flex-direction: column; }
    .input-row button { width: 100%; }
    .result-top { grid-template-columns: 1fr; }
    .score-box { text-align: left; }
    .evidence-grid, .signal-grid, .how-grid { grid-template-columns: 1fr; }
    .card { border-radius: 15px; }
}
@media print {
    body { background: white; color: black; }
    header, .hero, .scan-card, .how-section, footer, .no-print { display: none !important; }
    .wrap { width: 100%; max-width: none; }
    main { padding: 0; }
    .card { border: 0; box-shadow: none; margin: 0; padding: 8px; }
    .result-card { display: block; }
    details { display: block; }
    details:not([open]) > *:not(summary) { display: block !important; }
    details summary { display: none; }
}
</style>
</head>
<body>
<header>
    <div class="wrap nav">
        <div class="brand"><span class="brand-mark" aria-hidden="true">FG</span><span>FakeGuard</span></div>
        <div class="nav-note">A clearer way to check website warning signs</div>
    </div>
</header>

<main class="wrap">
    <section class="hero">
        <p class="eyebrow">Website safety check</p>
        <h1>Pause before you trust a link.</h1>
        <p class="lead">Check a website for warning signs before sharing passwords, payment details, or personal information.</p>
    </section>

    <section class="card scan-card">
        <form method="post">
            <label class="form-label" for="url">Website address</label>
            <div class="input-row">
                <input id="url" name="url" type="text" placeholder="https://example.com"
                       value="{{ url or '' }}" autocomplete="url" spellcheck="false" required>
                <button type="submit">Check website</button>
            </div>
            <p class="help">Paste the full link you want to check. Only check websites you are authorized to assess.</p>
        </form>
        <div class="notice">
            <strong>Important:</strong> FakeGuard looks for warning signs; it cannot guarantee that a website is safe. Never share a one-time code or password just because a scan reports low risk.
        </div>
    </section>

    {% if result %}
    <section class="card result-card" id="results" aria-live="polite">
        {% if result.label == "ANALYSIS ERROR" %}
            <span class="status-pill bad">Unable to check</span>
            <h2 style="margin-top:14px">We couldn't check this website</h2>
            <p>The address may be invalid, unreachable, or blocked by FakeGuard's safety checks.</p>
            <p class="small">Local and private network destinations are blocked. Check the address and try a public HTTP or HTTPS website.</p>
        {% else %}
            {% if result.meta.get('brand_domain_mismatch') %}
            <div class="advice warn" role="note" style="margin-bottom:16px">
                <strong>Manual review recommended — brand/domain mismatch</strong>
                <p>A supported brand term appears in a hostname whose registered domain is not on FakeGuard's configured official-domain list. This is a warning for manual review, not proof that the website is phishing.</p>
            </div>
            {% endif %}
            <div class="result-top">
                <div>
                    <p class="eyebrow">Your result</p>
                    {% if result.score >= 75 %}
                        <span class="status-pill bad">High risk</span>
                        <h2 style="margin-top:12px">Potential danger detected</h2>
                        <p>Several warning signs were found. Avoid entering sensitive information on this page.</p>
                    {% elif result.score >= 45 %}
                        <span class="status-pill warn">Use caution</span>
                        <h2 style="margin-top:12px">Check carefully before proceeding</h2>
                        <p>Some warning signs were found. Verify the website independently before sharing personal details.</p>
                    {% else %}
                        <span class="status-pill good">Lower risk in this scan</span>
                        {% if result.meta.get('brand_domain_mismatch') or result.reasons|length > 1 %}
                            <h2 style="margin-top:12px">Some warning signs were found</h2>
                            <p>The overall score is below the caution level, but review these findings before sharing personal information.</p>
                        {% else %}
                            <h2 style="margin-top:12px">No major warning signs found</h2>
                            <p>This scan did not find many warning signs. That does not mean the website is guaranteed safe.</p>
                        {% endif %}
                    {% endif %}
                </div>
                <div class="score-box">
                    <div class="score-caption">Overall risk score</div>
                    <div class="score-number">{{ result.score }}%</div>
                    <div class="score-caption">Heuristic score, not a probability</div>
                </div>
            </div>

            <div class="progress" role="img" aria-label="Overall heuristic risk score">
                <div class="progress-fill {{ result.cls }}" style="width: {{ result.score }}%"></div>
            </div>

            <div class="advice {{ result.cls }}">
                <strong>What should you do?</strong>
                {% if result.score >= 75 %}
                    Do not enter passwords, payment details, or one-time codes. If you received this link unexpectedly, close it and use the service's official app or type its known address yourself.
                {% elif result.score >= 45 %}
                    Pause before sharing information. Check the website address carefully and contact the organization using a contact method you already trust.
                {% else %}
                    No major warning signs were detected in this scan. Continue to check the address and do not share sensitive information unless you trust the website independently.
                {% endif %}
            </div>

            <div class="result-section">
                <h3>What we noticed</h3>
                <ul class="reason-list">
                    {% for x in result.reasons %}<li>{{ x }}</li>{% endfor %}
                </ul>
            </div>

            <div class="result-section">
                <h3>Website details</h3>
                <div class="evidence-grid">
                    <div class="evidence-item">
                        <span class="evidence-label">Website domain</span>
                        <span class="evidence-value">{{ result.meta.registered_domain }}</span>
                    </div>
                    <div class="evidence-item">
                        <span class="evidence-label">HTTPS connection detected</span>
                        <span class="evidence-value">{{ "Yes" if result.meta.https else "No" }}</span>
                    </div>
                    <div class="evidence-item">
                        <span class="evidence-label">Password entry boxes</span>
                        <span class="evidence-value">{{ "Found: " ~ result.meta.password_fields if result.meta.password_fields else "None found" }}</span>
                    </div>
                    <div class="evidence-item">
                        <span class="evidence-label">Forms that send information to another domain</span>
                        <span class="evidence-value">{{ result.meta.external_form_actions }}</span>
                    </div>
                    <div class="evidence-item">
                        <span class="evidence-label">Links to other websites</span>
                        <span class="evidence-value">{{ result.meta.external_links }} of {{ result.meta.total_links }}</span>
                    </div>
                    <div class="evidence-item">
                        <span class="evidence-label">Embedded frames</span>
                        <span class="evidence-value">{{ result.meta.iframes }}</span>
                    </div>
                </div>
                <p class="small">A single item, such as using HTTPS or linking to another website, does not by itself prove that a site is safe or fraudulent.</p>
            </div>

            <details class="technical-details">
                <summary>Technical details for advanced users</summary>
                <p class="small">These component scores are internal signals used by FakeGuard. They are not independently calibrated probabilities.</p>
                <div class="signal-grid">
                    <div class="signal-item">
                        <span class="signal-label">URL model score</span>
                        <div class="signal-value">{{ result.ml }}%</div>
                    </div>
                    <div class="signal-item">
                        <span class="signal-label">Page behavior score</span>
                        <div class="signal-value">{{ result.html }}%</div>
                    </div>
                    <div class="signal-item">
                        <span class="signal-label">Identity/deception signal</span>
                        <div class="signal-value">{{ result.identity }}%</div>
                    </div>
                    <div class="signal-item">
                        <span class="signal-label">Address length</span>
                        <div class="signal-value">{{ result.meta.url_length }} characters</div>
                    </div>
                </div>
                <p class="small">FakeGuard fetches page HTML but does not execute the page's JavaScript. Some signals are approximations, and detection may miss phishing pages or flag legitimate ones.</p>
            </details>
        {% endif %}

        <div class="actions no-print">
            <button type="button" class="button-secondary" onclick="window.print()">Print or save report</button>
        </div>
    </section>
    {% endif %}

    <section class="how-section">
        <p class="eyebrow">How it works</p>
        <h2>Three checks, one understandable result</h2>
        <div class="how-grid">
            <div class="how-item">
                <h3>1. The web address</h3>
                <p>FakeGuard checks address patterns that may appear in deceptive links.</p>
            </div>
            <div class="how-item">
                <h3>2. The page itself</h3>
                <p>It checks available page content, including password boxes and form destinations.</p>
            </div>
            <div class="how-item">
                <h3>3. The combined signals</h3>
                <p>It combines these clues into a risk score and explains the warning signs it found.</p>
            </div>
        </div>
    </section>
</main>

<footer>
    <div class="wrap">
        <p><strong>FakeGuard research prototype</strong></p>
        <p>A low-risk result is not a guarantee of safety. If a message asks you to act urgently, pay unexpectedly, or share a password or one-time code, verify it through a trusted channel.</p>
        <p>Webpages are fetched without executing JavaScript. Findings may be incomplete.</p>
    </div>
</footer>
</body>
</html>
"""

def load_model():
    if not os.path.exists(MODEL_FILE):
        return None
    return joblib.load(MODEL_FILE)

def validate_public_http_url(url):
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


def apply_brand_domain_review_floor(score, meta, threshold=0.45):
    # Apply a cautious manual-review floor; this is not proof of phishing.
    score = float(score)
    threshold = float(threshold)
    if not 0.0 <= score <= 1.0:
        raise ValueError('score must be between 0 and 1')
    if not 0.0 <= threshold <= 1.0:
        raise ValueError('threshold must be between 0 and 1')
    flagged = bool((meta or {}).get('brand_domain_mismatch'))
    return (max(score, threshold) if flagged else score), flagged


def analyze(url):
    url = safe_url(url)
    host = __import__("urllib.parse").parse.urlparse(url).hostname or ""
    try:
        ip = socket.gethostbyname(host)
        if private_or_local(ip):
            raise ValueError("Private/local destination blocked by FakeGuard safety policy.")
    except socket.gaierror:
        pass

    final_url, html, status = fetch_page(url)
    f, meta = extract_features(final_url, html, original_url=url)

    bundle = load_model()
    if bundle:
        X = pd.DataFrame(
            [feature_vector_for_model(f, bundle["feature_names"])],
            columns=bundle["feature_names"]
        )
        ml_risk = float(bundle["model"].predict_proba(X)[0][1])
    else:
        # Fallback only: not an ML result.
        suspicious = sum(1 for v in f.values() if v == -1)
        ml_risk = min(0.95, suspicious / 12.0)

    html_risk = meta["html_risk"]
    identity_risk = meta["identity_risk"]
    score, contradiction = calculate_fused_score(ml_risk, meta)
    base_score = score
    score, review_floor_applied = apply_brand_domain_review_floor(score, meta)

    reasons = []
    if ml_risk > 0.55: reasons.append("The web address has patterns that can appear in phishing links.")
    if len(final_url) >= 75: reasons.append("The web address is unusually long, which can make the destination harder to judge.")
    if "@" in final_url: reasons.append("The address contains an '@' character, which can make the true destination harder to spot.")
    if meta["external_form_actions"]: reasons.append("A form sends information to a different website. Check this carefully before entering personal details.")
    if meta["password_fields"]: reasons.append("This page asks for a password. Only enter it after independently verifying the website is official.")
    if meta["iframes"]: reasons.append("The page includes embedded content from another frame or page. This is worth reviewing, but is not proof of harm.")
    if meta["external_links"] > 0 and meta["total_links"] > 0: reasons.append("The page links to other websites or loads content from them. This can be normal and is not proof of a scam.")
    if not meta["https"]:
        reasons.append("This page uses an unencrypted HTTP connection. Avoid entering passwords or payment details until you independently verify the website. HTTP alone does not prove fraud.")
    if meta["suspicious_terms"]: reasons.append("The address or page includes account/security terms: " + ", ".join(meta["suspicious_terms"][:6]))
    if meta.get("brand_domain_mismatch"):
        brands = ", ".join(meta.get("brand_mismatch_brands", []))
        submitted_domain = meta.get("submitted_registered_domain") or "an unrecognized domain"
        reasons.append(
            f"Brand/domain review warning: the submitted hostname contains a known brand term ({brands}), "
            f"but its registered domain is {submitted_domain}. Verify the address through the brand's official website. "
            "This warning is not confirmation of phishing."
        )
    if contradiction: reasons.append("The address looked lower-risk to the model, but page behavior raised concerns, so FakeGuard increased the review score.")
    if not reasons: reasons.append("This scan did not find strong warning signs. No scanner can guarantee that a website is safe.")

    label, cls = risk_label(score)

    return {
        "label":label, "cls":cls, "score":round(score*100,1),
        "ml":round(ml_risk*100,1),
        "html":round(html_risk*100,1), "identity":round(identity_risk*100,1),
        "reasons":reasons, "meta":meta, "status":status, "final_url":final_url,
        "base_score":round(base_score*100,1),
        "brand_review_floor_applied":review_floor_applied
    }

@app.route("/", methods=["GET","POST"])
def home():
    result=None; url=""
    if request.method=="POST":
        url=request.form.get("url","")
        try:
            result=analyze(url)
        except Exception as e:
            result={"label":"ANALYSIS ERROR","cls":"bad","score":0,"conf":0,
                    "ml":0,"html":0,"identity":0,
                    "reasons":[str(e)],"meta":{"registered_domain":"-","url_length":0,
                    "forms":0,"password_fields":0,"external_form_actions":0,
                    "external_links":0,"total_links":0,"iframes":0,"https":False}}
    return render_template_string(PAGE,result=result,url=url)


@app.route("/api/analyze", methods=["POST"])
def api():
    data = request.get_json(silent=True)

    if (
        not isinstance(data, dict)
        or not isinstance(data.get("url"), str)
        or not data["url"].strip()
    ):
        return jsonify({
            "error": "Provide a JSON request containing a non-empty 'url' string."
        }), 400

    try:
        result = analyze(data["url"].strip())
        return jsonify(result)

    except ValueError as exc:
        return jsonify({"error": str(exc)}), 400

    except requests.Timeout:
        return jsonify({"error": "The target page request timed out."}), 504

    except requests.RequestException:
        return jsonify({"error": "The target page could not be fetched."}), 502

    except Exception:
        app.logger.exception("Unexpected API analysis error")
        return jsonify({"error": "An internal analysis error occurred."}), 500


if __name__=="__main__":
    print("FakeGuard running at http://127.0.0.1:5000")
    app.run(host="127.0.0.1", port=5000, debug=False)
