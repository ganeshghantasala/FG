
from pathlib import Path

app_file = Path("app.py")
source = app_file.read_text(encoding="utf-8")

start_marker = 'PAGE = """'
end_marker = '"""\n\ndef load_model'

start = source.find(start_marker)
end = source.find(end_marker, start)

if start < 0 or end < 0:
    raise RuntimeError(
        "Could not locate the PAGE template. No changes made."
    )

new_page = '''PAGE = """
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
                        <h2 style="margin-top:12px">No major warning signs found</h2>
                        <p>This scan did not find many warning signs. That does not mean the website is guaranteed safe.</p>
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
"""'''

reason_replacements = {
    "The URL-level model detected multiple phishing-associated URL/domain patterns.":
        "The web address has patterns that can appear in phishing links.",
    "The URL is unusually long and may be using obfuscation.":
        "The web address is unusually long, which can make the destination harder to judge.",
    "The URL contains '@', which can obscure the actual destination.":
        "The address contains an '@' character, which can make the true destination harder to spot.",
    "A form submits to an external domain, creating a credential-exfiltration signal.":
        "A form sends information to a different website. Check this carefully before entering personal details.",
    "The page requests password credentials.":
        "This page asks for a password. Only enter it after independently verifying the website is official.",
    "The page contains iframe/frame elements.":
        "The page includes embedded content from another frame or page. This is worth reviewing, but is not proof of harm.",
    "The page contains links/resources pointing outside its registered domain.":
        "The page links to other websites or loads content from them. This can be normal and is not proof of a scam.",
    "Security/account-related terms were found in the URL/page text: ":
        "The address or page includes account/security terms: ",
    "Cross-signal contradiction detected: URL-level and page-behavior evidence disagree, so FakeGuard increases review risk.":
        "The address looked lower-risk to the model, but page behavior raised concerns, so FakeGuard increased the review score.",
    "No strong phishing indicators were observed by the current prototype.":
        "This scan did not find strong warning signs. No scanner can guarantee that a website is safe.",
}

updated = source[:start] + new_page + source[end + len('"""'):]
for old, new in reason_replacements.items():
    if old not in updated:
        raise RuntimeError(
            f"Expected explanation text not found; no file written:\n{old}"
        )
    updated = updated.replace(old, new, 1)

app_file.write_text(updated, encoding="utf-8")
print("Interface redesign applied.")
print("Updated: responsive light interface, plain-language guidance, evidence cards, technical details, print/save report.")
print("Detection logic and model files were not changed.")
