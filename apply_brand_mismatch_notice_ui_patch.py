from pathlib import Path
import shutil

APP = Path(__file__).resolve().parent / "app.py"
BACKUP = Path(__file__).resolve().parent / "app.py.before_brand_mismatch_notice.bak"

if not APP.exists():
    raise SystemExit(f"app.py not found beside this script: {APP.parent}")

text = APP.read_text(encoding="utf-8")
marker = '<div class="result-top">'
notice = '''{% if result.meta.get('brand_domain_mismatch') %}
            <div class="advice warn" role="note" style="margin-bottom:16px">
                <strong>Manual review recommended — brand/domain mismatch</strong>
                <p>A supported brand term appears in a hostname whose registered domain is not on FakeGuard's configured official-domain list. This is a warning for manual review, not proof that the website is phishing.</p>
            </div>
            {% endif %}
            '''

if "Manual review recommended — brand/domain mismatch" in text:
    print("Brand/domain mismatch notice is already present. No changes made.")
    raise SystemExit(0)

# Limit replacement to the first result-top block after the result-card template branch.
start = text.find('<section class="card result-card" id="results"')
if start < 0:
    raise SystemExit('Could not find the result-card section in app.py; no files changed.')
idx = text.find(marker, start)
if idx < 0:
    raise SystemExit('Could not find result-top after result-card; no files changed.')

# Back up the exact pre-change file, never overwriting an earlier backup.
if BACKUP.exists():
    raise SystemExit(f"Backup already exists: {BACKUP}. Rename or remove it before retrying; no files changed.")
shutil.copy2(APP, BACKUP)
text = text[:idx] + notice + text[idx:]
APP.write_text(text, encoding="utf-8", newline="")

print("Brand/domain mismatch review notice added to the result card.")
print("It is displayed independently of the numeric risk score/classification.")
print("No model, feature-engine, risk formula, score, or threshold was changed.")
print(f"Backup created: {BACKUP.name}")
