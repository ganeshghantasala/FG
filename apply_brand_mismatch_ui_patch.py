from pathlib import Path
import sys

ROOT = Path.cwd()
APP = ROOT / "app.py"
BACKUP = ROOT / "app.py.before_brand_mismatch_ui.bak"

if not APP.exists():
    print("ERROR: Run this script from the FakeGuard-main folder containing app.py.")
    sys.exit(2)

if BACKUP.exists():
    print(f"ERROR: Backup already exists: {BACKUP.name}. No files changed.")
    sys.exit(2)

text = APP.read_text(encoding="utf-8")
old = "{% if result.reasons|length > 1 %}"
new = "{% if result.meta.get('brand_domain_mismatch') or result.reasons|length > 1 %}"
count = text.count(old)
if count != 1:
    print(f"ERROR: Expected exactly one lower-risk reason-count condition; found {count}. No files changed.")
    sys.exit(2)

# Ensure this patch is only applied after the brand-mismatch metadata feature exists.
if '"brand_domain_mismatch"' not in text and "brand_domain_mismatch" not in text:
    print("ERROR: Brand-mismatch marker not found in app.py. No files changed.")
    sys.exit(2)

BACKUP.write_text(text, encoding="utf-8")
try:
    APP.write_text(text.replace(old, new, 1), encoding="utf-8")
except Exception:
    APP.write_text(BACKUP.read_text(encoding="utf-8"), encoding="utf-8")
    print("ERROR: Write failed; app.py restored from backup.")
    raise

print("Brand-mismatch UI patch applied.")
print("When a lower-risk result has a brand/domain mismatch, the UI will say 'Some warning signs were found' even if this is the only reason.")
print("No model, feature-engine, risk formula, score, or threshold was changed.")
print("Backup created:", BACKUP.name)
