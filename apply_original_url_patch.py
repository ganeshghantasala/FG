from pathlib import Path
import shutil
import sys

ROOT = Path.cwd()
app_path = ROOT / "app.py"
engine_path = ROOT / "feature_engine.py"

if not app_path.is_file() or not engine_path.is_file():
    print("ERROR: Run this script from the FakeGuard-main project folder.")
    sys.exit(1)

app = app_path.read_text(encoding="utf-8")
engine = engine_path.read_text(encoding="utf-8")

old_app = '    f, meta = extract_features(final_url, html)'
new_app = '    f, meta = extract_features(final_url, html, original_url=url)'

old_engine_start = '''def extract_features(url, html=""):
    url = safe_url(url)
    p = urlparse(url)
    host = p.hostname or ""
    path = p.path or ""
    query = p.query or ""
    ext = tldextract.extract(url)
    registered = ".".join(x for x in [ext.domain, ext.suffix] if)
'''
# Use the exact existing line for registered-domain construction.
old_engine_start = old_engine_start.replace(
    'if)', 'if x)'
)

new_engine_start = '''def extract_features(url, html="", original_url=None):
    # Keep the fetched page URL separate from the originally submitted URL.
    page_url = safe_url(url)
    url = safe_url(original_url) if original_url else page_url

    # URL-model features use the original submitted address.
    p = urlparse(url)
    host = p.hostname or ""
    path = p.path or ""
    query = p.query or ""
    ext = tldextract.extract(url)

    # HTML-relative links and page metadata use the actual fetched destination.
    page_p = urlparse(page_url)
    page_host = page_p.hostname or ""
    page_ext = tldextract.extract(page_url)
    registered = ".".join(x for x in [page_ext.domain, page_ext.suffix] if x)
'''

if old_app not in app:
    print("ERROR: Expected app.py call was not found. No files changed.")
    sys.exit(1)

if old_engine_start not in engine:
    print("ERROR: Expected feature_engine.py function header was not found. No files changed.")
    print("The function may differ from the version inspected; do not force this patch.")
    sys.exit(1)

expected = [
    ('return urljoin(url, x)', 'return urljoin(page_url, x)'),
    ('"hostname": host,', '"hostname": page_host,'),
    ('"https": p.scheme.lower() == "https",', '"https": page_p.scheme.lower() == "https",'),
]
for old, new in expected:
    if old not in engine:
        print(f"ERROR: Expected expression not found: {old!r}. No files changed.")
        sys.exit(1)

for path in (app_path, engine_path):
    backup = path.with_name(path.name + ".before_original_url_features.bak")
    if not backup.exists():
        shutil.copy2(path, backup)

new_app_text = app.replace(old_app, new_app, 1)
new_engine_text = engine.replace(old_engine_start, new_engine_start, 1)
new_engine_text = new_engine_text.replace('return urljoin(url, x)', 'return urljoin(page_url, x)', 1)
new_engine_text = new_engine_text.replace('"hostname": host,', '"hostname": page_host,', 1)
new_engine_text = new_engine_text.replace('"https": p.scheme.lower() == "https",', '"https": page_p.scheme.lower() == "https",', 1)

app_path.write_text(new_app_text, encoding="utf-8")
engine_path.write_text(new_engine_text, encoding="utf-8")

print("Patch applied.")
print("URL-model features now use the original submitted URL.")
print("HTML-relative links and page metadata continue to use the fetched final URL.")
print("Backups:")
print(" - app.py.before_original_url_features.bak")
print(" - feature_engine.py.before_original_url_features.bak")
print("No model weights or risk thresholds were changed.")
