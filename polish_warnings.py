
from pathlib import Path
import shutil

app_file = Path("app.py")
backup_file = Path("app.py.before_warning_polish.bak")
source = app_file.read_text(encoding="utf-8")

old_reason = (
    '    if meta["suspicious_terms"]: reasons.append('
    '"The address or page includes account/security terms: "'
    ' + ", ".join(meta["suspicious_terms"][:6]))\n'
)

new_reason = (
    '    if not meta["https"]:\n'
    '        reasons.append("This page uses an unencrypted HTTP connection. '
    'Avoid entering passwords or payment details until you independently '
    'verify the website. HTTP alone does not prove fraud.")\n'
    + old_reason
)

old_ui = """                    {% else %}
                        <span class="status-pill good">Lower risk in this scan</span>
                        <h2 style="margin-top:12px">No major warning signs found</h2>
                        <p>This scan did not find many warning signs. That does not mean the website is guaranteed safe.</p>
                    {% endif %}"""

new_ui = """                    {% else %}
                        <span class="status-pill good">Lower risk in this scan</span>
                        {% if result.reasons|length > 1 %}
                            <h2 style="margin-top:12px">Some warning signs were found</h2>
                            <p>The overall score is below the caution level, but review these findings before sharing personal information.</p>
                        {% else %}
                            <h2 style="margin-top:12px">No major warning signs found</h2>
                            <p>This scan did not find many warning signs. That does not mean the website is guaranteed safe.</p>
                        {% endif %}
                    {% endif %}"""

if old_reason not in source:
    raise RuntimeError("Could not find the expected explanation line. No changes made.")

if old_ui not in source:
    raise RuntimeError("Could not find the expected result heading. No changes made.")

if not backup_file.exists():
    shutil.copy2(app_file, backup_file)

updated = source.replace(old_reason, new_reason, 1)
updated = updated.replace(old_ui, new_ui, 1)

app_file.write_text(updated, encoding="utf-8")

print("Warning-message update completed.")
print(f"Backup: {backup_file}")
print("HTTP warning added.")
print("Low-score result wording improved.")
print("Model and scoring formula unchanged.")
