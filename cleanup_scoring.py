from pathlib import Path
import shutil

app_file = Path("app.py")
backup_file = Path("app.py.before_scoring_cleanup.bak")

source = app_file.read_text(encoding="utf-8")

# Find the duplicate scoring block.
start_marker = (
    "    # FakeGuard evidence fusion: "
    "independent signals are weighted separately."
)
end_marker = "    reasons = []"

start = source.find(start_marker)
if start == -1:
    raise RuntimeError("Duplicate scoring block not found. No changes made.")

end = source.find(end_marker, start)
if end == -1:
    raise RuntimeError("Could not find the end of the scoring block. No changes made.")

duplicate_block = source[start:end]

if "contradiction = 0.0" not in duplicate_block:
    raise RuntimeError("Unexpected scoring block. No changes made.")

if "score = min(" not in duplicate_block:
    raise RuntimeError("Expected duplicate score calculation not found. No changes made.")

if "conf = min(" not in duplicate_block:
    raise RuntimeError("Expected duplicate confidence calculation not found. No changes made.")

# Back up the original before editing it.
if not backup_file.exists():
    shutil.copy2(app_file, backup_file)

# Remove the duplicate scoring block.
source = source[:start] + source[end:]

# Remove the remaining unused confidence calculation.
confidence_line = "    conf = min(0.99, abs(score - 0.5) * 1.7 + 0.55)\n"

if confidence_line not in source:
    raise RuntimeError("Remaining confidence calculation not found.")

source = source.replace(confidence_line, "", 1)

# Remove the unused confidence field from the result dictionary.
confidence_field = '"conf":round(conf*100,1), '

if confidence_field not in source:
    raise RuntimeError("Confidence field not found in result dictionary.")

source = source.replace(confidence_field, "", 1)

# Save only after all checks succeed.
app_file.write_text(source, encoding="utf-8")

print("Scoring cleanup completed.")
print(f"Backup created: {backup_file}")
print("Duplicate scoring block removed.")
print("Unused confidence calculation removed.")
print("Unused confidence field removed.")