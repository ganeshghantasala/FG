
from pathlib import Path
from ucimlrepo import fetch_ucirepo

output_dir = Path("research_results")
output_dir.mkdir(exist_ok=True)

print("[1/3] Downloading PhiUSIIL dataset...")
dataset = fetch_ucirepo(id=967)

X = dataset.data.features
y = dataset.data.targets

print("\n[2/3] Dataset summary")
print("Number of examples:", len(X))
print("Number of feature columns:", len(X.columns))
print("Target column(s):", list(y.columns))
print("\nTarget label counts:")
print(y.iloc[:, 0].value_counts(dropna=False).sort_index())

print("\n[3/3] Feature columns and data types")
for column in X.columns:
    print(f"{column}: {X[column].dtype}")

# Save the dataset's variable dictionary for our experiment design.
if hasattr(dataset, "variables") and dataset.variables is not None:
    dataset.variables.to_csv(
        output_dir / "phiusiil_variable_dictionary.csv",
        index=False
    )

# Save a compact profile without copying actual URL values.
profile = [
    f"Dataset: {dataset.metadata.name}",
    f"Examples: {len(X)}",
    f"Feature columns: {len(X.columns)}",
    f"Target columns: {list(y.columns)}",
    "",
    "Feature columns and data types:",
]

profile.extend(
    f"{column}: {X[column].dtype}"
    for column in X.columns
)

profile.extend([
    "",
    "Target label counts:",
    y.iloc[:, 0].value_counts(dropna=False).sort_index().to_string(),
])

(output_dir / "phiusiil_dataset_profile.txt").write_text(
    "\n".join(profile),
    encoding="utf-8"
)

print("\nSaved:")
print(output_dir / "phiusiil_dataset_profile.txt")
print(output_dir / "phiusiil_variable_dictionary.csv")
