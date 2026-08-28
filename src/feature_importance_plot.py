import os
import pandas as pd
import matplotlib.pyplot as plt


# ==========================================
# 1. PROJECT PATH
# ==========================================

BASE_DIR = os.path.dirname(
    os.path.dirname(
        os.path.abspath(__file__)
    )
)


# ==========================================
# 2. LOAD FEATURE IMPORTANCE FILE
# ==========================================

input_file = os.path.join(
    BASE_DIR,
    "models",
    "feature_importance.csv"
)

df = pd.read_csv(input_file)

print("Feature importance file loaded successfully!")

print("\nColumns found:")
print(df.columns.tolist())


# ==========================================
# 3. FIND FEATURE COLUMN
# ==========================================

feature_column = None
importance_column = None

for column in df.columns:

    column_lower = column.lower()

    if column_lower in [
        "feature",
        "features",
        "feature_name"
    ]:
        feature_column = column

    if column_lower in [
        "importance",
        "importance_score",
        "feature_importance"
    ]:
        importance_column = column


# ==========================================
# 4. CHECK COLUMNS
# ==========================================

if feature_column is None:

    raise ValueError(
        "Could not find the feature column."
    )


if importance_column is None:

    raise ValueError(
        "Could not find the importance column."
    )


print("\nFeature column:")
print(feature_column)

print("\nImportance column:")
print(importance_column)


# ==========================================
# 5. SORT FEATURES
# ==========================================

df = df.sort_values(
    by=importance_column,
    ascending=True
)


# ==========================================
# 6. CREATE GRAPH
# ==========================================

plt.figure(
    figsize=(10, 8)
)

plt.barh(
    df[feature_column],
    df[importance_column]
)

plt.xlabel(
    "Feature Importance"
)

plt.ylabel(
    "URL Feature"
)

plt.title(
    "PhishGuard - Feature Importance"
)

plt.tight_layout()


# ==========================================
# 7. SAVE GRAPH
# ==========================================

output_file = os.path.join(
    BASE_DIR,
    "models",
    "feature_importance.png"
)

plt.savefig(
    output_file,
    dpi=300,
    bbox_inches="tight"
)


print(
    "\nFeature importance graph saved successfully!"
)

print(
    "Location:",
    output_file
)


plt.show()