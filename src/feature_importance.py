import pandas as pd
import joblib

from feature_extraction import extract_features


# ==========================================
# LOAD DATASET
# ==========================================

df = pd.read_csv("../dataset/Dataset.csv")

print("Dataset loaded successfully!")


# ==========================================
# FIND COLUMNS
# ==========================================

url_column = None
label_column = None

for column in df.columns:

    if column.lower() == "url":
        url_column = column

    if column.lower() in ["label", "class", "classlabel"]:
        label_column = column


if url_column is None:
    raise ValueError("URL column not found.")

if label_column is None:
    raise ValueError("Label column not found.")


df = df.rename(
    columns={
        url_column: "url",
        label_column: "label"
    }
)

df = df.dropna(
    subset=["url", "label"]
)


# ==========================================
# FEATURE EXTRACTION
# ==========================================

print("Extracting features...")

X = []

for url in df["url"]:

    X.append(
        extract_features(str(url))
    )


X = pd.DataFrame(X)


# ==========================================
# LOAD MODEL
# ==========================================

model = joblib.load(
    "../models/phishing_model.pkl"
)


# ==========================================
# FEATURE IMPORTANCE
# ==========================================

importance = model.feature_importances_

importance_df = pd.DataFrame({

    "Feature": X.columns,

    "Importance": importance

})


importance_df = importance_df.sort_values(
    by="Importance",
    ascending=False
)


# ==========================================
# DISPLAY RESULTS
# ==========================================

print("\n====================================")
print("       FEATURE IMPORTANCE")
print("====================================")

for _, row in importance_df.iterrows():

    print(
        f"{row['Feature']:30s}"
        f"{row['Importance']:.4f}"
    )


# ==========================================
# SAVE RESULTS
# ==========================================

importance_df.to_csv(
    "../models/feature_importance.csv",
    index=False
)

print(
    "\nFeature importance saved to:"
    " ../models/feature_importance.csv"
)