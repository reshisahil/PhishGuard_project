import pandas as pd


# ==========================================
# LOAD DATASET
# ==========================================

import os

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

dataset_path = os.path.join(
    BASE_DIR,
    "dataset",
    "Dataset.csv"
)

df = pd.read_csv(dataset_path)

print("Dataset loaded successfully!")

print("\nColumns:")
print(df.columns.tolist())


# ==========================================
# FIND URL AND LABEL COLUMNS
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


# ==========================================
# BASIC INFORMATION
# ==========================================

print("\nTotal rows:", len(df))

print(
    "Unique URLs:",
    df["url"].nunique()
)


# ==========================================
# DUPLICATES
# ==========================================

duplicate_count = (
    df["url"].duplicated().sum()
)

print(
    "Duplicate URLs:",
    duplicate_count
)


duplicate_percentage = (
    duplicate_count / len(df)
) * 100


print(
    "Duplicate percentage:",
    round(duplicate_percentage, 2),
    "%"
)


# ==========================================
# DUPLICATE LABEL CONFLICTS
# ==========================================

label_counts = (
    df.groupby("url")["label"]
    .nunique()
)

conflicting_urls = (
    (label_counts > 1).sum()
)


print(
    "\nURLs having conflicting labels:",
    conflicting_urls
)


# ==========================================
# CLASS DISTRIBUTION
# ==========================================

print("\nClass distribution:")

print(
    df["label"].value_counts()
)


print("\nClass percentages:")

print(
    df["label"]
    .value_counts(normalize=True)
    .mul(100)
    .round(2)
)


print("\nDataset check completed.")