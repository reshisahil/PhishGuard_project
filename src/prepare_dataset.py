import pandas as pd


import os
import pandas as pd


# Get the main PhishGuard-ML folder
BASE_DIR = os.path.dirname(
    os.path.dirname(
        os.path.abspath(__file__)
    )
)


INPUT_FILE = os.path.join(
    BASE_DIR,
    "dataset",
    "Dataset.csv"
)

OUTPUT_FILE = os.path.join(
    BASE_DIR,
    "dataset",
    "Dataset_clean.csv"
)


# Load dataset
df = pd.read_csv(INPUT_FILE)

print("Original dataset size:", len(df))


# Remove missing URLs and labels
df = df.dropna(subset=["url", "label"])


# Remove exact duplicate URLs
before = len(df)

df = df.drop_duplicates(
    subset=["url"],
    keep="first"
)

removed = before - len(df)


# Save cleaned dataset
df.to_csv(
    OUTPUT_FILE,
    index=False
)


print("\n====================================")
print("       DATASET CLEANING")
print("====================================")

print("Original rows :", before)
print("Duplicates removed:", removed)
print("Final rows    :", len(df))

print("\nClass distribution:")

print(df["label"].value_counts())

print("\nClean dataset saved to:")
print(OUTPUT_FILE)