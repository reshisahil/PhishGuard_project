import os
import pandas as pd
import matplotlib.pyplot as plt

from sklearn.model_selection import train_test_split
from sklearn.metrics import confusion_matrix, ConfusionMatrixDisplay
import joblib

from feature_extraction import extract_features


# ==========================================
# 1. PROJECT PATH
# ==========================================

BASE_DIR = os.path.dirname(
    os.path.dirname(
        os.path.abspath(__file__)
    )
)


# ==========================================
# 2. LOAD CLEAN DATASET
# ==========================================

dataset_path = os.path.join(
    BASE_DIR,
    "dataset",
    "Dataset_clean.csv"
)

df = pd.read_csv(dataset_path)

print("Dataset loaded successfully!")
print("Number of samples:", len(df))


# ==========================================
# 3. CLEAN DATA
# ==========================================

df = df.dropna(
    subset=["url", "label"]
)


# ==========================================
# 4. EXTRACT FEATURES
# ==========================================

print("\nExtracting URL features...")

X = []

for url in df["url"]:

    X.append(
        extract_features(str(url))
    )

X = pd.DataFrame(X)

y = df["label"]

print("Feature extraction completed!")


# ==========================================
# 5. SAME TRAIN / TEST SPLIT
# ==========================================

X_train, X_test, y_train, y_test = train_test_split(
    X,
    y,
    test_size=0.20,
    random_state=42,
    stratify=y
)


# ==========================================
# 6. LOAD TRAINED MODEL
# ==========================================

model_path = os.path.join(
    BASE_DIR,
    "models",
    "phishing_model.pkl"
)

model = joblib.load(model_path)


# ==========================================
# 7. MAKE PREDICTIONS
# ==========================================

print("\nGenerating predictions...")

predictions = model.predict(X_test)


# ==========================================
# 8. CONFUSION MATRIX
# ==========================================

cm = confusion_matrix(
    y_test,
    predictions
)

print("\n====================================")
print("       CONFUSION MATRIX")
print("====================================")

print(cm)


# ==========================================
# 9. DISPLAY CONFUSION MATRIX
# ==========================================

# ==========================================
# 9. DISPLAY CONFUSION MATRIX
# ==========================================

display = ConfusionMatrixDisplay(
    confusion_matrix=cm,
    display_labels=[
        "Legitimate",
        "Phishing"
    ]
)

display.plot()

plt.title(
    "PhishGuard - Confusion Matrix"
)

plt.xlabel(
    "Predicted Label"
)

plt.ylabel(
    "Actual Label"
)

plt.grid(False)


# ==========================================
# 10. SAVE IMAGE
# ==========================================

output_file = os.path.join(
    BASE_DIR,
    "models",
    "confusion_matrix.png"
)

plt.savefig(
    output_file,
    dpi=300,
    bbox_inches="tight"
)

print("\nConfusion matrix saved successfully!")

print(
    "Location:",
    output_file
)

plt.show()


# ==========================================
# 10. SAVE IMAGE
# ==========================================

output_file = os.path.join(
    BASE_DIR,
    "models",
    "confusion_matrix.png"
)

plt.savefig(
    output_file,
    dpi=300,
    bbox_inches="tight"
)

plt.show()


print("\nConfusion matrix saved successfully!")

print(
    "Location:",
    output_file
)