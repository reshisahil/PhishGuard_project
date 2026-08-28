import os
import pandas as pd
import joblib

from sklearn.model_selection import train_test_split
from sklearn.metrics import roc_auc_score, roc_curve

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
# 2. DATASET PATH
# ==========================================

dataset_path = os.path.join(
    BASE_DIR,
    "dataset",
    "Dataset_clean.csv"
)


# ==========================================
# 3. LOAD DATASET
# ==========================================

df = pd.read_csv(dataset_path)

print("Dataset loaded successfully!")
print("Number of samples:", len(df))


# ==========================================
# 4. CLEAN DATA
# ==========================================

df = df.dropna(
    subset=["url", "label"]
)


# ==========================================
# 5. FEATURE EXTRACTION
# ==========================================

print("\nExtracting URL features...")

X = []

for url in df["url"]:

    features = extract_features(
        str(url)
    )

    X.append(features)


X = pd.DataFrame(X)

y = df["label"]


print("Feature extraction completed!")


# ==========================================
# 6. SAME TRAIN / TEST SPLIT
# ==========================================

X_train, X_test, y_train, y_test = train_test_split(

    X,
    y,

    test_size=0.20,

    random_state=42,

    stratify=y
)


# ==========================================
# 7. LOAD TRAINED MODEL
# ==========================================

model_path = os.path.join(
    BASE_DIR,
    "models",
    "phishing_model.pkl"
)


model = joblib.load(
    model_path
)


# ==========================================
# 8. PREDICT PROBABILITIES
# ==========================================

print("\nGenerating prediction probabilities...")

probabilities = model.predict_proba(
    X_test
)[:, 1]


# ==========================================
# 9. ROC-AUC
# ==========================================

auc = roc_auc_score(
    y_test,
    probabilities
)


print("\n====================================")
print("       PHISHGUARD ROC-AUC")
print("====================================")

print(
    "ROC-AUC Score:",
    round(auc, 4)
)

print(
    "ROC-AUC Percentage:",
    round(auc * 100, 2),
    "%"
)


# ==========================================
# 10. ROC CURVE DATA
# ==========================================

fpr, tpr, thresholds = roc_curve(
    y_test,
    probabilities
)


roc_data = pd.DataFrame({

    "False Positive Rate": fpr,

    "True Positive Rate": tpr,

    "Threshold": thresholds

})


roc_output = os.path.join(
    BASE_DIR,
    "models",
    "roc_curve_data.csv"
)


roc_data.to_csv(
    roc_output,
    index=False
)


print(
    "\nROC curve data saved to:"
)

print(roc_output)