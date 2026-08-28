import os
import pandas as pd
import joblib

from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, classification_report

from feature_extraction import extract_features


# ==========================================
# 1. PROJECT PATH
# ==========================================

# Get the main PhishGuard-ML folder
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
# 4. CHECK REQUIRED COLUMNS
# ==========================================

if "url" not in df.columns:
    raise ValueError(
        "Dataset must contain a 'url' column."
    )

if "label" not in df.columns:
    raise ValueError(
        "Dataset must contain a 'label' column."
    )


# Remove rows with missing values
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
print("Number of features:", X.shape[1])


# ==========================================
# 6. TRAIN / TEST SPLIT
# ==========================================

X_train, X_test, y_train, y_test = train_test_split(

    X,
    y,

    test_size=0.20,

    random_state=42,

    stratify=y
)


print("\nTraining samples:", len(X_train))
print("Testing samples:", len(X_test))


# ==========================================
# 7. CREATE RANDOM FOREST MODEL
# ==========================================

model = RandomForestClassifier(

    n_estimators=200,

    random_state=42,

    class_weight="balanced",

    n_jobs=-1
)


# ==========================================
# 8. TRAIN MODEL
# ==========================================

print("\nTraining model...")

model.fit(
    X_train,
    y_train
)

print("Training completed!")


# ==========================================
# 9. TEST MODEL
# ==========================================

predictions = model.predict(
    X_test
)


# ==========================================
# 10. CALCULATE ACCURACY
# ==========================================

accuracy = accuracy_score(
    y_test,
    predictions
)


print(
    "\nModel Accuracy:",
    round(accuracy * 100, 2),
    "%"
)


# ==========================================
# 11. CLASSIFICATION REPORT
# ==========================================

print("\nClassification Report:")

print(
    classification_report(
        y_test,
        predictions
    )
)


# ==========================================
# 12. SAVE MODEL
# ==========================================

models_directory = os.path.join(
    BASE_DIR,
    "models"
)


# Create models folder if it doesn't exist
os.makedirs(
    models_directory,
    exist_ok=True
)


model_path = os.path.join(
    models_directory,
    "phishing_model.pkl"
)


joblib.dump(
    model,
    model_path
)


print("\nModel saved successfully!")
print("Location:", model_path)