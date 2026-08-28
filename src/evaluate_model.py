import pandas as pd
import joblib

from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    classification_report,
    confusion_matrix
)

from feature_extraction import extract_features


# ==========================================
# 1. LOAD DATASET
# ==========================================

dataset_path = "../dataset/Dataset.csv"

df = pd.read_csv(dataset_path)

print("Dataset loaded successfully!")
print("Total samples:", len(df))


# ==========================================
# 2. FIND URL AND LABEL COLUMNS
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


# Remove missing values

df = df.dropna(subset=["url", "label"])


print("URL column:", url_column)
print("Label column:", label_column)
print("Samples after cleaning:", len(df))


# ==========================================
# 3. FEATURE EXTRACTION
# ==========================================

print("\nExtracting URL features...")

X = []

for url in df["url"]:

    features = extract_features(str(url))

    X.append(features)


X = pd.DataFrame(X)

y = df["label"]


print("Feature extraction completed.")


# ==========================================
# 4. TRAIN / TEST SPLIT
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
# 5. TRAIN MODEL
# ==========================================

print("\nTraining Random Forest...")

model = RandomForestClassifier(
    n_estimators=200,
    random_state=42,
    class_weight="balanced",
    n_jobs=-1
)

model.fit(X_train, y_train)

print("Training completed.")


# ==========================================
# 6. PREDICTIONS
# ==========================================

predictions = model.predict(X_test)


# ==========================================
# 7. EVALUATION
# ==========================================

accuracy = accuracy_score(y_test, predictions)

precision = precision_score(
    y_test,
    predictions,
    average="weighted"
)

recall = recall_score(
    y_test,
    predictions,
    average="weighted"
)

f1 = f1_score(
    y_test,
    predictions,
    average="weighted"
)


print("\n====================================")
print("       PHISHGUARD MODEL RESULTS")
print("====================================")

print("Accuracy :", round(accuracy * 100, 2), "%")
print("Precision:", round(precision * 100, 2), "%")
print("Recall   :", round(recall * 100, 2), "%")
print("F1 Score :", round(f1 * 100, 2), "%")


# ==========================================
# 8. CLASSIFICATION REPORT
# ==========================================

print("\nClassification Report:")
print(
    classification_report(
        y_test,
        predictions
    )
)


# ==========================================
# 9. CONFUSION MATRIX
# ==========================================

print("\nConfusion Matrix:")

cm = confusion_matrix(
    y_test,
    predictions
)

print(cm)


# ==========================================
# 10. SAVE MODEL
# ==========================================

joblib.dump(
    model,
    "../models/phishing_model.pkl"
)

print("\nModel saved successfully!")