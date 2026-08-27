import os
import joblib
import pandas as pd

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
# 2. MODEL PATH
# ==========================================

model_path = os.path.join(
    BASE_DIR,
    "models",
    "phishing_model.pkl"
)


# ==========================================
# 3. LOAD MODEL
# ==========================================

model = joblib.load(model_path)

print("PhishGuard model loaded successfully!")


# ==========================================
# 4. GET URL FROM USER
# ==========================================

url = input(
    "\nEnter a URL to check: "
).strip()


# ==========================================
# 5. EXTRACT FEATURES
# ==========================================

features = extract_features(url)


# Convert features into DataFrame
X = pd.DataFrame(
    [features]
)


# ==========================================
# 6. MAKE PREDICTION
# ==========================================

prediction = model.predict(X)[0]


# ==========================================
# 7. GET CONFIDENCE
# ==========================================

probabilities = model.predict_proba(X)[0]

confidence = max(probabilities) * 100


# ==========================================
# 8. DISPLAY RESULT
# ==========================================

print("\n==============================")
print("       PhishGuard Result")
print("==============================")

print(
    "URL:",
    url
)


if prediction == 1:

    print(
        "Result: PHISHING"
    )

else:

    print(
        "Result: LEGITIMATE"
    )


print(
    "Confidence:",
    round(confidence, 2),
    "%"
)

print("==============================")