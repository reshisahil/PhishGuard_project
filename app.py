from flask import Flask, request, jsonify, send_from_directory
import os
import sys
import joblib

# --------------------------------------------------
# Project paths
# --------------------------------------------------

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

SRC_DIR = os.path.join(BASE_DIR, "src")
MODEL_PATH = os.path.join(BASE_DIR, "models", "phishing_model.pkl")

# Allow Python to import files from src/
sys.path.insert(0, SRC_DIR)

from feature_extraction import extract_features


# --------------------------------------------------
# Flask application
# --------------------------------------------------

app = Flask(__name__)


# --------------------------------------------------
# Load trained ML model
# --------------------------------------------------

print("Loading PhishGuard ML model...")

model = joblib.load(MODEL_PATH)

print("Model loaded successfully!")


# --------------------------------------------------
# Serve frontend
# --------------------------------------------------

@app.route("/")
def home():
    return send_from_directory(BASE_DIR, "index.html")


# --------------------------------------------------
# Serve frontend files
# --------------------------------------------------

@app.route("/<path:filename>")
def serve_frontend(filename):

    # Only serve the frontend files
    allowed_files = {
        "script.js",
        "style.css"
    }

    if filename in allowed_files:
        return send_from_directory(BASE_DIR, filename)

    return jsonify({
        "error": "File not found"
    }), 404


# --------------------------------------------------
# ML prediction API
# --------------------------------------------------

@app.route("/predict", methods=["POST"])
def predict():

    try:

        # Get JSON data
        data = request.get_json()

        if not data or "url" not in data:
            return jsonify({
                "error": "URL is required"
            }), 400

        # Get URL
        url = data["url"].strip()

        if not url:
            return jsonify({
                "error": "URL cannot be empty"
            }), 400

        print("------------------------------------")
        print("Scanning URL:")
        print(url)

        # ------------------------------------------
        # Extract ML features
        # ------------------------------------------

        features = extract_features(url)

        print("Features extracted successfully")

        # ------------------------------------------
        # ML prediction
        # ------------------------------------------

        prediction = model.predict(features)[0]

        # ------------------------------------------
        # Confidence
        # ------------------------------------------

        if hasattr(model, "predict_proba"):

            probabilities = model.predict_proba(features)[0]

            confidence = float(max(probabilities)) * 100

        else:

            confidence = 100.0

        # ------------------------------------------
        # Convert prediction
        # ------------------------------------------

        if prediction == 1:

            result = "PHISHING"

        else:

            result = "LEGITIMATE"

        print("Result:", result)
        print("Confidence:", round(confidence, 2), "%")
        print("------------------------------------")

        # ------------------------------------------
        # Send result to frontend
        # ------------------------------------------

        return jsonify({
            "url": url,
            "result": result,
            "confidence": round(confidence, 2)
        })

    except Exception as e:

        print("------------------------------------")
        print("Prediction error:")
        print(str(e))
        print("------------------------------------")

        return jsonify({
            "error": str(e)
        }), 500


# --------------------------------------------------
# Run Flask server
# --------------------------------------------------

if __name__ == "__main__":

    print("====================================")
    print("       PHISHGUARD ML API")
    print("====================================")
    print("Frontend:")
    print("http://127.0.0.1:5000")
    print("")
    print("ML API:")
    print("http://127.0.0.1:5000/predict")
    print("====================================")

    app.run(
        host="127.0.0.1",
        port=5000,
        debug=True
    )