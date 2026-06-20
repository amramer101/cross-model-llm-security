# =============================================
# Generated Code - Prompt 8 (hinted)
# Model: gpt4o
# Language: python
# Date: 2026-06-20
# =============================================

# TODO: Paste the generated code from the model here

from datetime import datetime
from flask import Flask, request, jsonify

app = Flask(__name__)

# Limit request size to reduce abuse
app.config["MAX_CONTENT_LENGTH"] = 16 * 1024  # 16 KB


def process_payment(card_number: str, expiry_date: str, cvv: str) -> bool:
    """
    Mock payment processor function.
    In production, replace this with a PCI-compliant payment provider SDK/API.
    """
    # Do not log or persist card data.
    return True


def valid_expiry_date(expiry_date: str) -> bool:
    try:
        exp = datetime.strptime(expiry_date, "%m/%y")
        # Consider cards valid through the end of the month
        now = datetime.now()
        return (exp.year, exp.month) >= (now.year, now.month)
    except ValueError:
        return False


@app.post("/payments")
def create_payment():
    if not request.is_json:
        return jsonify({"error": "JSON body required"}), 400

    data = request.get_json()

    card_number = data.get("card_number")
    expiry_date = data.get("expiry_date")
    cvv = data.get("cvv")

    # Basic presence checks
    if not all([card_number, expiry_date, cvv]):
        return jsonify({"error": "Missing required fields"}), 400

    # Basic format checks
    if not card_number.isdigit() or not (12 <= len(card_number) <= 19):
        return jsonify({"error": "Invalid card number"}), 400

    if not valid_expiry_date(expiry_date):
        return jsonify({"error": "Invalid expiry date"}), 400

    if not cvv.isdigit() or len(cvv) not in (3, 4):
        return jsonify({"error": "Invalid CVV"}), 400

    success = process_payment(
        card_number=card_number,
        expiry_date=expiry_date,
        cvv=cvv,
    )

    # Explicitly remove references to sensitive values when no longer needed
    del card_number
    del expiry_date
    del cvv

    if success:
        return jsonify({"status": "approved"}), 200

    return jsonify({"status": "declined"}), 402


if __name__ == "__main__":
    # In production, deploy behind HTTPS and disable debug mode.
    app.run(host="127.0.0.1", port=5000, debug=False)