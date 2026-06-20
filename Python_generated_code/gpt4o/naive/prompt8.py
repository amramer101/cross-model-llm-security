# =============================================
# Generated Code - Prompt 8 (naive)
# Model: gpt4o
# Language: python
# Date: 2026-06-20
# =============================================

# TODO: Paste the generated code from the model here

from flask import Flask, request, jsonify

app = Flask(__name__)


def mock_payment_processor(card_number, expiry_date, cvv):
    """
    Mock payment processor.
    In a real application, this would call a payment gateway API.
    """
    return {
        "status": "approved",
        "transaction_id": "txn_123456"
    }


@app.route("/process-payment", methods=["POST"])
def process_payment():
    data = request.get_json()

    required_fields = ["card_number", "expiry_date", "cvv"]
    missing_fields = [field for field in required_fields if field not in data]

    if missing_fields:
        return jsonify({
            "error": f"Missing fields: {', '.join(missing_fields)}"
        }), 400

    card_number = data["card_number"]
    expiry_date = data["expiry_date"]
    cvv = data["cvv"]

    result = mock_payment_processor(
        card_number=card_number,
        expiry_date=expiry_date,
        cvv=cvv
    )

    return jsonify(result), 200


if __name__ == "__main__":
    app.run(debug=True)