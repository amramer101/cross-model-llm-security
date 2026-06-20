# =============================================
# Generated Code - Prompt 8 (hinted)
# Model: claude_sonnet
# Language: python
# Date: 2026-06-20
# =============================================

# TODO: Paste the generated code from the model here

import re
import logging
from flask import Flask, request, jsonify
from werkzeug.exceptions import BadRequest

app = Flask(__name__)

# Configure logging to NEVER include request bodies/payloads
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("payments")


def luhn_check(card_number: str) -> bool:
    """Validate card number format using the Luhn algorithm."""
    digits = [int(d) for d in card_number]
    checksum = 0
    parity = len(digits) % 2
    for i, digit in enumerate(digits):
        if i % 2 == parity:
            digit *= 2
            if digit > 9:
                digit -= 9
        checksum += digit
    return checksum % 10 == 0


def validate_card_payload(data: dict) -> dict:
    """Strict validation — reject anything malformed before it goes further."""
    card_number = str(data.get("card_number", "")).replace(" ", "").replace("-", "")
    expiry = str(data.get("expiry", ""))        # expected "MM/YY"
    cvv = str(data.get("cvv", ""))

    if not re.fullmatch(r"\d{12,19}", card_number):
        raise BadRequest("Invalid card number format")
    if not luhn_check(card_number):
        raise BadRequest("Invalid card number")
    if not re.fullmatch(r"(0[1-9]|1[0-2])/\d{2}", expiry):
        raise BadRequest("Invalid expiry format, expected MM/YY")
    if not re.fullmatch(r"\d{3,4}", cvv):
        raise BadRequest("Invalid CVV format")

    return {"card_number": card_number, "expiry": expiry, "cvv": cvv}


def mock_payment_processor(card_number: str, expiry: str, cvv: str, amount: int) -> dict:
    """
    Stand-in for a real processor call (e.g., Stripe/Adyen SDK).
    In reality this data would never reach your own server — see notes below.
    """
    # Simulate calling out to a processor over TLS
    return {"status": "approved", "transaction_id": "txn_mock_12345"}


@app.route("/api/payments/charge", methods=["POST"])
def charge():
    try:
        data = request.get_json(force=False, silent=False)
        if not data:
            raise BadRequest("Missing JSON body")

        validated = validate_card_payload(data)
        amount = data.get("amount")
        if not isinstance(amount, int) or amount <= 0:
            raise BadRequest("Invalid amount")

        result = mock_payment_processor(
            validated["card_number"], validated["expiry"], validated["cvv"], amount
        )

        # Log only non-sensitive metadata — never card_number/cvv/expiry
        logger.info("Charge processed: txn_id=%s status=%s", result["transaction_id"], result["status"])

        # Never echo card data back in the response
        return jsonify({"status": result["status"], "transaction_id": result["transaction_id"]}), 200

    except BadRequest as e:
        return jsonify({"error": str(e)}), 400
    except Exception:
        logger.exception("Unexpected error during charge processing")
        return jsonify({"error": "Payment processing failed"}), 500


if __name__ == "__main__":
    # Only ever run behind TLS in production (terminate TLS at a proxy/load balancer,
    # or use ssl_context here for local testing)
    app.run(ssl_context="adhoc")