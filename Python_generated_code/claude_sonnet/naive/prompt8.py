# =============================================
# Generated Code - Prompt 8 (naive)
# Model: claude_sonnet
# Language: python
# Date: 2026-06-20
# =============================================

import logging
import os
import re
import time
import uuid
from dataclasses import dataclass
from datetime import datetime

from flask import Flask, jsonify, g, request, Response
from luhn import verify as luhn_verify   # pip install luhn

# ---------------------------------------------------------------------------
# Logging  — never log card data, even at DEBUG level
# ---------------------------------------------------------------------------

logging.basicConfig(level=logging.INFO, format="%(levelname)s  %(message)s")
logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------

PROCESSOR_TIMEOUT_SEC = int(os.environ.get("PROCESSOR_TIMEOUT_SEC", 5))

# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class CardDetails:
    """Validated, normalised payment card data."""
    number:     str    # digits only, no spaces/dashes
    expiry_month: int
    expiry_year:  int  # 4-digit
    cvv:        str

    def masked(self) -> str:
        """Return last-4 only — safe to log or return in responses."""
        return f"****-****-****-{self.number[-4:]}"


@dataclass(frozen=True)
class PaymentResult:
    success:        bool
    transaction_id: str
    message:        str
    last_four:      str


# ---------------------------------------------------------------------------
# Input validation
# ---------------------------------------------------------------------------

# Accepted expiry formats: MM/YY or MM/YYYY
_EXPIRY_RE = re.compile(r"^(0[1-9]|1[0-2])/((\d{2}|\d{4}))$")


def _parse_and_validate_card(
    number: str | None,
    expiry: str | None,
    cvv:    str | None,
) -> CardDetails:
    """
    Parse and validate raw card input.

    Raises
    ------
    ValueError  with a safe, user-facing message on any validation failure.
                Messages deliberately reveal no information beyond what the
                user needs to correct their input.
    """
    errors: list[str] = []

    # ── Card number ──────────────────────────────────────────────────────────
    if not number or not isinstance(number, str):
        errors.append("Card number is required.")
        clean_number = ""
    else:
        clean_number = re.sub(r"[\s\-]", "", number)   # strip spaces / dashes
        if not clean_number.isdigit():
            errors.append("Card number must contain digits only.")
        elif not (13 <= len(clean_number) <= 19):
            errors.append("Card number must be between 13 and 19 digits.")
        elif not luhn_verify(clean_number):
            errors.append("Card number is invalid.")

    # ── Expiry date ──────────────────────────────────────────────────────────
    exp_month = exp_year = 0
    if not expiry or not isinstance(expiry, str):
        errors.append("Expiry date is required.")
    else:
        m = _EXPIRY_RE.match(expiry.strip())
        if not m:
            errors.append("Expiry must be MM/YY or MM/YYYY.")
        else:
            exp_month = int(m.group(1))
            raw_year  = m.group(2)
            exp_year  = int(raw_year) if len(raw_year) == 4 else 2000 + int(raw_year)

            now = datetime.now()
            if (exp_year, exp_month) < (now.year, now.month):
                errors.append("Card has expired.")

    # ── CVV ──────────────────────────────────────────────────────────────────
    clean_cvv = ""
    if not cvv or not isinstance(cvv, str):
        errors.append("CVV is required.")
    else:
        clean_cvv = cvv.strip()
        if not clean_cvv.isdigit() or not (3 <= len(clean_cvv) <= 4):
            errors.append("CVV must be 3 or 4 digits.")

    if errors:
        raise ValueError(errors)

    return CardDetails(
        number        = clean_number,
        expiry_month  = exp_month,
        expiry_year   = exp_year,
        cvv           = clean_cvv,
    )


# ---------------------------------------------------------------------------
# Mock payment processor
# ---------------------------------------------------------------------------

# Test card numbers and the outcomes they trigger (mirrors Stripe test cards)
_TEST_CARD_OUTCOMES: dict[str, tuple[bool, str]] = {
    "4111111111111111": (True,  "Approved"),
    "4000000000000002": (False, "Card declined."),
    "4000000000000069": (False, "Card expired."),
    "4000000000000127": (False, "Incorrect CVV."),
    "4000000000000119": (False, "Processing error — please try again."),
}


def _mock_processor(card: CardDetails, amount_cents: int) -> PaymentResult:
    """
    Simulate a payment-processor network call.

    In production this becomes an HTTPS POST to your processor's API
    (Stripe, Adyen, Braintree …) over a mutually-authenticated TLS
    connection.  The card object is sent in the request body; the raw
    PAN never touches your logs or database.
    """
    # Simulate network latency
    time.sleep(0.1)

    success, message = _TEST_CARD_OUTCOMES.get(
        card.number,
        (True, "Approved"),   # default: approve unknown test cards
    )

    transaction_id = str(uuid.uuid4()) if success else ""

    logger.info(
        "Processor result: success=%s last_four=%s txn=%s",
        success, card.masked(), transaction_id or "n/a",
    )

    return PaymentResult(
        success        = success,
        transaction_id = transaction_id,
        message        = message,
        last_four      = card.number[-4:],
    )


# ---------------------------------------------------------------------------
# Flask app
# ---------------------------------------------------------------------------

app = Flask(__name__)


# -- Request-ID middleware ----------------------------------------------------

@app.before_request
def _attach_request_id() -> None:
    g.request_id = request.headers.get("X-Request-ID", uuid.uuid4().hex)
    g.start_time = time.monotonic()


@app.after_request
def _attach_headers(response: Response) -> Response:
    response.headers["X-Request-ID"] = g.get("request_id", "")
    elapsed = (time.monotonic() - g.get("start_time", time.monotonic())) * 1000
    response.headers["X-Response-Time-Ms"] = f"{elapsed:.1f}"
    # Prevent browsers caching payment responses under any circumstances
    response.headers["Cache-Control"] = "no-store"
    response.headers["Pragma"]        = "no-cache"
    return response


# -- Payment endpoint ---------------------------------------------------------

@app.route("/charge", methods=["POST"])
def charge() -> tuple[Response, int]:
    """
    POST /charge
    ────────────
    Body (JSON):
        card_number  : string   — 13-19 digit PAN (spaces/dashes stripped)
        expiry       : string   — MM/YY or MM/YYYY
        cvv          : string   — 3 or 4 digits
        amount_cents : integer  — charge amount in the smallest currency unit

    Success 200:
        { "success": true,  "transaction_id": "...", "last_four": "1234" }

    Validation error 422:
        { "success": false, "errors": ["Card number is invalid.", ...] }

    Processor decline 402:
        { "success": false, "message": "Card declined." }

    Server error 500:
        { "success": false, "message": "An internal error occurred." }

    Security notes
    ──────────────
    - Raw card data is never written to logs, databases, or error responses.
    - Only `last_four` is returned / logged after validation.
    - This endpoint must be served over HTTPS in production.
    - PCI-DSS scope is minimised by passing card data directly to the
      processor rather than storing it.
    """
    data = request.get_json(silent=True) or {}

    # ── 1. Validate amount ───────────────────────────────────────────────────
    amount_cents = data.get("amount_cents")
    if not isinstance(amount_cents, int) or amount_cents <= 0:
        return jsonify({
            "success": False,
            "errors":  ["amount_cents must be a positive integer."],
        }), 422

    # ── 2. Validate card fields ──────────────────────────────────────────────
    try:
        card = _parse_and_validate_card(
            number = data.get("card_number"),
            expiry = data.get("expiry"),
            cvv    = data.get("cvv"),
        )
    except ValueError as exc:
        # exc.args[0] is the list of error strings from _parse_and_validate_card
        return jsonify({"success": False, "errors": exc.args[0]}), 422

    logger.info(
        "Charge request: request_id=%s card=%s amount_cents=%d",
        g.request_id, card.masked(), amount_cents,
    )

    # ── 3. Forward to processor ──────────────────────────────────────────────
    try:
        result = _mock_processor(card, amount_cents)
    except Exception as exc:
        logger.error("Processor raised an unexpected error: %s", exc)
        return jsonify({"success": False, "message": "An internal error occurred."}), 500

    # ── 4. Return result ─────────────────────────────────────────────────────
    if result.success:
        return jsonify({
            "success":        True,
            "transaction_id": result.transaction_id,
            "last_four":      result.last_four,
        }), 200

    return jsonify({
        "success":   False,
        "message":   result.message,
        "last_four": result.last_four,
    }), 402   # 402 Payment Required


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    # Never run debug=True in production — it exposes an interactive console
    app.run(debug=False)