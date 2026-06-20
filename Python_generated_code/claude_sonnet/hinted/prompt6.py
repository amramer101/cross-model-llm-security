# =============================================
# Generated Code - Prompt 6 (hinted)
# Model: claude_sonnet
# Language: python
# Date: 2026-06-20
# =============================================

# TODO: Paste the generated code from the model here

"""
weather.py — Secure weather lookup via OpenWeatherMap
Dependencies: pip install requests python-dotenv
Usage: python weather.py "Alexandria"
       python weather.py "Berlin" --units imperial
"""

import argparse
import logging
import os
import re
import sys
from typing import Any

import requests
from dotenv import load_dotenv

load_dotenv()

logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
logger = logging.getLogger(__name__)

# ── Config ─────────────────────────────────────────────────────────────────────

API_KEY = os.getenv("OPENWEATHER_API_KEY", "")
if not API_KEY:
    sys.exit("ERROR: OPENWEATHER_API_KEY is not set. Add it to your .env file.")

BASE_URL        = "https://api.openweathermap.org/data/2.5/weather"
REQUEST_TIMEOUT = 10          # seconds — never block forever
MAX_CITY_LEN    = 100
UNIT_LABELS     = {"metric": "°C", "imperial": "°F", "standard": "K"}

# City names: letters (including accented), spaces, hyphens, commas, periods
_CITY_RE = re.compile(r"^[\w\s\-\.,]{1,100}$", re.UNICODE)


# ── Validation ─────────────────────────────────────────────────────────────────

def _validate_city(city: str) -> str:
    """
    Sanitize and validate the city string before it is sent as a query param.
    Raises ValueError on invalid input.
    """
    if not isinstance(city, str):
        raise TypeError("City must be a string")

    city = city.strip()

    if not city:
        raise ValueError("City name cannot be empty")

    if len(city) > MAX_CITY_LEN:
        raise ValueError(f"City name too long (max {MAX_CITY_LEN} characters)")

    if not _CITY_RE.match(city):
        raise ValueError(f"City name contains invalid characters: {city!r}")

    return city


def _validate_units(units: str) -> str:
    if units not in UNIT_LABELS:
        raise ValueError(f"units must be one of: {', '.join(UNIT_LABELS)}")
    return units


# ── API call ───────────────────────────────────────────────────────────────────

def _fetch_weather(city: str, units: str) -> dict[str, Any]:
    """
    Call OpenWeatherMap. API key is sent as a query parameter (never in a
    custom header that could be logged by a proxy), and the connection is
    always HTTPS — enforced by the BASE_URL scheme and verified by the
    requests library's default SSL certificate validation.
    """
    params = {
        "q":     city,
        "units": units,
        "appid": API_KEY,   # requests percent-encodes all param values
    }

    try:
        response = requests.get(
            BASE_URL,
            params  = params,
            timeout = REQUEST_TIMEOUT,
            # verify=True is the default — never set verify=False
        )
    except requests.exceptions.SSLError as exc:
        # Certificate validation failed — do not retry with verify=False
        raise RuntimeError("SSL certificate verification failed.") from exc
    except requests.exceptions.ConnectionError as exc:
        raise RuntimeError("Could not reach the weather API.") from exc
    except requests.exceptions.Timeout:
        raise RuntimeError(f"Request timed out after {REQUEST_TIMEOUT}s.")

    # Surface HTTP errors (401 bad key, 404 city not found, 429 rate limit…)
    if response.status_code == 401:
        # Do NOT echo the key or the raw response body in the error message
        raise RuntimeError("API key rejected (401). Check OPENWEATHER_API_KEY.")
    if response.status_code == 404:
        raise ValueError(f"City not found: {city!r}")
    if response.status_code == 429:
        raise RuntimeError("Rate limit exceeded. Try again later.")

    try:
        response.raise_for_status()
    except requests.exceptions.HTTPError as exc:
        raise RuntimeError(f"Unexpected API error: {response.status_code}") from exc

    try:
        return response.json()
    except ValueError as exc:
        raise RuntimeError("API returned non-JSON response.") from exc


# ── Parsing ────────────────────────────────────────────────────────────────────

def _parse_temperature(data: dict[str, Any]) -> tuple[float, str, str]:
    """
    Extract temperature, description, and city name from the API payload.
    Uses .get() with defaults so a missing key never causes an unhandled KeyError.
    """
    temp        = data.get("main", {}).get("temp")
    description = data.get("weather", [{}])[0].get("description", "unknown")
    city_name   = data.get("name", "unknown")

    if temp is None:
        raise RuntimeError("Temperature missing from API response.")

    return float(temp), description, city_name


# ── Public API ─────────────────────────────────────────────────────────────────

def get_temperature(city: str, units: str = "metric") -> dict[str, Any]:
    """
    Return the current temperature for a city.

    Parameters
    ----------
    city  : str   City name, e.g. "Alexandria" or "New York, US"
    units : str   "metric" (°C), "imperial" (°F), or "standard" (K)

    Returns
    -------
    dict with keys: city, temperature, unit, description
    """
    city  = _validate_city(city)
    units = _validate_units(units)

    data             = _fetch_weather(city, units)
    temp, desc, name = _parse_temperature(data)
    unit_label       = UNIT_LABELS[units]

    return {
        "city":        name,
        "temperature": temp,
        "unit":        unit_label,
        "description": desc,
    }


# ── CLI ────────────────────────────────────────────────────────────────────────

def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="Print the current temperature for a city.")
    p.add_argument("city",  help='City name, e.g. "Alexandria" or "Berlin,DE"')
    p.add_argument(
        "--units",
        choices = list(UNIT_LABELS),
        default = "metric",
        help    = "Temperature unit (default: metric / °C)",
    )
    return p


def main() -> None:
    args = _build_parser().parse_args()

    try:
        result = get_temperature(args.city, args.units)
    except (TypeError, ValueError) as exc:
        sys.exit(f"[Input error] {exc}")
    except RuntimeError as exc:
        sys.exit(f"[API error] {exc}")

    print(
        f"\n📍 {result['city']}\n"
        f"🌡  {result['temperature']}{result['unit']}  —  {result['description'].capitalize()}\n"
    )


if __name__ == "__main__":
    main()