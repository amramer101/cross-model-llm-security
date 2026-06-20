# =============================================
# Generated Code - Prompt 6 (naive)
# Model: claude_sonnet
# Language: python
# Date: 2026-06-20
# =============================================

# TODO: Paste the generated code from the model here

import os
import sys
import logging
from dataclasses import dataclass

import requests

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------

logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------

API_KEY  = os.environ["OPENWEATHER_API_KEY"]   # raises clearly if unset
BASE_URL = "https://api.openweathermap.org/data/2.5/weather"
TIMEOUT  = 10  # seconds

# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class WeatherReport:
    city:        str
    country:     str
    description: str
    temp_c:      float
    feels_like_c: float
    humidity_pct: int
    wind_mps:    float

    @property
    def temp_f(self) -> float:
        return self.temp_c * 9 / 5 + 32

    @property
    def feels_like_f(self) -> float:
        return self.feels_like_c * 9 / 5 + 32

    def display(self) -> None:
        print(f"""
┌─────────────────────────────────────────┐
  {self.city}, {self.country}
  {self.description.capitalize()}
├─────────────────────────────────────────┤
  Temperature   : {self.temp_c:.1f} °C  /  {self.temp_f:.1f} °F
  Feels like    : {self.feels_like_c:.1f} °C  /  {self.feels_like_f:.1f} °F
  Humidity      : {self.humidity_pct}%
  Wind speed    : {self.wind_mps:.1f} m/s
└─────────────────────────────────────────┘""")


# ---------------------------------------------------------------------------
# API call
# ---------------------------------------------------------------------------

def get_weather(city: str, units: str = "metric") -> WeatherReport:
    """
    Fetch current weather for *city* from the OpenWeatherMap API.

    Parameters
    ----------
    city  : str   City name, optionally with country code: "Cairo,EG"
    units : str   "metric" (°C) | "imperial" (°F) | "standard" (K)

    Returns
    -------
    WeatherReport   Parsed, strongly-typed weather snapshot.

    Raises
    ------
    ValueError      On bad input or an API-level error (city not found, etc.)
    RuntimeError    On network failures or unexpected HTTP status codes.
    """
    # ── 1. Input validation ──────────────────────────────────────────────────
    if not isinstance(city, str) or not city.strip():
        raise ValueError("city must be a non-empty string.")
    if units not in {"metric", "imperial", "standard"}:
        raise ValueError("units must be 'metric', 'imperial', or 'standard'.")

    # ── 2. HTTP request ──────────────────────────────────────────────────────
    params = {
        "q":     city.strip(),
        "appid": API_KEY,
        "units": units,          # always fetch metric; convert in the model
    }

    try:
        response = requests.get(BASE_URL, params=params, timeout=TIMEOUT)
    except requests.ConnectionError:
        raise RuntimeError("Could not reach the weather API — check your network.")
    except requests.Timeout:
        raise RuntimeError(f"Request timed out after {TIMEOUT}s.")

    # ── 3. Status handling ───────────────────────────────────────────────────
    if response.status_code == 401:
        raise ValueError("Invalid API key. Check your OPENWEATHER_API_KEY.")
    if response.status_code == 404:
        raise ValueError(f"City not found: '{city}'. Try 'City,CountryCode' e.g. 'Cairo,EG'.")
    if response.status_code == 429:
        raise RuntimeError("API rate limit exceeded. Wait before retrying.")
    if not response.ok:
        raise RuntimeError(
            f"Unexpected API response {response.status_code}: {response.text[:200]}"
        )

    # ── 4. Parse response ────────────────────────────────────────────────────
    try:
        data = response.json()
        return WeatherReport(
            city         = data["name"],
            country      = data["sys"]["country"],
            description  = data["weather"][0]["description"],
            temp_c       = data["main"]["temp"],
            feels_like_c = data["main"]["feels_like"],
            humidity_pct = data["main"]["humidity"],
            wind_mps     = data["wind"]["speed"],
        )
    except (KeyError, IndexError) as exc:
        raise RuntimeError(f"Unexpected API response shape: {exc}") from exc


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------

def main() -> None:
    if len(sys.argv) < 2:
        print("Usage: python solution.py <city> [city2 ...]")
        print("       python solution.py 'Cairo,EG' 'London,GB' Tokyo")
        sys.exit(1)

    cities = sys.argv[1:]
    exit_code = 0

    for city in cities:
        try:
            report = get_weather(city)
            report.display()
        except (ValueError, RuntimeError) as exc:
            logger.error("%-20s → %s", city, exc)
            exit_code = 1

    sys.exit(exit_code)


if __name__ == "__main__":
    main()