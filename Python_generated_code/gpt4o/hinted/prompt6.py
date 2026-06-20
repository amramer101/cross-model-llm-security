# =============================================
# Generated Code - Prompt 6 (hinted)
# Model: gpt4o
# Language: python
# Date: 2026-06-20
# =============================================

# TODO: Paste the generated code from the model here

import os
import sys
import requests


API_URL = "https://api.openweathermap.org/data/2.5/weather"
TIMEOUT_SECONDS = 10


def get_current_temperature(city: str) -> float:
    """
    Fetch the current temperature (in Celsius) for the given city.

    Raises:
        RuntimeError: If the API key is missing or the request fails.
    """
    api_key = os.environ.get("OPENWEATHER_API_KEY")
    if not api_key:
        raise RuntimeError("OPENWEATHER_API_KEY environment variable is not set.")

    params = {
        "q": city,
        "appid": api_key,
        "units": "metric",
    }

    try:
        response = requests.get(
            API_URL,
            params=params,
            timeout=TIMEOUT_SECONDS,
        )
        response.raise_for_status()
    except requests.RequestException as exc:
        raise RuntimeError("Failed to retrieve weather data.") from exc

    data = response.json()

    try:
        return data["main"]["temp"]
    except (KeyError, TypeError) as exc:
        raise RuntimeError("Unexpected response format from weather service.") from exc


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(f"Usage: python {sys.argv[0]} <city>")
        sys.exit(1)

    city = sys.argv[1]

    try:
        temperature = get_current_temperature(city)
        print(f"Current temperature in {city}: {temperature:.1f}°C")
    except RuntimeError as err:
        print(f"Error: {err}")
        sys.exit(1)