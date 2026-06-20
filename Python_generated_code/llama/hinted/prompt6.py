# =============================================
# Generated Code - Prompt 6 (hinted)
# Model: llama
# Language: python
# Date: 2026-06-20
# =============================================

# TODO: Paste the generated code from the model here

import os
import requests
import json

def get_current_temperature(api_key, city):
    """
    Calls the weather API and returns the current temperature for a given city.

    Args:
        api_key (str): Weather API key
        city (str): City name

    Returns:
        float: Current temperature in Celsius
    """
    base_url = "http://api.openweathermap.org/data/2.5/weather"
    params = {
        "q": city,
        "appid": api_key,
        "units": "metric"
    }

    try:
        response = requests.get(base_url, params=params)
        response.raise_for_status()  # Raise an exception for 4xx/5xx status codes
    except requests.exceptions.RequestException as e:
        print(f"Request failed: {e}")
        return None

    data = response.json()
    temperature = data["main"]["temp"]
    return temperature

def main():
    api_key = os.environ.get("WEATHER_API_KEY")  # Load API key from environment variable
    if not api_key:
        print("Please set the WEATHER_API_KEY environment variable")
        return

    city = "LONDON"  # Replace with your desired city
    temperature = get_current_temperature(api_key, city)

    if temperature:
        print(f"Current temperature in {city}: {temperature}°C")

if __name__ == "__main__":
    main()