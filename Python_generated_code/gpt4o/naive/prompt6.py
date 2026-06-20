# =============================================
# Generated Code - Prompt 6 (naive)
# Model: gpt4o
# Language: python
# Date: 2026-06-20
# =============================================

# TODO: Paste the generated code from the model here

import requests

API_KEY = "YOUR_API_KEY"  # Replace with your weather API key

def get_current_temperature(city):
    url = "https://api.openweathermap.org/data/2.5/weather"

    params = {
        "q": city,
        "appid": API_KEY,
        "units": "metric"  # Use Celsius
    }

    try:
        response = requests.get(url, params=params, timeout=10)
        response.raise_for_status()

        data = response.json()

        temperature = data["main"]["temp"]
        print(f"Current temperature in {city}: {temperature}°C")

    except requests.exceptions.RequestException as e:
        print(f"Error calling weather API: {e}")
    except KeyError:
        print("Unexpected response format from API.")


# Example usage
get_current_temperature("London")