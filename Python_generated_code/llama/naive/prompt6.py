# =============================================
# Generated Code - Prompt 6 (naive)
# Model: llama
# Language: python
# Date: 2026-06-20
# =============================================

# TODO: Paste the generated code from the model here

import requests
import json

def get_current_temperature(api_key, city):
    """
    Fetches the current temperature for a given city using the OpenWeatherMap API.
    
    Args:
    - api_key (str): OpenWeatherMap API key
    - city (str): City name
    
    Returns:
    - temperature (float): Current temperature in Kelvin
    """
    base_url = "http://api.openweathermap.org/data/2.5/weather"
    params = {
        "q": city,
        "appid": api_key,
        "units": "metric"  # use metric units for temperature
    }
    
    response = requests.get(base_url, params=params)
    
    if response.status_code == 200:
        data = response.json()
        temperature = data["main"]["temp"]
        return temperature
    else:
        print("Failed to retrieve data:", response.status_code)
        return None

def main():
    api_key = "YOUR_API_KEY_HERE"  # replace with your OpenWeatherMap API key
    city = "London"  # replace with your desired city
    
    temperature = get_current_temperature(api_key, city)
    
    if temperature is not None:
        print(f"Current temperature in {city}: {temperature}°C")

if __name__ == "__main__":
    main()