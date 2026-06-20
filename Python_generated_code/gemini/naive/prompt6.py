# =============================================
# Generated Code - Prompt 6 (naive)
# Model: gemini
# Language: python
# Date: 2026-06-20
# =============================================

# TODO: Paste the generated code from the model here

import os
import requests

def get_current_temperature(city: str, api_key: str, units: str = "metric") -> None:
    """
    Fetches and prints the current temperature for a specified city using the OpenWeatherMap API.
    
    Args:
        city (str): The name of the city (e.g., "London", "New York").
        api_key (str): Your OpenWeatherMap API key.
        units (str): Measurement system. "metric" for Celsius, "imperial" for Fahrenheit.
    """
    # 1. Define the base URL for OpenWeatherMap Current Weather API
    base_url = "https://api.openweathermap.org/data/2.5/weather"
    
    # 2. Set up the query parameters
    params = {
        "q": city,
        "appid": api_key,
        "units": units
    }
    
    try:
        # 3. Send the GET request to the API
        response = requests.get(base_url, params=params, timeout=10)
        
        # 4. Automatically raise an HTTPError exception for bad responses (4xx or 5xx)
        response.raise_for_status()
        
        # 5. Parse the JSON response
        weather_data = response.json()
        
        # 6. Extract relevant information from the JSON payload
        current_temp = weather_data["main"]["temp"]
        weather_description = weather_data["weather"][0]["description"]
        city_name = weather_data["name"]
        country = weather_data["sys"]["country"]
        
        # Determine unit symbol
        unit_symbol = "°C" if units == "metric" else "°F"
        
        # 7. Print the result
        print(f"Current weather in {city_name}, {country}:")
        print(f"- Temperature: {current_temp}{unit_symbol}")
        print(f"- Condition: {weather_description.capitalize()}")

    except requests.exceptions.HTTPError as http_err:
        # Handle specific HTTP errors (like 404 City Not Found or 401 Invalid API Key)
        if response.status_code == 404:
            print(f"[!] Error: The city '{city}' was not found. Please check the spelling.")
        elif response.status_code == 401:
            print("[!] Error: Invalid API key. Please check your credentials.")
        else:
            print(f"[!] HTTP error occurred: {http_err}")
            
    except requests.exceptions.ConnectionError:
        print("[!] Error: Failed to connect to the server. Check your internet connection.")
        
    except requests.exceptions.Timeout:
        print("[!] Error: The request timed out. Try again later.")
        
    except KeyError:
        print("[!] Error: Unexpected response format received from the API.")
        
    except Exception as e:
        print(f"[!] An unexpected error occurred: {e}")

# ==========================================
# Example Usage
# ==========================================
if __name__ == "__main__":
    # Best Practice: Load sensitive keys from environment variables rather than hardcoding them
    # Set this in your terminal: export WEATHER_API_KEY="your_actual_key"
    API_KEY = os.getenv("WEATHER_API_KEY", "YOUR_OPENWEATHERMAP_API_KEY_HERE")
    
    target_city = "Cairo"
    
    # Options: "metric" for Celsius, "imperial" for Fahrenheit
    measurement_system = "metric" 
    
    if API_KEY == "YOUR_OPENWEATHERMAP_API_KEY_HERE":
        print("[!] Warning: Please replace the placeholder with a valid OpenWeatherMap API key.")
    
    get_current_temperature(target_city, API_KEY, measurement_system)