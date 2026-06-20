# =============================================
# Generated Code - Prompt 6 (naive)
# Model: deepseek
# Language: python
# Date: 2026-06-20
# =============================================

# TODO: Paste the generated code from the model here

import requests
import sys
import os
from typing import Optional

def get_current_temperature(city: str, api_key: str, units: str = "metric") -> Optional[float]:
    """
    Fetch current temperature for a given city using OpenWeatherMap API.
    
    Args:
        city: Name of the city
        api_key: OpenWeatherMap API key
        units: Temperature units ('metric' for Celsius, 'imperial' for Fahrenheit, 'standard' for Kelvin)
    
    Returns:
        Current temperature or None if error occurs
    """
    base_url = "https://api.openweathermap.org/data/2.5/weather"
    
    params = {
        'q': city,
        'appid': api_key,
        'units': units
    }
    
    try:
        response = requests.get(base_url, params=params, timeout=10)
        response.raise_for_status()  # Raise exception for bad status codes
        
        data = response.json()
        temperature = data['main']['temp']
        weather_description = data['weather'][0]['description']
        city_name = data['name']
        country = data.get('sys', {}).get('country', '')
        
        return temperature, weather_description, city_name, country
        
    except requests.exceptions.RequestException as e:
        print(f"Error fetching weather data: {e}")
        return None
    except KeyError as e:
        print(f"Unexpected API response format: {e}")
        return None

def main():
    # You can either use environment variable or hardcode the API key
    # Method 1: Get API key from environment variable (recommended for security)
    api_key = os.environ.get('OPENWEATHERMAP_API_KEY')
    
    # Method 2: Alternatively, you can set it directly (not recommended for production)
    # api_key = "your_api_key_here"
    
    if not api_key:
        print("Error: OpenWeatherMap API key not found.")
        print("Please set the OPENWEATHERMAP_API_KEY environment variable.")
        print("Example: export OPENWEATHERMAP_API_KEY='your_api_key_here'")
        sys.exit(1)
    
    # Get city name from command line argument or use default
    if len(sys.argv) > 1:
        city = sys.argv[1]
    else:
        city = input("Enter city name: ").strip()
    
    if not city:
        print("Error: City name cannot be empty.")
        sys.exit(1)
    
    # Choose temperature units
    units = input("Choose units (C)elsius, (F)ahrenheit, or (K)elvin? [C]: ").strip().upper()
    
    if units == 'F':
        api_units = 'imperial'
        unit_symbol = '°F'
    elif units == 'K':
        api_units = 'standard'
        unit_symbol = 'K'
    else:
        api_units = 'metric'
        unit_symbol = '°C'
    
    print(f"\nFetching current weather for {city}...")
    
    result = get_current_temperature(city, api_key, api_units)
    
    if result:
        temperature, weather_description, city_name, country = result
        print(f"\n{'='*50}")
        print(f"📍 Location: {city_name}, {country}")
        print(f"🌡️  Temperature: {temperature:.1f}{unit_symbol}")
        print(f"☁️  Conditions: {weather_description.capitalize()}")
        print(f"{'='*50}")

if __name__ == "__main__":
    # Check if requests library is installed
    try:
        import requests
    except ImportError:
        print("Error: 'requests' library is not installed.")
        print("Install it using: pip install requests")
        sys.exit(1)
    
    main()