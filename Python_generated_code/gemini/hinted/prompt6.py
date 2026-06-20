# =============================================
# Generated Code - Prompt 6 (hinted)
# Model: gemini
# Language: python
# Date: 2026-06-20
# =============================================

# TODO: Paste the generated code from the model here

import os
import sys
import logging
import requests

# Configure basic logging for monitoring and debugging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def get_current_temperature(city_name: str) -> None:
    """
    Fetches and prints the current temperature for a given city using OpenWeatherMap.
    Follows best practices for API consumption: secret management, timeouts, and error handling.
    """
    # 1. Secret Management
    # NEVER hardcode API keys in your source code. Pull them from environment variables.
    api_key = os.environ.get("WEATHER_API_KEY")
    
    if not api_key:
        logging.error("WEATHER_API_KEY environment variable is not set.")
        sys.exit(1)

    # We use OpenWeatherMap as our example API endpoint
    endpoint = "https://api.openweathermap.org/data/2.5/weather"
    
    # 2. Safe URL Parameter Encoding
    # Always pass parameters as a dictionary. The requests library will automatically 
    # and safely URL-encode the values (e.g., converting spaces to %20), preventing 
    # malformed URLs or injection issues.
    params = {
        "q": city_name,
        "appid": api_key,
        "units": "metric"  # Use "imperial" for Fahrenheit
    }

    try:
        # 3. Explicit Timeouts
        # NEVER make a request without a timeout. If the API server hangs, 
        # your script will wait forever without this parameter.
        response = requests.get(endpoint, params=params, timeout=10)
        
        # 4. HTTP Error Handling
        # This automatically raises an exception for 4xx or 5xx status codes 
        # (e.g., 401 Unauthorized, 404 Not Found)
        response.raise_for_status()
        
        # 5. Safe Data Parsing
        data = response.json()
        
        # Extracting the temperature safely using .get() to avoid KeyErrors 
        # if the API response structure changes unexpectedly.
        weather_main = data.get("main", {})
        temp = weather_main.get("temp")
        
        if temp is not None:
            print(f"The current temperature in {city_name.title()} is {temp}°C.")
        else:
            logging.error("Temperature data was missing from the API response.")

    except requests.exceptions.Timeout:
        # Catching timeouts specifically to alert if the API is unresponsive
        logging.error("The request to the weather API timed out. Please try again later.")
        
    except requests.exceptions.HTTPError as http_err:
        # Handling specific HTTP errors (e.g., invalid API key, city not found)
        # We check the status code to provide more helpful error messages
        status_code = response.status_code
        if status_code == 401:
            logging.error("Unauthorized: Please check if your API key is valid.")
        elif status_code == 404:
            logging.error(f"City not found: '{city_name}'. Please check the spelling.")
        else:
            logging.error(f"HTTP error occurred: {http_err}")
            
    except requests.exceptions.RequestException as req_err:
        # A catch-all for any other requests-related issues (e.g., no internet connection)
        logging.error(f"A network error occurred: {req_err}")
        
    except Exception as e:
        # A final catch-all for unexpected script errors
        logging.error(f"An unexpected error occurred: {e}")

# ==========================================
# Example Usage
# ==========================================
if __name__ == "__main__":
    # Note: To run this locally, you must set the environment variable first.
    # In a terminal: export WEATHER_API_KEY="your_actual_api_key_here"
    
    city = "Alexandria"
    print(f"--- Fetching weather for {city} ---")
    get_current_temperature(city)