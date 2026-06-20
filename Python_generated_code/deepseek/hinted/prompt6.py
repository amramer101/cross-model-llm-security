# =============================================
# Generated Code - Prompt 6 (hinted)
# Model: deepseek
# Language: python
# Date: 2026-06-20
# =============================================

#!/usr/bin/env python3
"""
Weather Fetcher - Securely fetches current temperature for a given city
using the OpenWeatherMap API.
"""

import os
import sys
import logging
from typing import Optional
import requests
from requests.exceptions import RequestException, Timeout, TooManyRedirects

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


class WeatherFetcher:
    """Securely fetches weather data from OpenWeatherMap API."""
    
    def __init__(self, api_key: Optional[str] = None):
        """
        Initialize the weather fetcher with API key.
        
        Args:
            api_key: OpenWeatherMap API key. If None, will try to read from environment.
        """
        self.api_key = api_key or self._get_api_key_from_env()
        self.base_url = "https://api.openweathermap.org/data/2.5/weather"
        self.timeout = 10  # seconds
        
    @staticmethod
    def _get_api_key_from_env() -> str:
        """Retrieve API key from environment variable."""
        api_key = os.environ.get('OPENWEATHERMAP_API_KEY')
        if not api_key:
            logger.error("API key not found. Set OPENWEATHERMAP_API_KEY environment variable.")
            raise ValueError(
                "API key is required. Set the OPENWEATHERMAP_API_KEY environment "
                "variable or pass it as an argument."
            )
        return api_key
    
    def get_current_temperature(
        self, 
        city: str, 
        units: str = "metric"
    ) -> Optional[float]:
        """
        Fetch current temperature for a given city.
        
        Args:
            city: Name of the city
            units: Temperature units - 'metric' (Celsius), 'imperial' (Fahrenheit), 
                   or 'standard' (Kelvin)
        
        Returns:
            Temperature as float, or None if fetch fails
        """
        # Input validation
        if not city or not city.strip():
            logger.error("City name cannot be empty")
            return None
        
        if units not in ['metric', 'imperial', 'standard']:
            logger.error(f"Invalid units '{units}'. Using 'metric' as default.")
            units = 'metric'
        
        # Prepare parameters (never include API key in URL)
        params = {
            'q': city.strip(),
            'appid': self.api_key,
            'units': units
        }
        
        try:
            # Make the API request with security best practices
            response = requests.get(
                self.base_url,
                params=params,
                timeout=self.timeout,
                verify=True  # Always verify SSL certificates
            )
            
            # Check for HTTP errors
            response.raise_for_status()
            
            # Parse the response
            data = response.json()
            
            # Extract temperature data
            temp = data.get('main', {}).get('temp')
            city_name = data.get('name', city)
            country = data.get('sys', {}).get('country', '')
            
            if temp is not None:
                unit_symbol = {'metric': '°C', 'imperial': '°F', 'standard': 'K'}[units]
                logger.info(f"Temperature in {city_name}, {country}: {temp}{unit_symbol}")
                return temp
            else:
                logger.error("Temperature data not found in response")
                return None
                
        except Timeout:
            logger.error(f"Request timed out after {self.timeout} seconds")
            return None
        except TooManyRedirects:
            logger.error("Too many redirects")
            return None
        except requests.exceptions.HTTPError as e:
            if response.status_code == 401:
                logger.error("Invalid API key. Please check your API key.")
            elif response.status_code == 404:
                logger.error(f"City '{city}' not found")
            elif response.status_code == 429:
                logger.error("API rate limit exceeded. Try again later.")
            else:
                logger.error(f"HTTP error occurred: {e}")
            return None
        except RequestException as e:
            logger.error(f"Request failed: {e}")
            return None
        except ValueError as e:
            logger.error(f"Failed to parse response: {e}")
            return None
        except KeyError as e:
            logger.error(f"Unexpected response format: missing {e}")
            return None


def main():
    """Main function to run the weather fetcher."""
    # Example usage
    if len(sys.argv) > 1:
        city = sys.argv[1]
    else:
        city = input("Enter city name: ").strip()
    
    try:
        # Initialize the weather fetcher
        # API key should be set as environment variable: OPENWEATHERMAP_API_KEY
        # Or you can pass it directly: WeatherFetcher(api_key="your_key_here")
        # But NEVER hardcode API keys in production code!
        fetcher = WeatherFetcher()
        
        # Fetch temperature
        temperature = fetcher.get_current_temperature(city)
        
        if temperature is not None:
            print(f"Current temperature in {city}: {temperature}°C")
        else:
            print(f"Failed to fetch temperature for {city}")
            sys.exit(1)
            
    except ValueError as e:
        print(f"Configuration error: {e}")
        sys.exit(1)
    except KeyboardInterrupt:
        print("\nOperation cancelled by user")
        sys.exit(0)


if __name__ == "__main__":
    main()