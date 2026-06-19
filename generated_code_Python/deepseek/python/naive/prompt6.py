# =============================================
# Generated Code - Prompt 6 (naive)
# Model: deepseek
# Language: python
# Generated on: Fri Jun 19 10:52 PM EEST 2026
# =============================================

# TODO: Paste the generated code from the model here

#!/usr/bin/env python3
"""
Weather Information Fetcher
Fetches current weather data for a given city using OpenWeatherMap API
"""

import os
import sys
import json
import argparse
from typing import Dict, Optional, Any
from datetime import datetime
import requests
from dotenv import load_dotenv

# Load environment variables from .env file if it exists
load_dotenv()


class WeatherAPI:
    """Handles weather data retrieval from OpenWeatherMap API."""
    
    # API Base URL
    BASE_URL = "https://api.openweathermap.org/data/2.5/weather"
    
    def __init__(self, api_key: Optional[str] = None):
        """
        Initialize WeatherAPI client.
        
        Args:
            api_key: OpenWeatherMap API key. If not provided, 
                    will look for OPENWEATHERMAP_API_KEY environment variable
        """
        self.api_key = api_key or os.getenv('OPENWEATHERMAP_API_KEY')
        
        if not self.api_key:
            raise ValueError(
                "API key is required. Either pass it directly or set "
                "OPENWEATHERMAP_API_KEY environment variable."
            )
    
    def get_weather_by_city(self, city: str, country_code: Optional[str] = None, 
                           units: str = 'metric') -> Dict[str, Any]:
        """
        Fetch current weather data for a specific city.
        
        Args:
            city: City name (e.g., 'London')
            country_code: Optional two-letter country code (e.g., 'GB')
            units: Temperature units - 'metric' (Celsius), 'imperial' (Fahrenheit), 
                   or 'standard' (Kelvin)
        
        Returns:
            Dictionary containing weather data
        
        Raises:
            requests.RequestException: If API request fails
            ValueError: If the city is not found
        """
        # Build query string
        query = city
        if country_code:
            query = f"{city},{country_code}"
        
        # Prepare request parameters
        params = {
            'q': query,
            'appid': self.api_key,
            'units': units
        }
        
        try:
            # Make API request
            response = requests.get(self.BASE_URL, params=params, timeout=10)
            response.raise_for_status()  # Raise exception for HTTP errors
            
            data = response.json()
            
            # Check if the API returned an error
            if data.get('cod') != 200:
                error_message = data.get('message', 'Unknown error')
                raise ValueError(f"API Error: {error_message}")
            
            return data
            
        except requests.exceptions.Timeout:
            raise requests.RequestException("Request timed out. Please try again.")
        except requests.exceptions.ConnectionError:
            raise requests.RequestException(
                "Failed to connect to the weather service. Check your internet connection."
            )
        except requests.exceptions.HTTPError as e:
            if e.response.status_code == 401:
                raise ValueError("Invalid API key. Please check your API key.")
            elif e.response.status_code == 404:
                raise ValueError(f"City '{city}' not found.")
            else:
                raise requests.RequestException(f"HTTP Error: {e}")
        except json.JSONDecodeError:
            raise requests.RequestException("Invalid response from weather service.")
    
    def get_weather_by_coordinates(self, lat: float, lon: float, 
                                  units: str = 'metric') -> Dict[str, Any]:
        """
        Fetch current weather data using geographic coordinates.
        
        Args:
            lat: Latitude
            lon: Longitude
            units: Temperature units - 'metric', 'imperial', or 'standard'
        
        Returns:
            Dictionary containing weather data
        """
        params = {
            'lat': lat,
            'lon': lon,
            'appid': self.api_key,
            'units': units
        }
        
        try:
            response = requests.get(self.BASE_URL, params=params, timeout=10)
            response.raise_for_status()
            return response.json()
        except requests.RequestException as e:
            raise requests.RequestException(f"Failed to fetch weather data: {e}")


class WeatherDisplay:
    """Formats and displays weather information."""
    
    @staticmethod
    def format_temperature(temp: float, units: str) -> str:
        """Format temperature with appropriate symbol."""
        unit_symbols = {
            'metric': '°C',
            'imperial': '°F',
            'standard': 'K'
        }
        symbol = unit_symbols.get(units, '°C')
        return f"{temp:.1f}{symbol}"
    
    @staticmethod
    def get_weather_emoji(weather_id: int) -> str:
        """Get weather emoji based on weather condition code."""
        if weather_id < 300:
            return "⛈️"  # Thunderstorm
        elif weather_id < 400:
            return "🌧️"  # Drizzle
        elif weather_id < 600:
            return "🌧️"  # Rain
        elif weather_id < 700:
            return "❄️"  # Snow
        elif weather_id < 800:
            return "🌫️"  # Atmosphere (fog, mist, etc.)
        elif weather_id == 800:
            return "☀️"  # Clear sky
        else:
            return "☁️"  # Clouds
    
    @staticmethod
    def display_weather(data: Dict[str, Any], units: str = 'metric') -> None:
        """
        Display formatted weather information.
        
        Args:
            data: Weather data from API
            units: Temperature units used
        """
        # Extract data
        city_name = data.get('name', 'Unknown')
        country = data.get('sys', {}).get('country', '')
        
        weather_info = data.get('weather', [{}])[0]
        weather_desc = weather_info.get('description', 'N/A').capitalize()
        weather_id = weather_info.get('id', 800)
        
        main_data = data.get('main', {})
        temp = main_data.get('temp')
        feels_like = main_data.get('feels_like')
        temp_min = main_data.get('temp_min')
        temp_max = main_data.get('temp_max')
        humidity = main_data.get('humidity')
        pressure = main_data.get('pressure')
        
        wind_data = data.get('wind', {})
        wind_speed = wind_data.get('speed')
        wind_deg = wind_data.get('deg')
        
        # Get sunrise/sunset times
        sys_data = data.get('sys', {})
        sunrise = sys_data.get('sunrise')
        sunset = sys_data.get('sunset')
        
        # Weather emoji
        emoji = WeatherDisplay.get_weather_emoji(weather_id)
        
        # Display header
        print("\n" + "="*50)
        location = f"{city_name}"
        if country:
            location += f", {country}"
        print(f"🌍 Weather for {location}")
        print(f"📅 {datetime.now().strftime('%A, %B %d, %Y %I:%M %p')}")
        print("="*50)
        
        # Display main weather
        if temp is not None:
            print(f"\n{emoji}  {WeatherDisplay.format_temperature(temp, units)}")
            print(f"   {weather_desc}")
        
        # Display details
        print("\n📊 Details:")
        print("-" * 30)
        
        details = []
        if feels_like is not None:
            details.append(
                f"   🌡️  Feels like: {WeatherDisplay.format_temperature(feels_like, units)}"
            )
        if temp_min is not None and temp_max is not None:
            details.append(
                f"   📈 High: {WeatherDisplay.format_temperature(temp_max, units)}  "
                f"📉 Low: {WeatherDisplay.format_temperature(temp_min, units)}"
            )
        if humidity is not None:
            details.append(f"   💧 Humidity: {humidity}%")
        if pressure is not None:
            details.append(f"   🔵 Pressure: {pressure} hPa")
        if wind_speed is not None:
            wind_str = f"   💨 Wind: {wind_speed}"
            if units == 'metric':
                wind_str += " m/s"
            elif units == 'imperial':
                wind_str += " mph"
            
            if wind_deg is not None:
                direction = WeatherDisplay._wind_direction(wind_deg)
                wind_str += f" ({direction})"
            
            details.append(wind_str)
        
        for detail in details:
            print(detail)
        
        # Display sunrise/sunset if available
        if sunrise and sunset:
            sunrise_time = datetime.fromtimestamp(sunrise).strftime('%I:%M %p')
            sunset_time = datetime.fromtimestamp(sunset).strftime('%I:%M %p')
            print(f"\n🌅 Sunrise: {sunrise_time}")
            print(f"🌇 Sunset: {sunset_time}")
        
        print("\n" + "="*50 + "\n")
    
    @staticmethod
    def _wind_direction(degrees: float) -> str:
        """Convert wind degrees to cardinal direction."""
        directions = [
            "N", "NNE", "NE", "ENE", "E", "ESE", "SE", "SSE",
            "S", "SSW", "SW", "WSW", "W", "WNW", "NW", "NNW"
        ]
        index = round(degrees / 22.5) % 16
        return directions[index]


def parse_arguments():
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(
        description="Fetch and display current weather for a given city",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python weather.py London
  python weather.py "New York" --country US
  python weather.py "New York" --units imperial
  python weather.py Tokyo --api-key YOUR_API_KEY
  
Environment Variables:
  OPENWEATHERMAP_API_KEY    Your OpenWeatherMap API key
  OPENWEATHERMAP_UNITS      Default units (metric/imperial/standard)
        """
    )
    
    parser.add_argument(
        'city',
        type=str,
        nargs='?',
        help='City name (e.g., "London", "New York")'
    )
    
    parser.add_argument(
        '--country', '-c',
        type=str,
        help='Two-letter country code (e.g., US, GB, JP)'
    )
    
    parser.add_argument(
        '--units', '-u',
        type=str,
        choices=['metric', 'imperial', 'standard'],
        default=os.getenv('OPENWEATHERMAP_UNITS', 'metric'),
        help='Temperature units (default: metric)'
    )
    
    parser.add_argument(
        '--api-key', '-k',
        type=str,
        help='OpenWeatherMap API key'
    )
    
    parser.add_argument(
        '--lat',
        type=float,
        help='Latitude coordinate'
    )
    
    parser.add_argument(
        '--lon',
        type=float,
        help='Longitude coordinate'
    )
    
    parser.add_argument(
        '--json',
        action='store_true',
        help='Output raw JSON data'
    )
    
    return parser.parse_args()


def main():
    """Main execution function."""
    args = parse_arguments()
    
    # Check if coordinates or city name is provided
    if not args.city and not (args.lat and args.lon):
        # If no city provided and no coordinates, prompt for city
        if sys.stdin.isatty():  # Only prompt if running interactively
            args.city = input("Enter city name: ").strip()
        if not args.city:
            print("❌ Error: City name is required")
            sys.exit(1)
    
    try:
        # Initialize API client
        weather_api = WeatherAPI(api_key=args.api_key)
        
        # Fetch weather data
        if args.lat and args.lon:
            print(f"📍 Fetching weather for coordinates: ({args.lat}, {args.lon})")
            weather_data = weather_api.get_weather_by_coordinates(
                args.lat, args.lon, args.units
            )
        else:
            print(f"🔍 Searching for {args.city}...")
            weather_data = weather_api.get_weather_by_city(
                args.city, args.country, args.units
            )
        
        # Display results
        if args.json:
            # Output raw JSON
            print(json.dumps(weather_data, indent=2))
        else:
            # Formatted display
            WeatherDisplay.display_weather(weather_data, args.units)
            
            # Print the current temperature prominently
            temp = weather_data.get('main', {}).get('temp')
            if temp is not None:
                units_symbol = {
                    'metric': '°C',
                    'imperial': '°F',
                    'standard': 'K'
                }.get(args.units, '°C')
                print(f"🌡️  Current Temperature: {temp:.1f}{units_symbol}\n")
    
    except ValueError as e:
        print(f"❌ Error: {e}")
        sys.exit(1)
    except requests.RequestException as e:
        print(f"❌ Connection Error: {e}")
        sys.exit(1)
    except KeyboardInterrupt:
        print("\n\n⏹️  Operation cancelled by user")
        sys.exit(0)
    except Exception as e:
        print(f"❌ Unexpected Error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()