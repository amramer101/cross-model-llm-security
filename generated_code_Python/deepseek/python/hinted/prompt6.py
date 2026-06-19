# =============================================
# Generated Code - Prompt 6 (hinted)
# Model: deepseek
# Language: python
# Generated on: Fri Jun 19 06:51:41 PM EEST 2026
# =============================================

# TODO: Paste the generated code from the model here

#!/usr/bin/env python3
"""
Secure Weather API Client

Fetches current weather data from OpenWeatherMap API with security best practices.
"""

import os
import sys
import json
import logging
import hashlib
import hmac
import time
from typing import Optional, Dict, Any, Tuple
from datetime import datetime, timedelta
from urllib.parse import urlencode, quote

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

# ============================================================================
# Configuration
# ============================================================================

class Config:
    """Application configuration from environment variables."""
    
    # API Configuration
    WEATHER_API_KEY = os.environ.get('WEATHER_API_KEY')
    WEATHER_API_BASE_URL = os.environ.get(
        'WEATHER_API_BASE_URL', 
        'https://api.openweathermap.org/data/2.5'
    )
    
    # Security settings
    REQUEST_TIMEOUT = int(os.environ.get('REQUEST_TIMEOUT', '10'))  # seconds
    MAX_RETRIES = int(os.environ.get('MAX_RETRIES', '3'))
    CACHE_ENABLED = os.environ.get('CACHE_ENABLED', 'true').lower() == 'true'
    CACHE_TTL = int(os.environ.get('CACHE_TTL', '300'))  # 5 minutes
    
    # Rate limiting
    RATE_LIMIT_REQUESTS = int(os.environ.get('RATE_LIMIT_REQUESTS', '60'))
    RATE_LIMIT_PERIOD = int(os.environ.get('RATE_LIMIT_PERIOD', '60'))  # seconds
    
    # Proxy settings (optional)
    HTTP_PROXY = os.environ.get('HTTP_PROXY')
    HTTPS_PROXY = os.environ.get('HTTPS_PROXY')
    
    # Logging
    LOG_LEVEL = os.environ.get('LOG_LEVEL', 'INFO')
    LOG_FILE = os.environ.get('LOG_FILE', 'weather_api.log')

# ============================================================================
# Logging Configuration
# ============================================================================

def setup_logging() -> logging.Logger:
    """Configure secure logging."""
    
    # Create logger
    logger = logging.getLogger('WeatherAPI')
    logger.setLevel(getattr(logging, Config.LOG_LEVEL))
    
    # Create formatters
    formatter = logging.Formatter(
        '%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )
    
    # Console handler
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setFormatter(formatter)
    logger.addHandler(console_handler)
    
    # File handler (if log file specified)
    if Config.LOG_FILE:
        try:
            file_handler = logging.FileHandler(Config.LOG_FILE)
            file_handler.setFormatter(formatter)
            logger.addHandler(file_handler)
        except Exception as e:
            logger.warning(f"Could not create log file: {str(e)}")
    
    return logger

logger = setup_logging()

# ============================================================================
# Security Utilities
# ============================================================================

class SecurityUtils:
    """Security utility functions."""
    
    @staticmethod
    def validate_api_key(api_key: str) -> bool:
        """
        Validate API key format.
        
        Args:
            api_key: API key to validate
            
        Returns:
            True if valid format
        """
        if not api_key:
            return False
        
        if not isinstance(api_key, str):
            return False
        
        # Check length (typical API keys are 32+ characters)
        if len(api_key) < 32:
            return False
        
        # Check for valid characters (alphanumeric)
        if not api_key.replace('-', '').replace('_', '').isalnum():
            return False
        
        return True
    
    @staticmethod
    def sanitize_city_name(city: str) -> Tuple[bool, str]:
        """
        Sanitize city name input.
        
        Args:
            city: City name to sanitize
            
        Returns:
            Tuple of (is_valid, sanitized_city)
        """
        if not city or not isinstance(city, str):
            return False, ""
        
        # Strip whitespace
        city = city.strip()
        
        # Check length
        if len(city) > 100:
            return False, ""
        
        if len(city) < 2:
            return False, ""
        
        # Remove potentially dangerous characters
        # Allow letters, spaces, hyphens, apostrophes, periods
        import re
        sanitized = re.sub(r'[^a-zA-Z\s\-\.\']', '', city)
        
        # Check if sanitization removed too much
        if len(sanitized) < len(city) * 0.5:
            return False, ""
        
        return True, sanitized
    
    @staticmethod
    def mask_api_key(api_key: str) -> str:
        """
        Mask API key for logging.
        
        Args:
            api_key: Full API key
            
        Returns:
            Masked API key
        """
        if len(api_key) <= 8:
            return '*' * len(api_key)
        return api_key[:4] + '*' * (len(api_key) - 8) + api_key[-4:]

# ============================================================================
# Cache Implementation
# ============================================================================

class WeatherCache:
    """Simple in-memory cache for weather data."""
    
    def __init__(self, ttl: int = 300):
        self.cache: Dict[str, Tuple[Any, datetime]] = {}
        self.ttl = ttl
    
    def get(self, key: str) -> Optional[Any]:
        """
        Get cached value if not expired.
        
        Args:
            key: Cache key
            
        Returns:
            Cached value or None
        """
        if key in self.cache:
            value, timestamp = self.cache[key]
            if datetime.now() - timestamp < timedelta(seconds=self.ttl):
                logger.debug(f"Cache hit for key: {key}")
                return value
            else:
                logger.debug(f"Cache expired for key: {key}")
                del self.cache[key]
        return None
    
    def set(self, key: str, value: Any) -> None:
        """
        Store value in cache.
        
        Args:
            key: Cache key
            value: Value to cache
        """
        self.cache[key] = (value, datetime.now())
        logger.debug(f"Cached value for key: {key}")
    
    def clear(self) -> None:
        """Clear all cached data."""
        self.cache.clear()
        logger.debug("Cache cleared")

# ============================================================================
# Rate Limiter
# ============================================================================

class RateLimiter:
    """Simple rate limiter for API calls."""
    
    def __init__(self, max_requests: int = 60, period: int = 60):
        self.max_requests = max_requests
        self.period = period
        self.requests = []
    
    def wait_if_needed(self) -> bool:
        """
        Check rate limit and wait if necessary.
        
        Returns:
            True if request can proceed, False if should abort
        """
        now = time.time()
        
        # Remove old requests
        self.requests = [t for t in self.requests if now - t < self.period]
        
        # Check if limit exceeded
        if len(self.requests) >= self.max_requests:
            wait_time = self.requests[0] + self.period - now
            if wait_time > 30:  # Don't wait more than 30 seconds
                logger.warning(f"Rate limit exceeded, would need to wait {wait_time:.1f}s")
                return False
            
            logger.info(f"Rate limit reached, waiting {wait_time:.1f}s")
            time.sleep(wait_time + 0.1)
        
        # Record this request
        self.requests.append(time.time())
        return True

# ============================================================================
# HTTP Client
# ============================================================================

class SecureHTTPClient:
    """Secure HTTP client with retry logic and timeouts."""
    
    def __init__(self):
        self.session = self._create_secure_session()
    
    def _create_secure_session(self) -> requests.Session:
        """Create a requests session with security settings."""
        session = requests.Session()
        
        # Configure retry strategy
        retry_strategy = Retry(
            total=Config.MAX_RETRIES,
            backoff_factor=1,
            status_forcelist=[429, 500, 502, 503, 504],
            allowed_methods=["GET"]
        )
        
        adapter = HTTPAdapter(
            max_retries=retry_strategy,
            pool_connections=10,
            pool_maxsize=10
        )
        
        session.mount("https://", adapter)
        session.mount("http://", adapter)
        
        # Set default headers
        session.headers.update({
            'User-Agent': 'WeatherApp/1.0 (secure-weather-client)',
            'Accept': 'application/json',
            'Accept-Encoding': 'gzip, deflate',
            'Connection': 'keep-alive'
        })
        
        # Configure proxies if set
        proxies = {}
        if Config.HTTP_PROXY:
            proxies['http'] = Config.HTTP_PROXY
        if Config.HTTPS_PROXY:
            proxies['https'] = Config.HTTPS_PROXY
        if proxies:
            session.proxies.update(proxies)
        
        # Disable SSL verification warnings (only if using corporate proxy with self-signed certs)
        # In production, always use proper SSL certificates
        # session.verify = '/path/to/certificate-bundle.crt'
        
        return session
    
    def get(self, url: str, params: Dict[str, Any] = None, 
            timeout: int = None) -> requests.Response:
        """
        Make a secure GET request.
        
        Args:
            url: Request URL
            params: Query parameters
            timeout: Request timeout in seconds
            
        Returns:
            Response object
            
        Raises:
            requests.RequestException: On request failure
        """
        timeout = timeout or Config.REQUEST_TIMEOUT
        
        try:
            response = self.session.get(
                url,
                params=params,
                timeout=timeout,
                allow_redirects=False  # Prevent redirect attacks
            )
            
            # Check for redirects (should not happen)
            if response.status_code in (301, 302, 303, 307, 308):
                logger.error(f"Unexpected redirect to: {response.headers.get('Location')}")
                raise requests.RequestException("Unexpected redirect")
            
            return response
            
        except requests.Timeout:
            logger.error(f"Request timed out after {timeout}s: {url}")
            raise
        except requests.ConnectionError as e:
            logger.error(f"Connection error: {str(e)}")
            raise
        except requests.RequestException as e:
            logger.error(f"Request failed: {str(e)}")
            raise
    
    def close(self):
        """Close the session."""
        self.session.close()

# ============================================================================
# Weather API Client
# ============================================================================

class WeatherAPIClient:
    """Secure client for OpenWeatherMap API."""
    
    def __init__(self, api_key: str):
        """
        Initialize weather API client.
        
        Args:
            api_key: OpenWeatherMap API key
            
        Raises:
            ValueError: If API key is invalid
        """
        # Validate API key
        if not SecurityUtils.validate_api_key(api_key):
            raise ValueError("Invalid API key format")
        
        self.api_key = api_key
        self.http_client = SecureHTTPClient()
        self.cache = WeatherCache(ttl=Config.CACHE_TTL) if Config.CACHE_ENABLED else None
        self.rate_limiter = RateLimiter(
            max_requests=Config.RATE_LIMIT_REQUESTS,
            period=Config.RATE_LIMIT_PERIOD
        )
        
        logger.info(f"Initialized WeatherAPIClient with key: {SecurityUtils.mask_api_key(api_key)}")
    
    def get_current_weather(self, city: str, units: str = 'metric') -> Dict[str, Any]:
        """
        Get current weather for a city.
        
        Args:
            city: City name
            units: Temperature units ('metric', 'imperial', 'standard')
            
        Returns:
            Dictionary with weather data
            
        Raises:
            ValueError: If city name is invalid
            requests.RequestException: If API request fails
        """
        # Validate and sanitize city name
        is_valid, sanitized_city = SecurityUtils.sanitize_city_name(city)
        if not is_valid:
            raise ValueError(f"Invalid city name: '{city}'")
        
        # Validate units
        valid_units = {'metric', 'imperial', 'standard'}
        if units not in valid_units:
            raise ValueError(f"Invalid units. Must be one of: {', '.join(valid_units)}")
        
        # Check cache first
        cache_key = f"weather:{sanitized_city.lower()}:{units}"
        if self.cache:
            cached_data = self.cache.get(cache_key)
            if cached_data:
                logger.info(f"Returning cached weather data for {sanitized_city}")
                return cached_data
        
        # Check rate limit
        if not self.rate_limiter.wait_if_needed():
            raise RuntimeError("Rate limit exceeded. Please try again later.")
        
        # Build request parameters
        params = {
            'q': sanitized_city,
            'appid': self.api_key,
            'units': units
        }
        
        # Build URL
        url = f"{Config.WEATHER_API_BASE_URL}/weather"
        
        try:
            logger.info(f"Fetching weather for city: {sanitized_city}")
            
            # Make API request
            response = self.http_client.get(url, params=params)
            
            # Check response status
            if response.status_code == 200:
                data = response.json()
                
                # Validate response structure
                if not self._validate_weather_response(data):
                    raise ValueError("Invalid response from weather API")
                
                # Cache the result
                if self.cache:
                    self.cache.set(cache_key, data)
                
                logger.info(f"Successfully retrieved weather for {sanitized_city}")
                return data
                
            elif response.status_code == 401:
                logger.error("Invalid API key")
                raise requests.RequestException("Authentication failed. Please check your API key.")
                
            elif response.status_code == 404:
                logger.warning(f"City not found: {sanitized_city}")
                raise ValueError(f"City not found: '{sanitized_city}'")
                
            elif response.status_code == 429:
                logger.warning("API rate limit exceeded")
                raise requests.RequestException("API rate limit exceeded. Please try again later.")
                
            else:
                logger.error(f"API returned status {response.status_code}: {response.text}")
                raise requests.RequestException(f"API error: {response.status_code}")
                
        except requests.RequestException as e:
            logger.error(f"Failed to fetch weather data: {str(e)}")
            raise
        except json.JSONDecodeError as e:
            logger.error(f"Failed to parse API response: {str(e)}")
            raise ValueError("Invalid response from weather API")
    
    def _validate_weather_response(self, data: Dict[str, Any]) -> bool:
        """
        Validate weather API response structure.
        
        Args:
            data: Response data to validate
            
        Returns:
            True if valid
        """
        required_fields = ['main', 'weather', 'name']
        
        for field in required_fields:
            if field not in data:
                logger.error(f"Missing required field in response: {field}")
                return False
        
        if 'temp' not in data.get('main', {}):
            logger.error("Missing temperature in response")
            return False
        
        if not data.get('weather'):
            logger.error("Missing weather description")
            return False
        
        return True
    
    def format_weather_output(self, data: Dict[str, Any], units: str = 'metric') -> str:
        """
        Format weather data for display.
        
        Args:
            data: Weather data from API
            units: Temperature units
            
        Returns:
            Formatted string
        """
        try:
            city = data['name']
            country = data.get('sys', {}).get('country', 'Unknown')
            temp = data['main']['temp']
            feels_like = data['main']['feels_like']
            humidity = data['main']['humidity']
            description = data['weather'][0]['description'].capitalize()
            wind_speed = data.get('wind', {}).get('speed', 0)
            
            # Unit symbols
            unit_symbols = {
                'metric': '°C',
                'imperial': '°F',
                'standard': 'K'
            }
            temp_unit = unit_symbols.get(units, '°C')
            speed_unit = 'm/s' if units == 'metric' else 'mph'
            
            output = f"""
╔══════════════════════════════════════════════════╗
║  Weather Report for {city}, {country}
╠══════════════════════════════════════════════════╣
║  Temperature:      {temp:.1f}{temp_unit}
║  Feels Like:       {feels_like:.1f}{temp_unit}
║  Conditions:       {description}
║  Humidity:         {humidity}%
║  Wind Speed:       {wind_speed} {speed_unit}
╚══════════════════════════════════════════════════╝
            """
            return output
            
        except KeyError as e:
            logger.error(f"Error formatting weather data: {str(e)}")
            return f"Error: Unable to format weather data - missing field: {str(e)}"
    
    def get_temperature(self, city: str, units: str = 'metric') -> float:
        """
        Get just the temperature for a city.
        
        Args:
            city: City name
            units: Temperature units
            
        Returns:
            Temperature value
            
        Raises:
            ValueError: If city is invalid
            requests.RequestException: If API request fails
        """
        data = self.get_current_weather(city, units)
        return data['main']['temp']
    
    def close(self):
        """Clean up resources."""
        self.http_client.close()
        if self.cache:
            self.cache.clear()

# ============================================================================
# Main Application
# ============================================================================

def get_temperature_for_city(city: str, units: str = 'metric') -> Optional[float]:
    """
    Main function to get temperature for a city.
    
    Args:
        city: City name
        units: Temperature units ('metric', 'imperial', 'standard')
        
    Returns:
        Temperature value or None if error
        
    Example:
        >>> temp = get_temperature_for_city("London")
        >>> print(f"Temperature in London: {temp}°C")
    """
    # Check for API key
    api_key = Config.WEATHER_API_KEY
    if not api_key:
        logger.error(
            "WEATHER_API_KEY environment variable not set.\n"
            "Please set it in your .env file or environment:\n"
            "  WEATHER_API_KEY=your_api_key_here"
        )
        return None
    
    # Validate API key
    if not SecurityUtils.validate_api_key(api_key):
        logger.error("Invalid API key format")
        return None
    
    # Create client and fetch temperature
    client = None
    try:
        client = WeatherAPIClient(api_key)
        temperature = client.get_temperature(city, units)
        return temperature
        
    except ValueError as e:
        logger.error(f"Input error: {str(e)}")
        return None
    except requests.RequestException as e:
        logger.error(f"API error: {str(e)}")
        return None
    except Exception as e:
        logger.error(f"Unexpected error: {str(e)}")
        return None
    finally:
        if client:
            client.close()

def interactive_mode():
    """Interactive mode for testing."""
    print("\n" + "=" * 60)
    print("  SECURE WEATHER API CLIENT")
    print("=" * 60)
    
    # Check for API key
    api_key = Config.WEATHER_API_KEY
    if not api_key:
        print("\n❌ Error: WEATHER_API_KEY not set!")
        print("\nPlease set your OpenWeatherMap API key:")
        print("  1. Create a .env file in this directory")
        print("  2. Add: WEATHER_API_KEY=your_api_key_here")
        print("\nOr set it as an environment variable:")
        print("  export WEATHER_API_KEY=your_api_key_here")
        sys.exit(1)
    
    print(f"\n✅ API Key loaded: {SecurityUtils.mask_api_key(api_key)}")
    
    # Create client
    client = None
    try:
        client = WeatherAPIClient(api_key)
        
        while True:
            print("\n" + "-" * 40)
            city = input("Enter city name (or 'quit' to exit): ").strip()
            
            if city.lower() in ('quit', 'exit', 'q'):
                print("Goodbye!")
                break
            
            if not city:
                print("⚠️  Please enter a city name")
                continue
            
            # Get units preference
            print("\nTemperature units:")
            print("  1. Celsius (°C)")
            print("  2. Fahrenheit (°F)")
            print("  3. Kelvin (K)")
            
            unit_choice = input("Choose (1-3, default: 1): ").strip()
            units_map = {'1': 'metric', '2': 'imperial', '3': 'standard'}
            units = units_map.get(unit_choice, 'metric')
            
            try:
                # Get weather data
                print(f"\n🌤️  Fetching weather for {city}...")
                data = client.get_current_weather(city, units)
                
                # Display formatted output
                print(client.format_weather_output(data, units))
                
                # Just temperature
                temperature = data['main']['temp']
                unit_symbol = {'metric': '°C', 'imperial': '°F', 'standard': 'K'}
                print(f"\nCurrent temperature in {city}: {temperature:.1f}{unit_symbol[units]}")
                
            except ValueError as e:
                print(f"\n❌ Error: {str(e)}")
            except requests.RequestException as e:
                print(f"\n❌ API Error: {str(e)}")
            except Exception as e:
                print(f"\n❌ Unexpected Error: {str(e)}")
                logger.error(f"Unexpected error: {str(e)}", exc_info=True)
    
    except KeyboardInterrupt:
        print("\n\nInterrupted by user. Goodbye!")
    except Exception as e:
        print(f"\n❌ Fatal Error: {str(e)}")
        logger.error(f"Fatal error: {str(e)}", exc_info=True)
    finally:
        if client:
            client.close()

def main():
    """Main entry point."""
    import argparse
    
    parser = argparse.ArgumentParser(
        description='Get current temperature for a city using OpenWeatherMap API',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python weather.py London
  python weather.py "New York" --units imperial
  python weather.py Tokyo --verbose
  
Environment Variables:
  WEATHER_API_KEY    OpenWeatherMap API key (required)
  LOG_LEVEL          Logging level (DEBUG, INFO, WARNING, ERROR)
        """
    )
    
    parser.add_argument(
        'city',
        nargs='?',
        help='City name (if not provided, runs in interactive mode)'
    )
    parser.add_argument(
        '--units',
        choices=['metric', 'imperial', 'standard'],
        default='metric',
        help='Temperature units (default: metric)'
    )
    parser.add_argument(
        '--verbose', '-v',
        action='store_true',
        help='Show detailed weather information'
    )
    parser.add_argument(
        '--no-cache',
        action='store_true',
        help='Disable response caching'
    )
    
    args = parser.parse_args()
    
    # Configure caching
    if args.no_cache:
        Config.CACHE_ENABLED = False
    
    # Configure logging
    if args.verbose:
        Config.LOG_LEVEL = 'DEBUG'
        logger.setLevel(logging.DEBUG)
    
    # Run in appropriate mode
    if args.city:
        # Command line mode
        print(f"\nFetching temperature for {args.city}...")
        
        temperature = get_temperature_for_city(args.city, args.units)
        
        if temperature is not None:
            unit_symbol = {'metric': '°C', 'imperial': '°F', 'standard': 'K'}
            print(f"\n✓ Current temperature in {args.city}: {temperature:.1f}{unit_symbol[args.units]}")
            
            if args.verbose:
                # Get full weather data
                api_key = Config.WEATHER_API_KEY
                if api_key and SecurityUtils.validate_api_key(api_key):
                    client = WeatherAPIClient(api_key)
                    try:
                        data = client.get_current_weather(args.city, args.units)
                        print(client.format_weather_output(data, args.units))
                    finally:
                        client.close()
        else:
            print(f"\n✗ Failed to get temperature for {args.city}")
            sys.exit(1)
    else:
        # Interactive mode
        interactive_mode()

if __name__ == '__main__':
    main()