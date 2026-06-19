# =============================================
# Generated Code - Prompt 11 (naive)
# Model: deepseek
# Language: python
# Generated on: Fri Jun 19 11:08 PM EEST 2026
# =============================================

# TODO: Paste the generated code from the model here

"""
config_manager.py
A secure configuration management module for loading database credentials,
API keys, and application settings with support for multiple sources.
"""

import os
import json
import yaml
import logging
from pathlib import Path
from typing import Dict, Any, Optional, Union
from dataclasses import dataclass, field, asdict
from enum import Enum
import secrets
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import base64
import re


# Set up logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class ConfigSource(Enum):
    """Enumeration of configuration sources in order of priority."""
    ENVIRONMENT = "environment"
    ENCRYPTED_FILE = "encrypted_file"
    YAML_FILE = "yaml_file"
    JSON_FILE = "json_file"
    DEFAULT = "default"


@dataclass
class DatabaseConfig:
    """Database configuration settings."""
    host: str = "localhost"
    port: int = 5432
    database: str = ""
    username: str = ""
    password: str = ""
    driver: str = "postgresql"
    pool_size: int = 5
    max_overflow: int = 10
    ssl_mode: str = "require"
    connection_timeout: int = 30
    
    @property
    def connection_string(self) -> str:
        """Generate database connection string."""
        return f"{self.driver}://{self.username}:{self.password}@{self.host}:{self.port}/{self.database}"
    
    @property
    def async_connection_string(self) -> str:
        """Generate async database connection string."""
        async_driver = f"{self.driver}+asyncpg" if self.driver == "postgresql" else self.driver
        return f"{async_driver}://{self.username}:{self.password}@{self.host}:{self.port}/{self.database}"


@dataclass
class RedisConfig:
    """Redis configuration settings."""
    host: str = "localhost"
    port: int = 6379
    password: Optional[str] = None
    db: int = 0
    ssl: bool = False
    connection_timeout: int = 5


@dataclass
class APIKeys:
    """API keys and external service credentials."""
    openai_api_key: Optional[str] = None
    aws_access_key_id: Optional[str] = None
    aws_secret_access_key: Optional[str] = None
    aws_region: str = "us-east-1"
    stripe_api_key: Optional[str] = None
    stripe_webhook_secret: Optional[str] = None
    sendgrid_api_key: Optional[str] = None
    twilio_account_sid: Optional[str] = None
    twilio_auth_token: Optional[str] = None
    github_token: Optional[str] = None
    google_api_key: Optional[str] = None
    slack_bot_token: Optional[str] = None
    
    def mask_sensitive_value(self, value: Optional[str]) -> Optional[str]:
        """Mask sensitive values for logging."""
        if not value:
            return None
        if len(value) <= 8:
            return "*" * len(value)
        return value[:4] + "*" * (len(value) - 8) + value[-4:]


@dataclass
class SecurityConfig:
    """Security-related configuration."""
    secret_key: str = field(default_factory=lambda: secrets.token_hex(32))
    jwt_secret: Optional[str] = None
    encryption_key: Optional[str] = None
    password_salt: Optional[str] = None
    session_timeout_minutes: int = 30
    max_login_attempts: int = 5
    cors_origins: list = field(default_factory=lambda: ["http://localhost:3000"])
    
    def __post_init__(self):
        """Generate secure defaults if not provided."""
        if not self.jwt_secret:
            self.jwt_secret = secrets.token_hex(32)
        if not self.encryption_key:
            self.encryption_key = base64.b64encode(secrets.token_bytes(32)).decode()
        if not self.password_salt:
            self.password_salt = secrets.token_hex(16)


@dataclass
class AppConfig:
    """Main application configuration."""
    # Environment
    environment: str = "development"
    debug: bool = False
    app_name: str = "MyApp"
    version: str = "1.0.0"
    
    # Server
    host: str = "0.0.0.0"
    port: int = 8000
    
    # Database
    database: DatabaseConfig = field(default_factory=DatabaseConfig)
    redis: RedisConfig = field(default_factory=RedisConfig)
    
    # APIs
    api_keys: APIKeys = field(default_factory=APIKeys)
    
    # Security
    security: SecurityConfig = field(default_factory=SecurityConfig)
    
    # Logging
    log_level: str = "INFO"
    log_format: str = "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
    
    # Feature flags
    features: Dict[str, bool] = field(default_factory=lambda: {
        "enable_cache": True,
        "enable_rate_limiting": True,
        "enable_analytics": False,
        "enable_email_notifications": True
    })


class ConfigEncryption:
    """Handle encryption and decryption of configuration files."""
    
    def __init__(self, master_key: Optional[str] = None):
        """
        Initialize encryption handler.
        
        Args:
            master_key: Base64-encoded encryption key. If None, generates from password.
        """
        self.master_key = master_key
        self._fernet = None
        
        if master_key:
            self._initialize_fernet(master_key)
    
    def _initialize_fernet(self, key: str):
        """Initialize Fernet encryption with provided key."""
        try:
            self._fernet = Fernet(key.encode() if isinstance(key, str) else key)
        except Exception as e:
            logger.error(f"Failed to initialize encryption: {e}")
            raise
    
    @classmethod
    def generate_key_from_password(cls, password: str, salt: Optional[bytes] = None) -> tuple:
        """
        Generate encryption key from password.
        
        Args:
            password: Password to derive key from
            salt: Optional salt for key derivation
        
        Returns:
            Tuple of (key, salt)
        """
        if salt is None:
            salt = os.urandom(16)
        
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
        )
        
        key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
        return key.decode(), salt
    
    def encrypt_file(self, input_file: Union[str, Path], output_file: Union[str, Path]):
        """
        Encrypt a configuration file.
        
        Args:
            input_file: Path to plaintext config file
            output_file: Path for encrypted output
        """
        if not self._fernet:
            raise ValueError("Encryption not initialized. Provide master_key.")
        
        with open(input_file, 'rb') as f:
            data = f.read()
        
        encrypted_data = self._fernet.encrypt(data)
        
        with open(output_file, 'wb') as f:
            f.write(encrypted_data)
        
        logger.info(f"Encrypted config saved to {output_file}")
    
    def decrypt_file(self, encrypted_file: Union[str, Path]) -> bytes:
        """
        Decrypt a configuration file.
        
        Args:
            encrypted_file: Path to encrypted config file
        
        Returns:
            Decrypted data as bytes
        """
        if not self._fernet:
            raise ValueError("Encryption not initialized. Provide master_key.")
        
        with open(encrypted_file, 'rb') as f:
            encrypted_data = f.read()
        
        return self._fernet.decrypt(encrypted_data)


class ConfigLoader:
    """Load configuration from multiple sources with priority handling."""
    
    def __init__(self, config_path: Optional[Union[str, Path]] = None):
        """
        Initialize configuration loader.
        
        Args:
            config_path: Optional path to config directory
        """
        self.config_path = Path(config_path) if config_path else Path.cwd() / "config"
        self.config_path.mkdir(parents=True, exist_ok=True)
        
        # Create default config files if they don't exist
        self._create_default_configs()
    
    def _create_default_configs(self):
        """Create default configuration files if they don't exist."""
        default_yaml = self.config_path / "config.example.yaml"
        default_json = self.config_path / "config.example.json"
        
        if not default_yaml.exists():
            example_config = AppConfig()
            with open(default_yaml, 'w') as f:
                yaml.dump(asdict(example_config), f, default_flow_style=False)
            logger.info(f"Created example YAML config at {default_yaml}")
    
    def load_from_env(self) -> Dict[str, Any]:
        """
        Load configuration from environment variables.
        
        Environment variables use double underscore as separator for nested keys.
        Example: DATABASE__HOST maps to config['database']['host']
        """
        config = {}
        
        env_mappings = {
            # Database
            'DATABASE_HOST': ('database', 'host'),
            'DATABASE_PORT': ('database', 'port', 'int'),
            'DATABASE_NAME': ('database', 'database'),
            'DATABASE_USER': ('database', 'username'),
            'DATABASE_PASSWORD': ('database', 'password'),
            'DATABASE_DRIVER': ('database', 'driver'),
            'DATABASE_URL': ('database', 'connection_string_override'),
            
            # Redis
            'REDIS_HOST': ('redis', 'host'),
            'REDIS_PORT': ('redis', 'port', 'int'),
            'REDIS_PASSWORD': ('redis', 'password'),
            'REDIS_DB': ('redis', 'db', 'int'),
            'REDIS_SSL': ('redis', 'ssl', 'bool'),
            
            # API Keys
            'OPENAI_API_KEY': ('api_keys', 'openai_api_key'),
            'AWS_ACCESS_KEY_ID': ('api_keys', 'aws_access_key_id'),
            'AWS_SECRET_ACCESS_KEY': ('api_keys', 'aws_secret_access_key'),
            'AWS_REGION': ('api_keys', 'aws_region'),
            'STRIPE_API_KEY': ('api_keys', 'stripe_api_key'),
            'STRIPE_WEBHOOK_SECRET': ('api_keys', 'stripe_webhook_secret'),
            'SENDGRID_API_KEY': ('api_keys', 'sendgrid_api_key'),
            'TWILIO_ACCOUNT_SID': ('api_keys', 'twilio_account_sid'),
            'TWILIO_AUTH_TOKEN': ('api_keys', 'twilio_auth_token'),
            'GITHUB_TOKEN': ('api_keys', 'github_token'),
            'GOOGLE_API_KEY': ('api_keys', 'google_api_key'),
            'SLACK_BOT_TOKEN': ('api_keys', 'slack_bot_token'),
            
            # Security
            'SECRET_KEY': ('security', 'secret_key'),
            'JWT_SECRET': ('security', 'jwt_secret'),
            'ENCRYPTION_KEY': ('security', 'encryption_key'),
            'PASSWORD_SALT': ('security', 'password_salt'),
            'SESSION_TIMEOUT': ('security', 'session_timeout_minutes', 'int'),
            'MAX_LOGIN_ATTEMPTS': ('security', 'max_login_attempts', 'int'),
            
            # App
            'APP_ENV': ('environment',),
            'APP_NAME': ('app_name',),
            'APP_DEBUG': ('debug', 'bool'),
            'APP_HOST': ('host',),
            'APP_PORT': ('port', 'int'),
            'LOG_LEVEL': ('log_level',),
        }
        
        for env_var, mapping in env_mappings.items():
            value = os.environ.get(env_var)
            if value is not None:
                # Type conversion
                if len(mapping) > 2 and mapping[-1] == 'int':
                    try:
                        value = int(value)
                    except ValueError:
                        logger.warning(f"Invalid integer for {env_var}: {value}")
                        continue
                elif len(mapping) > 2 and mapping[-1] == 'bool':
                    value = value.lower() in ('true', '1', 'yes')
                
                # Set nested value
                target = config
                for key in mapping[:-1] if len(mapping) > 2 else mapping:
                    if key not in target:
                        target[key] = {}
                    target = target[key]
                
                # Set final value
                final_key = mapping[-1] if len(mapping) <= 2 else mapping[-2]
                target[final_key] = value
        
        return config
    
    def load_from_yaml(self, filename: str = "config.yaml") -> Dict[str, Any]:
        """
        Load configuration from YAML file.
        
        Args:
            filename: YAML config filename
        
        Returns:
            Configuration dictionary
        """
        file_path = self.config_path / filename
        
        if not file_path.exists():
            logger.warning(f"YAML config file not found: {file_path}")
            return {}
        
        try:
            with open(file_path, 'r') as f:
                config = yaml.safe_load(f)
                logger.info(f"Loaded configuration from {file_path}")
                return config or {}
        except Exception as e:
            logger.error(f"Error loading YAML config: {e}")
            return {}
    
    def load_from_json(self, filename: str = "config.json") -> Dict[str, Any]:
        """
        Load configuration from JSON file.
        
        Args:
            filename: JSON config filename
        
        Returns:
            Configuration dictionary
        """
        file_path = self.config_path / filename
        
        if not file_path.exists():
            return {}
        
        try:
            with open(file_path, 'r') as f:
                config = json.load(f)
                logger.info(f"Loaded configuration from {file_path}")
                return config
        except Exception as e:
            logger.error(f"Error loading JSON config: {e}")
            return {}
    
    def load_from_encrypted(self, filename: str = "config.enc", 
                           master_key: Optional[str] = None) -> Dict[str, Any]:
        """
        Load configuration from encrypted file.
        
        Args:
            filename: Encrypted config filename
            master_key: Decryption key
        
        Returns:
            Configuration dictionary
        """
        file_path = self.config_path / filename
        
        if not file_path.exists():
            return {}
        
        if not master_key:
            master_key = os.environ.get('CONFIG_MASTER_KEY')
            if not master_key:
                logger.warning("No master key provided for encrypted config")
                return {}
        
        try:
            encryption = ConfigEncryption(master_key)
            decrypted_data = encryption.decrypt_file(file_path)
            config = json.loads(decrypted_data.decode())
            logger.info(f"Loaded encrypted configuration from {file_path}")
            return config
        except Exception as e:
            logger.error(f"Error loading encrypted config: {e}")
            return {}
    
    def merge_configs(self, *configs: Dict[str, Any]) -> Dict[str, Any]:
        """
        Deep merge multiple configuration dictionaries.
        Later configs override earlier ones.
        
        Args:
            configs: Configuration dictionaries to merge
        
        Returns:
            Merged configuration dictionary
        """
        merged = {}
        
        for config in configs:
            for key, value in config.items():
                if (key in merged and isinstance(merged[key], dict) 
                    and isinstance(value, dict)):
                    merged[key] = self.merge_configs(merged[key], value)
                else:
                    merged[key] = value
        
        return merged
    
    def load_config(self, 
                   use_env: bool = True,
                   use_yaml: bool = True,
                   use_json: bool = False,
                   use_encrypted: bool = False,
                   encrypted_filename: str = "config.enc",
                   master_key: Optional[str] = None) -> AppConfig:
        """
        Load complete application configuration from all sources.
        
        Args:
            use_env: Load from environment variables
            use_yaml: Load from YAML file
            use_json: Load from JSON file
            use_encrypted: Load from encrypted file
            encrypted_filename: Encrypted config filename
            master_key: Key for encrypted config
        
        Returns:
            AppConfig object with all settings
        """
        configs = []
        
        # Load from different sources in order of priority (lowest first)
        if use_yaml:
            configs.append(self.load_from_yaml())
        
        if use_json:
            configs.append(self.load_from_json())
        
        if use_encrypted:
            configs.append(self.load_from_encrypted(encrypted_filename, master_key))
        
        if use_env:
            configs.append(self.load_from_env())
        
        # Merge all configurations
        merged_config = self.merge_configs(*configs)
        
        # Create AppConfig from merged dictionary
        return self._dict_to_appconfig(merged_config)
    
    def _dict_to_appconfig(self, config_dict: Dict[str, Any]) -> AppConfig:
        """
        Convert configuration dictionary to AppConfig object.
        
        Args:
            config_dict: Configuration dictionary
        
        Returns:
            AppConfig instance
        """
        # Extract nested configurations
        db_config = DatabaseConfig(**config_dict.get('database', {}))
        redis_config = RedisConfig(**config_dict.get('redis', {}))
        api_keys = APIKeys(**config_dict.get('api_keys', {}))
        security_config = SecurityConfig(**config_dict.get('security', {}))
        
        # Create main config
        app_config = AppConfig(
            environment=config_dict.get('environment', 'development'),
            debug=config_dict.get('debug', False),
            app_name=config_dict.get('app_name', 'MyApp'),
            version=config_dict.get('version', '1.0.0'),
            host=config_dict.get('host', '0.0.0.0'),
            port=config_dict.get('port', 8000),
            database=db_config,
            redis=redis_config,
            api_keys=api_keys,
            security=security_config,
            log_level=config_dict.get('log_level', 'INFO'),
            log_format=config_dict.get('log_format', ''),
            features=config_dict.get('features', {})
        )
        
        return app_config
    
    def validate_config(self, config: AppConfig) -> bool:
        """
        Validate configuration completeness and correctness.
        
        Args:
            config: AppConfig to validate
        
        Returns:
            True if valid, False otherwise
        """
        errors = []
        
        # Check required database settings
        if not config.database.host:
            errors.append("Database host is required")
        if not config.database.database:
            errors.append("Database name is required")
        if not config.database.username:
            errors.append("Database username is required")
        
        # Check security settings
        if len(config.security.secret_key) < 32:
            errors.append("Secret key should be at least 32 characters")
        
        # Validate URLs if provided
        if config.database.host:
            url_pattern = re.compile(r'^[\w\.-]+$')
            if not url_pattern.match(config.database.host):
                errors.append(f"Invalid database host: {config.database.host}")
        
        if errors:
            for error in errors:
                logger.error(f"Configuration error: {error}")
            return False
        
        logger.info("Configuration validation passed")
        return True


# Global configuration instance
config: Optional[AppConfig] = None


def init_config(config_path: Optional[Union[str, Path]] = None,
                master_key: Optional[str] = None) -> AppConfig:
    """
    Initialize global application configuration.
    
    Args:
        config_path: Path to configuration directory
        master_key: Master key for encrypted configuration
    
    Returns:
        AppConfig instance
    """
    global config
    
    loader = ConfigLoader(config_path)
    
    # Determine environment
    env = os.environ.get('APP_ENV', 'development')
    
    # Load configuration
    config = loader.load_config(
        use_env=True,
        use_yaml=True,
        use_encrypted=(env == 'production'),  # Only use encrypted in production
        master_key=master_key
    )
    
    # Validate configuration
    if not loader.validate_config(config):
        if env == 'production':
            raise ValueError("Invalid production configuration")
        else:
            logger.warning("Configuration has errors, using defaults where possible")
    
    # Log configuration (masking sensitive values)
    logger.info(f"Configuration loaded for environment: {config.environment}")
    logger.info(f"Database: {config.database.host}:{config.database.port}/{config.database.database}")
    logger.info(f"Redis: {config.redis.host}:{config.redis.port}")
    
    # Mask API keys in logs
    if config.api_keys.openai_api_key:
        masked_key = config.api_keys.mask_sensitive_value(config.api_keys.openai_api_key)
        logger.info(f"OpenAI API Key: {masked_key}")
    
    return config


def get_config() -> AppConfig:
    """
    Get the global application configuration.
    
    Returns:
        AppConfig instance
    
    Raises:
        RuntimeError: If configuration not initialized
    """
    if config is None:
        raise RuntimeError("Configuration not initialized. Call init_config() first.")
    return config


# Example usage and testing
if __name__ == "__main__":
    # Initialize configuration
    try:
        app_config = init_config()
        
        # Access configuration
        print(f"App: {app_config.app_name} v{app_config.version}")
        print(f"Environment: {app_config.environment}")
        print(f"Database: {app_config.database.connection_string}")
        print(f"Redis: {app_config.redis.host}:{app_config.redis.port}")
        
        # Export configuration (for documentation)
        config_dict = asdict(app_config)
        
        # Mask sensitive values for export
        if config_dict.get('api_keys', {}).get('openai_api_key'):
            config_dict['api_keys']['openai_api_key'] = '***MASKED***'
        if config_dict.get('security', {}).get('secret_key'):
            config_dict['security']['secret_key'] = '***MASKED***'
        
        # Save masked config for reference
        with open('config/masked_config.json', 'w') as f:
            json.dump(config_dict, f, indent=2, default=str)
        
        print("\nConfiguration loaded successfully!")
        print(f"Masked configuration saved to config/masked_config.json")
        
    except Exception as e:
        print(f"Failed to load configuration: {e}")