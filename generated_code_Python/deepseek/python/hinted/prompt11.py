# =============================================
# Generated Code - Prompt 11 (hinted)
# Model: deepseek
# Language: python
# Generated on: Fri Jun 19 10:40 PM EEST 2026
# =============================================

# TODO: Paste the generated code from the model here

"""
config_manager.py - Secure Configuration Management Module

This module provides secure loading and management of application configuration,
including database credentials, API keys, and other sensitive settings.
Implements security best practices for secret management.
"""

import os
import json
import logging
from pathlib import Path
from typing import Any, Dict, Optional, List, Union
from dataclasses import dataclass, field
from enum import Enum
from functools import lru_cache
import warnings

# Optional imports for different secret backends
try:
    import boto3
    from botocore.exceptions import ClientError
    AWS_AVAILABLE = True
except ImportError:
    AWS_AVAILABLE = False

try:
    from azure.identity import DefaultAzureCredential
    from azure.keyvault.secrets import SecretClient
    AZURE_AVAILABLE = True
except ImportError:
    AZURE_AVAILABLE = False

try:
    import hvac  # HashiCorp Vault
    VAULT_AVAILABLE = True
except ImportError:
    VAULT_AVAILABLE = False

# ============================================================================
# Configuration Exceptions
# ============================================================================

class ConfigurationError(Exception):
    """Base exception for configuration errors"""
    pass

class SecretNotFoundError(ConfigurationError):
    """Raised when a required secret is not found"""
    pass

class SecretBackendError(ConfigurationError):
    """Raised when secret backend fails"""
    pass

class ValidationError(ConfigurationError):
    """Raised when configuration validation fails"""
    pass

# ============================================================================
# Secret Backend Interface
# ============================================================================

class SecretSource(Enum):
    """Supported secret sources"""
    ENVIRONMENT = "environment"
    FILE = "file"
    AWS_SECRETS_MANAGER = "aws_secrets_manager"
    AWS_PARAMETER_STORE = "aws_parameter_store"
    AZURE_KEY_VAULT = "azure_key_vault"
    HASHICORP_VAULT = "hashicorp_vault"
    ENCRYPTED_FILE = "encrypted_file"

class SecretBackend:
    """Base class for secret backends"""
    
    def get_secret(self, key: str) -> Optional[str]:
        """Retrieve a secret by key"""
        raise NotImplementedError
    
    def get_secrets(self, keys: List[str]) -> Dict[str, str]:
        """Retrieve multiple secrets"""
        return {key: self.get_secret(key) for key in keys}

# ============================================================================
# Secret Backend Implementations
# ============================================================================

class EnvironmentBackend(SecretBackend):
    """Load secrets from environment variables"""
    
    def __init__(self, prefix: str = ""):
        self.prefix = prefix
    
    def get_secret(self, key: str) -> Optional[str]:
        env_key = f"{self.prefix}{key}".upper()
        return os.environ.get(env_key)

class FileBackend(SecretBackend):
    """Load secrets from a JSON file"""
    
    def __init__(self, file_path: Union[str, Path]):
        self.file_path = Path(file_path)
        self._cache: Optional[Dict[str, Any]] = None
    
    def _load_file(self) -> Dict[str, Any]:
        """Load and cache file contents"""
        if self._cache is None:
            if not self.file_path.exists():
                raise SecretNotFoundError(f"Config file not found: {self.file_path}")
            
            try:
                with open(self.file_path, 'r') as f:
                    self._cache = json.load(f)
            except json.JSONDecodeError as e:
                raise ConfigurationError(f"Invalid JSON in config file: {e}")
        
        return self._cache
    
    def get_secret(self, key: str) -> Optional[str]:
        data = self._load_file()
        return data.get(key)

class EncryptedFileBackend(SecretBackend):
    """Load secrets from an encrypted file"""
    
    def __init__(self, file_path: Union[str, Path], encryption_key: str):
        self.file_path = Path(file_path)
        self.encryption_key = encryption_key
    
    def get_secret(self, key: str) -> Optional[str]:
        try:
            from cryptography.fernet import Fernet
            from cryptography.hazmat.primitives import hashes
            from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2
            import base64
            
            if not self.file_path.exists():
                raise SecretNotFoundError(f"Encrypted config file not found: {self.file_path}")
            
            with open(self.file_path, 'rb') as f:
                encrypted_data = f.read()
            
            # Derive key from password
            kdf = PBKDF2(
                algorithm=hashes.SHA256(),
                length=32,
                salt=b'config-manager-salt',  # Store salt securely in production
                iterations=100000,
            )
            key = base64.urlsafe_b64encode(kdf.derive(self.encryption_key.encode()))
            
            fernet = Fernet(key)
            decrypted_data = fernet.decrypt(encrypted_data)
            secrets = json.loads(decrypted_data)
            
            return secrets.get(key)
            
        except ImportError:
            raise ConfigurationError("cryptography package required for encrypted files")
        except Exception as e:
            raise ConfigurationError(f"Failed to decrypt config: {e}")

class AWSSecretsManagerBackend(SecretBackend):
    """Load secrets from AWS Secrets Manager"""
    
    def __init__(self, secret_name: str, region_name: Optional[str] = None):
        if not AWS_AVAILABLE:
            raise ConfigurationError("boto3 required for AWS Secrets Manager")
        
        self.secret_name = secret_name
        self.region_name = region_name or os.environ.get('AWS_REGION', 'us-east-1')
        self._client = None
        self._cache: Optional[Dict[str, Any]] = None
    
    @property
    def client(self):
        if self._client is None:
            session = boto3.session.Session()
            self._client = session.client(
                service_name='secretsmanager',
                region_name=self.region_name
            )
        return self._client
    
    def _load_secret(self) -> Dict[str, Any]:
        """Load and cache secret from AWS"""
        if self._cache is None:
            try:
                response = self.client.get_secret_value(SecretId=self.secret_name)
                if 'SecretString' in response:
                    self._cache = json.loads(response['SecretString'])
                else:
                    self._cache = json.loads(response['SecretBinary'])
            except ClientError as e:
                raise SecretBackendError(f"AWS Secrets Manager error: {e}")
            except json.JSONDecodeError as e:
                raise ConfigurationError(f"Invalid JSON in AWS secret: {e}")
        
        return self._cache
    
    def get_secret(self, key: str) -> Optional[str]:
        data = self._load_secret()
        return data.get(key)

class AWSParameterStoreBackend(SecretBackend):
    """Load secrets from AWS Systems Manager Parameter Store"""
    
    def __init__(self, path_prefix: str, region_name: Optional[str] = None):
        if not AWS_AVAILABLE:
            raise ConfigurationError("boto3 required for AWS Parameter Store")
        
        self.path_prefix = path_prefix
        self.region_name = region_name or os.environ.get('AWS_REGION', 'us-east-1')
        self._client = None
    
    @property
    def client(self):
        if self._client is None:
            session = boto3.session.Session()
            self._client = session.client('ssm', region_name=self.region_name)
        return self._client
    
    def get_secret(self, key: str) -> Optional[str]:
        try:
            param_name = f"{self.path_prefix}/{key}"
            response = self.client.get_parameter(
                Name=param_name,
                WithDecryption=True
            )
            return response['Parameter']['Value']
        except ClientError as e:
            raise SecretBackendError(f"AWS Parameter Store error: {e}")

class AzureKeyVaultBackend(SecretBackend):
    """Load secrets from Azure Key Vault"""
    
    def __init__(self, vault_url: str):
        if not AZURE_AVAILABLE:
            raise ConfigurationError("azure-identity and azure-keyvault-secrets required")
        
        self.vault_url = vault_url
        credential = DefaultAzureCredential()
        self._client = SecretClient(vault_url=vault_url, credential=credential)
    
    def get_secret(self, key: str) -> Optional[str]:
        try:
            secret = self._client.get_secret(key)
            return secret.value
        except Exception as e:
            raise SecretBackendError(f"Azure Key Vault error: {e}")

class HashiCorpVaultBackend(SecretBackend):
    """Load secrets from HashiCorp Vault"""
    
    def __init__(self, url: str, token: Optional[str] = None, 
                 mount_point: str = "secret", path: str = ""):
        if not VAULT_AVAILABLE:
            raise ConfigurationError("hvac required for HashiCorp Vault")
        
        self.url = url
        self.token = token or os.environ.get('VAULT_TOKEN')
        self.mount_point = mount_point
        self.path = path
        self._client = None
    
    @property
    def client(self):
        if self._client is None:
            self._client = hvac.Client(url=self.url, token=self.token)
            if not self._client.is_authenticated():
                raise SecretBackendError("Failed to authenticate with Vault")
        return self._client
    
    def get_secret(self, key: str) -> Optional[str]:
        try:
            secret_path = f"{self.mount_point}/data/{self.path}"
            response = self.client.secrets.kv.v2.read_secret_version(
                path=secret_path
            )
            return response['data']['data'].get(key)
        except Exception as e:
            raise SecretBackendError(f"Vault error: {e}")

# ============================================================================
# Configuration Validators
# ============================================================================

@dataclass
class ConfigField:
    """Configuration field definition with validation"""
    key: str
    required: bool = False
    default: Any = None
    secret: bool = False
    validator: Optional[callable] = None
    description: str = ""
    sensitive: bool = False  # Mask in logs
    
    def validate(self, value: Any) -> bool:
        """Validate field value"""
        if self.required and value is None:
            raise ValidationError(f"Required field '{self.key}' is missing")
        
        if self.validator and value is not None:
            try:
                self.validator(value)
            except Exception as e:
                raise ValidationError(f"Validation failed for '{self.key}': {e}")
        
        return True

# ============================================================================
# Main Configuration Manager
# ============================================================================

class ConfigManager:
    """
    Central configuration manager with secure secret handling
    
    Usage:
        config = ConfigManager()
        config.add_source(SecretSource.ENVIRONMENT, prefix="APP_")
        config.add_source(SecretSource.FILE, file_path="config/secrets.json")
        config.add_source(SecretSource.AWS_SECRETS_MANAGER, secret_name="prod/myapp")
        
        config.define_field("DATABASE_URL", required=True, secret=True)
        config.define_field("API_KEY", required=True, secret=True)
        config.define_field("DEBUG", default=False)
        
        config.load()
        
        db_url = config.get("DATABASE_URL")
    """
    
    def __init__(self, validate_on_load: bool = True, 
                 cache_secrets: bool = True,
                 logger: Optional[logging.Logger] = None):
        self.sources: List[tuple] = []
        self.fields: Dict[str, ConfigField] = {}
        self._config: Dict[str, Any] = {}
        self._secrets_cache: Dict[str, str] = {}
        self.validate_on_load = validate_on_load
        self.cache_secrets = cache_secrets
        self.logger = logger or logging.getLogger(__name__)
        self._loaded = False
    
    def add_source(self, source_type: SecretSource, **kwargs):
        """Add a configuration source"""
        if self._loaded:
            raise ConfigurationError("Cannot add sources after loading")
        
        backend = self._create_backend(source_type, **kwargs)
        self.sources.append((source_type, backend, kwargs))
    
    def define_field(self, key: str, **kwargs):
        """Define a configuration field"""
        if self._loaded:
            raise ConfigurationError("Cannot define fields after loading")
        
        self.fields[key] = ConfigField(key=key, **kwargs)
    
    def load(self) -> 'ConfigManager':
        """Load configuration from all sources"""
        if self._loaded:
            self.logger.warning("Configuration already loaded")
            return self
        
        self.logger.info("Loading configuration...")
        
        # Load from all sources in order of priority (last wins)
        for source_type, backend, kwargs in self.sources:
            self.logger.debug(f"Loading from {source_type.value}")
            try:
                for field in self.fields.values():
                    try:
                        value = backend.get_secret(field.key)
                        if value is not None:
                            self._set_value(field.key, value)
                            self.logger.debug(f"Loaded {field.key} from {source_type.value}")
                    except Exception as e:
                        self.logger.error(f"Error loading {field.key} from {source_type.value}: {e}")
            except Exception as e:
                self.logger.error(f"Source {source_type.value} failed: {e}")
        
        # Set defaults for missing optional fields
        for key, field in self.fields.items():
            if key not in self._config and not field.required:
                if field.default is not None:
                    self._set_value(key, field.default)
                    self.logger.debug(f"Using default for {key}")
        
        # Validate if requested
        if self.validate_on_load:
            self.validate()
        
        self._loaded = True
        self.logger.info("Configuration loaded successfully")
        return self
    
    def get(self, key: str, default: Any = None) -> Any:
        """Get a configuration value"""
        if not self._loaded:
            raise ConfigurationError("Configuration not loaded. Call load() first.")
        
        if key not in self.fields:
            raise ConfigurationError(f"Unknown configuration key: {key}")
        
        return self._config.get(key, default)
    
    def get_secret(self, key: str) -> str:
        """Get a secret value (ensures it's not logged)"""
        value = self.get(key)
        if value is None:
            raise SecretNotFoundError(f"Secret not found: {key}")
        return value
    
    def validate(self):
        """Validate all configuration fields"""
        self.logger.info("Validating configuration...")
        errors = []
        
        for key, field in self.fields.items():
            value = self._config.get(key)
            
            try:
                field.validate(value)
            except ValidationError as e:
                errors.append(str(e))
        
        if errors:
            raise ValidationError(f"Configuration validation failed: {'; '.join(errors)}")
        
        self.logger.info("Configuration validation passed")
    
    def mask_sensitive_data(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Mask sensitive values for logging/display"""
        masked = {}
        for key, value in data.items():
            field = self.fields.get(key)
            if field and (field.secret or field.sensitive):
                masked[key] = "********"
            else:
                masked[key] = value
        return masked
    
    def to_dict(self, mask_secrets: bool = True) -> Dict[str, Any]:
        """Convert configuration to dictionary"""
        if mask_secrets:
            return self.mask_sensitive_data(self._config)
        return self._config.copy()
    
    def reload(self):
        """Reload configuration from sources"""
        self._loaded = False
        self._config.clear()
        self._secrets_cache.clear()
        self.load()
    
    def _set_value(self, key: str, value: Any):
        """Set a configuration value with caching"""
        field = self.fields.get(key)
        if field and field.secret and self.cache_secrets:
            self._secrets_cache[key] = value
        
        # Type conversion for common types
        if isinstance(value, str):
            if value.lower() in ('true', 'false'):
                value = value.lower() == 'true'
            elif value.isdigit():
                value = int(value)
        
        self._config[key] = value
    
    def _create_backend(self, source_type: SecretSource, **kwargs) -> SecretBackend:
        """Create appropriate backend based on source type"""
        backends = {
            SecretSource.ENVIRONMENT: EnvironmentBackend,
            SecretSource.FILE: FileBackend,
            SecretSource.ENCRYPTED_FILE: EncryptedFileBackend,
            SecretSource.AWS_SECRETS_MANAGER: AWSSecretsManagerBackend,
            SecretSource.AWS_PARAMETER_STORE: AWSParameterStoreBackend,
            SecretSource.AZURE_KEY_VAULT: AzureKeyVaultBackend,
            SecretSource.HASHICORP_VAULT: HashiCorpVaultBackend,
        }
        
        backend_class = backends.get(source_type)
        if not backend_class:
            raise ConfigurationError(f"Unknown secret source: {source_type}")
        
        return backend_class(**kwargs)

# ============================================================================
# Configuration Schema Definitions
# ============================================================================

@dataclass
class DatabaseConfig:
    """Database configuration schema"""
    url: str
    pool_size: int = 10
    max_overflow: int = 20
    pool_timeout: int = 30
    echo: bool = False

@dataclass
class RedisConfig:
    """Redis configuration schema"""
    url: str
    max_connections: int = 50
    socket_timeout: int = 5
    decode_responses: bool = True

@dataclass
class SecurityConfig:
    """Security configuration schema"""
    secret_key: str
    jwt_secret: str
    session_timeout: int = 3600
    password_salt: str = ""
    cors_origins: List[str] = field(default_factory=list)

@dataclass  
class APIConfig:
    """External API configuration"""
    api_key: str
    api_url: str
    timeout: int = 30
    retry_count: int = 3

# ============================================================================
# Configuration Factory
# ============================================================================

class AppConfig:
    """
    Application-specific configuration factory
    
    Usage:
        config = AppConfig.create()
        db_config = config.get_database_config()
        api_config = config.get_api_config("stripe")
    """
    
    def __init__(self, manager: ConfigManager):
        self.manager = manager
    
    @classmethod
    def create(cls, env: Optional[str] = None) -> 'AppConfig':
        """Create application configuration based on environment"""
        env = env or os.environ.get('APP_ENV', 'development')
        
        manager = ConfigManager(validate_on_load=True)
        
        # Add sources based on environment
        manager.add_source(SecretSource.ENVIRONMENT, prefix=f"APP_{env}_".upper())
        
        # Local development
        if env == 'development':
            config_file = Path('config/development.json')
            if config_file.exists():
                manager.add_source(SecretSource.FILE, file_path=config_file)
        
        # Production uses cloud secret managers
        elif env in ('production', 'staging'):
            if AWS_AVAILABLE:
                manager.add_source(
                    SecretSource.AWS_SECRETS_MANAGER,
                    secret_name=f"{env}/myapp"
                )
            elif AZURE_AVAILABLE:
                vault_url = os.environ.get('AZURE_KEY_VAULT_URL')
                if vault_url:
                    manager.add_source(SecretSource.AZURE_KEY_VAULT, vault_url=vault_url)
            elif VAULT_AVAILABLE:
                vault_url = os.environ.get('VAULT_ADDR')
                if vault_url:
                    manager.add_source(SecretSource.HASHICORP_VAULT, url=vault_url)
        
        # Define all configuration fields
        cls._define_fields(manager)
        
        # Load configuration
        manager.load()
        
        return cls(manager)
    
    @staticmethod
    def _define_fields(manager: ConfigManager):
        """Define all application configuration fields"""
        
        # Database configuration
        manager.define_field(
            "DATABASE_URL",
            required=True,
            secret=True,
            description="Database connection URL"
        )
        manager.define_field(
            "DATABASE_POOL_SIZE",
            default="10",
            validator=lambda x: int(x) > 0
        )
        manager.define_field(
            "DATABASE_MAX_OVERFLOW",
            default="20"
        )
        
        # Redis configuration
        manager.define_field(
            "REDIS_URL",
            required=True,
            secret=True,
            description="Redis connection URL"
        )
        
        # Security
        manager.define_field(
            "SECRET_KEY",
            required=True,
            secret=True,
            description="Application secret key",
            validator=lambda x: len(x) >= 32
        )
        manager.define_field(
            "JWT_SECRET",
            required=True,
            secret=True,
            description="JWT signing secret"
        )
        
        # API keys (dynamic)
        api_keys = [
            "STRIPE_API_KEY",
            "SENDGRID_API_KEY", 
            "AWS_ACCESS_KEY_ID",
            "AWS_SECRET_ACCESS_KEY",
            "GOOGLE_API_KEY",
            "SLACK_WEBHOOK_URL"
        ]
        for key in api_keys:
            manager.define_field(
                key,
                required=False,
                secret=True,
                sensitive=True
            )
        
        # Application settings
        manager.define_field("DEBUG", default="false")
        manager.define_field("LOG_LEVEL", default="INFO")
        manager.define_field("APP_NAME", default="MyApp")
        manager.define_field("APP_ENV", default="development")
        manager.define_field("APP_PORT", default="5000")
        manager.define_field("APP_HOST", default="0.0.0.0")
        
        # Email configuration
        manager.define_field("SMTP_HOST", default="localhost")
        manager.define_field("SMTP_PORT", default="587")
        manager.define_field("SMTP_USER", secret=True)
        manager.define_field("SMTP_PASSWORD", secret=True, sensitive=True)
        
        # Feature flags
        manager.define_field("ENABLE_METRICS", default="false")
        manager.define_field("ENABLE_RATE_LIMITING", default="true")
        manager.define_field("ENABLE_CACHE", default="true")
    
    def get_database_config(self) -> DatabaseConfig:
        """Get database configuration"""
        return DatabaseConfig(
            url=self.manager.get_secret("DATABASE_URL"),
            pool_size=int(self.manager.get("DATABASE_POOL_SIZE", 10)),
            max_overflow=int(self.manager.get("DATABASE_MAX_OVERFLOW", 20)),
            echo=self.manager.get("DEBUG", False)
        )
    
    def get_redis_config(self) -> RedisConfig:
        """Get Redis configuration"""
        return RedisConfig(
            url=self.manager.get_secret("REDIS_URL")
        )
    
    def get_security_config(self) -> SecurityConfig:
        """Get security configuration"""
        return SecurityConfig(
            secret_key=self.manager.get_secret("SECRET_KEY"),
            jwt_secret=self.manager.get_secret("JWT_SECRET"),
            session_timeout=3600
        )
    
    def get_api_config(self, service: str) -> APIConfig:
        """Get API configuration for a specific service"""
        service_upper = service.upper()
        api_key = self.manager.get_secret(f"{service_upper}_API_KEY")
        api_url = self.manager.get(f"{service_upper}_API_URL")
        
        if not api_url:
            # Default URLs for known services
            default_urls = {
                "STRIPE": "https://api.stripe.com/v1",
                "SENDGRID": "https://api.sendgrid.com/v3",
                "GITHUB": "https://api.github.com"
            }
            api_url = default_urls.get(service_upper, "")
        
        return APIConfig(api_key=api_key, api_url=api_url)
    
    def get(self, key: str, default: Any = None) -> Any:
        """Get any configuration value"""
        return self.manager.get(key, default)
    
    def is_production(self) -> bool:
        """Check if running in production"""
        return self.manager.get("APP_ENV") == "production"
    
    def is_development(self) -> bool:
        """Check if running in development"""
        return self.manager.get("APP_ENV") == "development"

# ============================================================================
# Singleton Configuration
# ============================================================================

@lru_cache(maxsize=1)
def get_config() -> AppConfig:
    """
    Get cached application configuration singleton
    
    Usage:
        from config_manager import get_config
        
        config = get_config()
        db_config = config.get_database_config()
    """
    return AppConfig.create()

# ============================================================================
# Configuration Initialization Example
# ============================================================================

def init_app_config(config_path: Optional[Path] = None) -> AppConfig:
    """
    Initialize application configuration
    
    This function should be called at application startup.
    
    Args:
        config_path: Optional path to configuration file
        
    Returns:
        AppConfig instance
        
    Raises:
        ConfigurationError: If configuration loading fails
    """
    logger = logging.getLogger(__name__)
    
    try:
        # Set configuration file path
        if config_path:
            os.environ['APP_CONFIG_PATH'] = str(config_path)
        
        # Create configuration
        logger.info("Initializing application configuration...")
        config = AppConfig.create()
        
        # Log configuration summary
        masked_config = config.manager.to_dict(mask_secrets=True)
        logger.info(f"Configuration loaded: {json.dumps(masked_config, indent=2)}")
        
        # Validate critical secrets exist
        critical_secrets = ['SECRET_KEY', 'JWT_SECRET', 'DATABASE_URL']
        for secret in critical_secrets:
            if not config.manager.get(secret):
                raise ConfigurationError(f"Critical secret missing: {secret}")
        
        # Warn if using default values in production
        if config.is_production():
            check_defaults = [
                ('SECRET_KEY', 32),
                ('DEBUG', False),
                ('ENABLE_METRICS', True)
            ]
            for key, expected in check_defaults:
                value = config.manager.get(key)
                if value != str(expected):
                    logger.warning(f"Production config: {key} should be {expected}")
        
        logger.info("Configuration initialization complete")
        return config
        
    except Exception as e:
        logger.critical(f"Failed to initialize configuration: {e}")
        raise ConfigurationError(f"Configuration initialization failed: {e}")

# ============================================================================
# Usage Example
# ============================================================================

if __name__ == "__main__":
    # Setup logging
    logging.basicConfig(level=logging.INFO)
    
    try:
        # Example 1: Basic usage
        print("=== Example 1: Basic Configuration ===")
        manager = ConfigManager()
        manager.add_source(SecretSource.ENVIRONMENT, prefix="MYAPP_")
        manager.define_field("DATABASE_URL", required=True, secret=True)
        manager.define_field("API_KEY", secret=True)
        manager.define_field("DEBUG", default="false")
        manager.load()
        
        # Masked output for logging
        print("Configuration:", manager.to_dict(mask_secrets=True))
        
        # Example 2: Application configuration
        print("\n=== Example 2: App Configuration ===")
        config = AppConfig.create()
        print(f"Environment: {config.get('APP_ENV')}")
        print(f"Debug mode: {config.get('DEBUG')}")
        
        # Example 3: Multiple sources
        print("\n=== Example 3: Multiple Sources ===")
        multi_manager = ConfigManager()
        
        # Load from environment first (lowest priority)
        multi_manager.add_source(SecretSource.ENVIRONMENT, prefix="APP_")
        
        # Then from local config file
        if Path("config/local.json").exists():
            multi_manager.add_source(SecretSource.FILE, file_path="config/local.json")
        
        # Define fields
        multi_manager.define_field("DATABASE_URL", required=True, secret=True)
        multi_manager.define_field("API_KEY", required=True, secret=True)
        multi_manager.define_field("DEBUG", default="false")
        
        try:
            multi_manager.load()
            print("Multi-source configuration loaded successfully")
        except ConfigurationError as e:
            print(f"Configuration error: {e}")
        
    except ConfigurationError as e:
        logging.error(f"Configuration failed: {e}")
    except Exception as e:
        logging.error(f"Unexpected error: {e}")