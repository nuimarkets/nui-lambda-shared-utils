"""
Base client class providing common functionality for AWS service clients.
"""

import logging
from typing import Optional, Dict, Any
from abc import ABC, abstractmethod

from .config import get_config
from .secrets_helper import get_secret
from .utils import resolve_config_value, validate_required_param, handle_client_errors

log = logging.getLogger(__name__)


class BaseClient(ABC):
    """
    Base class for AWS service clients providing standardized:
    - Credential resolution and management
    - Configuration integration
    - Error handling patterns
    - Logging context
    """

    def __init__(
        self, 
        secret_name: Optional[str] = None,
        config_key_prefix: Optional[str] = None,
        **kwargs
    ):
        """
        Initialize base client with standardized credential and config resolution.
        
        Args:
            secret_name: Override secret name for credentials
            config_key_prefix: Prefix for config keys (e.g., 'slack', 'es', 'db')
            **kwargs: Additional client-specific parameters
        """
        self.config = get_config()
        self.config_key_prefix = config_key_prefix or self._get_default_config_prefix()
        
        # Resolve and store credentials
        self.credentials = self._resolve_credentials(secret_name)
        
        # Store additional configuration
        self.client_config = kwargs
        
        # Initialize service-specific client
        self._service_client = self._create_service_client()
        
        log.info(
            f"Initialized {self.__class__.__name__}",
            extra={
                "client_type": self.__class__.__name__,
                "config_prefix": self.config_key_prefix,
                "has_credentials": bool(self.credentials)
            }
        )

    @abstractmethod
    def _get_default_config_prefix(self) -> str:
        """Return the default configuration key prefix for this client type."""
        pass

    @abstractmethod
    def _create_service_client(self) -> Any:
        """Create and return the underlying service client (e.g., WebClient, Elasticsearch)."""
        pass

    @abstractmethod
    def _get_default_secret_name(self) -> str:
        """Return the default secret name for this client type."""
        pass

    def _resolve_credentials(self, secret_name: Optional[str]) -> Dict[str, Any]:
        """
        Resolve credentials using standardized precedence.
        
        Args:
            secret_name: Optional override for secret name
            
        Returns:
            Dictionary containing resolved credentials
        """
        # Determine secret name with precedence
        resolved_secret_name = resolve_config_value(
            secret_name,
            [
                f"{self.config_key_prefix.upper()}_CREDENTIALS_SECRET",
                f"{self.config_key_prefix.upper()}CREDENTIALS_SECRET"  # Alternative format
            ],
            getattr(self.config, f"{self.config_key_prefix}_credentials_secret", self._get_default_secret_name())
        )
        
        validate_required_param(resolved_secret_name, "secret_name")
        
        # Retrieve and return credentials
        try:
            credentials = get_secret(resolved_secret_name)
            log.debug(f"Retrieved credentials from secret: {resolved_secret_name}")
            return credentials
        except Exception as e:
            log.error(
                f"Failed to retrieve credentials from secret: {resolved_secret_name}",
                extra={"secret_name": resolved_secret_name, "error": str(e)}
            )
            raise

    def _get_config_value(self, key: str, env_vars: Optional[list] = None, default: Any = None) -> Any:
        """
        Get configuration value with standardized precedence.
        
        Args:
            key: Configuration key (without prefix)
            env_vars: Environment variable names to check
            default: Default value
            
        Returns:
            Resolved configuration value
        """
        # Get from client config (constructor kwargs) first
        if key in self.client_config:
            return self.client_config[key]
        
        # Build full config key
        config_key = f"{self.config_key_prefix}_{key}"
        config_value = getattr(self.config, config_key, default)
        
        # Use utility for full resolution
        return resolve_config_value(
            None,  # No explicit parameter (already checked client_config)
            env_vars or [],
            config_value
        )

    @handle_client_errors(reraise=True)
    def _execute_with_error_handling(self, operation_name: str, operation_func, **log_context):
        """
        Execute an operation with standardized error handling and logging.
        
        Args:
            operation_name: Name of the operation for logging
            operation_func: Function to execute
            **log_context: Additional logging context
            
        Returns:
            Result of operation_func
        """
        context = {
            "client_type": self.__class__.__name__,
            "operation": operation_name,
            **log_context
        }
        
        log.debug(f"Executing {operation_name}", extra=context)
        
        try:
            result = operation_func()
            log.debug(f"Successfully completed {operation_name}", extra=context)
            return result
        except Exception as e:
            context["error_type"] = type(e).__name__
            context["error_message"] = str(e)
            log.error(f"Failed to execute {operation_name}: {e}", extra=context)
            raise

    def get_client_info(self) -> Dict[str, Any]:
        """
        Get information about this client instance.
        
        Returns:
            Dictionary with client information
        """
        return {
            "client_type": self.__class__.__name__,
            "config_prefix": self.config_key_prefix,
            "has_credentials": bool(self.credentials),
            "client_config": {k: v for k, v in self.client_config.items() if not k.startswith('_')},
        }


class ServiceHealthMixin:
    """
    Mixin providing common health check functionality for service clients.
    """

    def health_check(self) -> Dict[str, Any]:
        """
        Perform a basic health check for the service.
        
        Returns:
            Dictionary with health status information
        """
        try:
            self._perform_health_check()
            return {
                "status": "healthy",
                "client_type": self.__class__.__name__,
                "timestamp": log.time.time() if hasattr(log, 'time') else None
            }
        except Exception as e:
            return {
                "status": "unhealthy",
                "client_type": self.__class__.__name__,
                "error": str(e),
                "error_type": type(e).__name__,
                "timestamp": log.time.time() if hasattr(log, 'time') else None
            }

    @abstractmethod
    def _perform_health_check(self):
        """Perform service-specific health check. Should raise exception if unhealthy."""
        pass


class RetryableOperationMixin:
    """
    Mixin providing retry functionality for operations.
    """

    def execute_with_retry(
        self,
        operation_func,
        operation_name: str,
        max_attempts: int = 3,
        **retry_kwargs
    ):
        """
        Execute operation with retry logic.
        
        Args:
            operation_func: Function to execute
            operation_name: Name for logging
            max_attempts: Maximum retry attempts
            **retry_kwargs: Additional retry configuration
            
        Returns:
            Result of operation_func
        """
        from .error_handler import with_retry
        
        # Apply retry decorator dynamically
        retried_operation = with_retry(
            max_attempts=max_attempts,
            **retry_kwargs
        )(operation_func)
        
        return self._execute_with_error_handling(
            operation_name,
            retried_operation
        )