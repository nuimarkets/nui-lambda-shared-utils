"""
Utility functions for DRY code patterns across the lambda shared utils.
"""

import os
import time
import logging
import functools
from typing import Union, List, Optional, Any, Dict
import boto3
from botocore.exceptions import ClientError, NoCredentialsError

from .config import get_config

log = logging.getLogger(__name__)

# AWS region resolution constants
DEFAULT_AWS_REGION = "ap-southeast-2"


def resolve_config_value(
    param_value: Optional[Any], 
    env_var_names: Union[str, List[str]], 
    config_default: Any
) -> Any:
    """
    Resolve configuration value with priority: param > env vars > config default.
    
    Args:
        param_value: Explicitly provided parameter value
        env_var_names: Environment variable name(s) to check (string or list)
        config_default: Default value from configuration
        
    Returns:
        Resolved configuration value
        
    Example:
        host = resolve_config_value(
            host_param, 
            ["ES_HOST", "ELASTICSEARCH_HOST"], 
            "localhost:9200"
        )
    """
    # Parameter takes highest precedence
    if param_value is not None:
        return param_value
    
    # Check environment variables
    if isinstance(env_var_names, str):
        env_var_names = [env_var_names]
    
    for env_var in env_var_names:
        value = os.environ.get(env_var)
        if value is not None:
            return value
    
    # Fall back to config default
    return config_default


def resolve_aws_region(explicit_region: Optional[str] = None) -> str:
    """
    Resolve AWS region with priority: param > env > config > session > default.
    
    Args:
        explicit_region: Explicitly provided region
        
    Returns:
        AWS region string
    """
    # Explicit parameter wins
    if explicit_region:
        return explicit_region
    
    # Check environment variables
    env_region = resolve_config_value(
        None,
        ["AWS_REGION", "AWS_DEFAULT_REGION"],
        None
    )
    if env_region:
        return env_region
    
    # Check config
    config = get_config()
    if hasattr(config, 'aws_region') and config.aws_region:
        return config.aws_region
    
    # Check boto3 session default
    try:
        session = boto3.session.Session()
        if session.region_name:
            return session.region_name
    except Exception as e:
        log.debug(f"Failed to get session region: {e}")
    
    # Final fallback
    return DEFAULT_AWS_REGION


def create_aws_client(service_name: str, region: Optional[str] = None):
    """
    Create AWS client with consistent region resolution and error handling.
    
    Args:
        service_name: AWS service name (e.g., 'secretsmanager', 'cloudwatch')
        region: Optional explicit region
        
    Returns:
        AWS service client
        
    Raises:
        NoCredentialsError: When AWS credentials are not configured
        ClientError: When client creation fails
    """
    resolved_region = resolve_aws_region(region)
    
    try:
        session = boto3.session.Session()
        client = session.client(
            service_name=service_name,
            region_name=resolved_region
        )
        
        log.debug(f"Created {service_name} client for region {resolved_region}")
        return client
        
    except NoCredentialsError:
        log.error(f"AWS credentials not configured for {service_name} client")
        raise
    except ClientError as e:
        log.error(f"Failed to create {service_name} client: {e}")
        raise
    except Exception as e:
        log.error(f"Unexpected error creating {service_name} client: {e}")
        raise


def handle_client_errors(
    default_return: Any = None,
    log_context: Optional[Dict[str, Any]] = None,
    reraise: bool = False
):
    """
    Decorator for standardized client error handling.
    
    Args:
        default_return: Value to return on error (if not reraising)
        log_context: Additional context for error logging
        reraise: Whether to re-raise exceptions after logging
        
    Example:
        @handle_client_errors(default_return=[])
        def search_documents(self, query):
            # Implementation that might fail
            return results
    """
    def decorator(func):
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            try:
                return func(*args, **kwargs)
            except Exception as e:
                # Build log context
                context = {
                    "function": func.__name__,
                    "error_type": type(e).__name__,
                    "error_message": str(e)
                }
                if log_context:
                    context.update(log_context)
                
                log.error(
                    f"{func.__name__} failed: {e}",
                    exc_info=True,
                    extra=context
                )
                
                if reraise:
                    raise
                
                return default_return
        
        return wrapper
    return decorator


def merge_dimensions(base_dimensions: Dict[str, str], additional_dimensions: Optional[Dict[str, str]] = None) -> List[Dict[str, str]]:
    """
    Merge CloudWatch metric dimensions and format for API.
    
    Args:
        base_dimensions: Base dimensions dictionary
        additional_dimensions: Additional dimensions to merge
        
    Returns:
        List of dimension dictionaries formatted for CloudWatch API
        
    Example:
        dimensions = merge_dimensions(
            {"Service": "auth", "Environment": "prod"},
            {"Version": "1.2.3"}
        )
        # Returns: [{"Name": "Service", "Value": "auth"}, ...]
    """
    all_dimensions = {**base_dimensions}
    if additional_dimensions:
        all_dimensions.update(additional_dimensions)
    
    return [
        {"Name": str(key), "Value": str(value)} 
        for key, value in all_dimensions.items()
    ]


def validate_required_param(param_value: Any, param_name: str) -> Any:
    """
    Validate that a required parameter is provided.
    
    Args:
        param_value: Parameter value to validate
        param_name: Parameter name for error messages
        
    Returns:
        The parameter value if valid
        
    Raises:
        ValueError: If parameter is None or empty string
    """
    if param_value is None:
        raise ValueError(f"{param_name} is required")
    
    if isinstance(param_value, str) and not param_value.strip():
        raise ValueError(f"{param_name} cannot be empty")
    
    return param_value


def safe_close_connection(connection) -> None:
    """
    Safely close a database connection with proper error handling.
    
    Args:
        connection: Database connection to close
    """
    if connection and hasattr(connection, "close"):
        # Check if connection is already closed (database-specific checks)
        try:
            # PyMySQL specific checks
            if hasattr(connection, "_closed") and connection._closed:
                return
            if hasattr(connection, "open") and not connection.open:
                return
                
            # Generic close
            connection.close()
            log.debug("Database connection closed successfully")
            
        except Exception as e:
            log.debug(f"Error closing connection (non-fatal): {e}")


def format_log_context(
    operation: str,
    **context_data
) -> Dict[str, Any]:
    """
    Format consistent logging context for operations.
    
    Args:
        operation: Operation name
        **context_data: Additional context key-value pairs
        
    Returns:
        Formatted context dictionary
        
    Example:
        context = format_log_context(
            "database_query",
            table="users",
            query_type="SELECT",
            duration_ms=150
        )
    """
    context = {
        "operation": operation,
        "timestamp": time.time(),
    }
    context.update(context_data)
    
    return context