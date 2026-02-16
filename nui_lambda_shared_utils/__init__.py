"""
Enterprise-grade utilities for AWS Lambda functions with Slack, Elasticsearch, and monitoring integrations.
"""

# Configuration system
from .config import (
    Config,
    get_config,
    set_config,
    configure,
    get_es_host,
    get_es_credentials_secret,
    get_db_credentials_secret,
    get_slack_credentials_secret,
)

# Core utilities
from .secrets_helper import (
    get_secret,
    get_database_credentials,
    get_elasticsearch_credentials,
    get_slack_credentials,
    get_api_key,
    clear_cache,
)

# Common utilities
from .utils import (
    resolve_config_value,
    create_aws_client,
    handle_client_errors,
    merge_dimensions,
    validate_required_param,
)

# Base client architecture
from .base_client import BaseClient, ServiceHealthMixin, RetryableOperationMixin

# Client implementations - only fail if actually used
try:
    from .slack_client import SlackClient
except ImportError:
    SlackClient = None  # type: ignore

try:
    from .es_client import ElasticsearchClient
except ImportError:
    ElasticsearchClient = None  # type: ignore

try:
    from .db_client import DatabaseClient, PostgreSQLClient, get_pool_stats
except ImportError:
    DatabaseClient = None  # type: ignore
    PostgreSQLClient = None  # type: ignore
    get_pool_stats = None  # type: ignore

from .timezone import nz_time, format_nz_time

# Slack formatting utilities (no external dependencies)
from .slack_formatter import (
    SlackBlockBuilder,
    format_currency,
    format_percentage,
    format_number,
    format_nz_time as format_nz_time_slack,
    format_date_range,
    format_daily_header,
    format_weekly_header,
    format_error_alert,
    SEVERITY_EMOJI,
    STATUS_EMOJI,
)

# ES query builder - optional import
try:
    from .es_query_builder import (
        ESQueryBuilder,
        build_error_rate_query,
        build_top_errors_query,
        build_response_time_query,
        build_service_volume_query,
        build_user_activity_query,
        build_pattern_detection_query,
        build_tender_participant_query,
    )
except ImportError:
    ESQueryBuilder = None  # type: ignore
    build_error_rate_query = None  # type: ignore
    build_top_errors_query = None  # type: ignore
    build_response_time_query = None  # type: ignore
    build_service_volume_query = None  # type: ignore
    build_user_activity_query = None  # type: ignore
    build_pattern_detection_query = None  # type: ignore
    build_tender_participant_query = None  # type: ignore
from .error_handler import (
    RetryableError,
    NonRetryableError,
    ErrorPatternMatcher,
    ErrorAggregator,
    with_retry,
    retry_on_network_error,
    retry_on_db_error,
    retry_on_es_error,
    handle_lambda_error,
    categorize_retryable_error,
)
from .cloudwatch_metrics import (
    MetricsPublisher,
    MetricAggregator,
    StandardMetrics,
    TimedMetric,
    track_lambda_performance,
    create_service_dimensions,
    publish_health_metric,
)

# AWS Powertools integration - optional import
try:
    from .powertools_helpers import get_powertools_logger, powertools_handler
except ImportError:
    get_powertools_logger = None  # type: ignore
    powertools_handler = None  # type: ignore

# Log processing utilities (no external dependencies)
from .log_processors import (
    CloudWatchLogEvent,
    CloudWatchLogsData,
    derive_index_name,
    extract_cloudwatch_logs_from_kinesis,
)

# Lambda context helpers (no external dependencies)
from .lambda_helpers import get_lambda_environment_info

# JWT authentication - optional import
try:
    from .jwt_auth import (
        validate_jwt,
        require_auth,
        check_auth,
        get_jwt_public_key,
        JWTValidationError,
        AuthenticationError,
    )
except ImportError:
    validate_jwt = None  # type: ignore
    require_auth = None  # type: ignore
    check_auth = None  # type: ignore
    get_jwt_public_key = None  # type: ignore
    JWTValidationError = None  # type: ignore
    AuthenticationError = None  # type: ignore

# Slack setup utilities (for CLI usage) - optional import
try:
    from . import slack_setup
except ImportError:
    slack_setup = None  # type: ignore

__all__ = [
    # Configuration system
    "Config",
    "get_config",
    "set_config",
    "configure",
    "get_es_host",
    "get_es_credentials_secret",
    "get_db_credentials_secret",
    "get_slack_credentials_secret",
    # Core utilities
    "get_secret",
    "get_database_credentials",
    "get_elasticsearch_credentials",
    "get_slack_credentials",
    "get_api_key",
    "clear_cache",
    # Common utilities
    "resolve_config_value",
    "create_aws_client",
    "handle_client_errors",
    "merge_dimensions",
    "validate_required_param",
    # Base client architecture
    "BaseClient",
    "ServiceHealthMixin",
    "RetryableOperationMixin",
    # Client implementations
    "SlackClient",
    "ElasticsearchClient",
    "DatabaseClient",
    "PostgreSQLClient",
    "get_pool_stats",  # Legacy compatibility (None)
    "nz_time",
    "format_nz_time",
    "slack_setup",
    # Slack formatting
    "SlackBlockBuilder",
    "format_currency",
    "format_percentage",
    "format_number",
    "format_nz_time_slack",
    "format_date_range",
    "format_daily_header",
    "format_weekly_header",
    "format_error_alert",
    "SEVERITY_EMOJI",
    "STATUS_EMOJI",
    # ES query building
    "ESQueryBuilder",
    "build_error_rate_query",
    "build_top_errors_query",
    "build_response_time_query",
    "build_service_volume_query",
    "build_user_activity_query",
    "build_pattern_detection_query",
    "build_tender_participant_query",
    # Error handling
    "RetryableError",
    "NonRetryableError",
    "ErrorPatternMatcher",
    "ErrorAggregator",
    "with_retry",
    "retry_on_network_error",
    "retry_on_db_error",
    "retry_on_es_error",
    "handle_lambda_error",
    "categorize_retryable_error",
    # CloudWatch metrics
    "MetricsPublisher",
    "MetricAggregator",
    "StandardMetrics",
    "TimedMetric",
    "track_lambda_performance",
    "create_service_dimensions",
    "publish_health_metric",
    # AWS Powertools integration
    "get_powertools_logger",
    "powertools_handler",
    # Log processing
    "extract_cloudwatch_logs_from_kinesis",
    "derive_index_name",
    "CloudWatchLogEvent",
    "CloudWatchLogsData",
    # Lambda context helpers
    "get_lambda_environment_info",
    # JWT authentication
    "validate_jwt",
    "require_auth",
    "check_auth",
    "get_jwt_public_key",
    "JWTValidationError",
    "AuthenticationError",
]
