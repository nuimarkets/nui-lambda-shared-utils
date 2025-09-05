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
from .slack_client import SlackClient

# Optional imports - only fail if actually used
try:
    from .es_client import ElasticsearchClient
except ImportError:
    ElasticsearchClient = None

try:
    from .db_client import DatabaseClient, get_pool_stats
except ImportError:
    DatabaseClient = None
    get_pool_stats = None
from .timezone import nz_time, format_nz_time

# New utilities
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
    SERVICE_EMOJI,
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
    ESQueryBuilder = None
    build_error_rate_query = None
    build_top_errors_query = None
    build_response_time_query = None
    build_service_volume_query = None
    build_user_activity_query = None
    build_pattern_detection_query = None
    build_tender_participant_query = None
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


# Slack setup utilities (for CLI usage)
from . import slack_setup

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
    "SlackClient",
    "ElasticsearchClient",
    "DatabaseClient",
    "get_pool_stats",
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
    "SERVICE_EMOJI",
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
]
