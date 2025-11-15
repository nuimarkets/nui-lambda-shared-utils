# NUI Lambda Shared Utilities

[![PyPI version](https://badge.fury.io/py/nui-lambda-shared-utils.svg)](https://badge.fury.io/py/nui-lambda-shared-utils)
[![Python 3.9+](https://img.shields.io/badge/python-3.9+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

Enterprise-grade utilities for AWS Lambda functions with Slack, Elasticsearch, and monitoring integrations. This package provides standardized, production-ready patterns for common serverless operations while maintaining flexibility and configurability.

## Key Features

- **AWS Secrets Manager Integration** - Secure credential management with caching
- **Slack Messaging** - Rich formatting, threading, file uploads, and channel management
- **Elasticsearch Operations** - Query builders, index management, and health monitoring
- **Database Connections** - Connection pooling, automatic retries, and transaction management
- **CloudWatch Metrics** - Batched publishing with custom dimensions
- **Error Handling** - Intelligent retry patterns with exponential backoff
- **Timezone Utilities** - Timezone handling and formatting
- **Configurable Defaults** - Environment-aware configuration system

## Quick Start

### Installation

```bash
pip install nui-lambda-shared-utils

# With specific extras for optional dependencies
pip install nui-lambda-shared-utils[all]          # All integrations
pip install nui-lambda-shared-utils[slack]        # Slack only
pip install nui-lambda-shared-utils[elasticsearch] # Elasticsearch only
pip install nui-lambda-shared-utils[database]     # Database only
```

### Basic Configuration

```python
import nui_lambda_shared_utils as nui

# Configure for your environment (optional - uses sensible defaults)
nui.configure(
    es_host="your-elasticsearch-host:9200",
    es_credentials_secret="your-es-secret-name",
    slack_credentials_secret="your-slack-secret-name",
    db_credentials_secret="your-database-secret-name"
)

# Or use environment variables:
# ES_HOST, ES_CREDENTIALS_SECRET, SLACK_CREDENTIALS_SECRET, etc.
```

## Usage Examples

### Secrets Management

```python
from nui_lambda_shared_utils import get_secret, get_slack_credentials, get_database_credentials

# Generic secret retrieval
api_keys = get_secret("my-service/api-keys")

# Specialized getters with normalized field names
slack_creds = get_slack_credentials()  # Uses configured secret name
db_creds = get_database_credentials()  # Standardized: host, port, username, password, database
```

### Slack Integration

```python
from nui_lambda_shared_utils import SlackClient, SlackBlockBuilder

# Initialize client
slack = SlackClient()

# Simple message
response = slack.send_message(
    channel='#alerts',
    text='Service deployment complete'
)

# Rich formatted message with blocks
builder = SlackBlockBuilder()
blocks = (builder
    .add_header("Production Alert", emoji="warning")
    .add_section("Error Rate", "15.2% (above 10% threshold)")
    .add_section("Time Range", "Last 10 minutes")
    .add_divider()
    .add_context("Alert ID: PROD-2025-001")
    .build()
)

slack.send_message(channel='#incidents', blocks=blocks)

# File upload
slack.send_file(
    channel='#reports',
    content='Daily metrics...',
    filename='metrics-2025-01-05.csv',
    title='Daily Metrics Report'
)

# Thread reply
slack.reply_to_thread(
    channel='#incidents',
    thread_ts='1735689600.123',
    text='Issue resolved!'
)
```

#### Configuring AWS Account Names

By default, the library uses example account IDs for display. Lambda clients should configure their own AWS account name mappings for proper identification in Slack messages.

**Option 1: Direct dictionary (programmatic)**
```python
from nui_lambda_shared_utils import SlackClient

# Provide custom account mappings (replace with your AWS account IDs)
account_mappings = {
    "111222333444": "my-prod",
    "555666777888": "my-dev"
}

slack = SlackClient(account_names=account_mappings)
```

**Option 2: YAML config file (recommended)**
```python
from nui_lambda_shared_utils import SlackClient

# Copy docs/slack_config.yaml.template to your Lambda project
# and customize with your AWS account IDs

slack = SlackClient(account_names_config="slack_config.yaml")
```

**Benefits**:
- Slack headers show meaningful account names instead of "Unknown"
- Separate config files per Lambda service
- No sensitive account IDs hardcoded in shared library

### Elasticsearch Operations

```python
from nui_lambda_shared_utils import ElasticsearchClient, ESQueryBuilder

# Initialize client
es = ElasticsearchClient()

# Query builder for complex searches
query_builder = ESQueryBuilder()
query = (query_builder
    .date_range("@timestamp", "now-1h", "now")
    .term("level", "ERROR")
    .wildcard("message", "*timeout*")
    .build()
)

results = es.search(index="logs-*", body={"query": query})

# Built-in query helpers
error_stats = es.get_error_stats(
    index="application-logs", 
    time_range="1h",
    service_filter="payment-service"
)
```

### Database Connections

```python
from nui_lambda_shared_utils import DatabaseClient

# Initialize with connection pooling
db = DatabaseClient()

# Execute queries with automatic retry
async with db.get_connection() as conn:
    results = await conn.execute(
        "SELECT * FROM orders WHERE created_at > %s",
        [datetime.now() - timedelta(hours=1)]
    )

# Bulk operations
records = [{"id": 1, "name": "Item 1"}, {"id": 2, "name": "Item 2"}]
db.bulk_insert("items", records)
```

### CloudWatch Metrics

```python
from nui_lambda_shared_utils import MetricsPublisher, StandardMetrics

# Initialize publisher
metrics = MetricsPublisher(namespace="MyApplication")

# Individual metrics
metrics.put_metric("ProcessedItems", 150, "Count")
metrics.put_metric("ResponseTime", 245.5, "Milliseconds")

# Batch publishing (more efficient)
metrics.batch_publish([
    StandardMetrics.count("Errors", 3),
    StandardMetrics.duration("ProcessingTime", 1.2),
    StandardMetrics.gauge("QueueSize", 45)
])

# Decorator for Lambda performance tracking
@track_lambda_performance(metrics)
def lambda_handler(event, context):
    # Your Lambda logic here
    return {"statusCode": 200}
```

### Error Handling

```python
from nui_lambda_shared_utils import with_retry, retry_on_network_error, handle_lambda_error

# Automatic retry with exponential backoff
@retry_on_network_error
def call_external_api():
    response = requests.get("https://api.external-service.com/data")
    return response.json()

# Custom retry configuration
@with_retry(max_attempts=5, initial_delay=2.0)
def critical_operation():
    # Operation that might fail
    return perform_critical_task()

# Lambda error handling wrapper
@handle_lambda_error
def lambda_handler(event, context):
    # Your Lambda logic here
    return {"statusCode": 200, "body": "Success"}
```

## Configuration

The package supports multiple configuration methods:

### Environment Variables

```bash
# Core settings
ES_HOST=localhost:9200                    # Elasticsearch host
ES_CREDENTIALS_SECRET=elasticsearch-creds # AWS secret name for ES credentials
DB_CREDENTIALS_SECRET=database-creds      # AWS secret name for DB credentials
SLACK_CREDENTIALS_SECRET=slack-bot-token  # AWS secret name for Slack token

# AWS settings
AWS_REGION=us-east-1                      # AWS region for services
```

### Programmatic Configuration

```python
import nui_lambda_shared_utils as nui

# Configure all at once
config = nui.Config(
    es_host="prod-elastic:9200",
    es_credentials_secret="prod/elasticsearch",
    db_credentials_secret="prod/database",
    slack_credentials_secret="prod/slack",
    aws_region="us-west-2"
)
nui.set_config(config)

# Or configure specific settings
nui.configure(
    es_host="localhost:9200",
    slack_credentials_secret="dev/slack-token"
)
```

## AWS Infrastructure Requirements

This package expects certain AWS resources to be available:

### Secrets Manager

Create secrets with these structures:

```json
// Elasticsearch credentials
{
  "host": "your-elasticsearch-host:9200",
  "username": "elastic", 
  "password": "your-password"
}

// Database credentials
{
  "host": "your-db-host",
  "port": 3306,
  "username": "dbuser",
  "password": "dbpassword", 
  "database": "your_database"
}

// Slack credentials
{
  "bot_token": "xoxb-your-slack-bot-token",
  "webhook_url": "https://hooks.slack.com/..." // optional
}
```

### IAM Permissions

Your Lambda execution role needs:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "secretsmanager:GetSecretValue"
      ],
      "Resource": "arn:aws:secretsmanager:*:*:secret:your-secret-*"
    },
    {
      "Effect": "Allow", 
      "Action": [
        "cloudwatch:PutMetricData"
      ],
      "Resource": "*"
    }
  ]
}
```

## Testing

```bash
# Install with dev dependencies
pip install nui-lambda-shared-utils[dev]

# Run tests
pytest

# Run tests with coverage
pytest --cov=nui_lambda_shared_utils --cov-report=html

# Run specific test categories
pytest -m unit      # Unit tests only
pytest -m integration  # Integration tests (requires AWS access)
```

## Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## Documentation & Support

- **GitHub Repository**: https://github.com/nuimarkets/nui-lambda-shared-utils
- **Issue Tracker**: https://github.com/nuimarkets/nui-lambda-shared-utils/issues
- **PyPI Package**: https://pypi.org/project/nui-lambda-shared-utils/

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## About NUI Markets

NUI Markets is a technology company focused on building innovative trading and marketplace platforms. This package represents our commitment to open-source tooling and enterprise-grade infrastructure patterns.

