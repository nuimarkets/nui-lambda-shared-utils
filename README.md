# NUI Lambda Shared Utilities

[![PyPI version](https://badge.fury.io/py/nui-lambda-shared-utils.svg)](https://badge.fury.io/py/nui-lambda-shared-utils)
[![Python 3.9+](https://img.shields.io/badge/python-3.9+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

Enterprise-grade utilities for AWS Lambda functions with Slack, Elasticsearch, and monitoring integrations. This package provides standardized, production-ready patterns for common serverless operations while maintaining flexibility and configurability.

## Table of Contents

- [Key Features](#key-features)
- [Documentation](#documentation)
- [Quick Start](#quick-start)
- [Usage Examples](#usage-examples)
- [Configuration](#configuration)
- [AWS Infrastructure Requirements](#aws-infrastructure-requirements)
- [Testing](#testing)
- [Contributing](#contributing)
- [Documentation & Support](#documentation--support)
- [License](#license)

## Key Features

- **AWS Secrets Manager Integration** - Secure credential management with caching
- **Slack Messaging** - Rich formatting, threading, file uploads, and channel management
- **Elasticsearch Operations** - Query builders, index management, and health monitoring
- **Database Connections** - Connection pooling, automatic retries, and transaction management
- **CloudWatch Metrics** - Batched publishing with custom dimensions
- **Error Handling** - Intelligent retry patterns with exponential backoff
- **Timezone Utilities** - Timezone handling and formatting
- **Configurable Defaults** - Environment-aware configuration system

## Documentation

**New to this package?** Start with our comprehensive guides:

- **[Quick Start Guide](docs/getting-started/quickstart.md)** - Common patterns and complete examples
- **[Installation Guide](docs/getting-started/installation.md)** - Setup and dependency management
- **[Configuration Guide](docs/getting-started/configuration.md)** - Environment setup and AWS Secrets
- **[Slack Integration Guide](docs/guides/slack-integration.md)** - Messaging, blocks, threading, and files
- **[Testing Guide](docs/development/testing.md)** - Test strategies and coverage

**Complete documentation**: See [docs/](docs/README.md) for all guides and references.

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

## What's Next?

After installing the package:

1. **Configuration** → Set up environment variables or programmatic config ([guide](docs/getting-started/configuration.md))
2. **AWS Setup** → Configure Secrets Manager and IAM permissions ([guide](docs/getting-started/configuration.md#aws-infrastructure))
3. **Integration** → Choose your integration and follow the detailed guide:
   - [Slack Integration](docs/guides/slack-integration.md) - Messaging, formatting, file uploads
   - [Elasticsearch Operations](docs/getting-started/quickstart.md#elasticsearch-operations) - Query builders and search
   - [Database Connections](docs/getting-started/quickstart.md#database-connections) - Connection pooling and queries
   - [CloudWatch Metrics](docs/getting-started/quickstart.md#cloudwatch-metrics) - Performance tracking
4. **Testing** → Learn testing strategies ([guide](docs/development/testing.md))

**Complete documentation**: [docs/](docs/README.md)

## Usage Examples

Below are minimal examples to get you started. **For complete examples and detailed usage, see [docs/getting-started/quickstart.md](docs/getting-started/quickstart.md)**.

### Secrets Management

```python
from nui_lambda_shared_utils import get_secret, get_slack_credentials

# Generic secret retrieval
api_keys = get_secret("my-service/api-keys")

# Specialized getters with normalized field names
slack_creds = get_slack_credentials()  # Uses configured secret name
```

**[→ See full secrets management guide](docs/getting-started/configuration.md#aws-secrets-manager)**

### Slack Integration

```python
from nui_lambda_shared_utils import SlackClient, SlackBlockBuilder

slack = SlackClient()

# Simple message
slack.send_message(channel='#alerts', text='Service deployment complete')

# Rich formatted message with blocks
builder = SlackBlockBuilder()
blocks = builder.add_header("Alert", emoji="warning").add_section("Status", "Active").build()
slack.send_message(channel='#incidents', blocks=blocks)
```

**[→ See comprehensive Slack integration guide](docs/guides/slack-integration.md)**

### Elasticsearch Operations

```python
from nui_lambda_shared_utils import ElasticsearchClient, ESQueryBuilder

es = ElasticsearchClient()
query_builder = ESQueryBuilder()
query = query_builder.date_range("@timestamp", "now-1h", "now").term("level", "ERROR").build()
results = es.search(index="logs-*", body={"query": query})
```

**[→ See full Elasticsearch guide](docs/getting-started/quickstart.md#elasticsearch-operations)**

### Database Connections

```python
from nui_lambda_shared_utils import DatabaseClient

db = DatabaseClient()

# Execute queries with automatic retry and connection pooling
async with db.get_connection() as conn:
    results = await conn.execute("SELECT * FROM orders WHERE status = %s", ["confirmed"])
```

**[→ See full database guide](docs/getting-started/quickstart.md#database-connections)**

### CloudWatch Metrics

```python
from nui_lambda_shared_utils import MetricsPublisher, track_lambda_performance

metrics = MetricsPublisher(namespace="MyApplication")

@track_lambda_performance(metrics)
def lambda_handler(event, context):
    metrics.put_metric("ProcessedItems", 150, "Count")
    return {"statusCode": 200}
```

**[→ See full metrics guide](docs/getting-started/quickstart.md#cloudwatch-metrics)**

### Error Handling

```python
from nui_lambda_shared_utils import with_retry, handle_lambda_error

@handle_lambda_error
@with_retry(max_attempts=3)
def lambda_handler(event, context):
    # Your Lambda logic with automatic error handling and retries
    return {"statusCode": 200}
```

**[→ See full error handling guide](docs/getting-started/quickstart.md#error-handling)**

## Configuration

The package supports multiple configuration methods. **For detailed configuration options, see [docs/getting-started/configuration.md](docs/getting-started/configuration.md)**.

### Environment Variables

```bash
ES_HOST=localhost:9200                    # Elasticsearch host
ES_CREDENTIALS_SECRET=elasticsearch-creds # AWS secret name for ES
DB_CREDENTIALS_SECRET=database-creds      # AWS secret name for database
SLACK_CREDENTIALS_SECRET=slack-bot-token  # AWS secret name for Slack
AWS_REGION=us-east-1                      # AWS region
```

### Programmatic Configuration

```python
import nui_lambda_shared_utils as nui

nui.configure(
    es_host="localhost:9200",
    slack_credentials_secret="dev/slack-token"
)
```

**[→ See complete configuration guide](docs/getting-started/configuration.md)**

## AWS Infrastructure Requirements

This package requires AWS Secrets Manager for credential storage and IAM permissions for CloudWatch metrics.

**For detailed AWS setup instructions, see [docs/getting-started/configuration.md#aws-infrastructure](docs/getting-started/configuration.md)**.

### Quick Reference

**Secrets Manager** - Store credentials as JSON:
- Elasticsearch: `{"host": "...", "username": "...", "password": "..."}`
- Database: `{"host": "...", "port": 3306, "username": "...", "password": "...", "database": "..."}`
- Slack: `{"bot_token": "xoxb-...", "webhook_url": "..."}`

**IAM Permissions** - Lambda execution role needs:
- `secretsmanager:GetSecretValue` for credential access
- `cloudwatch:PutMetricData` for metrics publishing

**[→ See complete AWS infrastructure guide](docs/getting-started/configuration.md#aws-infrastructure)**

## Testing

**For comprehensive testing guide, see [docs/development/testing.md](docs/development/testing.md)**.

```bash
# Install with dev dependencies
pip install nui-lambda-shared-utils[dev]

# Run all tests
pytest

# Run with coverage
pytest --cov=nui_lambda_shared_utils --cov-report=html

# Run specific test categories
pytest -m unit           # Unit tests only
pytest -m integration    # Integration tests (requires AWS)
```

## Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## Documentation & Support

### 📚 Documentation
- **[Complete Documentation](docs/README.md)** - Comprehensive guides and references
- **[Quick Start Guide](docs/getting-started/quickstart.md)** - Get up and running fast
- **[Configuration Guide](docs/getting-started/configuration.md)** - Setup and AWS integration
- **[Slack Integration Guide](docs/guides/slack-integration.md)** - Detailed Slack features
- **[Testing Guide](docs/development/testing.md)** - Test strategies and coverage

### 🔗 Links
- **GitHub Repository**: https://github.com/nuimarkets/nui-lambda-shared-utils
- **Issue Tracker**: https://github.com/nuimarkets/nui-lambda-shared-utils/issues
- **PyPI Package**: https://pypi.org/project/nui-lambda-shared-utils/
- **Changelog**: [CHANGELOG.md](CHANGELOG.md)

### 💬 Support
- **Bug Reports**: [GitHub Issues](https://github.com/nuimarkets/nui-lambda-shared-utils/issues)
- **Feature Requests**: [GitHub Issues](https://github.com/nuimarkets/nui-lambda-shared-utils/issues)
- **Questions**: Check [docs/](docs/README.md) first, then open an issue

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## About NUI Markets

NUI Markets is a technology company focused on building innovative trading and marketplace platforms. This package represents our commitment to open-source tooling and enterprise-grade infrastructure patterns.

