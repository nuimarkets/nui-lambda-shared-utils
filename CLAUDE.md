# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

This is `nui-lambda-shared-utils`, a Python package providing enterprise-grade utilities for AWS Lambda functions. It offers standardized integrations for Slack, Elasticsearch, database operations, CloudWatch metrics, and error handling patterns commonly used across NUI platform Lambda services.

## Architecture

### Core Module Structure
- **Configuration System** (`config.py`) - Environment-aware configuration with AWS Secrets Manager integration
- **Secrets Management** (`secrets_helper.py`) - Centralized credential handling with caching
- **Slack Integration** (`slack_client.py`, `slack_formatter.py`) - Rich messaging, threading, and file uploads
- **Elasticsearch** (`es_client.py`, `es_query_builder.py`) - Query builders and health monitoring
- **Database** (`db_client.py`) - Connection pooling with retry logic
- **Metrics** (`cloudwatch_metrics.py`) - Batched CloudWatch publishing with decorators
- **Error Handling** (`error_handler.py`) - Retry patterns with exponential backoff
- **Timezone Utils** (`timezone.py`) - New Zealand timezone handling

### Optional Dependencies
The package uses optional extras to minimize Lambda bundle size:
- `elasticsearch` - Elasticsearch client and query builders
- `database` - MySQL/PostgreSQL drivers
- `slack` - Slack SDK
- `all` - All integrations
- `dev` - Development and testing tools

### Slack Setup Module
The `slack_setup/` submodule provides automated Slack workspace configuration:
- **Channel Creation** - Programmatic channel and permission setup
- **Template System** - YAML-based channel definitions
- **CLI Tool** - `nui-slack-setup` command for deployment

## Development Commands

### Environment Setup
```bash
# Install package in development mode with all dependencies
pip install -e .[dev]

# Install with specific integrations only
pip install -e .[slack,elasticsearch]

# Set up virtual environment
python -m venv venv
source venv/bin/activate  # Linux/Mac
```

### Testing
```bash
# Run all tests
pytest

# Run with coverage reporting
pytest --cov=nui_lambda_shared_utils --cov-report=html

# Run only unit tests (skip integration tests requiring AWS)
pytest -m "not integration"

# Run specific test categories
pytest -m unit           # Unit tests only
pytest -m integration    # Integration tests only
pytest -m slow          # Slow tests only

# Run single test file
pytest tests/test_slack_client.py -v
```

### Code Quality
```bash
# Format code with Black (line length: 120)
black nui_lambda_shared_utils/ tests/

# Check formatting without changes
black --check nui_lambda_shared_utils/

# Type checking with MyPy
mypy nui_lambda_shared_utils/ --config-file mypy.ini

# Run linting (currently configured to use Black)
black --check nui_lambda_shared_utils/
```

### Package Building and Publishing
```bash
# Build package
python -m build

# Install build tools
pip install build twine

# Publish to PyPI (requires credentials)
python -m twine upload dist/*
```

## Configuration Patterns

### Environment Variables
The package expects these environment variables for runtime configuration:
- `ES_HOST` - Elasticsearch endpoint
- `ES_CREDENTIALS_SECRET` - AWS secret name for ES credentials
- `DB_CREDENTIALS_SECRET` - AWS secret name for database credentials  
- `SLACK_CREDENTIALS_SECRET` - AWS secret name for Slack token
- `AWS_REGION` - AWS region for services

### AWS Secrets Format
Secrets should follow standardized JSON structures:
```json
// Elasticsearch
{"host": "elastic:9200", "username": "user", "password": "pass"}

// Database  
{"host": "db-host", "port": 3306, "username": "user", "password": "pass", "database": "db"}

// Slack
{"bot_token": "xoxb-...", "webhook_url": "https://hooks.slack.com/..."}
```

### Programmatic Configuration
```python
import nui_lambda_shared_utils as nui

# Configure specific settings
nui.configure(
    es_host="localhost:9200",
    slack_credentials_secret="dev/slack-token"
)

# Or use Config object
config = nui.Config(es_host="prod:9200")
nui.set_config(config)
```

## Common Usage Patterns

### Error Handling with Decorators
```python
from nui_lambda_shared_utils import with_retry, handle_lambda_error

@handle_lambda_error
@with_retry(max_attempts=3)
def lambda_handler(event, context):
    # Lambda logic with automatic error handling and retries
    pass
```

### Metrics Publishing
```python
from nui_lambda_shared_utils import MetricsPublisher, track_lambda_performance

metrics = MetricsPublisher(namespace="MyService")

@track_lambda_performance(metrics)
def lambda_handler(event, context):
    # Automatically tracked performance metrics
    metrics.put_metric("ProcessedItems", len(items), "Count")
```

### Slack Integration
```python
from nui_lambda_shared_utils import SlackClient, SlackBlockBuilder

slack = SlackClient()
builder = SlackBlockBuilder()

blocks = (builder
    .add_header("Alert", emoji="warning")
    .add_section("Status", "Error detected")
    .build()
)

slack.send_message(channel="#alerts", blocks=blocks)
```

## Testing Strategy

### Test Categories (pytest markers)
- `@pytest.mark.unit` - Fast unit tests with mocking
- `@pytest.mark.integration` - Tests requiring AWS services
- `@pytest.mark.slow` - Long-running tests

### AWS Testing
Integration tests use `moto` for AWS service mocking. Some tests require real AWS credentials for full integration testing.

### Test Structure
```
tests/
├── test_<module>.py     # Main module tests
├── conftest.py         # Shared fixtures
└── fixtures/           # Test data files
```

## Package Distribution

### Version Management
Version is defined in both `setup.py` and `pyproject.toml` and should be kept in sync. The package follows semantic versioning.

### PyPI Publishing
The package is published to PyPI as `nui-lambda-shared-utils` with GitHub Actions automation for releases.

### CLI Tools
The package provides `nui-slack-setup` CLI tool for Slack workspace configuration.

## AWS Lambda Integration

### Bundle Size Optimization
- Use specific extras (`[slack]`, `[elasticsearch]`) rather than `[all]`
- Optional imports prevent failure if dependencies aren't installed
- Core utilities work without optional dependencies

### Lambda Layer Usage
The package is designed to work well in Lambda layers for sharing across multiple functions.

### Environment Integration
- Automatic AWS region detection
- Secrets Manager integration with credential caching
- CloudWatch metrics with proper dimensions