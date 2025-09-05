# NUI Lambda Shared Utilities Documentation

Welcome to the comprehensive documentation for `nui-lambda-shared-utils`, an enterprise-grade Python package designed for AWS Lambda functions with integrated support for Slack, Elasticsearch, database operations, and monitoring.

## Overview

This package provides standardized, production-ready patterns for common serverless operations while maintaining flexibility and configurability. It's specifically designed to reduce boilerplate code and ensure consistent patterns across Lambda functions in the NUI platform.

## Quick Navigation

### Getting Started
- [Installation Guide](installation.md) - Setup and dependency management
- [Configuration Guide](configuration.md) - Environment setup and credential management
- [Quick Start Examples](quickstart.md) - Common usage patterns

### Core Components
- [Secrets Management](secrets.md) - AWS Secrets Manager integration
- [Slack Integration](slack.md) - Messaging, formatting, and channel management
- [Elasticsearch Operations](elasticsearch.md) - Query building and search operations
- [Database Connections](database.md) - Connection pooling and query execution
- [CloudWatch Metrics](metrics.md) - Performance monitoring and custom metrics
- [Error Handling](error-handling.md) - Retry patterns and exception management
- [Timezone Utilities](timezone.md) - New Zealand timezone handling

### Advanced Topics
- [AWS Infrastructure](aws-infrastructure.md) - Required AWS resources and IAM permissions
- [Testing Guide](testing.md) - Unit and integration testing strategies
- [Lambda Integration](lambda-integration.md) - Bundle optimization and layer usage
- [CLI Tools](cli-tools.md) - Command-line utilities and automation

### Developer Resources
- [API Reference](api/) - Complete module and function documentation
- [Contributing Guide](contributing.md) - Development workflow and standards
- [Changelog](changelog.md) - Version history and migration notes
- [Troubleshooting](troubleshooting.md) - Common issues and solutions

## Key Features

- **Modular Design**: Optional dependencies reduce Lambda bundle size
- **Configuration System**: Environment-aware with sensible defaults
- **Production Ready**: Battle-tested patterns with comprehensive error handling
- **Standardized Patterns**: Consistent interfaces across all integrations
- **Performance Optimized**: Connection pooling, caching, and batch operations
- **Developer Friendly**: Rich type hints and comprehensive documentation

## Architecture

The package is built around a central configuration system that manages credentials and environment-specific settings. Each integration module (Slack, Elasticsearch, Database, etc.) can be used independently or combined as needed.

```
nui_lambda_shared_utils/
├── config.py              # Configuration system
├── secrets_helper.py      # AWS Secrets Manager integration
├── slack_client.py        # Slack messaging
├── slack_formatter.py     # Rich message formatting
├── es_client.py           # Elasticsearch operations
├── es_query_builder.py    # Query construction utilities
├── db_client.py           # Database connection management
├── cloudwatch_metrics.py  # Metrics publishing
├── error_handler.py       # Retry and error patterns
├── timezone.py            # Timezone utilities
└── slack_setup/           # Automated Slack workspace setup
```

## Support

- **GitHub Issues**: Report bugs and request features
- **Documentation**: Comprehensive guides and API reference
- **Examples**: Real-world usage patterns and integration examples

---

*This documentation is generated for version 1.0.0 of nui-lambda-shared-utils.*