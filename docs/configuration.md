# Configuration Guide

This guide covers all configuration options for `nui-lambda-shared-utils`, including environment variables, programmatic configuration, and AWS integration.

## Configuration System Overview

The package uses a hierarchical configuration system with the following priority order:

1. **Direct Parameters** - Values passed to function/class constructors
2. **Environment Variables** - System environment variables
3. **Configuration Defaults** - Package default values

## Environment Variables

### Core Configuration

| Variable | Description | Default |
|----------|-------------|---------|
| `ES_HOST` | Elasticsearch host and port | `localhost:9200` |
| `ES_CREDENTIALS_SECRET` | AWS secret name for Elasticsearch credentials | `elasticsearch-credentials` |
| `DB_CREDENTIALS_SECRET` | AWS secret name for database credentials | `database-credentials` |
| `SLACK_CREDENTIALS_SECRET` | AWS secret name for Slack credentials | `slack-credentials` |
| `AWS_REGION` | AWS region for services | `us-east-1` |

### Alternative Variable Names

The package supports alternative environment variable names for compatibility:

| Primary | Alternative |
|---------|-------------|
| `ES_HOST` | `ELASTICSEARCH_HOST` |
| `ES_CREDENTIALS_SECRET` | `ELASTICSEARCH_CREDENTIALS_SECRET` |
| `DB_CREDENTIALS_SECRET` | `DATABASE_CREDENTIALS_SECRET` |
| `AWS_REGION` | `AWS_DEFAULT_REGION` |

### Example Environment Setup

```bash
# Basic configuration
export ES_HOST="prod-elasticsearch:9200"
export ES_CREDENTIALS_SECRET="prod/elasticsearch-creds"
export DB_CREDENTIALS_SECRET="prod/database-creds"
export SLACK_CREDENTIALS_SECRET="prod/slack-token"
export AWS_REGION="us-west-2"

# Alternative names (equivalent)
export ELASTICSEARCH_HOST="prod-elasticsearch:9200"
export DATABASE_CREDENTIALS_SECRET="prod/database-creds"
```

## Programmatic Configuration

### Using the Config Class

```python
import nui_lambda_shared_utils as nui

# Create configuration object
config = nui.Config(
    es_host="prod-elastic:9200",
    es_credentials_secret="prod/elasticsearch",
    db_credentials_secret="prod/database",
    slack_credentials_secret="prod/slack",
    aws_region="us-west-2"
)

# Set as global configuration
nui.set_config(config)
```

### Using the Configure Helper

```python
import nui_lambda_shared_utils as nui

# Convenient one-liner configuration
nui.configure(
    es_host="localhost:9200",
    slack_credentials_secret="dev/slack-token",
    aws_region="us-east-1"
)
```

### Getting Current Configuration

```python
import nui_lambda_shared_utils as nui

# Get current configuration
config = nui.get_config()
print(config.to_dict())

# Access individual settings
print(f"ES Host: {config.es_host}")
print(f"AWS Region: {config.aws_region}")
```

## AWS Secrets Manager Integration

### Secret Formats

The package expects AWS secrets in specific JSON formats:

#### Elasticsearch Credentials

```json
{
  "host": "your-elasticsearch-host:9200",
  "username": "elastic",
  "password": "your-password"
}
```

**Optional Fields:**
- `host` - Can override ES_HOST if provided
- `username` - Defaults to "elastic" if not provided

#### Database Credentials

```json
{
  "host": "your-db-host",
  "port": 3306,
  "username": "dbuser",
  "password": "dbpassword",
  "database": "your_database"
}
```

**All fields are required** for database connections.

#### Slack Credentials

```json
{
  "bot_token": "xoxb-your-slack-bot-token",
  "webhook_url": "https://hooks.slack.com/services/..."
}
```

**Optional Fields:**
- `webhook_url` - Alternative to bot token for simple messaging

### Creating Secrets

#### Using AWS CLI

```bash
# Create Elasticsearch secret
aws secretsmanager create-secret \
  --name "elasticsearch-credentials" \
  --description "Elasticsearch credentials for Lambda functions" \
  --secret-string '{"host":"es-cluster:9200","username":"elastic","password":"secret"}'

# Create database secret
aws secretsmanager create-secret \
  --name "database-credentials" \
  --description "Database credentials for Lambda functions" \
  --secret-string '{"host":"db-host","port":3306,"username":"user","password":"pass","database":"mydb"}'

# Create Slack secret
aws secretsmanager create-secret \
  --name "slack-credentials" \
  --description "Slack bot token for notifications" \
  --secret-string '{"bot_token":"xoxb-your-token"}'
```

#### Using AWS Console

1. Navigate to AWS Secrets Manager
2. Click "Store a new secret"
3. Select "Other type of secret"
4. Enter the JSON values as key-value pairs
5. Name the secret according to your configuration

### Secret Access Patterns

#### Automatic Credential Loading

```python
# Credentials are automatically loaded based on configuration
es = nui.ElasticsearchClient()  # Uses ES_CREDENTIALS_SECRET
db = nui.DatabaseClient()       # Uses DB_CREDENTIALS_SECRET
slack = nui.SlackClient()       # Uses SLACK_CREDENTIALS_SECRET
```

#### Override Credential Sources

```python
# Override default secret names
es = nui.ElasticsearchClient(secret_name="custom-es-secret")
db = nui.DatabaseClient(secret_name="custom-db-secret")
slack = nui.SlackClient(secret_name="custom-slack-secret")
```

#### Manual Credential Retrieval

```python
# Get credentials directly
es_creds = nui.get_elasticsearch_credentials("custom-es-secret")
db_creds = nui.get_database_credentials("custom-db-secret")
slack_creds = nui.get_slack_credentials("custom-slack-secret")

# Generic secret retrieval
api_keys = nui.get_secret("my-service/api-keys")
```

## Environment-Specific Configuration

### Development Environment

```python
# Development configuration
nui.configure(
    es_host="localhost:9200",
    es_credentials_secret="dev/elasticsearch",
    db_credentials_secret="dev/database",
    slack_credentials_secret="dev/slack",
    aws_region="us-east-1"
)
```

### Production Environment

```python
# Production configuration
nui.configure(
    es_host="prod-cluster:9200",
    es_credentials_secret="prod/elasticsearch",
    db_credentials_secret="prod/database",
    slack_credentials_secret="prod/slack",
    aws_region="us-west-2"
)
```

### Lambda Environment Configuration

```python
import os
import nui_lambda_shared_utils as nui

def lambda_handler(event, context):
    # Configure based on Lambda environment variables
    stage = os.environ.get('STAGE', 'dev')
    
    nui.configure(
        es_host=os.environ.get('ES_HOST'),
        es_credentials_secret=f"{stage}/elasticsearch",
        db_credentials_secret=f"{stage}/database", 
        slack_credentials_secret=f"{stage}/slack"
    )
    
    # Use configured clients
    slack = nui.SlackClient()
    # ... rest of Lambda logic
```

## Configuration Validation

### Checking Configuration

```python
import nui_lambda_shared_utils as nui

# Get configuration and check values
config = nui.get_config()
print("Configuration:")
for key, value in config.to_dict().items():
    print(f"  {key}: {value}")

# Test secret access
try:
    es_creds = nui.get_elasticsearch_credentials()
    print("Elasticsearch credentials: OK")
except Exception as e:
    print(f"Elasticsearch credentials: ERROR - {e}")
```

### Configuration Debug Mode

```python
import nui_lambda_shared_utils as nui
import json

# Enable debug logging for configuration issues
config = nui.get_config()
print(json.dumps(config.to_dict(), indent=2))

# Test each integration
integrations = [
    ("Elasticsearch", lambda: nui.get_elasticsearch_credentials()),
    ("Database", lambda: nui.get_database_credentials()),
    ("Slack", lambda: nui.get_slack_credentials()),
]

for name, test_func in integrations:
    try:
        test_func()
        print(f"{name}: Configuration OK")
    except Exception as e:
        print(f"{name}: Configuration ERROR - {e}")
```

## Legacy Compatibility

The package provides legacy compatibility functions:

```python
# Legacy functions (deprecated, use get_config() instead)
es_host = nui.get_es_host()
es_secret = nui.get_es_credentials_secret()
db_secret = nui.get_db_credentials_secret()
slack_secret = nui.get_slack_credentials_secret()
```

## Best Practices

1. **Use Environment Variables in Lambda**: Set configuration via Lambda environment variables
2. **Separate Secrets by Environment**: Use prefixes like `dev/`, `staging/`, `prod/`
3. **Validate Configuration Early**: Check configuration during application startup
4. **Use Descriptive Secret Names**: Make secret names self-documenting
5. **Rotate Secrets Regularly**: Implement secret rotation for production environments
6. **Minimize Secret Scope**: Only include necessary fields in secrets
7. **Cache Configuration**: The package caches secrets automatically for performance