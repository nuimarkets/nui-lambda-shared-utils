# Testing Guide

Comprehensive testing guide for `nui-lambda-shared-utils` developers.

**Last Updated**: 2025-11-16

## Overview

The package uses `pytest` as the testing framework with comprehensive test coverage across all modules. Tests are organized into categories using pytest markers for flexible test execution.

## Quick Start

```bash
# Run all tests
pytest

# Run with coverage report
pytest --cov=nui_lambda_shared_utils --cov-report=html

# Run specific test categories
pytest -m unit              # Unit tests only
pytest -m integration       # Integration tests only
pytest -m slow             # Long-running tests
```

## Test Structure

```
tests/
├── conftest.py               # Shared fixtures and configuration
├── test_config.py           # Configuration system tests
├── test_secrets_helper.py   # Secrets Manager integration tests
├── test_slack_client.py     # Slack integration tests
├── test_slack_formatter.py  # Slack formatting tests
├── test_es_client.py        # Elasticsearch client tests
├── test_es_query_builder.py # Query builder tests
├── test_db_client.py        # Database client tests
├── test_cloudwatch_metrics.py  # CloudWatch metrics tests
├── test_error_handler.py    # Error handling tests
├── test_timezone.py         # Timezone utility tests
├── test_base_client.py      # Base client tests
└── test_utils.py            # Utility function tests
```

## Test Categories

### Unit Tests (`@pytest.mark.unit`)

Fast, isolated tests that mock external dependencies.

**Characteristics:**

- No AWS service calls
- Use mocking extensively
- Fast execution (< 1 second per test)
- High coverage of code paths

**Example:**

```python
@pytest.mark.unit
def test_config_defaults():
    """Test default configuration values."""
    config = Config()
    assert config.es_host == "localhost:9200"
    assert config.aws_region == "us-east-1"
```

### Integration Tests (`@pytest.mark.integration`)

Tests requiring actual AWS services or external dependencies.

**Characteristics:**

- May require AWS credentials
- Use `moto` for AWS service mocking
- Slower execution
- Test actual integration patterns

**Example:**

```python
@pytest.mark.integration
def test_secrets_manager_integration():
    """Test actual Secrets Manager integration."""
    # Requires AWS credentials or moto mock
    secret = get_secret("test-secret")
    assert secret is not None
```

### Slow Tests (`@pytest.mark.slow`)

Long-running tests that may timeout or require special attention.

**Example:**

```python
@pytest.mark.slow
def test_large_elasticsearch_query():
    """Test query with large result set."""
    # ... slow operation
```

## Running Tests

### Basic Commands

```bash
# All tests with output
pytest -v

# Stop on first failure
pytest -x

# Run specific test file
pytest tests/test_slack_client.py

# Run specific test function
pytest tests/test_slack_client.py::test_send_message

# Run tests matching pattern
pytest -k "slack"  # All tests with "slack" in name
```

### Coverage Reports

```bash
# Terminal coverage report
pytest --cov=nui_lambda_shared_utils

# HTML coverage report
pytest --cov=nui_lambda_shared_utils --cov-report=html
# Opens in: htmlcov/index.html

# Coverage with missing lines
pytest --cov=nui_lambda_shared_utils --cov-report=term-missing

# Fail if coverage below threshold
pytest --cov=nui_lambda_shared_utils --cov-fail-under=90
```

### Filtering Tests

```bash
# Unit tests only (fast)
pytest -m unit

# Skip integration tests
pytest -m "not integration"

# Skip slow tests
pytest -m "not slow"

# Unit tests excluding slow ones
pytest -m "unit and not slow"
```

## Test Environment Setup

### AWS Mocking with Moto

The package uses `moto` for mocking AWS services in tests:

```python
import pytest
from moto import mock_secretsmanager
import boto3

@pytest.fixture
def mock_secrets():
    """Mock AWS Secrets Manager."""
    with mock_secretsmanager():
        client = boto3.client('secretsmanager', region_name='us-east-1')
        client.create_secret(
            Name='test-secret',
            SecretString='{"key": "value"}'
        )
        yield client

def test_with_mock_secrets(mock_secrets):
    """Test using mocked secrets."""
    from nui_lambda_shared_utils import get_secret
    secret = get_secret('test-secret')
    assert secret['key'] == 'value'
```

### Environment Variables for Testing

```bash
# Set test environment variables
export AWS_ACCESS_KEY_ID=test
export AWS_SECRET_ACCESS_KEY=test
export AWS_DEFAULT_REGION=us-east-1

# Run tests
pytest
```

### Test Configuration

The `pytest.ini` file configures pytest behavior:

```ini
[pytest]
testpaths = tests
python_files = test_*.py
python_classes = Test*
python_functions = test_*
markers =
    unit: Unit tests (fast, no external dependencies)
    integration: Integration tests (require AWS/external services)
    slow: Slow-running tests
```

## Writing Tests

### Test Structure Best Practices

```python
import pytest
from nui_lambda_shared_utils import SlackClient

class TestSlackClient:
    """Test suite for SlackClient."""

    @pytest.fixture
    def mock_slack_config(self):
        """Fixture for Slack configuration."""
        return {
            'bot_token': 'xoxb-test-token',
            'webhook_url': 'https://hooks.slack.com/test'
        }

    @pytest.mark.unit
    def test_initialization(self, mock_slack_config):
        """Test client initialization."""
        # Arrange
        config = mock_slack_config

        # Act
        client = SlackClient(bot_token=config['bot_token'])

        # Assert
        assert client.bot_token == config['bot_token']

    @pytest.mark.unit
    def test_message_formatting(self):
        """Test message formatting."""
        # Test implementation
        pass
```

### Mocking External Dependencies

```python
from unittest.mock import Mock, patch

@pytest.mark.unit
def test_elasticsearch_search():
    """Test Elasticsearch search with mocking."""
    with patch('elasticsearch.Elasticsearch') as mock_es:
        # Configure mock
        mock_es.return_value.search.return_value = {
            'hits': {'hits': [{'_source': {'data': 'test'}}]}
        }

        # Test code
        from nui_lambda_shared_utils import ElasticsearchClient
        client = ElasticsearchClient()
        results = client.search(index='test', body={})

        # Assertions
        assert len(results['hits']['hits']) == 1
        mock_es.return_value.search.assert_called_once()
```

### Testing Error Handling

```python
@pytest.mark.unit
def test_error_retry_logic():
    """Test retry decorator behavior."""
    from nui_lambda_shared_utils import with_retry

    call_count = 0

    @with_retry(max_attempts=3)
    def failing_function():
        nonlocal call_count
        call_count += 1
        raise Exception("Test error")

    with pytest.raises(Exception):
        failing_function()

    assert call_count == 3  # Should retry 3 times
```

### Parametrized Tests

```python
@pytest.mark.parametrize("input_value,expected", [
    ("test", "TEST"),
    ("hello", "HELLO"),
    ("", ""),
])
def test_uppercase_conversion(input_value, expected):
    """Test uppercase conversion with multiple inputs."""
    result = input_value.upper()
    assert result == expected
```

## Coverage Goals

### Current Coverage (as of 0.0.6)

- **utils.py**: 100% coverage
- **base_client.py**: 94.52% coverage
- **config.py**: 100% coverage
- **Overall Target**: 90%+ coverage

### Checking Coverage

```bash
# Generate coverage report
pytest --cov=nui_lambda_shared_utils --cov-report=term-missing

# View detailed HTML report
pytest --cov=nui_lambda_shared_utils --cov-report=html
open htmlcov/index.html  # Mac
xdg-open htmlcov/index.html  # Linux
```

### Coverage Improvements

When adding new code:

1. Write tests before implementation (TDD)
2. Aim for 90%+ coverage on new modules
3. Include edge cases and error paths
4. Test both success and failure scenarios

## Continuous Integration

### GitHub Actions Workflow

The project uses GitHub Actions for automated testing:

```yaml
# .github/workflows/test.yml
- Run tests with coverage
- Upload coverage reports
- Fail if coverage drops below threshold
```

### Local CI Testing

```bash
# Simulate CI environment locally
pytest --cov=nui_lambda_shared_utils --cov-fail-under=90 -v
```

## Troubleshooting Tests

### Common Issues

#### AWS Credentials Not Found

**Error:**

```
NoCredentialsError: Unable to locate credentials
```

**Solution:**

```bash
# Set dummy credentials for testing
export AWS_ACCESS_KEY_ID=test
export AWS_SECRET_ACCESS_KEY=test
export AWS_DEFAULT_REGION=us-east-1
```

#### Import Errors

**Error:**

```
ImportError: No module named 'elasticsearch'
```

**Solution:**

```bash
# Install dev dependencies
pip install -e .[dev]
```

#### Fixture Not Found

**Error:**

```
fixture 'mock_config' not found
```

**Solution:**

- Check `conftest.py` for fixture definitions
- Ensure fixture scope is correct
- Verify fixture name matches usage

### Debugging Tests

```bash
# Run with verbose output
pytest -v

# Show print statements
pytest -s

# Drop into debugger on failure
pytest --pdb

# Show local variables on failure
pytest -l

# Increase verbosity
pytest -vv
```

## Best Practices

### Test Organization

1. **One test file per module** - `test_slack_client.py` for `slack_client.py`
2. **Group related tests** - Use test classes for logical grouping
3. **Clear test names** - `test_send_message_with_valid_token()`
4. **Use fixtures** - Share setup code via fixtures

### Test Quality

1. **Test one thing** - Each test should verify one behavior
2. **Arrange-Act-Assert** - Clear test structure
3. **No test interdependencies** - Tests should run independently
4. **Mock external services** - Don't rely on external APIs
5. **Test edge cases** - Empty inputs, None values, errors

### Maintenance

1. **Update tests with code changes** - Keep tests in sync
2. **Remove obsolete tests** - Clean up when refactoring
3. **Document complex tests** - Explain why, not just what
4. **Keep tests fast** - Use mocking to avoid slow operations

## Resources

- [pytest Documentation](https://docs.pytest.org/)
- [unittest.mock Guide](https://docs.python.org/3/library/unittest.mock.html)
- [moto Documentation](https://docs.getmoto.org/)
- [Coverage.py](https://coverage.readthedocs.io/)

---

*For general contribution guidelines, see [CONTRIBUTING.md](../../CONTRIBUTING.md)*
