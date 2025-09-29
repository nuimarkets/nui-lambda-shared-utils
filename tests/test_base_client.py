"""
Tests for base client functionality and contract compliance.
"""

import pytest
import time
import logging

pytestmark = pytest.mark.unit
from unittest.mock import patch, Mock, MagicMock, call
from abc import ABC, abstractmethod
from typing import Optional, Dict, Any

from nui_lambda_shared_utils.base_client import BaseClient, ServiceHealthMixin, RetryableOperationMixin


class BaseClientContract(ABC):
    """
    Abstract base class defining the contract that all clients must follow.
    This ensures consistent behavior across all client implementations.
    """

    @abstractmethod
    def create_client_instance(self, secret_name: Optional[str] = None, **kwargs):
        """Create a client instance for testing."""
        pass

    @abstractmethod
    def get_expected_secret_key(self) -> str:
        """Return the expected configuration key for this client type."""
        pass

    @abstractmethod
    def get_client_specific_kwargs(self) -> Dict[str, Any]:
        """Return client-specific kwargs for testing."""
        pass

    @abstractmethod
    def get_secret_patch_target(self) -> str:
        """Return the fully qualified secret retrieval function to patch."""
        pass


class TestClientContract:
    """Contract tests that all client implementations must pass."""

    def test_initialization_with_required_secret(self, client_contract):
        """Test that all clients require a secret name for initialization."""
        with patch(client_contract.get_secret_patch_target()) as mock_get_secret:
            mock_get_secret.return_value = {"token": "test-token", "host": "test-host", "port": 3306, "username": "test-user", "password": "test-pass", "database": "test"}

            # Should work with secret name
            client = client_contract.create_client_instance(secret_name="test-secret")
            assert client is not None

    def test_secret_retrieval_consistent(self, client_contract):
        """Test that all clients retrieve secrets consistently."""
        with patch(client_contract.get_secret_patch_target()) as mock_get_secret:
            mock_get_secret.return_value = {"token": "test-token", "host": "test-host", "port": 3306, "username": "test-user", "password": "test-pass", "database": "test"}

            client_contract.create_client_instance(secret_name="custom-secret")

            # All clients should call get_secret with the provided name
            mock_get_secret.assert_called_with("custom-secret")

    def test_configuration_integration(self, client_contract):
        """Test that all clients integrate with configuration system."""
        with patch(client_contract.get_secret_patch_target()) as mock_get_secret:
            with patch("nui_lambda_shared_utils.base_client.get_config") as mock_get_config:
                mock_get_secret.return_value = {"token": "test-token", "host": "test-host", "port": 3306, "username": "test-user", "password": "test-pass", "database": "test"}
                mock_config = Mock()
                mock_get_config.return_value = mock_config

                # Set up config mock for this client type
                setattr(mock_config, client_contract.get_expected_secret_key(), "config-secret")

                # Create client without explicit secret (should use config)
                client_contract.create_client_instance(**client_contract.get_client_specific_kwargs())

                # Should have consulted the config system
                assert mock_get_config.called
                mock_get_secret.assert_called_once_with("config-secret")


# Specific client contract implementations
class SlackClientContract(BaseClientContract):
    """Contract implementation for SlackClient."""

    def create_client_instance(self, secret_name: Optional[str] = None, **kwargs):
        from nui_lambda_shared_utils.slack_client import SlackClient
        return SlackClient(secret_name=secret_name, **kwargs)

    def get_expected_secret_key(self) -> str:
        return "slack_credentials_secret"

    def get_client_specific_kwargs(self) -> Dict[str, Any]:
        return {}

    def get_secret_patch_target(self) -> str:
        return "nui_lambda_shared_utils.base_client.get_secret"


class ElasticsearchClientContract(BaseClientContract):
    """Contract implementation for ElasticsearchClient."""

    def create_client_instance(self, secret_name: Optional[str] = None, **kwargs):
        from nui_lambda_shared_utils.es_client import ElasticsearchClient
        return ElasticsearchClient(secret_name=secret_name, **kwargs)

    def get_expected_secret_key(self) -> str:
        return "es_credentials_secret"

    def get_client_specific_kwargs(self) -> Dict[str, Any]:
        return {"host": "test-es:9200"}

    def get_secret_patch_target(self) -> str:
        return "nui_lambda_shared_utils.base_client.get_secret"


class DatabaseClientContract(BaseClientContract):
    """Contract implementation for DatabaseClient."""

    def create_client_instance(self, secret_name: Optional[str] = None, **kwargs):
        from nui_lambda_shared_utils.db_client import DatabaseClient
        return DatabaseClient(secret_name=secret_name, **kwargs)

    def get_expected_secret_key(self) -> str:
        return "db_credentials_secret"

    def get_client_specific_kwargs(self) -> Dict[str, Any]:
        return {"use_pool": False}

    def get_secret_patch_target(self) -> str:
        return "nui_lambda_shared_utils.db_client.get_database_credentials"


# Pytest fixtures for contract testing
@pytest.fixture(params=[
    SlackClientContract(),
    ElasticsearchClientContract(),
    DatabaseClientContract(),
])
def client_contract(request):
    """Parameterized fixture that runs contract tests against all clients."""
    return request.param


# Test implementation for BaseClient
class TestBaseClient(BaseClient):
    """Concrete implementation of BaseClient for testing."""

    def _get_default_config_prefix(self) -> str:
        return "test"

    def _create_service_client(self) -> Any:
        return Mock()  # Mock service client

    def _get_default_secret_name(self) -> str:
        return "test-credentials"


class TestBaseClientImplementation:
    """Tests for the BaseClient class implementation."""

    @patch('nui_lambda_shared_utils.base_client.get_secret')
    @patch('nui_lambda_shared_utils.base_client.get_config')
    def test_base_client_initialization(self, mock_get_config, mock_get_secret):
        """Test BaseClient initialization with credential resolution."""
        # Mock config
        mock_config = Mock()
        mock_config.test_credentials_secret = "config-secret"
        mock_get_config.return_value = mock_config

        # Mock credentials
        mock_credentials = {"username": "test_user", "password": "test_pass"}
        mock_get_secret.return_value = mock_credentials

        # Create client
        client = TestBaseClient()

        # Verify initialization
        assert client.config == mock_config
        assert client.config_key_prefix == "test"
        assert client.credentials == mock_credentials
        assert isinstance(client._service_client, Mock)

        # Verify secret was retrieved with config value
        mock_get_secret.assert_called_once_with("config-secret")

    @patch('nui_lambda_shared_utils.base_client.get_secret')
    @patch('nui_lambda_shared_utils.base_client.get_config')
    def test_explicit_secret_name_precedence(self, mock_get_config, mock_get_secret):
        """Test that explicit secret name takes precedence over config."""
        mock_config = Mock()
        mock_config.test_credentials_secret = "config-secret"
        mock_get_config.return_value = mock_config

        mock_get_secret.return_value = {"token": "test-token"}

        # Create client with explicit secret name
        TestBaseClient(secret_name="explicit-secret")

        # Should use explicit secret name
        mock_get_secret.assert_called_once_with("explicit-secret")

    @patch('nui_lambda_shared_utils.base_client.get_secret')
    @patch('nui_lambda_shared_utils.base_client.get_config')
    @patch.dict('os.environ', {'TEST_CREDENTIALS_SECRET': 'env-secret'})
    def test_environment_variable_precedence(self, mock_get_config, mock_get_secret):
        """Test that environment variable takes precedence over config."""
        mock_config = Mock()
        mock_config.test_credentials_secret = "config-secret"
        mock_get_config.return_value = mock_config

        mock_get_secret.return_value = {"token": "test-token"}

        # Create client without explicit secret (should use env var)
        TestBaseClient()

        # Should use environment variable
        mock_get_secret.assert_called_once_with("env-secret")

    @patch('nui_lambda_shared_utils.base_client.get_secret')
    @patch('nui_lambda_shared_utils.base_client.get_config')
    def test_credential_resolution_failure(self, mock_get_config, mock_get_secret):
        """Test handling of credential resolution failures."""
        mock_config = Mock()
        mock_config.test_credentials_secret = "bad-secret"
        mock_get_config.return_value = mock_config

        # Mock secret retrieval failure
        mock_get_secret.side_effect = Exception("Secret not found")

        # Should raise exception
        with pytest.raises(Exception, match="Secret not found"):
            TestBaseClient()

    @patch('nui_lambda_shared_utils.base_client.get_secret')
    @patch('nui_lambda_shared_utils.base_client.get_config')
    def test_get_config_value_method(self, mock_get_config, mock_get_secret):
        """Test _get_config_value method with precedence logic."""
        mock_config = Mock()
        mock_config.test_credentials_secret = "test-secret"
        mock_config.test_host = "config-host"

        # Configure the mock to return AttributeError for missing attributes
        def config_side_effect(obj, name, default=None):
            if name == "test_missing_key":
                return default
            return getattr(mock_config, name, default)

        mock_get_config.return_value = mock_config
        mock_get_secret.return_value = {"token": "test-token"}

        # Create client with client config
        client = TestBaseClient(host="client-host", port=8080)

        # Client config should take precedence
        assert client._get_config_value("host") == "client-host"
        assert client._get_config_value("port") == 8080

        # For missing keys, should return default
        # Mock the getattr call in the _get_config_value method
        with patch('nui_lambda_shared_utils.base_client.getattr', side_effect=config_side_effect):
            assert client._get_config_value("missing_key", default="default-value") == "default-value"

    @patch('nui_lambda_shared_utils.base_client.get_secret')
    @patch('nui_lambda_shared_utils.base_client.get_config')
    def test_execute_with_error_handling_success(self, mock_get_config, mock_get_secret, caplog):
        """Test successful operation execution with error handling."""
        mock_get_config.return_value = Mock(test_credentials_secret="test-secret")
        mock_get_secret.return_value = {"token": "test-token"}

        client = TestBaseClient()

        # Mock operation that succeeds
        def successful_operation():
            return "success_result"

        # Set log level to debug to capture debug messages
        with caplog.at_level(logging.DEBUG):
            result = client._execute_with_error_handling(
                "test_operation",
                successful_operation,
                custom_context="test_value"
            )

        assert result == "success_result"

        # Check debug logging
        assert "Executing test_operation" in caplog.text
        assert "Successfully completed test_operation" in caplog.text

    @patch('nui_lambda_shared_utils.base_client.get_secret')
    @patch('nui_lambda_shared_utils.base_client.get_config')
    def test_execute_with_error_handling_failure(self, mock_get_config, mock_get_secret, caplog):
        """Test operation execution with error handling when operation fails."""
        mock_get_config.return_value = Mock(test_credentials_secret="test-secret")
        mock_get_secret.return_value = {"token": "test-token"}

        client = TestBaseClient()

        # Mock operation that fails
        def failing_operation():
            raise ValueError("Operation failed")

        with pytest.raises(ValueError, match="Operation failed"):
            client._execute_with_error_handling(
                "test_operation",
                failing_operation,
                custom_context="test_value"
            )

        # Check error logging
        assert "Failed to execute test_operation: Operation failed" in caplog.text

    @patch('nui_lambda_shared_utils.base_client.get_secret')
    @patch('nui_lambda_shared_utils.base_client.get_config')
    def test_get_client_info(self, mock_get_config, mock_get_secret):
        """Test get_client_info method."""
        mock_get_config.return_value = Mock(test_credentials_secret="test-secret")
        mock_get_secret.return_value = {"username": "test_user"}

        client = TestBaseClient(host="test-host", debug=True)

        info = client.get_client_info()

        expected_info = {
            "client_type": "TestBaseClient",
            "config_prefix": "test",
            "has_credentials": True,
            "client_config": {"host": "test-host", "debug": True}
        }

        assert info == expected_info

    @patch('nui_lambda_shared_utils.base_client.get_secret')
    @patch('nui_lambda_shared_utils.base_client.get_config')
    def test_custom_config_key_prefix(self, mock_get_config, mock_get_secret):
        """Test custom config key prefix override."""
        mock_config = Mock()
        mock_config.custom_credentials_secret = "custom-secret"
        mock_get_config.return_value = mock_config
        mock_get_secret.return_value = {"token": "test-token"}

        # Create client with custom config prefix
        client = TestBaseClient(config_key_prefix="custom")

        assert client.config_key_prefix == "custom"
        mock_get_secret.assert_called_once_with("custom-secret")

    @patch('nui_lambda_shared_utils.base_client.get_secret')
    @patch('nui_lambda_shared_utils.base_client.get_config')
    def test_validation_required_param_error(self, mock_get_config, _mock_get_secret):
        """Test that required parameter validation works."""
        mock_config = Mock()
        # No credentials secret configured
        mock_config.test_credentials_secret = None
        mock_get_config.return_value = mock_config

        # Should raise ValueError for missing secret name
        with pytest.raises(ValueError, match="secret_name is required"):
            TestBaseClient()


class TestServiceHealthMixin:
    """Test ServiceHealthMixin functionality."""

    class TestClientWithHealthMixin(TestBaseClient, ServiceHealthMixin):
        """Test client that includes health mixin."""

        def _perform_health_check(self):
            # Simulate health check that can succeed or fail
            if hasattr(self, '_health_check_should_fail'):
                raise Exception("Health check failed")
            return True

    @patch('nui_lambda_shared_utils.base_client.get_secret')
    @patch('nui_lambda_shared_utils.base_client.get_config')
    def test_health_check_success(self, mock_get_config, mock_get_secret):
        """Test successful health check."""
        mock_get_config.return_value = Mock(test_credentials_secret="test-secret")
        mock_get_secret.return_value = {"token": "test-token"}

        client = self.TestClientWithHealthMixin()

        result = client.health_check()

        assert result["status"] == "healthy"
        assert result["client_type"] == "TestClientWithHealthMixin"
        assert "timestamp" in result

    @patch('nui_lambda_shared_utils.base_client.get_secret')
    @patch('nui_lambda_shared_utils.base_client.get_config')
    def test_health_check_failure(self, mock_get_config, mock_get_secret):
        """Test health check failure handling."""
        mock_get_config.return_value = Mock(test_credentials_secret="test-secret")
        mock_get_secret.return_value = {"token": "test-token"}

        client = self.TestClientWithHealthMixin()
        client._health_check_should_fail = True

        result = client.health_check()

        assert result["status"] == "unhealthy"
        assert result["client_type"] == "TestClientWithHealthMixin"
        assert result["error"] == "Health check failed"
        assert result["error_type"] == "Exception"
        assert "timestamp" in result


class TestRetryableOperationMixin:
    """Test RetryableOperationMixin functionality."""

    class TestClientWithRetryMixin(TestBaseClient, RetryableOperationMixin):
        """Test client that includes retry mixin."""
        pass

    @patch('nui_lambda_shared_utils.base_client.get_secret')
    @patch('nui_lambda_shared_utils.base_client.get_config')
    def test_execute_with_retry_success(self, mock_get_config, mock_get_secret):
        """Test successful retry operation."""
        mock_get_config.return_value = Mock(test_credentials_secret="test-secret")
        mock_get_secret.return_value = {"token": "test-token"}

        client = self.TestClientWithRetryMixin()

        def successful_operation():
            return "success"

        result = client.execute_with_retry(
            successful_operation,
            "test_operation",
            max_attempts=3
        )

        assert result == "success"

    @patch('nui_lambda_shared_utils.base_client.get_secret')
    @patch('nui_lambda_shared_utils.base_client.get_config')
    def test_execute_with_retry_requires_error_handling(self, mock_get_config, mock_get_secret):
        """Test that retry mixin requires _execute_with_error_handling method."""
        mock_get_config.return_value = Mock(test_credentials_secret="test-secret")
        mock_get_secret.return_value = {"token": "test-token"}

        # Create a minimal client without _execute_with_error_handling
        class MinimalClient(RetryableOperationMixin):
            pass

        client = MinimalClient()

        def test_operation():
            return "test"

        with pytest.raises(AttributeError, match="must implement _execute_with_error_handling"):
            client.execute_with_retry(test_operation, "test_op")

    @patch('nui_lambda_shared_utils.base_client.get_secret')
    @patch('nui_lambda_shared_utils.base_client.get_config')
    @patch('nui_lambda_shared_utils.error_handler.with_retry')
    def test_execute_with_retry_configures_retry_decorator(self, mock_with_retry, mock_get_config, mock_get_secret):
        """Test that retry decorator is configured correctly."""
        mock_get_config.return_value = Mock(test_credentials_secret="test-secret")
        mock_get_secret.return_value = {"token": "test-token"}

        # Mock the retry decorator
        def mock_decorator(func):
            return func
        mock_with_retry.return_value = mock_decorator

        client = self.TestClientWithRetryMixin()

        def test_operation():
            return "test"

        client.execute_with_retry(
            test_operation,
            "test_operation",
            max_attempts=5,
            backoff_factor=2.0
        )

        # Verify retry decorator was configured with correct parameters
        mock_with_retry.assert_called_once_with(
            max_attempts=5,
            backoff_factor=2.0
        )


class TestBackwardCompatibility:
    """Tests to ensure refactoring maintains backward compatibility."""

    def test_existing_slack_client_api_unchanged(self):
        """Test that SlackClient public API remains unchanged."""
        from nui_lambda_shared_utils.slack_client import SlackClient
        
        # Verify constructor signature
        import inspect
        sig = inspect.signature(SlackClient.__init__)
        params = list(sig.parameters.keys())
        
        # Should still require secret_name parameter
        assert 'secret_name' in params
        assert 'self' in params

    def test_existing_es_client_api_unchanged(self):
        """Test that ElasticsearchClient public API remains unchanged."""
        from nui_lambda_shared_utils.es_client import ElasticsearchClient
        
        # Verify constructor signature
        import inspect
        sig = inspect.signature(ElasticsearchClient.__init__)
        params = list(sig.parameters.keys())
        
        # Should support optional parameters
        assert 'host' in params
        assert 'secret_name' in params

    def test_existing_db_client_api_unchanged(self):
        """Test that DatabaseClient public API remains unchanged."""
        from nui_lambda_shared_utils.db_client import DatabaseClient
        
        # Verify constructor signature
        import inspect
        sig = inspect.signature(DatabaseClient.__init__)
        params = list(sig.parameters.keys())
        
        # Should support pooling parameters
        assert 'use_pool' in params
        assert 'pool_size' in params


class TestClientInteroperability:
    """Test that different clients work together correctly."""

    @patch("nui_lambda_shared_utils.base_client.get_secret")
    @patch("nui_lambda_shared_utils.db_client.get_database_credentials")
    def test_multiple_clients_same_process(self, mock_db_creds, mock_get_secret):
        """Test that multiple clients can coexist in the same process."""
        # Mock return values - since they all use the same get_secret, return different values based on args
        def mock_secret_side_effect(secret_name):
            if "slack" in secret_name:
                return {"bot_token": "slack-token"}
            elif "es" in secret_name:
                return {"username": "elastic", "password": "pass"}
            else:
                return {"token": "default-token"}

        mock_get_secret.side_effect = mock_secret_side_effect
        mock_db_creds.return_value = {
            "host": "db-host", "port": 3306, "username": "user",
            "password": "pass", "database": "db"
        }

        # Import and create all clients
        from nui_lambda_shared_utils.slack_client import SlackClient
        from nui_lambda_shared_utils.es_client import ElasticsearchClient
        from nui_lambda_shared_utils.db_client import DatabaseClient

        with patch("nui_lambda_shared_utils.slack_client.WebClient"):
            slack = SlackClient(secret_name="slack-secret")

        with patch("nui_lambda_shared_utils.es_client.Elasticsearch"):
            es = ElasticsearchClient(secret_name="es-secret")

        db = DatabaseClient(secret_name="db-secret")

        # All should be created successfully
        assert slack is not None
        assert es is not None
        assert db is not None

    def test_shared_configuration_isolation(self):
        """Test that clients don't interfere with each other's configuration."""
        from nui_lambda_shared_utils.config import configure, get_config
        
        # Configure global settings
        configure(
            es_host="global-es:9200",
            slack_credentials_secret="global-slack-secret"
        )
        
        config = get_config()
        
        # Each client should get appropriate config values
        assert config.es_host == "global-es:9200"
        assert config.slack_credentials_secret == "global-slack-secret"
        
        # Different clients should access different config keys
        assert hasattr(config, 'es_credentials_secret')
        assert hasattr(config, 'db_credentials_secret')
        assert hasattr(config, 'slack_credentials_secret')


class TestClientInheritanceIntegration:
    """Integration tests for client inheritance hierarchy."""

    @patch("nui_lambda_shared_utils.base_client.get_secret")
    @patch("nui_lambda_shared_utils.slack_client.WebClient")
    def test_slack_client_inherits_base_functionality(self, mock_web_client, mock_get_secret):
        """Test that SlackClient properly inherits BaseClient functionality."""
        from nui_lambda_shared_utils.slack_client import SlackClient

        # Mock credentials and Slack client
        mock_get_secret.return_value = {"bot_token": "test-token"}
        mock_slack_instance = Mock()
        mock_web_client.return_value = mock_slack_instance

        # Create SlackClient
        client = SlackClient(secret_name="test-secret")

        # Verify BaseClient inherited functionality
        assert hasattr(client, '_get_config_value')
        assert hasattr(client, '_execute_with_error_handling')
        assert hasattr(client, 'get_client_info')

        # Test inherited method works
        info = client.get_client_info()
        assert info['client_type'] == 'SlackClient'
        assert info['has_credentials'] is True

        # Verify credentials were resolved correctly
        mock_get_secret.assert_called_once_with("test-secret")

    @patch("nui_lambda_shared_utils.base_client.get_secret")
    @patch("nui_lambda_shared_utils.es_client.Elasticsearch")
    def test_elasticsearch_client_inherits_base_functionality(self, mock_es_class, mock_get_secret):
        """Test that ElasticsearchClient properly inherits BaseClient functionality."""
        from nui_lambda_shared_utils.es_client import ElasticsearchClient

        # Mock credentials and ES client
        mock_get_secret.return_value = {"username": "elastic", "password": "test"}
        mock_es_instance = Mock()
        mock_es_class.return_value = mock_es_instance

        # Create ElasticsearchClient
        client = ElasticsearchClient(secret_name="test-secret", host="test:9200")

        # Verify BaseClient inherited functionality
        assert hasattr(client, '_get_config_value')
        assert hasattr(client, '_execute_with_error_handling')
        assert hasattr(client, 'get_client_info')

        # Test inherited method works
        info = client.get_client_info()
        assert info['client_type'] == 'ElasticsearchClient'
        assert info['has_credentials'] is True

        # Verify credentials were resolved correctly
        mock_get_secret.assert_called_once_with("test-secret")

    @patch("nui_lambda_shared_utils.db_client.get_database_credentials")
    def test_database_client_inherits_base_functionality(self, mock_get_creds):
        """Test that DatabaseClient properly inherits BaseClient functionality."""
        from nui_lambda_shared_utils.db_client import DatabaseClient

        # Mock credentials
        mock_get_creds.return_value = {
            "host": "test-host", "port": 3306, "username": "user",
            "password": "pass", "database": "testdb"
        }

        # Create DatabaseClient
        client = DatabaseClient(secret_name="test-secret", use_pool=False)

        # Verify BaseClient inherited functionality
        assert hasattr(client, '_get_config_value')
        assert hasattr(client, '_execute_with_error_handling')
        assert hasattr(client, 'get_client_info')

        # Test inherited method works
        info = client.get_client_info()
        assert info['client_type'] == 'DatabaseClient'
        assert info['has_credentials'] is True

        # Verify credentials were resolved correctly
        mock_get_creds.assert_called_once_with("test-secret")

    def test_client_inheritance_hierarchy_consistency(self):
        """Test that all clients follow consistent inheritance patterns."""
        from nui_lambda_shared_utils.slack_client import SlackClient
        from nui_lambda_shared_utils.es_client import ElasticsearchClient
        from nui_lambda_shared_utils.db_client import DatabaseClient
        from nui_lambda_shared_utils.base_client import BaseClient

        # All clients should inherit from BaseClient
        assert issubclass(SlackClient, BaseClient)
        assert issubclass(ElasticsearchClient, BaseClient)
        assert issubclass(DatabaseClient, BaseClient)

        # All clients should implement required abstract methods
        for client_class in [SlackClient, ElasticsearchClient, DatabaseClient]:
            required_methods = [
                '_get_default_config_prefix',
                '_create_service_client',
                '_get_default_secret_name'
            ]
            for method in required_methods:
                assert hasattr(client_class, method), f"{client_class.__name__} missing {method}"

    @patch("nui_lambda_shared_utils.base_client.get_secret")
    @patch("nui_lambda_shared_utils.slack_client.WebClient")
    def test_inherited_error_handling_integration(self, mock_web_client, mock_get_secret):
        """Test that inherited error handling works in actual client implementations."""
        from nui_lambda_shared_utils.slack_client import SlackClient

        # Mock credentials
        mock_get_secret.return_value = {"bot_token": "test-token"}
        mock_slack_instance = Mock()
        mock_web_client.return_value = mock_slack_instance

        client = SlackClient(secret_name="test-secret")

        # Test that inherited _execute_with_error_handling works
        def test_operation():
            return "operation_result"

        result = client._execute_with_error_handling(
            "test_operation",
            test_operation,
            test_context="integration_test"
        )

        assert result == "operation_result"

    @patch("nui_lambda_shared_utils.base_client.get_secret")
    @patch("nui_lambda_shared_utils.es_client.Elasticsearch")
    @patch("nui_lambda_shared_utils.base_client.get_config")
    def test_inherited_config_resolution_integration(self, mock_get_config, mock_es_class, mock_get_secret):
        """Test that inherited config resolution works in actual client implementations."""
        from nui_lambda_shared_utils.es_client import ElasticsearchClient

        # Mock credentials and config
        mock_get_secret.return_value = {"username": "elastic", "password": "test"}
        mock_es_instance = Mock()
        mock_es_class.return_value = mock_es_instance

        # Mock clean config for this test
        mock_config = Mock()
        mock_config.es_credentials_secret = "test-secret"
        mock_get_config.return_value = mock_config

        # Create client with constructor kwargs
        client = ElasticsearchClient(
            secret_name="test-secret",
            host="test:9200",
            timeout=30
        )

        # Test that inherited _get_config_value works
        # ElasticsearchClient stores host as _host_override, not in client_config
        # So let's test with a parameter that actually gets stored in client_config
        assert client._get_config_value("timeout") == 30  # From client constructor kwargs
        assert hasattr(client, '_host_override')  # Host is stored separately
        assert client._host_override == "test:9200"  # Verify host override works

        # Test with a fresh config mock to ensure missing keys return defaults
        with patch('nui_lambda_shared_utils.base_client.getattr') as mock_getattr:
            mock_getattr.return_value = "default"
            assert client._get_config_value("missing_key", default="default") == "default"

    @patch("nui_lambda_shared_utils.base_client.get_secret")
    @patch("nui_lambda_shared_utils.db_client.get_database_credentials")
    @patch("nui_lambda_shared_utils.slack_client.WebClient")
    @patch("nui_lambda_shared_utils.es_client.Elasticsearch")
    def test_cross_client_independence(self, mock_es_class, mock_web_client, mock_db_creds, mock_get_secret):
        """Test that multiple clients operate independently without interfering."""
        from nui_lambda_shared_utils.slack_client import SlackClient
        from nui_lambda_shared_utils.es_client import ElasticsearchClient
        from nui_lambda_shared_utils.db_client import DatabaseClient

        # Mock all credentials and services - use side effect for shared get_secret mock
        def mock_secret_side_effect(secret_name):
            if "slack" in secret_name:
                return {"bot_token": "slack-token"}
            elif "es" in secret_name:
                return {"username": "elastic", "password": "pass"}
            else:
                return {"token": "default-token"}

        mock_get_secret.side_effect = mock_secret_side_effect
        mock_db_creds.return_value = {"host": "db", "port": 3306, "username": "user", "password": "pass", "database": "test"}

        mock_slack_instance = Mock()
        mock_web_client.return_value = mock_slack_instance
        mock_es_instance = Mock()
        mock_es_class.return_value = mock_es_instance

        # Create multiple clients
        slack_client = SlackClient(secret_name="slack-secret")
        es_client = ElasticsearchClient(secret_name="es-secret", host="es:9200")
        db_client = DatabaseClient(secret_name="db-secret", use_pool=False)

        # Each should have independent configuration
        slack_info = slack_client.get_client_info()
        es_info = es_client.get_client_info()
        db_info = db_client.get_client_info()

        assert slack_info['client_type'] == 'SlackClient'
        assert es_info['client_type'] == 'ElasticsearchClient'
        assert db_info['client_type'] == 'DatabaseClient'

        # Each should have independent config prefixes
        assert slack_client.config_key_prefix == 'slack'
        assert es_client.config_key_prefix == 'es'
        assert db_client.config_key_prefix == 'db'

        # Verify credentials were called for each client independently
        # get_secret should be called multiple times with different secret names
        assert mock_get_secret.call_count >= 2  # At least for slack and es clients
        mock_db_creds.assert_called_once_with("db-secret")