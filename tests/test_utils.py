"""
Comprehensive tests for nui_lambda_shared_utils.utils module.
"""

import pytest
import os
import logging
from unittest.mock import Mock, patch, MagicMock
from botocore.exceptions import ClientError, NoCredentialsError

from nui_lambda_shared_utils.utils import (
    resolve_config_value,
    resolve_aws_region,
    create_aws_client,
    handle_client_errors,
    merge_dimensions,
    validate_required_param,
    safe_close_connection,
    format_log_context,
    DEFAULT_AWS_REGION
)


class TestResolveConfigValue:
    """Test resolve_config_value function precedence logic."""

    def test_param_value_takes_precedence(self):
        """Test that explicit parameter value takes highest precedence."""
        with patch.dict(os.environ, {"TEST_ENV": "env_value"}):
            result = resolve_config_value("param_value", "TEST_ENV", "config_default")
            assert result == "param_value"

    def test_env_var_takes_precedence_over_config(self):
        """Test that environment variable takes precedence over config default."""
        with patch.dict(os.environ, {"TEST_ENV": "env_value"}):
            result = resolve_config_value(None, "TEST_ENV", "config_default")
            assert result == "env_value"

    def test_config_default_fallback(self):
        """Test that config default is used when param and env are None."""
        with patch.dict(os.environ, {}, clear=True):
            result = resolve_config_value(None, "NON_EXISTENT_ENV", "config_default")
            assert result == "config_default"

    def test_multiple_env_vars_precedence(self):
        """Test that first found env var is used with multiple env var names."""
        with patch.dict(os.environ, {"ENV_VAR_2": "second_env", "ENV_VAR_3": "third_env"}):
            result = resolve_config_value(None, ["ENV_VAR_1", "ENV_VAR_2", "ENV_VAR_3"], "default")
            assert result == "second_env"

    def test_single_env_var_as_string(self):
        """Test that single env var can be passed as string instead of list."""
        with patch.dict(os.environ, {"SINGLE_ENV": "single_value"}):
            result = resolve_config_value(None, "SINGLE_ENV", "default")
            assert result == "single_value"

    def test_param_value_zero_is_returned(self):
        """Test that parameter value of 0 is considered valid."""
        result = resolve_config_value(0, "TEST_ENV", "default")
        assert result == 0

    def test_param_value_false_is_returned(self):
        """Test that parameter value of False is considered valid."""
        result = resolve_config_value(False, "TEST_ENV", "default")
        assert result is False

    def test_param_value_empty_string_is_returned(self):
        """Test that parameter value of empty string is considered valid."""
        result = resolve_config_value("", "TEST_ENV", "default")
        assert result == ""


class TestResolveAwsRegion:
    """Test resolve_aws_region function."""

    def test_explicit_region_takes_precedence(self):
        """Test that explicit region parameter takes highest precedence."""
        with patch.dict(os.environ, {"AWS_REGION": "us-west-2"}):
            result = resolve_aws_region("eu-west-1")
            assert result == "eu-west-1"

    @patch('nui_lambda_shared_utils.utils.get_config')
    def test_env_var_precedence(self, mock_get_config):
        """Test that AWS_REGION environment variable is used."""
        mock_config = Mock()
        mock_config.aws_region = "config-region"
        mock_get_config.return_value = mock_config

        with patch.dict(os.environ, {"AWS_REGION": "env-region"}):
            result = resolve_aws_region()
            assert result == "env-region"

    @patch('nui_lambda_shared_utils.utils.get_config')
    def test_aws_default_region_env_var(self, mock_get_config):
        """Test that AWS_DEFAULT_REGION environment variable is used."""
        mock_config = Mock()
        mock_config.aws_region = "config-region"
        mock_get_config.return_value = mock_config

        with patch.dict(os.environ, {"AWS_DEFAULT_REGION": "default-env-region"}, clear=True):
            result = resolve_aws_region()
            assert result == "default-env-region"

    @patch('nui_lambda_shared_utils.utils.get_config')
    def test_config_region_fallback(self, mock_get_config):
        """Test that config aws_region is used when env vars not set."""
        mock_config = Mock()
        mock_config.aws_region = "config-region"
        mock_get_config.return_value = mock_config

        with patch.dict(os.environ, {}, clear=True):
            result = resolve_aws_region()
            assert result == "config-region"

    @patch('nui_lambda_shared_utils.utils.get_config')
    @patch('boto3.session.Session')
    def test_boto3_session_fallback(self, mock_session_class, mock_get_config):
        """Test that boto3 session region is used as fallback."""
        mock_config = Mock()
        mock_config.aws_region = None
        mock_get_config.return_value = mock_config

        mock_session = Mock()
        mock_session.region_name = "session-region"
        mock_session_class.return_value = mock_session

        with patch.dict(os.environ, {}, clear=True):
            result = resolve_aws_region()
            assert result == "session-region"

    @patch('nui_lambda_shared_utils.utils.get_config')
    @patch('boto3.session.Session')
    def test_default_region_final_fallback(self, mock_session_class, mock_get_config):
        """Test that DEFAULT_AWS_REGION is used as final fallback."""
        mock_config = Mock()
        mock_config.aws_region = None
        mock_get_config.return_value = mock_config

        mock_session = Mock()
        mock_session.region_name = None
        mock_session_class.return_value = mock_session

        with patch.dict(os.environ, {}, clear=True):
            result = resolve_aws_region()
            assert result == DEFAULT_AWS_REGION

    @patch('nui_lambda_shared_utils.utils.get_config')
    @patch('boto3.session.Session')
    def test_boto3_session_exception_handling(self, mock_session_class, mock_get_config):
        """Test that boto3 session exceptions are handled gracefully."""
        mock_config = Mock()
        mock_config.aws_region = None
        mock_get_config.return_value = mock_config

        mock_session_class.side_effect = Exception("Session error")

        with patch.dict(os.environ, {}, clear=True):
            result = resolve_aws_region()
            assert result == DEFAULT_AWS_REGION


class TestCreateAwsClient:
    """Test create_aws_client function."""

    @patch('nui_lambda_shared_utils.utils.resolve_aws_region')
    @patch('boto3.session.Session')
    def test_successful_client_creation(self, mock_session_class, mock_resolve_region):
        """Test successful AWS client creation."""
        mock_resolve_region.return_value = "us-east-1"
        mock_session = Mock()
        mock_client = Mock()
        mock_session.client.return_value = mock_client
        mock_session_class.return_value = mock_session

        result = create_aws_client("secretsmanager", "us-west-2")

        assert result == mock_client
        mock_resolve_region.assert_called_once_with("us-west-2")
        mock_session.client.assert_called_once_with(
            service_name="secretsmanager",
            region_name="us-east-1"
        )

    @patch('nui_lambda_shared_utils.utils.resolve_aws_region')
    @patch('boto3.session.Session')
    def test_no_credentials_error(self, mock_session_class, mock_resolve_region):
        """Test handling of NoCredentialsError."""
        mock_resolve_region.return_value = "us-east-1"
        mock_session = Mock()
        mock_session.client.side_effect = NoCredentialsError()
        mock_session_class.return_value = mock_session

        with pytest.raises(NoCredentialsError):
            create_aws_client("secretsmanager")

    @patch('nui_lambda_shared_utils.utils.resolve_aws_region')
    @patch('boto3.session.Session')
    def test_client_error(self, mock_session_class, mock_resolve_region):
        """Test handling of ClientError."""
        mock_resolve_region.return_value = "us-east-1"
        mock_session = Mock()
        mock_session.client.side_effect = ClientError(
            {"Error": {"Code": "AccessDenied", "Message": "Access denied"}},
            "CreateClient"
        )
        mock_session_class.return_value = mock_session

        with pytest.raises(ClientError):
            create_aws_client("secretsmanager")

    @patch('nui_lambda_shared_utils.utils.resolve_aws_region')
    @patch('boto3.session.Session')
    def test_unexpected_error(self, mock_session_class, mock_resolve_region):
        """Test handling of unexpected errors."""
        mock_resolve_region.return_value = "us-east-1"
        mock_session = Mock()
        mock_session.client.side_effect = ValueError("Unexpected error")
        mock_session_class.return_value = mock_session

        with pytest.raises(ValueError):
            create_aws_client("secretsmanager")


class TestHandleClientErrors:
    """Test handle_client_errors decorator."""

    def test_successful_execution(self):
        """Test that decorator doesn't interfere with successful execution."""
        @handle_client_errors()
        def test_func():
            return "success"

        result = test_func()
        assert result == "success"

    def test_error_with_default_return(self, caplog):
        """Test that error returns default value and logs error."""
        @handle_client_errors(default_return="default_value")
        def test_func():
            raise ValueError("Test error")

        with caplog.at_level(logging.ERROR):
            result = test_func()

        assert result == "default_value"
        assert "test_func failed: Test error" in caplog.text
        assert "ValueError" in caplog.text

    def test_error_with_reraise(self):
        """Test that error is reraised when reraise=True."""
        @handle_client_errors(reraise=True)
        def test_func():
            raise ValueError("Test error")

        with pytest.raises(ValueError, match="Test error"):
            test_func()

    def test_error_with_log_context(self, caplog):
        """Test that additional log context is included."""
        @handle_client_errors(
            default_return=None,
            log_context={"service": "test", "operation": "query"}
        )
        def test_func():
            raise ConnectionError("Connection failed")

        with caplog.at_level(logging.ERROR):
            test_func()

        # Check that log context is present
        log_record = caplog.records[0]
        assert log_record.service == "test"
        assert log_record.operation == "query"
        assert log_record.function == "test_func"
        assert log_record.error_type == "ConnectionError"

    def test_function_metadata_preserved(self):
        """Test that original function metadata is preserved."""
        @handle_client_errors()
        def test_func_with_metadata():
            """Test function docstring."""
            pass

        assert test_func_with_metadata.__name__ == "test_func_with_metadata"
        assert test_func_with_metadata.__doc__ == "Test function docstring."

    def test_function_arguments_passed_through(self):
        """Test that function arguments are passed through correctly."""
        @handle_client_errors()
        def test_func(arg1, arg2, kwarg1=None):
            return f"{arg1}-{arg2}-{kwarg1}"

        result = test_func("a", "b", kwarg1="c")
        assert result == "a-b-c"


class TestMergeDimensions:
    """Test merge_dimensions function."""

    def test_base_dimensions_only(self):
        """Test with only base dimensions."""
        base = {"Service": "auth", "Environment": "prod"}
        result = merge_dimensions(base)

        expected = [
            {"Name": "Service", "Value": "auth"},
            {"Name": "Environment", "Value": "prod"}
        ]
        assert len(result) == 2
        assert all(dim in result for dim in expected)

    def test_base_and_additional_dimensions(self):
        """Test with both base and additional dimensions."""
        base = {"Service": "auth"}
        additional = {"Version": "1.2.3", "Region": "us-east-1"}
        result = merge_dimensions(base, additional)

        expected = [
            {"Name": "Service", "Value": "auth"},
            {"Name": "Version", "Value": "1.2.3"},
            {"Name": "Region", "Value": "us-east-1"}
        ]
        assert len(result) == 3
        assert all(dim in result for dim in expected)

    def test_additional_dimensions_override_base(self):
        """Test that additional dimensions override base dimensions."""
        base = {"Service": "auth", "Environment": "dev"}
        additional = {"Environment": "prod", "Version": "1.0.0"}
        result = merge_dimensions(base, additional)

        # Should have 3 dimensions with Environment=prod (overridden)
        assert len(result) == 3
        env_dimension = next(d for d in result if d["Name"] == "Environment")
        assert env_dimension["Value"] == "prod"

    def test_numeric_values_converted_to_strings(self):
        """Test that numeric values are converted to strings."""
        base = {"Port": 8080, "Count": 42}
        result = merge_dimensions(base)

        expected = [
            {"Name": "Port", "Value": "8080"},
            {"Name": "Count", "Value": "42"}
        ]
        assert len(result) == 2
        assert all(dim in result for dim in expected)

    def test_none_additional_dimensions(self):
        """Test with None additional dimensions."""
        base = {"Service": "auth"}
        result = merge_dimensions(base, None)

        expected = [{"Name": "Service", "Value": "auth"}]
        assert result == expected

    def test_empty_dimensions(self):
        """Test with empty base dimensions."""
        result = merge_dimensions({})
        assert result == []

    def test_empty_additional_dimensions(self):
        """Test with empty additional dimensions."""
        base = {"Service": "auth"}
        result = merge_dimensions(base, {})

        expected = [{"Name": "Service", "Value": "auth"}]
        assert result == expected


class TestValidateRequiredParam:
    """Test validate_required_param function."""

    def test_valid_string_param(self):
        """Test with valid string parameter."""
        result = validate_required_param("valid_value", "test_param")
        assert result == "valid_value"

    def test_valid_non_string_param(self):
        """Test with valid non-string parameter."""
        result = validate_required_param(42, "test_param")
        assert result == 42

        result = validate_required_param([], "test_param")
        assert result == []

    def test_none_param_raises_error(self):
        """Test that None parameter raises ValueError."""
        with pytest.raises(ValueError, match="test_param is required"):
            validate_required_param(None, "test_param")

    def test_empty_string_raises_error(self):
        """Test that empty string raises ValueError."""
        with pytest.raises(ValueError, match="test_param cannot be empty"):
            validate_required_param("", "test_param")

    def test_whitespace_only_string_raises_error(self):
        """Test that whitespace-only string raises ValueError."""
        with pytest.raises(ValueError, match="test_param cannot be empty"):
            validate_required_param("   ", "test_param")

    def test_zero_is_valid(self):
        """Test that zero is considered valid."""
        result = validate_required_param(0, "test_param")
        assert result == 0

    def test_false_is_valid(self):
        """Test that False is considered valid."""
        result = validate_required_param(False, "test_param")
        assert result is False


class TestSafeCloseConnection:
    """Test safe_close_connection function."""

    def test_successful_close(self, caplog):
        """Test successful connection close."""
        mock_connection = Mock()
        mock_connection._closed = False
        mock_connection.open = True

        with caplog.at_level(logging.DEBUG):
            safe_close_connection(mock_connection)

        mock_connection.close.assert_called_once()
        assert "Database connection closed successfully" in caplog.text

    def test_already_closed_connection_pymysql(self):
        """Test connection that's already closed (PyMySQL style)."""
        mock_connection = Mock()
        mock_connection._closed = True

        safe_close_connection(mock_connection)

        # Should not attempt to close
        mock_connection.close.assert_not_called()

    def test_already_closed_connection_open_attr(self):
        """Test connection that's already closed (open attribute)."""
        mock_connection = Mock()
        mock_connection.open = False

        safe_close_connection(mock_connection)

        # Should not attempt to close
        mock_connection.close.assert_not_called()

    def test_close_exception_handled(self, caplog):
        """Test that close exceptions are handled gracefully."""
        mock_connection = Mock()
        mock_connection._closed = False
        mock_connection.open = True
        mock_connection.close.side_effect = Exception("Close error")

        with caplog.at_level(logging.DEBUG):
            safe_close_connection(mock_connection)

        assert "Error closing connection (non-fatal): Close error" in caplog.text

    def test_none_connection(self):
        """Test with None connection."""
        # Should not raise any exception
        safe_close_connection(None)

    def test_connection_without_close_method(self):
        """Test with object that doesn't have close method."""
        not_a_connection = "not a connection"
        # Should not raise any exception
        safe_close_connection(not_a_connection)


class TestFormatLogContext:
    """Test format_log_context function."""

    @patch('time.time')
    def test_basic_log_context(self, mock_time):
        """Test basic log context formatting."""
        mock_time.return_value = 1234567890.0

        result = format_log_context("database_query")

        expected = {
            "operation": "database_query",
            "timestamp": 1234567890.0
        }
        assert result == expected

    @patch('time.time')
    def test_log_context_with_additional_data(self, mock_time):
        """Test log context with additional context data."""
        mock_time.return_value = 1234567890.0

        result = format_log_context(
            "database_query",
            table="users",
            query_type="SELECT",
            duration_ms=150
        )

        expected = {
            "operation": "database_query",
            "timestamp": 1234567890.0,
            "table": "users",
            "query_type": "SELECT",
            "duration_ms": 150
        }
        assert result == expected

    @patch('time.time')
    def test_context_data_overwrites_defaults(self, mock_time):
        """Test that context data can overwrite default keys."""
        mock_time.return_value = 1234567890.0

        result = format_log_context(
            "test_operation",
            timestamp=9999999999.0,
            custom_field="custom_value"
        )

        # Additional context should supplement and override timestamp
        expected = {
            "operation": "test_operation",
            "timestamp": 9999999999.0,
            "custom_field": "custom_value"
        }
        assert result == expected

    @patch('time.time')
    def test_empty_additional_context(self, mock_time):
        """Test with no additional context data."""
        mock_time.return_value = 1234567890.0

        result = format_log_context("simple_operation")

        expected = {
            "operation": "simple_operation",
            "timestamp": 1234567890.0
        }
        assert result == expected