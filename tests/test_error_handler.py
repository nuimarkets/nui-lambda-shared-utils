"""
Tests for error_handler module.
"""

import pytest
import time
from unittest.mock import patch, Mock, call
from datetime import datetime
from nui_lambda_shared_utils.error_handler import (
    RetryableError,
    NonRetryableError,
    ErrorPatternMatcher,
    with_retry,
    categorize_retryable_error,
    ErrorAggregator,
)


class TestErrorPatternMatcher:
    """Tests for ErrorPatternMatcher class."""

    def test_init_default_patterns(self):
        """Test initialization with default patterns."""
        matcher = ErrorPatternMatcher()

        assert len(matcher.patterns) > 0
        assert len(matcher.compiled_patterns) == len(matcher.patterns)
        assert "json_parse" in matcher.patterns
        assert "db_timeout" in matcher.patterns

    def test_init_custom_patterns(self):
        """Test initialization with custom patterns."""
        custom_patterns = {
            "custom_error": {
                "pattern": r"CustomError.*occurred",
                "category": "custom",
                "severity": "warning",
                "description": "Custom error pattern",
            }
        }

        matcher = ErrorPatternMatcher(patterns=custom_patterns)

        assert len(matcher.patterns) == 1
        assert "custom_error" in matcher.patterns

    def test_match_error_json_parse(self):
        """Test matching JSON parse errors."""
        matcher = ErrorPatternMatcher()

        error = "Unable to parse JSON data: Syntax error at position 42"
        result = matcher.match_error(error)

        assert result is not None
        assert result["pattern_key"] == "json_parse"
        assert result["category"] == "data_format"
        assert result["severity"] == "critical"

    def test_match_error_db_timeout(self):
        """Test matching database timeout errors."""
        matcher = ErrorPatternMatcher()

        error = Exception("Maximum execution time of 30 seconds exceeded")
        result = matcher.match_error(error)

        assert result is not None
        assert result["pattern_key"] == "db_timeout"
        assert result["category"] == "database"

    def test_match_error_rate_limit(self):
        """Test matching rate limit errors."""
        matcher = ErrorPatternMatcher()

        error = "Error 429: Too many requests"
        result = matcher.match_error(error)

        assert result is not None
        assert result["pattern_key"] == "rate_limit"
        assert result["category"] == "rate_limit"

    def test_match_error_no_match(self):
        """Test when no pattern matches."""
        matcher = ErrorPatternMatcher()

        error = "Some random error that doesn't match any pattern"
        result = matcher.match_error(error)

        assert result is None

    def test_categorize_error_matched(self):
        """Test categorizing a matched error."""
        matcher = ErrorPatternMatcher()

        error = "Connection refused to database server"
        result = matcher.categorize_error(error)

        assert result["category"] == "network"
        assert result["severity"] == "critical"
        assert result["pattern_matched"] == "connection_refused"
        assert result["is_retryable"] is True

    def test_categorize_error_unmatched(self):
        """Test categorizing an unmatched error."""
        matcher = ErrorPatternMatcher()

        error = "Unknown error occurred"
        result = matcher.categorize_error(error)

        assert result["category"] == "unknown"
        assert result["severity"] == "warning"
        assert result["pattern_matched"] is None
        assert result["is_retryable"] is False

    def test_retryable_categories(self):
        """Test which categories are marked as retryable."""
        matcher = ErrorPatternMatcher()

        retryable_errors = [
            "Connection refused",  # network
            "Query execution was interrupted",  # database
            "search_phase_execution_exception timeout",  # elasticsearch
            "Rate limit exceeded",  # rate_limit
        ]

        for error in retryable_errors:
            result = matcher.categorize_error(error)
            assert result["is_retryable"] is True

        non_retryable_errors = [
            "Permission denied",  # authorization
            "404 Not Found",  # not_found
            "Unable to parse JSON data: Syntax error",  # data_format
        ]

        for error in non_retryable_errors:
            result = matcher.categorize_error(error)
            assert result["is_retryable"] is False


class TestWithRetry:
    """Tests for with_retry decorator."""

    @patch("time.sleep")
    def test_retry_success_on_second_attempt(self, mock_sleep):
        """Test function succeeds on second attempt."""
        call_count = 0

        @with_retry(max_attempts=3, initial_delay=1.0)
        def flaky_function():
            nonlocal call_count
            call_count += 1
            if call_count < 2:
                raise Exception("Temporary error")
            return "success"

        result = flaky_function()

        assert result == "success"
        assert call_count == 2
        assert mock_sleep.call_count == 1

    def test_retry_exhaust_attempts(self):
        """Test function fails after max attempts."""
        call_count = 0

        @with_retry(max_attempts=3, initial_delay=0.1)
        def always_fails():
            nonlocal call_count
            call_count += 1
            raise Exception("Always fails")

        with pytest.raises(Exception) as exc_info:
            always_fails()

        assert "Always fails" in str(exc_info.value)
        assert call_count == 3

    def test_non_retryable_exception(self):
        """Test non-retryable exceptions are raised immediately."""
        call_count = 0

        @with_retry(max_attempts=3, non_retryable_exceptions=(ValueError,))
        def raises_value_error():
            nonlocal call_count
            call_count += 1
            raise ValueError("Non-retryable error")

        with pytest.raises(ValueError) as exc_info:
            raises_value_error()

        assert "Non-retryable error" in str(exc_info.value)
        assert call_count == 1  # Should not retry

    @patch("time.sleep")
    @patch("random.random")
    def test_exponential_backoff_with_jitter(self, mock_random, mock_sleep):
        """Test exponential backoff calculation with jitter."""
        mock_random.return_value = 0.5  # Middle of jitter range

        @with_retry(max_attempts=4, initial_delay=1.0, exponential_base=2.0, jitter=True)
        def always_fails():
            raise Exception("Error")

        with pytest.raises(Exception):
            always_fails()

        # Check sleep delays
        # With random.random() = 0.5, jitter multiplier is 0.5 + 0.5 = 1.0
        expected_delays = [
            1.0 * 1.0,  # 1.0
            2.0 * 1.0,  # 2.0
            4.0 * 1.0,  # 4.0
        ]

        actual_delays = [call[0][0] for call in mock_sleep.call_args_list]

        for expected, actual in zip(expected_delays, actual_delays):
            assert abs(expected - actual) < 0.01

    @patch("time.sleep")
    def test_max_delay_cap(self, mock_sleep):
        """Test that delay is capped at max_delay."""

        @with_retry(max_attempts=5, initial_delay=10.0, max_delay=20.0, exponential_base=2.0, jitter=False)
        def always_fails():
            raise Exception("Error")

        with pytest.raises(Exception):
            always_fails()

        # Delays should be: 10, 20 (capped), 20 (capped), 20 (capped)
        delays = [call[0][0] for call in mock_sleep.call_args_list]
        assert delays[0] == 10.0
        assert all(d == 20.0 for d in delays[1:])

    def test_retry_callback(self):
        """Test on_retry callback is called."""
        retry_calls = []

        def on_retry(func_name, attempt, error, delay):
            retry_calls.append({"func_name": func_name, "attempt": attempt, "error": str(error), "delay": delay})

        @with_retry(max_attempts=3, initial_delay=0.1, on_retry=on_retry)
        def flaky_function():
            raise Exception("Retry me")

        with pytest.raises(Exception):
            flaky_function()

        assert len(retry_calls) == 2  # Called on retry, not on final failure
        assert retry_calls[0]["attempt"] == 1
        assert retry_calls[1]["attempt"] == 2
        assert all("Retry me" in call["error"] for call in retry_calls)

    def test_custom_retryable_exceptions(self):
        """Test custom retryable exceptions."""

        class CustomError(Exception):
            pass

        @with_retry(max_attempts=2, initial_delay=0.1, retryable_exceptions=(CustomError,))
        def raises_custom_error():
            raise CustomError("Custom error")

        with pytest.raises(CustomError):
            raises_custom_error()

        # Should retry for CustomError

        @with_retry(max_attempts=2, initial_delay=0.1, retryable_exceptions=(ValueError,))
        def raises_other_error():
            raise RuntimeError("Not retryable")

        with pytest.raises(RuntimeError):
            raises_other_error()


class TestCategorizeRetryableError:
    """Tests for categorize_retryable_error function."""

    def test_retryable_network_error(self):
        """Test network errors are retryable."""
        error = Exception("Connection refused")
        assert categorize_retryable_error(error) is True

    def test_retryable_db_error(self):
        """Test database errors are retryable."""
        error = Exception("Query execution was interrupted")
        assert categorize_retryable_error(error) is True

    def test_non_retryable_auth_error(self):
        """Test auth errors are not retryable."""
        error = Exception("Permission denied")
        assert categorize_retryable_error(error) is False

    def test_non_retryable_unknown_error(self):
        """Test unknown errors are not retryable."""
        error = Exception("Some random error")
        assert categorize_retryable_error(error) is False


class TestErrorAggregator:
    """Tests for ErrorAggregator class."""

    def test_init(self):
        """Test initialization."""
        aggregator = ErrorAggregator(max_errors=50)

        assert aggregator.max_errors == 50
        assert len(aggregator.errors) == 0

    @patch("nui_lambda_shared_utils.error_handler.datetime")
    def test_add_error_string(self, mock_datetime):
        """Test adding string error."""
        mock_datetime.utcnow.return_value.isoformat.return_value = "2024-01-30T10:00:00"

        aggregator = ErrorAggregator()
        aggregator.add_error("Connection refused to server")

        assert len(aggregator.errors) == 1
        error = aggregator.errors[0]
        assert error["error"] == "Connection refused to server"
        assert error["type"] == "str"
        assert error["timestamp"] == "2024-01-30T10:00:00"
        assert error["category"] == "network"
        assert error["is_retryable"] is True

    def test_add_error_exception(self):
        """Test adding exception error."""
        aggregator = ErrorAggregator()
        exc = ValueError("Invalid input")
        aggregator.add_error(exc)

        assert len(aggregator.errors) == 1
        error = aggregator.errors[0]
        assert error["error"] == "Invalid input"
        assert error["type"] == "ValueError"

    def test_add_error_with_context(self):
        """Test adding error with context."""
        aggregator = ErrorAggregator()
        context = {"user_id": 123, "action": "create_order"}

        aggregator.add_error("Database timeout", context=context)

        error = aggregator.errors[0]
        assert "context" in error
        assert error["context"]["user_id"] == 123
        assert error["context"]["action"] == "create_order"

    def test_max_errors_limit(self):
        """Test that errors are limited to max_errors."""
        aggregator = ErrorAggregator(max_errors=5)

        # Add 10 errors
        for i in range(10):
            aggregator.add_error(f"Error {i}")

        # Should only keep last 5
        assert len(aggregator.errors) == 5
        assert aggregator.errors[0]["error"] == "Error 5"
        assert aggregator.errors[-1]["error"] == "Error 9"

    def test_get_summary_empty(self):
        """Test summary for empty aggregator."""
        aggregator = ErrorAggregator()
        summary = aggregator.get_summary()

        assert summary["total_errors"] == 0
        assert summary["by_category"] == {}
        assert summary["by_severity"] == {}
        assert summary["recent_errors"] == []

    def test_get_summary_with_errors(self):
        """Test summary with various errors."""
        aggregator = ErrorAggregator()

        # Add various errors
        aggregator.add_error("Connection refused")  # network, critical
        aggregator.add_error("Connection refused again")  # network, critical
        aggregator.add_error("Rate limit exceeded")  # rate_limit, warning
        aggregator.add_error("404 Not Found")  # not_found, info
        aggregator.add_error("Permission denied")  # authorization, critical
        aggregator.add_error("Unknown error")  # unknown, warning

        summary = aggregator.get_summary()

        assert summary["total_errors"] == 6

        # Check category counts
        assert summary["by_category"]["network"] == 2
        assert summary["by_category"]["rate_limit"] == 1
        assert summary["by_category"]["not_found"] == 1
        assert summary["by_category"]["authorization"] == 1
        assert summary["by_category"]["unknown"] == 1

        # Check severity counts
        assert summary["by_severity"]["critical"] == 3
        assert summary["by_severity"]["warning"] == 2
        assert summary["by_severity"]["info"] == 1

        # Check recent errors (last 5)
        assert len(summary["recent_errors"]) == 5
        assert summary["recent_errors"][0]["error"] == "Connection refused again"
