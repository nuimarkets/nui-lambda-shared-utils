"""
Tests for slack_client module.
"""

import pytest

pytestmark = pytest.mark.unit

from unittest.mock import patch, Mock
from slack_sdk.errors import SlackApiError
from nui_lambda_shared_utils.slack_client import SlackClient, DEFAULT_ACCOUNT_NAMES
import os


class TestSlackClient:
    """Tests for SlackClient class."""

    @patch("nui_lambda_shared_utils.base_client.get_secret")
    @patch("nui_lambda_shared_utils.slack_client.WebClient")
    def test_init_required_secret(self, mock_webclient, mock_get_secret):
        """Test initialization requires secret name parameter."""
        mock_get_secret.return_value = {"bot_token": "xoxb-test-token"}

        client = SlackClient(secret_name="test-secret")

        mock_get_secret.assert_called_once_with("test-secret")
        mock_webclient.assert_called_once_with(token="xoxb-test-token")

    @patch("nui_lambda_shared_utils.base_client.get_secret")
    @patch("nui_lambda_shared_utils.slack_client.WebClient")
    def test_init_custom_secret(self, mock_webclient, mock_get_secret):
        """Test initialization with custom secret name."""
        mock_get_secret.return_value = {"bot_token": "xoxb-custom-token"}

        client = SlackClient(secret_name="custom-slack-secret")

        mock_get_secret.assert_called_once_with("custom-slack-secret")
        mock_webclient.assert_called_once_with(token="xoxb-custom-token")

    @patch("nui_lambda_shared_utils.base_client.get_secret")
    @patch("nui_lambda_shared_utils.slack_client.WebClient")
    @patch.dict("os.environ", {}, clear=True)
    def test_init_with_default_secret_name(self, mock_webclient, mock_get_secret):
        """Test initialization with default secret name."""
        mock_get_secret.return_value = {"bot_token": "xoxb-default-token"}
        
        with patch("nui_lambda_shared_utils.base_client.resolve_config_value") as mock_resolve:
            mock_resolve.return_value = "slack-credentials"
            
            client = SlackClient()
        
        mock_get_secret.assert_called_once_with("slack-credentials")
        mock_webclient.assert_called_once_with(token="xoxb-default-token")


class TestSendMessage:
    """Tests for send_message method."""

    @patch("nui_lambda_shared_utils.base_client.get_secret")
    @patch("nui_lambda_shared_utils.slack_client.WebClient")
    def test_send_message_success(self, mock_webclient, mock_get_secret):
        """Test successful message sending."""
        mock_get_secret.return_value = {"bot_token": "xoxb-test-token"}
        mock_client = Mock()
        mock_webclient.return_value = mock_client
        mock_client.chat_postMessage.return_value = {"ok": True, "ts": "1234567890.123456"}

        slack = SlackClient(secret_name="test-secret")
        result = slack.send_message("C123", "Test message", include_lambda_header=False)

        assert result is True
        mock_client.chat_postMessage.assert_called_once_with(channel="C123", text="Test message", blocks=None)

    @patch("nui_lambda_shared_utils.base_client.get_secret")
    @patch("nui_lambda_shared_utils.slack_client.WebClient")
    def test_send_message_with_blocks(self, mock_webclient, mock_get_secret):
        """Test sending message with blocks."""
        mock_get_secret.return_value = {"bot_token": "xoxb-test-token"}
        mock_client = Mock()
        mock_webclient.return_value = mock_client
        mock_client.chat_postMessage.return_value = {"ok": True, "ts": "1234567890.123456"}

        blocks = [{"type": "section", "text": {"type": "mrkdwn", "text": "Test block"}}]

        slack = SlackClient(secret_name="test-secret")
        result = slack.send_message("C123", "Fallback text", blocks=blocks, include_lambda_header=False)

        assert result is True
        mock_client.chat_postMessage.assert_called_once_with(channel="C123", text="Fallback text", blocks=blocks)

    @patch("nui_lambda_shared_utils.base_client.get_secret")
    @patch("nui_lambda_shared_utils.slack_client.WebClient")
    def test_send_message_api_error(self, mock_webclient, mock_get_secret):
        """Test handling of Slack API error."""
        mock_get_secret.return_value = {"bot_token": "xoxb-test-token"}
        mock_client = Mock()
        mock_webclient.return_value = mock_client
        mock_client.chat_postMessage.side_effect = SlackApiError(
            message="channel_not_found", response={"error": "channel_not_found"}
        )

        slack = SlackClient(secret_name="test-secret")
        result = slack.send_message("C123", "Test message")

        assert result is False

    @patch("nui_lambda_shared_utils.base_client.get_secret")
    @patch("nui_lambda_shared_utils.slack_client.WebClient")
    def test_send_message_not_ok(self, mock_webclient, mock_get_secret):
        """Test handling of not ok response."""
        mock_get_secret.return_value = {"bot_token": "xoxb-test-token"}
        mock_client = Mock()
        mock_webclient.return_value = mock_client
        mock_client.chat_postMessage.return_value = {"ok": False, "error": "invalid_auth"}

        slack = SlackClient(secret_name="test-secret")
        result = slack.send_message("C123", "Test message")

        assert result is False

    @patch("nui_lambda_shared_utils.base_client.get_secret")
    @patch("nui_lambda_shared_utils.slack_client.WebClient")
    def test_send_message_unexpected_error(self, mock_webclient, mock_get_secret):
        """Test handling of unexpected errors."""
        mock_get_secret.return_value = {"bot_token": "xoxb-test-token"}
        mock_client = Mock()
        mock_webclient.return_value = mock_client
        mock_client.chat_postMessage.side_effect = Exception("Network error")

        slack = SlackClient(secret_name="test-secret")
        result = slack.send_message("C123", "Test message")

        assert result is False


class TestSendFile:
    """Tests for send_file method."""

    @patch("nui_lambda_shared_utils.base_client.get_secret")
    @patch("nui_lambda_shared_utils.slack_client.WebClient")
    def test_send_file_success(self, mock_webclient, mock_get_secret):
        """Test successful file upload."""
        mock_get_secret.return_value = {"bot_token": "xoxb-test-token"}
        mock_client = Mock()
        mock_webclient.return_value = mock_client
        mock_client.files_upload_v2.return_value = {"ok": True, "file": {"id": "F123"}}

        slack = SlackClient(secret_name="test-secret")
        result = slack.send_file("C123", "File content", "test.txt", "Test File")

        assert result is True
        mock_client.files_upload_v2.assert_called_once_with(
            channel="C123", content="File content", filename="test.txt", title="Test File"
        )

    @patch("nui_lambda_shared_utils.base_client.get_secret")
    @patch("nui_lambda_shared_utils.slack_client.WebClient")
    def test_send_file_default_title(self, mock_webclient, mock_get_secret):
        """Test file upload with default title."""
        mock_get_secret.return_value = {"bot_token": "xoxb-test-token"}
        mock_client = Mock()
        mock_webclient.return_value = mock_client
        mock_client.files_upload_v2.return_value = {"ok": True, "file": {"id": "F123"}}

        slack = SlackClient(secret_name="test-secret")
        result = slack.send_file("C123", "File content", "report.csv")

        assert result is True
        mock_client.files_upload_v2.assert_called_once_with(
            channel="C123", content="File content", filename="report.csv", title="report.csv"
        )

    @patch("nui_lambda_shared_utils.base_client.get_secret")
    @patch("nui_lambda_shared_utils.slack_client.WebClient")
    def test_send_file_api_error(self, mock_webclient, mock_get_secret):
        """Test handling of file upload API error."""
        mock_get_secret.return_value = {"bot_token": "xoxb-test-token"}
        mock_client = Mock()
        mock_webclient.return_value = mock_client
        mock_client.files_upload_v2.side_effect = SlackApiError(
            message="file_upload_error", response={"error": "file_upload_error"}
        )

        slack = SlackClient(secret_name="test-secret")
        result = slack.send_file("C123", "Content", "file.txt")

        assert result is False


class TestSendThreadReply:
    """Tests for send_thread_reply method."""

    @patch("nui_lambda_shared_utils.base_client.get_secret")
    @patch("nui_lambda_shared_utils.slack_client.WebClient")
    def test_send_thread_reply_success(self, mock_webclient, mock_get_secret):
        """Test successful thread reply."""
        mock_get_secret.return_value = {"bot_token": "xoxb-test-token"}
        mock_client = Mock()
        mock_webclient.return_value = mock_client
        mock_client.chat_postMessage.return_value = {"ok": True, "ts": "1234567890.123457"}

        slack = SlackClient(secret_name="test-secret")
        result = slack.send_thread_reply("C123", "1234567890.123456", "Reply text")

        assert result is True
        mock_client.chat_postMessage.assert_called_once_with(
            channel="C123", thread_ts="1234567890.123456", text="Reply text", blocks=None
        )

    @patch("nui_lambda_shared_utils.base_client.get_secret")
    @patch("nui_lambda_shared_utils.slack_client.WebClient")
    def test_send_thread_reply_with_blocks(self, mock_webclient, mock_get_secret):
        """Test thread reply with blocks."""
        mock_get_secret.return_value = {"bot_token": "xoxb-test-token"}
        mock_client = Mock()
        mock_webclient.return_value = mock_client
        mock_client.chat_postMessage.return_value = {"ok": True, "ts": "1234567890.123457"}

        blocks = [{"type": "section", "text": {"type": "mrkdwn", "text": "Reply"}}]

        slack = SlackClient(secret_name="test-secret")
        result = slack.send_thread_reply("C123", "1234567890.123456", "Reply", blocks)

        assert result is True
        mock_client.chat_postMessage.assert_called_once_with(
            channel="C123", thread_ts="1234567890.123456", text="Reply", blocks=blocks
        )


class TestUpdateMessage:
    """Tests for update_message method."""

    @patch("nui_lambda_shared_utils.base_client.get_secret")
    @patch("nui_lambda_shared_utils.slack_client.WebClient")
    def test_update_message_success(self, mock_webclient, mock_get_secret):
        """Test successful message update."""
        mock_get_secret.return_value = {"bot_token": "xoxb-test-token"}
        mock_client = Mock()
        mock_webclient.return_value = mock_client
        mock_client.chat_update.return_value = {"ok": True, "ts": "1234567890.123456"}

        slack = SlackClient(secret_name="test-secret")
        result = slack.update_message("C123", "1234567890.123456", "Updated text")

        assert result is True
        mock_client.chat_update.assert_called_once_with(
            channel="C123", ts="1234567890.123456", text="Updated text", blocks=None
        )

    @patch("nui_lambda_shared_utils.base_client.get_secret")
    @patch("nui_lambda_shared_utils.slack_client.WebClient")
    def test_update_message_api_error(self, mock_webclient, mock_get_secret):
        """Test handling of update API error."""
        mock_get_secret.return_value = {"bot_token": "xoxb-test-token"}
        mock_client = Mock()
        mock_webclient.return_value = mock_client
        mock_client.chat_update.side_effect = SlackApiError(
            message="message_not_found", response={"error": "message_not_found"}
        )

        slack = SlackClient(secret_name="test-secret")
        result = slack.update_message("C123", "1234567890.123456", "Updated")

        assert result is False


class TestAddReaction:
    """Tests for add_reaction method."""

    @patch("nui_lambda_shared_utils.base_client.get_secret")
    @patch("nui_lambda_shared_utils.slack_client.WebClient")
    def test_add_reaction_success(self, mock_webclient, mock_get_secret):
        """Test successful reaction addition."""
        mock_get_secret.return_value = {"bot_token": "xoxb-test-token"}
        mock_client = Mock()
        mock_webclient.return_value = mock_client
        mock_client.reactions_add.return_value = {"ok": True}

        slack = SlackClient(secret_name="test-secret")
        result = slack.add_reaction("C123", "1234567890.123456", "thumbsup")

        assert result is True
        mock_client.reactions_add.assert_called_once_with(
            channel="C123", timestamp="1234567890.123456", name="thumbsup"
        )

    @patch("nui_lambda_shared_utils.base_client.get_secret")
    @patch("nui_lambda_shared_utils.slack_client.WebClient")
    def test_add_reaction_already_exists(self, mock_webclient, mock_get_secret):
        """Test handling when reaction already exists."""
        mock_get_secret.return_value = {"bot_token": "xoxb-test-token"}
        mock_client = Mock()
        mock_webclient.return_value = mock_client
        mock_client.reactions_add.side_effect = SlackApiError(
            message="already_reacted", response={"error": "already_reacted"}
        )

        slack = SlackClient(secret_name="test-secret")
        result = slack.add_reaction("C123", "1234567890.123456", "thumbsup")

        assert result is True  # Should return True for already_reacted

    @patch("nui_lambda_shared_utils.base_client.get_secret")
    @patch("nui_lambda_shared_utils.slack_client.WebClient")
    def test_add_reaction_api_error(self, mock_webclient, mock_get_secret):
        """Test handling of reaction API error."""
        mock_get_secret.return_value = {"bot_token": "xoxb-test-token"}
        mock_client = Mock()
        mock_webclient.return_value = mock_client
        mock_client.reactions_add.side_effect = SlackApiError(
            message="invalid_name", response={"error": "invalid_name"}
        )

        slack = SlackClient(secret_name="test-secret")
        result = slack.add_reaction("C123", "1234567890.123456", "invalid")

        assert result is False


class TestLambdaContextHeader:
    """Tests for Lambda context header functionality."""

    @staticmethod
    def assert_header_format(header_text: str, expected_parts: dict):
        """
        Helper to assert header format with nice error messages.

        Args:
            header_text: Full header text from Slack block
            expected_parts: Dict of expected values to check

        Shows the full header on assertion failure for easy debugging.
        """
        failure_msg = f"\n\nFull header text:\n{header_text}\n\nExpected to contain: {expected_parts}\n"

        for key, value in expected_parts.items():
            assert value in header_text, f"{failure_msg}Missing {key}: {value}"

    @patch("nui_lambda_shared_utils.slack_client.create_aws_client")
    @patch("nui_lambda_shared_utils.base_client.get_secret")
    @patch("nui_lambda_shared_utils.slack_client.WebClient")
    @patch.dict(
        os.environ,
        {
            "AWS_LAMBDA_FUNCTION_NAME": "test-function",
            "AWS_LAMBDA_FUNCTION_VERSION": "$LATEST",
            "AWS_LAMBDA_LOG_GROUP_NAME": "/aws/lambda/test-function",
            "AWS_LAMBDA_LOG_STREAM_NAME": "2023/11/15/[$LATEST]abc123",
            "AWS_REGION": "eu-west-1",
            "STAGE": "prod",
            "AWS_EXECUTION_ENV": "AWS_Lambda_python3.9",
        },
    )
    def test_lambda_header_connect_production(self, mock_webclient, mock_get_secret, mock_boto3):
        """Test Lambda header generation for Production."""
        # Setup mocks
        mock_get_secret.return_value = {"bot_token": "xoxb-test-token"}
        mock_client = Mock()
        mock_webclient.return_value = mock_client
        mock_client.chat_postMessage.return_value = {"ok": True, "ts": "123"}

        # Mock STS for account info
        mock_sts = Mock()
        mock_boto3.return_value = mock_sts
        mock_sts.get_caller_identity.return_value = {
            "Account": "123456789012",  # Production
            "Arn": "arn:aws:sts::123456789012:assumed-role/test-role/test-function",
        }

        # Mock Lambda client for deployment time
        mock_lambda = Mock()
        mock_boto3.side_effect = lambda service: mock_sts if service == "sts" else mock_lambda
        mock_lambda.get_function.return_value = {"Configuration": {"LastModified": "2023-11-15T10:30:45.123+0000"}}

        # Mock config file check
        with patch("os.path.exists") as mock_exists:
            mock_exists.return_value = True  # .lambda-deploy.yml exists

            slack = SlackClient(secret_name="test-secret")
            result = slack.send_message("C123", "Test message")

            # Verify the header was included
            call_args = mock_client.chat_postMessage.call_args
            blocks = call_args.kwargs.get("blocks", call_args[1].get("blocks"))

            assert blocks is not None
            assert len(blocks) >= 1  # At least the context header

            # Check header content - it's now a context block
            header_block = blocks[0]
            assert header_block["type"] == "context"
            header_text = header_block["elements"][0]["text"]

            # Use helper to check all expected parts
            self.assert_header_format(header_text, {
                "robot emoji": "🤖",
                "function name": "test-function",
                "account name": "Production",
                "account ID": "(123456789012)",
                "region": "eu-west-1",
                "log emoji": "📋",
                "log group": "`/aws/lambda/test-function`"
            })

    @patch("nui_lambda_shared_utils.slack_client.create_aws_client")
    @patch("nui_lambda_shared_utils.base_client.get_secret")
    @patch("nui_lambda_shared_utils.slack_client.WebClient")
    @patch.dict(
        os.environ,
        {
            "AWS_LAMBDA_FUNCTION_NAME": "nui-service",
            "AWS_REGION": "ap-southeast-2",
            "STAGE": "dev",
        },
    )
    def test_lambda_header_nui_development(self, mock_webclient, mock_get_secret, mock_boto3):
        """Test Lambda header generation for Development."""
        # Setup mocks
        mock_get_secret.return_value = {"bot_token": "xoxb-test-token"}
        mock_client = Mock()
        mock_webclient.return_value = mock_client
        mock_client.chat_postMessage.return_value = {"ok": True, "ts": "123"}

        # Mock STS for account info
        mock_sts = Mock()
        mock_boto3.return_value = mock_sts
        mock_sts.get_caller_identity.return_value = {
            "Account": "234567890123",  # Development
            "Arn": "arn:aws:sts::234567890123:assumed-role/test-role/nui-service",
        }

        # Mock Lambda client - deployment time fails
        mock_lambda = Mock()
        mock_boto3.side_effect = lambda service: mock_sts if service == "sts" else mock_lambda
        mock_lambda.get_function.side_effect = Exception("Access denied")

        # Mock config file check
        with patch("os.path.exists") as mock_exists:
            mock_exists.side_effect = lambda path: path.endswith("serverless.yml")

            slack = SlackClient(secret_name="test-secret")
            result = slack.send_message("C123", "Test message")

            # Verify the header was included
            call_args = mock_client.chat_postMessage.call_args
            blocks = call_args.kwargs.get("blocks", call_args[1].get("blocks"))

            assert blocks is not None

            # Check header content - it's now a context block
            header_block = blocks[0]
            assert header_block["type"] == "context"
            header_text = header_block["elements"][0]["text"]

            # Use helper to check all expected parts
            self.assert_header_format(header_text, {
                "robot emoji": "🤖",
                "function name": "nui-service",
                "account name": "Development",
                "account ID": "(234567890123)",
                "region": "ap-southeast-2",
                "log emoji": "📋"
            })

    @patch("nui_lambda_shared_utils.slack_client.create_aws_client")
    @patch("nui_lambda_shared_utils.base_client.get_secret")
    @patch("nui_lambda_shared_utils.slack_client.WebClient")
    @patch.dict(
        os.environ,
        {
            "AWS_LAMBDA_FUNCTION_NAME": "connect-prod-long-service-name-12345",
            "AWS_REGION": "eu-west-1",
            "STAGE": "prod",
        },
    )
    def test_custom_service_name_in_header(self, mock_webclient, mock_get_secret, mock_boto3):
        """Service name parameter overrides function name in header."""
        # Setup mocks
        mock_get_secret.return_value = {"bot_token": "xoxb-test-token"}
        mock_client = Mock()
        mock_webclient.return_value = mock_client
        mock_client.chat_postMessage.return_value = {"ok": True, "ts": "123"}

        # Mock STS for account info
        mock_sts = Mock()
        mock_boto3.return_value = mock_sts
        mock_sts.get_caller_identity.return_value = {
            "Account": "123456789012",  # Production
            "Arn": "arn:aws:sts::123456789012:assumed-role/test-role/connect-prod-long-service-name-12345",
        }

        # Mock Lambda client
        mock_lambda = Mock()
        mock_boto3.side_effect = lambda service: mock_sts if service == "sts" else mock_lambda
        mock_lambda.get_function.return_value = {
            "Configuration": {"FunctionName": "connect-prod-long-service-name-12345"}
        }

        # Mock config file check
        with patch("os.path.exists") as mock_exists:
            mock_exists.return_value = False

            # Create client with custom service name
            slack = SlackClient(
                secret_name="test-secret",
                service_name="my-service",
                account_names={"123456789012": "Production"}
            )
            result = slack.send_message("C123", "Test message")

            # Verify the header was included
            call_args = mock_client.chat_postMessage.call_args
            blocks = call_args.kwargs.get("blocks", call_args[1].get("blocks"))

            assert blocks is not None
            header_block = blocks[0]
            assert header_block["type"] == "context"
            header_text = header_block["elements"][0]["text"]

            # Should show custom service name, not full function name
            assert "my-service" in header_text
            assert "connect-prod-long-service-name-12345" not in header_text

            # Other header elements should still be present
            self.assert_header_format(header_text, {
                "robot emoji": "🤖",
                "function name": "my-service",  # Custom name
                "account name": "Production",
                "account ID": "(123456789012)",
                "region": "eu-west-1",
                "log emoji": "📋"
            })

    @patch("nui_lambda_shared_utils.slack_client.create_aws_client")
    @patch("nui_lambda_shared_utils.base_client.get_secret")
    @patch("nui_lambda_shared_utils.slack_client.WebClient")
    @patch.dict(
        os.environ,
        {
            "AWS_LAMBDA_FUNCTION_NAME": "test-function",
            "AWS_REGION": "eu-west-1",
            "STAGE": "prod",
        },
    )
    def test_missing_service_name_uses_function_name(self, mock_webclient, mock_get_secret, mock_boto3):
        """Without service_name, falls back to function name."""
        # Setup mocks
        mock_get_secret.return_value = {"bot_token": "xoxb-test-token"}
        mock_client = Mock()
        mock_webclient.return_value = mock_client
        mock_client.chat_postMessage.return_value = {"ok": True, "ts": "123"}

        # Mock STS for account info
        mock_sts = Mock()
        mock_boto3.return_value = mock_sts
        mock_sts.get_caller_identity.return_value = {
            "Account": "123456789012",
            "Arn": "arn:aws:sts::123456789012:assumed-role/test-role/test-function",
        }

        # Mock Lambda client
        mock_lambda = Mock()
        mock_boto3.side_effect = lambda service: mock_sts if service == "sts" else mock_lambda
        mock_lambda.get_function.return_value = {
            "Configuration": {"FunctionName": "test-function"}
        }

        # Mock config file check
        with patch("os.path.exists") as mock_exists:
            mock_exists.return_value = False

            # Create client WITHOUT custom service name
            slack = SlackClient(
                secret_name="test-secret",
                account_names={"123456789012": "Production"}
            )
            result = slack.send_message("C123", "Test message")

            # Verify the header was included
            call_args = mock_client.chat_postMessage.call_args
            blocks = call_args.kwargs.get("blocks", call_args[1].get("blocks"))

            assert blocks is not None
            header_block = blocks[0]
            assert header_block["type"] == "context"
            header_text = header_block["elements"][0]["text"]

            # Should show full function name
            assert "test-function" in header_text

            # All header elements should be present
            self.assert_header_format(header_text, {
                "robot emoji": "🤖",
                "function name": "test-function",  # Original function name
                "account name": "Production",
                "account ID": "(123456789012)",
                "region": "eu-west-1",
                "log emoji": "📋"
            })

    @patch("nui_lambda_shared_utils.slack_client.create_aws_client")
    @patch("nui_lambda_shared_utils.base_client.get_secret")
    @patch("nui_lambda_shared_utils.slack_client.WebClient")
    @patch.dict(os.environ, {})  # No Lambda environment variables
    def test_lambda_header_not_in_lambda(self, mock_webclient, mock_get_secret, mock_boto3):
        """Test that Lambda header is not included when not running in Lambda."""
        mock_get_secret.return_value = {"bot_token": "xoxb-test-token"}
        mock_client = Mock()
        mock_webclient.return_value = mock_client
        mock_client.chat_postMessage.return_value = {"ok": True, "ts": "123"}

        # Mock STS to simulate that we can't get account info when not in Lambda
        mock_sts = Mock()
        mock_boto3.return_value = mock_sts
        mock_sts.get_caller_identity.side_effect = Exception("Not authenticated")

        slack = SlackClient(secret_name="test-secret")
        result = slack.send_message(
            "C123", "Test message", blocks=[{"type": "section", "text": {"type": "mrkdwn", "text": "Original block"}}]
        )

        # Verify local header was added (not Lambda header)
        call_args = mock_client.chat_postMessage.call_args
        blocks = call_args.kwargs.get("blocks", call_args[1].get("blocks"))

        assert len(blocks) == 2  # Local header + original block
        assert blocks[0]["type"] == "context"  # First block is header
        assert blocks[1]["text"]["text"] == "Original block"  # Second block is original

    @patch("nui_lambda_shared_utils.slack_client.create_aws_client")
    @patch("nui_lambda_shared_utils.base_client.get_secret")
    @patch("nui_lambda_shared_utils.slack_client.WebClient")
    @patch.dict(os.environ, {"AWS_LAMBDA_FUNCTION_NAME": "test-function", "STAGE": "prod"})
    def test_lambda_header_can_be_disabled(self, mock_webclient, mock_get_secret, mock_boto3):
        """Test that Lambda header can be disabled."""
        mock_get_secret.return_value = {"bot_token": "xoxb-test-token"}
        mock_client = Mock()
        mock_webclient.return_value = mock_client
        mock_client.chat_postMessage.return_value = {"ok": True, "ts": "123"}

        # Mock STS
        mock_sts = Mock()
        mock_boto3.return_value = mock_sts
        mock_sts.get_caller_identity.return_value = {"Account": "123456789012"}

        slack = SlackClient(secret_name="test-secret")
        result = slack.send_message("C123", "Test message", include_lambda_header=False)

        # Verify no header was added
        call_args = mock_client.chat_postMessage.call_args
        blocks = call_args.kwargs.get("blocks", call_args[1].get("blocks"))

        assert blocks is None  # No blocks added

    @patch("nui_lambda_shared_utils.slack_client.create_aws_client")
    @patch("nui_lambda_shared_utils.base_client.get_secret")
    @patch("nui_lambda_shared_utils.slack_client.WebClient")
    @patch.dict(os.environ, {"AWS_LAMBDA_FUNCTION_NAME": "test-function", "STAGE": "prod"})
    def test_thread_reply_no_header_by_default(self, mock_webclient, mock_get_secret, mock_boto3):
        """Test that thread replies don't include header by default."""
        mock_get_secret.return_value = {"bot_token": "xoxb-test-token"}
        mock_client = Mock()
        mock_webclient.return_value = mock_client
        mock_client.chat_postMessage.return_value = {"ok": True, "ts": "123"}

        # Mock STS
        mock_sts = Mock()
        mock_boto3.return_value = mock_sts
        mock_sts.get_caller_identity.return_value = {"Account": "123456789012"}

        slack = SlackClient(secret_name="test-secret")
        result = slack.send_thread_reply("C123", "1234567890.123456", "Reply")

        # Verify no header was added
        call_args = mock_client.chat_postMessage.call_args
        blocks = call_args.kwargs.get("blocks", call_args[1].get("blocks"))

        assert blocks is None

    @patch("nui_lambda_shared_utils.slack_client.create_aws_client")
    @patch("nui_lambda_shared_utils.base_client.get_secret")
    @patch("nui_lambda_shared_utils.slack_client.WebClient")
    @patch.dict(os.environ, {"AWS_LAMBDA_FUNCTION_NAME": "test-function", "STAGE": "prod"})
    def test_unknown_account_id_handling(self, mock_webclient, mock_get_secret, mock_boto3):
        """Test handling of unknown AWS account IDs."""
        mock_get_secret.return_value = {"bot_token": "xoxb-test-token"}
        mock_client = Mock()
        mock_webclient.return_value = mock_client
        mock_client.chat_postMessage.return_value = {"ok": True, "ts": "123"}

        # Mock STS with unknown account
        mock_sts = Mock()
        mock_boto3.return_value = mock_sts
        mock_sts.get_caller_identity.return_value = {
            "Account": "999999999999",  # Unknown account
            "Arn": "arn:aws:sts::999999999999:assumed-role/test-role/test-function",
        }

        slack = SlackClient(secret_name="test-secret")
        result = slack.send_message("C123", "Test message")

        # Check header contains unknown account info
        call_args = mock_client.chat_postMessage.call_args
        blocks = call_args.kwargs.get("blocks", call_args[1].get("blocks"))
        header_block = blocks[0]
        header_text = header_block["elements"][0]["text"]

        assert "Unknown (999999999999)" in header_text

    @patch("nui_lambda_shared_utils.slack_client.create_aws_client")
    @patch("nui_lambda_shared_utils.base_client.get_secret")
    @patch("nui_lambda_shared_utils.slack_client.WebClient")
    @patch.dict(
        os.environ,
        {"AWS_LAMBDA_FUNCTION_NAME": "dev-test-function", "STAGE": "dev", "AWS_REGION": "eu-west-1"},  # Dev stage
    )
    def test_stage_mismatch_shown_in_header(self, mock_webclient, mock_get_secret, mock_boto3):
        """Test that header shows account name regardless of stage env var."""
        mock_get_secret.return_value = {"bot_token": "xoxb-test-token"}
        mock_client = Mock()
        mock_webclient.return_value = mock_client
        mock_client.chat_postMessage.return_value = {"ok": True, "ts": "123"}

        # Mock STS for Production account
        mock_sts = Mock()
        mock_boto3.return_value = mock_sts
        mock_sts.get_caller_identity.return_value = {
            "Account": "123456789012",  # Production
            "Arn": "arn:aws:sts::123456789012:assumed-role/test-role/test-function",
        }

        slack = SlackClient(secret_name="test-secret")
        result = slack.send_message("C123", "Test message")

        # Check header shows account name only (not stage)
        call_args = mock_client.chat_postMessage.call_args
        blocks = call_args.kwargs.get("blocks", call_args[1].get("blocks"))
        header_block = blocks[0]
        header_text = header_block["elements"][0]["text"]

        # Shared library doesn't interpret stage - just shows account name
        assert "dev-test-function" in header_text
        assert "(dev)" not in header_text  # No stage suffix
        assert "Production" in header_text


class TestAccountNameConsistency:
    """Tests to ensure account name mappings are consistent across functions."""

    @patch("nui_lambda_shared_utils.slack_client.create_aws_client")
    @patch("nui_lambda_shared_utils.base_client.get_secret")
    @patch("nui_lambda_shared_utils.slack_client.WebClient")
    @patch.dict(os.environ, {})  # No Lambda environment variables
    def test_centralized_account_mappings(self, mock_webclient, mock_get_secret, mock_boto3):
        """Test that both lambda context and local header use the same account mappings."""
        mock_get_secret.return_value = {"bot_token": "xoxb-test-token"}
        mock_client = Mock()
        mock_webclient.return_value = mock_client
        mock_client.chat_postMessage.return_value = {"ok": True, "ts": "123"}

        # Test Development ID specifically (the one that was inconsistent)
        mock_sts = Mock()
        mock_boto3.return_value = mock_sts
        mock_sts.get_caller_identity.return_value = {"Account": "234567890123"}  # Development

        slack = SlackClient(secret_name="test-secret")

        # Verify lambda context uses centralized mapping
        assert slack._lambda_context["aws_account_name"] == "Development"

        # Send message to trigger local header creation (since no Lambda env vars)
        slack.send_message("C123", "Test message")

        # Verify local header also uses centralized mapping
        call_args = mock_client.chat_postMessage.call_args
        blocks = call_args.kwargs.get("blocks", call_args[1].get("blocks"))
        header_text = blocks[0]["elements"][0]["text"]

        assert "Development" in header_text

    def test_default_account_names_constant(self):
        """Test that DEFAULT_ACCOUNT_NAMES constant contains only example mappings."""
        expected_accounts = {
            "123456789012": "Production",
            "234567890123": "Development",
            "345678901234": "Staging",
        }

        assert DEFAULT_ACCOUNT_NAMES == expected_accounts

        # Verify example account IDs are present
        assert DEFAULT_ACCOUNT_NAMES["123456789012"] == "Production"
        assert DEFAULT_ACCOUNT_NAMES["234567890123"] == "Development"
        assert DEFAULT_ACCOUNT_NAMES["345678901234"] == "Staging"

        # Verify no real account IDs are hardcoded
        assert "043836023178" not in DEFAULT_ACCOUNT_NAMES
        assert "036220212417" not in DEFAULT_ACCOUNT_NAMES

    @patch("nui_lambda_shared_utils.slack_client.create_aws_client")
    @patch("nui_lambda_shared_utils.base_client.get_secret")
    @patch("nui_lambda_shared_utils.slack_client.WebClient")
    @patch.dict(
        os.environ,
        {
            "AWS_LAMBDA_FUNCTION_NAME": "custom-function",
            "AWS_LAMBDA_LOG_GROUP_NAME": "/aws/lambda/custom-function",
            "AWS_REGION": "us-east-1",
        },
    )
    def test_custom_account_names_via_dict(self, mock_webclient, mock_get_secret, mock_boto3):
        """Test that clients can provide custom account name mappings via dict."""
        mock_get_secret.return_value = {"bot_token": "xoxb-test-token"}
        mock_client = Mock()
        mock_webclient.return_value = mock_client
        mock_client.chat_postMessage.return_value = {"ok": True, "ts": "123"}

        # Mock custom account ID
        mock_sts = Mock()
        mock_boto3.return_value = mock_sts
        mock_sts.get_caller_identity.return_value = {
            "Account": "999888777666",
            "Arn": "arn:aws:sts::999888777666:assumed-role/test-role/custom-function",
        }

        # Create client with custom account names
        custom_accounts = {"999888777666": "MyCustomAccount"}
        slack = SlackClient(secret_name="test-secret", account_names=custom_accounts)
        result = slack.send_message("C123", "Test message")
        assert result is True

        # Verify custom account name is used
        call_args = mock_client.chat_postMessage.call_args
        blocks = call_args.kwargs.get("blocks", call_args[1].get("blocks"))
        header_text = blocks[0]["elements"][0]["text"]

        assert "MyCustomAccount" in header_text
        assert "(999888777666)" in header_text

    @patch("nui_lambda_shared_utils.slack_client.create_aws_client")
    @patch("nui_lambda_shared_utils.base_client.get_secret")
    @patch("nui_lambda_shared_utils.slack_client.WebClient")
    @patch.dict(
        os.environ,
        {
            "AWS_LAMBDA_FUNCTION_NAME": "yaml-config-function",
            "AWS_LAMBDA_LOG_GROUP_NAME": "/aws/lambda/yaml-config-function",
            "AWS_REGION": "eu-central-1",
        },
    )
    def test_custom_account_names_via_yaml(self, mock_webclient, mock_get_secret, mock_boto3, tmp_path):
        """Test that clients can provide custom account name mappings via YAML config."""
        mock_get_secret.return_value = {"bot_token": "xoxb-test-token"}
        mock_client = Mock()
        mock_webclient.return_value = mock_client
        mock_client.chat_postMessage.return_value = {"ok": True, "ts": "123"}

        # Mock custom account ID
        mock_sts = Mock()
        mock_boto3.return_value = mock_sts
        mock_sts.get_caller_identity.return_value = {
            "Account": "111222333444",
            "Arn": "arn:aws:sts::111222333444:assumed-role/test-role/yaml-config-function",
        }

        # Create YAML config file
        config_file = tmp_path / "slack_config.yaml"
        config_file.write_text("""
account_names:
  "111222333444": "YAMLConfiguredAccount"
  "555666777888": "AnotherAccount"
""")

        # Create client with config file
        slack = SlackClient(secret_name="test-secret", account_names_config=str(config_file))
        result = slack.send_message("C123", "Test message")
        assert result is True

        # Verify YAML account name is used
        call_args = mock_client.chat_postMessage.call_args
        blocks = call_args.kwargs.get("blocks", call_args[1].get("blocks"))
        header_text = blocks[0]["elements"][0]["text"]

        assert "YAMLConfiguredAccount" in header_text
        assert "(111222333444)" in header_text

    @patch("nui_lambda_shared_utils.slack_client.create_aws_client")
    @patch("nui_lambda_shared_utils.base_client.get_secret")
    @patch("nui_lambda_shared_utils.slack_client.WebClient")
    @patch.dict(os.environ, {"AWS_LAMBDA_FUNCTION_NAME": "test-function"})
    def test_malformed_yaml_fallback_to_defaults(self, mock_webclient, mock_get_secret, mock_boto3, tmp_path):
        """Test that malformed YAML falls back to defaults gracefully."""
        mock_get_secret.return_value = {"bot_token": "xoxb-test-token"}
        mock_webclient.return_value = Mock()

        mock_sts = Mock()
        mock_boto3.return_value = mock_sts
        mock_sts.get_caller_identity.return_value = {"Account": "123456789012"}

        # Create malformed YAML file
        config_file = tmp_path / "bad_config.yaml"
        config_file.write_text("account_names: [this, is, not, a, dict]")

        # Should initialize without error and use defaults
        slack = SlackClient(secret_name="test-secret", account_names_config=str(config_file))

        # Should fall back to default account name
        assert slack._lambda_context["aws_account_name"] == "Production"  # From defaults

    @patch("nui_lambda_shared_utils.slack_client.create_aws_client")
    @patch("nui_lambda_shared_utils.base_client.get_secret")
    @patch("nui_lambda_shared_utils.slack_client.WebClient")
    @patch.dict(os.environ, {"AWS_LAMBDA_FUNCTION_NAME": "test-function"})
    def test_empty_yaml_file_fallback(self, mock_webclient, mock_get_secret, mock_boto3, tmp_path):
        """Test that empty YAML file falls back to defaults."""
        mock_get_secret.return_value = {"bot_token": "xoxb-test-token"}
        mock_webclient.return_value = Mock()

        mock_sts = Mock()
        mock_boto3.return_value = mock_sts
        mock_sts.get_caller_identity.return_value = {"Account": "234567890123"}

        # Create empty YAML file
        config_file = tmp_path / "empty_config.yaml"
        config_file.write_text("")

        slack = SlackClient(secret_name="test-secret", account_names_config=str(config_file))

        # Should use default account name
        assert slack._lambda_context["aws_account_name"] == "Development"

    @patch("nui_lambda_shared_utils.slack_client.create_aws_client")
    @patch("nui_lambda_shared_utils.base_client.get_secret")
    @patch("nui_lambda_shared_utils.slack_client.WebClient")
    @patch.dict(os.environ, {"AWS_LAMBDA_FUNCTION_NAME": "test-function"})
    def test_missing_yaml_file_fallback(self, mock_webclient, mock_get_secret, mock_boto3, tmp_path):
        """Test that missing YAML file falls back to defaults."""
        mock_get_secret.return_value = {"bot_token": "xoxb-test-token"}
        mock_webclient.return_value = Mock()

        mock_sts = Mock()
        mock_boto3.return_value = mock_sts
        mock_sts.get_caller_identity.return_value = {"Account": "345678901234"}

        # Reference non-existent file
        config_file = tmp_path / "nonexistent.yaml"

        slack = SlackClient(secret_name="test-secret", account_names_config=str(config_file))

        # Should use default account name
        assert slack._lambda_context["aws_account_name"] == "Staging"

    @patch("nui_lambda_shared_utils.slack_client.create_aws_client")
    @patch("nui_lambda_shared_utils.base_client.get_secret")
    @patch("nui_lambda_shared_utils.slack_client.WebClient")
    @patch.dict(os.environ, {"AWS_LAMBDA_FUNCTION_NAME": "test-function"})
    def test_invalid_account_names_type_ignored(self, mock_webclient, mock_get_secret, mock_boto3):
        """Test that invalid account_names parameter type is ignored gracefully."""
        mock_get_secret.return_value = {"bot_token": "xoxb-test-token"}
        mock_webclient.return_value = Mock()

        mock_sts = Mock()
        mock_boto3.return_value = mock_sts
        mock_sts.get_caller_identity.return_value = {"Account": "123456789012"}

        # Pass invalid type (list instead of dict)
        slack = SlackClient(secret_name="test-secret", account_names=["not", "a", "dict"])

        # Should use default account name, ignoring invalid parameter
        assert slack._lambda_context["aws_account_name"] == "Production"

    @patch("nui_lambda_shared_utils.slack_client.create_aws_client")
    @patch("nui_lambda_shared_utils.base_client.get_secret")
    @patch("nui_lambda_shared_utils.slack_client.WebClient")
    @patch.dict(os.environ, {"AWS_LAMBDA_FUNCTION_NAME": "test-function"})
    def test_yaml_with_non_string_values_ignored(self, mock_webclient, mock_get_secret, mock_boto3, tmp_path):
        """Test that YAML with non-string values is validated and ignored."""
        mock_get_secret.return_value = {"bot_token": "xoxb-test-token"}
        mock_webclient.return_value = Mock()

        mock_sts = Mock()
        mock_boto3.return_value = mock_sts
        mock_sts.get_caller_identity.return_value = {"Account": "123456789012"}

        # Create YAML with non-string values
        config_file = tmp_path / "invalid_types.yaml"
        config_file.write_text("""
account_names:
  "123456789012": 12345
  "234567890123": true
""")

        slack = SlackClient(secret_name="test-secret", account_names_config=str(config_file))

        # Should fall back to defaults due to type validation failure
        assert slack._lambda_context["aws_account_name"] == "Production"

    @patch("nui_lambda_shared_utils.slack_client.create_aws_client")
    @patch("nui_lambda_shared_utils.base_client.get_secret")
    @patch("nui_lambda_shared_utils.slack_client.WebClient")
    @patch("nui_lambda_shared_utils.slack_client.get_lambda_environment_info")
    @patch.dict(os.environ, {})
    def test_uses_shared_lambda_environment_helper(self, mock_env_info, mock_webclient, mock_get_secret, mock_boto3):
        """Verify SlackClient delegates to get_lambda_environment_info"""
        mock_get_secret.return_value = {"bot_token": "xoxb-test-token"}
        mock_env_info.return_value = {
            "function_name": "test-fn",
            "function_version": "$LATEST",
            "aws_region": "ap-southeast-2",
            "environment": "unknown",
            "memory_limit": "",
            "is_local": True,
        }
        SlackClient(secret_name="test-secret")
        mock_env_info.assert_called_once()
