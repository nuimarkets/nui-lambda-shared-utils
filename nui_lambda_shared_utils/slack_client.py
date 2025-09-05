"""
Shared Slack client for AWS Lambda functions.
"""

import os
import logging
from typing import List, Dict, Optional
from slack_sdk import WebClient
from slack_sdk.errors import SlackApiError
import boto3
from datetime import datetime
import yaml
import json

from .secrets_helper import get_secret
from .slack_formatter import SlackBlockBuilder, format_nz_time

log = logging.getLogger(__name__)

# AWS account ID to friendly name mapping
# Configure this mapping for your environment
ACCOUNT_NAMES = {
    # Example entries - replace with your account IDs
    "123456789012": "Production",
    "234567890123": "Development",
    "345678901234": "Staging",
}


class SlackClient:
    def __init__(self, secret_name: str):
        """
        Initialize Slack client with credentials from Secrets Manager.

        Args:
            secret_name: Secret name in AWS Secrets Manager (REQUIRED)
        """
        secret = secret_name
        slack_credentials = get_secret(secret)
        self.token = slack_credentials["bot_token"]
        self.client = WebClient(token=self.token)

        # Collect Lambda context for headers
        self._lambda_context = self._get_lambda_context()

    def _get_lambda_context(self) -> Dict[str, str]:
        """
        Collect Lambda runtime context from environment variables.

        Returns:
            Dict containing Lambda metadata
        """
        context = {
            "function_name": os.environ.get("AWS_LAMBDA_FUNCTION_NAME", "Unknown"),
            "function_version": os.environ.get("AWS_LAMBDA_FUNCTION_VERSION", "Unknown"),
            "log_group": os.environ.get("AWS_LAMBDA_LOG_GROUP_NAME", "Unknown"),
            "log_stream": os.environ.get("AWS_LAMBDA_LOG_STREAM_NAME", "Unknown"),
            "aws_region": os.environ.get("AWS_REGION", "Unknown"),
            "stage": os.environ.get("STAGE", os.environ.get("ENV", "Unknown")),
            "execution_env": os.environ.get("AWS_EXECUTION_ENV", "Unknown"),
        }

        # Try to get AWS account info
        try:
            sts = boto3.client("sts")
            account_info = sts.get_caller_identity()
            context["aws_account_id"] = account_info.get("Account", "Unknown")
            context["aws_account_arn"] = account_info.get("Arn", "Unknown")

            # Map account ID to friendly name using centralized mapping
            context["aws_account_name"] = ACCOUNT_NAMES.get(
                context["aws_account_id"], f"Unknown Account ({context['aws_account_id']})"
            )
        except Exception as e:
            log.debug(f"Could not fetch AWS account info: {e}")
            context["aws_account_id"] = "Unknown"
            context["aws_account_name"] = "Unknown"
            context["aws_account_arn"] = "Unknown"

        # Get deployment info from .lambda-deploy.yml or serverless.yml
        context["deploy_time"] = self._get_deployment_time()
        context["deploy_config_type"] = self._detect_config_type()

        return context

    def _detect_config_type(self) -> str:
        """
        Detect whether the Lambda uses .lambda-deploy.yml or serverless.yml.

        Returns:
            Config type string
        """
        # Check for config files in the Lambda's directory
        # In Lambda runtime, we're in /var/task/
        try:
            if os.path.exists("/var/task/.lambda-deploy.yml"):
                return "lambda-deploy v3.0+"
            elif os.path.exists("/var/task/serverless.yml"):
                return "serverless.yml"
            else:
                return "Unknown"
        except Exception:
            return "Unknown"

    def _get_deployment_time(self) -> str:
        """
        Get the last deployment time of the Lambda function as a human-friendly age.

        Returns:
            Human-friendly age string (e.g., "5m ago", "2h ago", "3d ago")
        """
        try:
            # Get function name from environment
            function_name = os.environ.get("AWS_LAMBDA_FUNCTION_NAME")
            if not function_name:
                return "Unknown"

            # Get the function's last modified time
            lambda_client = boto3.client("lambda")
            response = lambda_client.get_function(FunctionName=function_name)

            # LastModified is in the Configuration
            last_modified = response["Configuration"].get("LastModified", "Unknown")

            if last_modified != "Unknown":
                # Parse the timestamp
                # Lambda returns format: '2023-11-15T10:30:45.123+0000'
                dt = datetime.fromisoformat(last_modified.replace("+0000", "+00:00"))

                # Calculate age
                now = datetime.now(dt.tzinfo)
                age = now - dt

                # Format as human-friendly age
                if age.total_seconds() < 60:
                    return f"{int(age.total_seconds())}s ago"
                elif age.total_seconds() < 3600:
                    return f"{int(age.total_seconds() / 60)}m ago"
                elif age.total_seconds() < 86400:
                    return f"{int(age.total_seconds() / 3600)}h ago"
                else:
                    return f"{int(age.total_seconds() / 86400)}d ago"
            else:
                return "Unknown"

        except Exception as e:
            log.debug(f"Could not fetch deployment time: {e}")
            return "Unknown"

    def _create_lambda_header_block(self) -> List[Dict]:
        """
        Create a concise header block with Lambda metadata.

        Returns:
            List of Slack blocks for the header
        """
        # Simplify account name to "Production", "Development", etc.
        account_name = self._lambda_context["aws_account_name"]
        if "Production" in account_name:
            simple_account = "Production"
            expected_stage = "prod"
        elif "Development" in account_name:
            simple_account = "Development"
            expected_stage = "dev"
        elif "Production" in account_name:
            simple_account = "Production"
            expected_stage = "prod"
        elif "Development" in account_name:
            simple_account = "Development"
            expected_stage = "dev"
        else:
            simple_account = f"Unknown ({self._lambda_context['aws_account_id']})"
            expected_stage = None

        # Only show stage if it doesn't match the expected environment
        stage = self._lambda_context["stage"]
        stage_suffix = ""
        if expected_stage and stage != expected_stage:
            # Stage doesn't match environment (e.g., dev Lambda in prod account)
            stage_suffix = f" ({stage})"

        # Create concise context lines with AI robot emoji
        line1 = f"🤖 `{self._lambda_context['function_name']}`{stage_suffix}"
        line2 = f"📍 {simple_account} • {self._lambda_context['aws_region']} • Deployed: {self._lambda_context['deploy_time']}"
        line3 = f"📋 Log: `{self._lambda_context['log_group']}`"

        # Single context block with all lines
        return [{"type": "context", "elements": [{"type": "mrkdwn", "text": f"{line1}\n{line2}\n{line3}"}]}]

    def _create_local_header_block(self) -> List[Dict]:
        """
        Create a context header block for local/manual testing.

        Returns:
            List of blocks for local testing context
        """
        import getpass
        from datetime import datetime, timezone

        # Get current user and timestamp
        try:
            username = getpass.getuser()
        except Exception:
            username = "Unknown"

        timestamp = datetime.now(timezone.utc).strftime("%H:%M UTC")

        # Map account ID to friendly name using centralized mapping
        account_name = ACCOUNT_NAMES.get(
            self._lambda_context["aws_account_id"], f"Unknown ({self._lambda_context['aws_account_id']})"
        )

        # Create local testing context lines with human emoji
        line1 = f"👤 `Local Testing` • {username}"
        line2 = f"📍 {account_name} • {self._lambda_context['aws_region']} • {timestamp}"
        line3 = "📋 Context: Manual/Development Testing"

        return [{"type": "context", "elements": [{"type": "mrkdwn", "text": f"{line1}\n{line2}\n{line3}"}]}]

    def send_message(
        self, channel: str, text: str, blocks: Optional[List[Dict]] = None, include_lambda_header: bool = True
    ) -> bool:
        """
        Send a message to a Slack channel.

        Args:
            channel: Channel ID (not name)
            text: Fallback text for notifications
            blocks: Rich formatted blocks
            include_lambda_header: Whether to include Lambda context header (default: True)

        Returns:
            bool: True if successful
        """
        try:
            # Add appropriate header based on environment
            if include_lambda_header:
                if self._lambda_context["function_name"] != "Unknown":
                    # Running in Lambda environment - use Lambda header
                    header_blocks = self._create_lambda_header_block()
                else:
                    # Running locally/manually - use local header
                    header_blocks = self._create_local_header_block()

                if blocks:
                    blocks = header_blocks + blocks
                else:
                    blocks = header_blocks

            response = self.client.chat_postMessage(channel=channel, text=text, blocks=blocks)

            if response["ok"]:
                log.info("Slack message sent successfully", extra={"channel": channel, "ts": response["ts"]})
                return True
            else:
                log.error("Slack API returned error", extra={"error": response.get("error", "Unknown error")})
                return False

        except SlackApiError as e:
            log.error("Slack API error", exc_info=True, extra={"error": str(e), "channel": channel})
            return False
        except Exception as e:
            log.error(
                "Unexpected error sending Slack message", exc_info=True, extra={"error": str(e), "channel": channel}
            )
            return False

    def send_file(self, channel: str, content: str, filename: str, title: Optional[str] = None) -> bool:
        """
        Upload a file to Slack.

        Args:
            channel: Channel ID
            content: File content as string
            filename: Name for the file
            title: Optional title for the upload

        Returns:
            bool: True if successful
        """
        try:
            response = self.client.files_upload_v2(
                channel=channel, content=content, filename=filename, title=title or filename
            )

            if response["ok"]:
                log.info("File uploaded successfully", extra={"channel": channel, "file_name": filename})
                return True
            else:
                log.error("Slack file upload failed", extra={"error": response.get("error", "Unknown error")})
                return False

        except SlackApiError as e:
            log.error(
                "Slack API error uploading file",
                exc_info=True,
                extra={"error": str(e), "channel": channel, "file_name": filename},
            )
            return False

    def send_thread_reply(
        self,
        channel: str,
        thread_ts: str,
        text: str,
        blocks: Optional[List[Dict]] = None,
        include_lambda_header: bool = False,
    ) -> bool:
        """
        Send a reply in a thread.

        Args:
            channel: Channel ID
            thread_ts: Timestamp of the parent message
            text: Reply text
            blocks: Optional rich formatted blocks
            include_lambda_header: Whether to include Lambda context header (default: False for thread replies)

        Returns:
            bool: True if successful
        """
        try:
            # Optionally add Lambda header to thread replies
            if include_lambda_header and self._lambda_context["function_name"] != "Unknown":
                header_blocks = self._create_lambda_header_block()
                if blocks:
                    blocks = header_blocks + blocks
                else:
                    blocks = header_blocks

            response = self.client.chat_postMessage(channel=channel, thread_ts=thread_ts, text=text, blocks=blocks)

            if response["ok"]:
                log.info(
                    "Thread reply sent successfully",
                    extra={"channel": channel, "thread_ts": thread_ts, "reply_ts": response["ts"]},
                )
                return True
            else:
                log.error("Failed to send thread reply", extra={"error": response.get("error", "Unknown error")})
                return False

        except SlackApiError as e:
            log.error(
                "Slack API error sending thread reply",
                exc_info=True,
                extra={"error": str(e), "channel": channel, "thread_ts": thread_ts},
            )
            return False

    def update_message(self, channel: str, ts: str, text: str, blocks: Optional[List[Dict]] = None) -> bool:
        """
        Update an existing message.

        Args:
            channel: Channel ID
            ts: Timestamp of the message to update
            text: New text
            blocks: New blocks

        Returns:
            bool: True if successful
        """
        try:
            response = self.client.chat_update(channel=channel, ts=ts, text=text, blocks=blocks)

            if response["ok"]:
                log.info("Message updated successfully", extra={"channel": channel, "ts": ts})
                return True
            else:
                log.error("Failed to update message", extra={"error": response.get("error", "Unknown error")})
                return False

        except SlackApiError as e:
            log.error(
                "Slack API error updating message", exc_info=True, extra={"error": str(e), "channel": channel, "ts": ts}
            )
            return False

    def add_reaction(self, channel: str, ts: str, emoji: str) -> bool:
        """
        Add a reaction emoji to a message.

        Args:
            channel: Channel ID
            ts: Timestamp of the message
            emoji: Emoji name (without colons)

        Returns:
            bool: True if successful
        """
        try:
            response = self.client.reactions_add(channel=channel, timestamp=ts, name=emoji)

            if response["ok"]:
                log.info("Reaction added successfully", extra={"channel": channel, "ts": ts, "emoji": emoji})
                return True
            else:
                log.error("Failed to add reaction", extra={"error": response.get("error", "Unknown error")})
                return False

        except SlackApiError as e:
            # already_reacted is not really an error
            if e.response["error"] == "already_reacted":
                log.debug("Reaction already exists", extra={"channel": channel, "ts": ts, "emoji": emoji})
                return True

            log.error(
                "Slack API error adding reaction",
                exc_info=True,
                extra={"error": str(e), "channel": channel, "ts": ts, "emoji": emoji},
            )
            return False
