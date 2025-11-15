"""
Refactored Slack client using BaseClient for DRY code patterns.
"""

import os
import logging
from typing import List, Dict, Optional
from pathlib import Path
from slack_sdk import WebClient
from slack_sdk.errors import SlackApiError
from datetime import datetime
import json

try:
    import yaml
    YAML_AVAILABLE = True
except ImportError:
    YAML_AVAILABLE = False

from .base_client import BaseClient, ServiceHealthMixin
from .utils import create_aws_client, handle_client_errors
from .slack_formatter import format_nz_time

log = logging.getLogger(__name__)

# Default account ID mappings (examples only - override via config in consuming lambdas)
DEFAULT_ACCOUNT_NAMES = {
    "123456789012": "Production",
    "234567890123": "Development",
    "345678901234": "Staging",
}


class SlackClient(BaseClient, ServiceHealthMixin):
    """
    Refactored Slack client with standardized patterns and reduced duplication.
    """

    def __init__(
        self,
        secret_name: Optional[str] = None,
        account_names: Optional[Dict[str, str]] = None,
        account_names_config: Optional[str] = None,
        **kwargs
    ):
        """
        Initialize Slack client with base class functionality.

        Args:
            secret_name: Override default secret name
            account_names: Dict mapping AWS account IDs to display names
            account_names_config: Path to YAML file with account_names mapping
            **kwargs: Additional configuration options

        Examples:
            Basic initialization with defaults:
                >>> slack = SlackClient()

            With custom account names (programmatic):
                >>> account_mappings = {
                ...     "123456789012": "my-prod",
                ...     "234567890123": "my-dev"
                ... }
                >>> slack = SlackClient(account_names=account_mappings)

            With YAML config file (recommended for Lambdas):
                >>> slack = SlackClient(account_names_config="slack_config.yaml")

            Combined (YAML + runtime overrides):
                >>> slack = SlackClient(
                ...     account_names_config="slack_config.yaml",
                ...     account_names={"999888777666": "temporary-dev"}
                ... )
        """
        super().__init__(secret_name=secret_name, **kwargs)

        # Load account names from config file or use provided dict
        self._account_names = self._load_account_names(account_names, account_names_config)

        # Collect Lambda context once during initialization
        self._lambda_context = self._collect_lambda_context()

    def _load_account_names(
        self,
        account_names: Optional[Dict[str, str]],
        config_path: Optional[str]
    ) -> Dict[str, str]:
        """
        Load account name mappings from config file or dict.

        Priority order (later overrides earlier):
        1. DEFAULT_ACCOUNT_NAMES (built-in examples)
        2. YAML config file (if provided)
        3. Direct dict parameter (if provided)

        Args:
            account_names: Direct dict of account mappings
            config_path: Path to YAML file with account_names mapping

        Returns:
            Dict mapping account IDs to display names

        Raises:
            No exceptions - failures are logged and defaults are used
        """
        # Start with defaults
        mappings = DEFAULT_ACCOUNT_NAMES.copy()

        # Load from config file if provided
        if config_path:
            if not YAML_AVAILABLE:
                log.warning("PyYAML not installed, cannot load config from YAML file")
                return mappings if not account_names else {**mappings, **account_names}

            try:
                config_file = Path(config_path).resolve()

                if not config_file.exists():
                    log.debug(f"Account names config file not found: {config_path} (optional)")
                    return mappings if not account_names else {**mappings, **account_names}

                with open(config_file, 'r', encoding='utf-8') as f:
                    config_data = yaml.safe_load(f)

                    if config_data is None:
                        log.warning(f"Account names config file is empty: {config_path}")
                    elif not isinstance(config_data, dict):
                        log.warning(f"Account names config file is not a valid YAML dict: {config_path}")
                    elif 'account_names' not in config_data:
                        log.warning(f"Account names config file missing 'account_names' key: {config_path}")
                    elif not isinstance(config_data['account_names'], dict):
                        log.warning(f"'account_names' must be a dict in config file: {config_path}")
                    else:
                        # Validate all keys and values are strings
                        account_data = config_data['account_names']
                        if all(isinstance(k, str) and isinstance(v, str) for k, v in account_data.items()):
                            mappings.update(account_data)
                            log.debug(f"Loaded {len(account_data)} account name(s) from {config_path}")
                        else:
                            log.warning(f"Account names config contains non-string keys/values: {config_path}")

            except yaml.YAMLError as e:
                log.warning(f"Invalid YAML in account names config {config_path}: {e}")
            except (IOError, OSError) as e:
                log.warning(f"Failed to read account names config {config_path}: {e}")
            except Exception as e:
                log.warning(f"Unexpected error loading account names config {config_path}: {e}")

        # Override with direct dict if provided
        if account_names:
            if isinstance(account_names, dict) and all(
                isinstance(k, str) and isinstance(v, str) for k, v in account_names.items()
            ):
                mappings.update(account_names)
                log.debug(f"Applied {len(account_names)} custom account name mapping(s)")
            else:
                log.warning("account_names parameter must be Dict[str, str], ignoring")

        return mappings

    def _get_default_config_prefix(self) -> str:
        """Return configuration prefix for Slack."""
        return "slack"

    def _get_default_secret_name(self) -> str:
        """Return default secret name for Slack credentials."""
        return "slack-credentials"

    def _create_service_client(self) -> WebClient:
        """Create Slack WebClient with credentials."""
        bot_token = self.credentials.get("bot_token") or self.credentials.get("token")
        if not bot_token:
            raise ValueError("Slack credentials must include 'bot_token' or 'token'")
        
        return WebClient(token=bot_token)

    def _collect_lambda_context(self) -> Dict[str, str]:
        """
        Collect Lambda runtime context with AWS client integration.
        
        Returns:
            Dictionary containing Lambda and AWS context
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

        # Get AWS account info using utility
        try:
            sts_client = create_aws_client("sts")
            account_info = sts_client.get_caller_identity()
            context["aws_account_id"] = account_info.get("Account", "Unknown")
            context["aws_account_arn"] = account_info.get("Arn", "Unknown")
            context["aws_account_name"] = self._account_names.get(
                context["aws_account_id"],
                f"Unknown Account ({context['aws_account_id']})"
            )
        except Exception as e:
            log.debug(f"Could not fetch AWS account info: {e}")
            context.update({
                "aws_account_id": "Unknown",
                "aws_account_name": "Unknown", 
                "aws_account_arn": "Unknown"
            })

        # Get deployment info
        context["deploy_time"] = self._get_deployment_age()
        context["deploy_config_type"] = self._detect_config_type()

        return context

    def _get_deployment_age(self) -> str:
        """
        Get Lambda function deployment age using AWS client factory.
        
        Returns:
            Human-friendly age string
        """
        try:
            function_name = self._lambda_context.get("function_name")
            if function_name == "Unknown":
                return "Unknown"

            lambda_client = create_aws_client("lambda")
            response = lambda_client.get_function(FunctionName=function_name)
            last_modified = response["Configuration"].get("LastModified")

            if last_modified:
                dt = datetime.fromisoformat(last_modified.replace("+0000", "+00:00"))
                now = datetime.now(dt.tzinfo)
                age = now - dt

                if age.total_seconds() < 60:
                    return f"{int(age.total_seconds())}s ago"
                elif age.total_seconds() < 3600:
                    return f"{int(age.total_seconds() / 60)}m ago"
                elif age.total_seconds() < 86400:
                    return f"{int(age.total_seconds() / 3600)}h ago"
                else:
                    return f"{int(age.total_seconds() / 86400)}d ago"

            return "Unknown"

        except Exception as e:
            log.debug(f"Could not fetch deployment time: {e}")
            return "Unknown"

    def _detect_config_type(self) -> str:
        """
        Detect deployment configuration type.
        
        Returns:
            Configuration type string
        """
        try:
            if os.path.exists("/var/task/.lambda-deploy.yml"):
                return "lambda-deploy v3.0+"
            elif os.path.exists("/var/task/serverless.yml"):
                return "serverless.yml"
            return "Unknown"
        except Exception:
            return "Unknown"

    def _create_lambda_header_block(self) -> List[Dict]:
        """
        Create Lambda context header block.

        Returns:
            List of Slack blocks for Lambda context
        """
        # Get account name from configured mappings or show as Unknown
        account_id = self._lambda_context['aws_account_id']
        simple_account = self._account_names.get(account_id, f"Unknown ({account_id})")

        # Build header lines
        line1 = f"🤖 {self._lambda_context['function_name']}"
        line2 = f"📍 {simple_account} ({account_id}) • {self._lambda_context['aws_region']}"
        line3 = f"📋 Log: `{self._lambda_context['log_group']}`"

        return [{
            "type": "context",
            "elements": [{
                "type": "mrkdwn",
                "text": f"{line1}\n{line2}\n{line3}"
            }]
        }]

    def _create_local_header_block(self) -> List[Dict]:
        """
        Create header block for local/manual execution.
        
        Returns:
            List of blocks for local context
        """
        import getpass
        from datetime import timezone

        try:
            username = getpass.getuser()
        except Exception:
            username = "Unknown"

        timestamp = datetime.now(timezone.utc).strftime("%H:%M UTC")
        account_name = self._account_names.get(
            self._lambda_context["aws_account_id"],
            f"Unknown ({self._lambda_context['aws_account_id']})"
        )

        line1 = f"👤 `Local Testing` • {username}"
        line2 = f"📍 {account_name} • {self._lambda_context['aws_region']} • {timestamp}"
        line3 = "📋 Context: Manual/Development Testing"

        return [{
            "type": "context",
            "elements": [{
                "type": "mrkdwn",
                "text": f"{line1}\n{line2}\n{line3}"
            }]
        }]

    @handle_client_errors(default_return=False)
    def send_message(
        self,
        channel: str,
        text: str,
        blocks: Optional[List[Dict]] = None,
        include_lambda_header: bool = True
    ) -> bool:
        """
        Send message to Slack channel with standardized error handling.
        
        Args:
            channel: Channel ID
            text: Fallback text
            blocks: Rich formatted blocks
            include_lambda_header: Whether to include context header
            
        Returns:
            True if successful, False otherwise
        """
        def _send_operation():
            # Add context header if requested
            if include_lambda_header:
                if self._lambda_context["function_name"] != "Unknown":
                    header_blocks = self._create_lambda_header_block()
                else:
                    header_blocks = self._create_local_header_block()

                if blocks:
                    blocks_with_header = header_blocks + blocks
                else:
                    blocks_with_header = header_blocks
            else:
                blocks_with_header = blocks

            response = self._service_client.chat_postMessage(
                channel=channel,
                text=text,
                blocks=blocks_with_header
            )

            if response["ok"]:
                log.info(
                    "Slack message sent successfully",
                    extra={"channel": channel, "ts": response["ts"]}
                )
                return True
            else:
                log.error(
                    "Slack API returned error",
                    extra={"error": response.get("error", "Unknown error")}
                )
                return False

        return self._execute_with_error_handling(
            "send_message",
            _send_operation,
            channel=channel
        )

    @handle_client_errors(default_return=False)
    def send_file(
        self,
        channel: str,
        content: str,
        filename: str,
        title: Optional[str] = None
    ) -> bool:
        """
        Upload file to Slack channel.
        
        Args:
            channel: Channel ID
            content: File content
            filename: File name
            title: Optional title
            
        Returns:
            True if successful, False otherwise
        """
        def _upload_operation():
            response = self._service_client.files_upload_v2(
                channel=channel,
                content=content,
                filename=filename,
                title=title or filename
            )

            if response["ok"]:
                log.info(
                    "File uploaded successfully",
                    extra={"channel": channel, "file_name": filename}
                )
                return True
            else:
                log.error(
                    "Slack file upload failed",
                    extra={"error": response.get("error", "Unknown error")}
                )
                return False

        return self._execute_with_error_handling(
            "send_file",
            _upload_operation,
            channel=channel,
            filename=filename
        )

    @handle_client_errors(default_return=False)
    def send_thread_reply(
        self,
        channel: str,
        thread_ts: str,
        text: str,
        blocks: Optional[List[Dict]] = None,
        include_lambda_header: bool = False
    ) -> bool:
        """
        Send thread reply with standardized error handling.
        
        Args:
            channel: Channel ID
            thread_ts: Parent message timestamp
            text: Reply text
            blocks: Optional blocks
            include_lambda_header: Whether to include header
            
        Returns:
            True if successful, False otherwise
        """
        def _reply_operation():
            # Add header if requested (uncommon for thread replies)
            blocks_with_header = blocks
            if include_lambda_header and self._lambda_context["function_name"] != "Unknown":
                header_blocks = self._create_lambda_header_block()
                if blocks:
                    blocks_with_header = header_blocks + blocks
                else:
                    blocks_with_header = header_blocks

            response = self._service_client.chat_postMessage(
                channel=channel,
                thread_ts=thread_ts,
                text=text,
                blocks=blocks_with_header
            )

            if response["ok"]:
                log.info(
                    "Thread reply sent successfully",
                    extra={
                        "channel": channel,
                        "thread_ts": thread_ts,
                        "reply_ts": response["ts"]
                    }
                )
                return True
            else:
                log.error(
                    "Failed to send thread reply",
                    extra={"error": response.get("error", "Unknown error")}
                )
                return False

        return self._execute_with_error_handling(
            "send_thread_reply",
            _reply_operation,
            channel=channel,
            thread_ts=thread_ts
        )

    @handle_client_errors(default_return=False)
    def update_message(
        self,
        channel: str,
        ts: str,
        text: str,
        blocks: Optional[List[Dict]] = None
    ) -> bool:
        """
        Update existing message.
        
        Args:
            channel: Channel ID
            ts: Message timestamp
            text: New text
            blocks: New blocks
            
        Returns:
            True if successful, False otherwise
        """
        def _update_operation():
            response = self._service_client.chat_update(
                channel=channel,
                ts=ts,
                text=text,
                blocks=blocks
            )

            if response["ok"]:
                log.info("Message updated successfully", extra={"channel": channel, "ts": ts})
                return True
            else:
                log.error("Failed to update message", extra={"error": response.get("error", "Unknown error")})
                return False

        return self._execute_with_error_handling(
            "update_message",
            _update_operation,
            channel=channel,
            ts=ts
        )

    @handle_client_errors(default_return=False)
    def add_reaction(self, channel: str, ts: str, emoji: str) -> bool:
        """
        Add reaction emoji to message.
        
        Args:
            channel: Channel ID
            ts: Message timestamp
            emoji: Emoji name (without colons)
            
        Returns:
            True if successful, False otherwise
        """
        def _reaction_operation():
            response = self._service_client.reactions_add(
                channel=channel,
                timestamp=ts,
                name=emoji
            )

            if response["ok"]:
                log.info("Reaction added successfully", extra={"channel": channel, "ts": ts, "emoji": emoji})
                return True
            else:
                log.error("Failed to add reaction", extra={"error": response.get("error", "Unknown error")})
                return False

        try:
            return self._execute_with_error_handling(
                "add_reaction",
                _reaction_operation,
                channel=channel,
                ts=ts,
                emoji=emoji
            )
        except SlackApiError as e:
            # Special case: already_reacted is not an error
            if e.response["error"] == "already_reacted":
                log.debug("Reaction already exists", extra={"channel": channel, "ts": ts, "emoji": emoji})
                return True
            raise

    def _perform_health_check(self):
        """Perform Slack API health check."""
        try:
            response = self._service_client.auth_test()
            if not response["ok"]:
                raise Exception(f"Slack auth test failed: {response.get('error', 'Unknown error')}")
        except Exception as e:
            raise Exception(f"Slack health check failed: {e}")

    def get_bot_info(self) -> Dict:
        """
        Get information about the Slack bot.
        
        Returns:
            Dictionary with bot information
        """
        try:
            response = self._service_client.auth_test()
            if response["ok"]:
                return {
                    "bot_id": response.get("bot_id"),
                    "user_id": response.get("user_id"),
                    "team": response.get("team"),
                    "team_id": response.get("team_id"),
                    "url": response.get("url")
                }
            else:
                raise Exception(f"Auth test failed: {response.get('error')}")
        except Exception as e:
            log.error(f"Failed to get bot info: {e}")
            return {"error": str(e)}