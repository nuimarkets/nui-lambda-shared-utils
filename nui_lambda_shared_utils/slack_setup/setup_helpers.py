"""
Helper functions for Slack setup operations.
"""

import os
import sys
import logging
from typing import List, Dict, Optional
from slack_sdk import WebClient
from slack_sdk.errors import SlackApiError

log = logging.getLogger(__name__)


class SlackSetupHelper:
    """Helper utilities for Slack setup operations."""

    def __init__(self, token: Optional[str] = None):
        """Initialize with Slack token."""
        self.token = token or os.environ.get("SLACK_BOT_TOKEN")
        if not self.token:
            raise ValueError("No Slack bot token provided")

        self.client = WebClient(token=self.token)

    def test_channel_access(self, channel_ids: List[str]) -> Dict[str, bool]:
        """
        Test if bot can post to channels.

        Args:
            channel_ids: List of channel IDs to test

        Returns:
            Dict mapping channel IDs to success status
        """
        results = {}

        for channel_id in channel_ids:
            try:
                self.client.chat_postMessage(channel=channel_id, text="🔧 Testing channel access...")
                results[channel_id] = True
                log.info(f"✅ Can post to channel {channel_id}")
            except SlackApiError as e:
                results[channel_id] = False
                log.error(f"❌ Cannot post to channel {channel_id}: {e.response['error']}")

        return results

    def get_channel_info(self, channel_id: str) -> Optional[Dict]:
        """Get detailed channel information."""
        try:
            response = self.client.conversations_info(channel=channel_id)
            return response["channel"]
        except SlackApiError as e:
            log.error(f"Error getting channel info: {e}")
            return None

    def list_bot_channels(self) -> List[Dict]:
        """List all channels the bot is a member of."""
        channels = []
        cursor = None

        try:
            while True:
                response = self.client.conversations_list(exclude_archived=True, types="public_channel", cursor=cursor)

                # Filter to only channels bot is member of
                for channel in response["channels"]:
                    if channel.get("is_member", False):
                        channels.append(
                            {
                                "id": channel["id"],
                                "name": channel["name"],
                                "purpose": channel.get("purpose", {}).get("value", ""),
                                "topic": channel.get("topic", {}).get("value", ""),
                                "num_members": channel.get("num_members", 0),
                            }
                        )

                cursor = response.get("response_metadata", {}).get("next_cursor")
                if not cursor:
                    break

        except SlackApiError as e:
            log.error(f"Error listing channels: {e}")

        return channels

    def validate_bot_permissions(self) -> Dict[str, bool]:
        """Check if bot has required permissions."""
        required_scopes = ["channels:manage", "channels:join", "chat:write", "channels:read", "users:read"]

        try:
            response = self.client.auth_test()
            # Note: auth.test doesn't return scopes in newer apps
            # This would need to be checked via the app's OAuth settings

            return {
                "authenticated": True,
                "bot_id": response.get("user_id"),
                "bot_name": response.get("user"),
                "team": response.get("team"),
                "url": response.get("url"),
            }

        except SlackApiError as e:
            log.error(f"Auth test failed: {e}")
            return {"authenticated": False, "error": str(e)}


def prompt_for_token() -> str:
    """Interactive prompt for Slack bot token."""
    print("\n" + "=" * 60)
    print("Slack Bot Token Required")
    print("=" * 60)
    print("\nTo get your bot token:")
    print("1. Go to https://api.slack.com/apps")
    print("2. Select your app (or create a new one)")
    print("3. Go to 'OAuth & Permissions'")
    print("4. Copy the 'Bot User OAuth Token' (starts with xoxb-)")
    print("\nRequired OAuth Scopes:")
    print("  - channels:manage    (create channels)")
    print("  - channels:join      (join channels)")
    print("  - chat:write         (send messages)")
    print("  - channels:read      (list channels)")
    print("  - users:read         (look up users)")
    print("  - channels:write.invites (invite users)")
    print("\n" + "=" * 60)

    token = input("\nEnter Bot Token (xoxb-...): ").strip()

    if not token.startswith("xoxb-"):
        print("\n⚠️  Warning: Token doesn't start with 'xoxb-'")
        confirm = input("Continue anyway? (y/n): ")
        if confirm.lower() != "y":
            sys.exit(1)

    return token


def print_channel_summary(channel_map: Dict[str, str], service_name: str):
    """Print summary of created channels."""
    print("\n" + "=" * 60)
    print(f"Channel Setup Complete for {service_name}")
    print("=" * 60)

    if not channel_map:
        print("\n❌ No channels were created")
        return

    print("\n✅ Channels ready:")
    for name, channel_id in channel_map.items():
        print(f"  #{name:<30} ID: {channel_id}")

    print("\n📋 Next steps:")
    print("1. Use the channel IDs in your application configuration")
    print("2. Deploy your application")
    print("3. Test by sending messages to the channels")

    print("\n💡 Tips:")
    print("- Bot is already in all channels")
    print("- Invited users have been added to channels")
    print("- Channels are public for transparency")


def confirm_channel_creation(definitions: List["ChannelDefinition"], existing: Dict[str, Optional[str]]) -> bool:
    """
    Interactive confirmation for channel creation.

    Args:
        definitions: Channel definitions to create
        existing: Map of existing channels

    Returns:
        True if user confirms, False otherwise
    """
    print("\n" + "=" * 60)
    print("Channel Creation Plan")
    print("=" * 60)

    to_create = []
    already_exist = []

    for definition in definitions:
        if existing.get(definition.name):
            already_exist.append(definition)
        else:
            to_create.append(definition)

    if already_exist:
        print("\n✅ Existing channels (will configure/join):")
        for definition in already_exist:
            print(f"  #{definition.name}")
            print(f"    Purpose: {definition.purpose}")

    if to_create:
        print("\n🆕 Channels to create:")
        for definition in to_create:
            print(f"  #{definition.name}")
            print(f"    Purpose: {definition.purpose}")
            print(f"    Topic: {definition.topic}")
            if definition.invite_users:
                print(f"    Inviting: {', '.join(definition.invite_users)}")

    if not to_create and not already_exist:
        print("\n❌ No channels to process")
        return False

    print("\n" + "=" * 60)
    response = input("\nProceed with channel setup? (y/n): ")
    return response.lower() == "y"
