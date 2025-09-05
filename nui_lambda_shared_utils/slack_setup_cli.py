#!/usr/bin/env python3
"""
CLI for Slack channel setup across Lambda services.

Usage:
    python -m lambda_shared_utils.slack_setup_cli --config channel_config.yaml
"""
import os
import sys
import argparse
import logging
from pathlib import Path

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent))

from slack_setup import ChannelCreator, load_channel_config
from slack_setup.channel_definitions import validate_channel_names, generate_serverless_config
from slack_setup.setup_helpers import (
    SlackSetupHelper,
    prompt_for_token,
    print_channel_summary,
    confirm_channel_creation,
)

# Set up logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(name)s - %(levelname)s - %(message)s")
log = logging.getLogger(__name__)


def main():
    """Main CLI entrypoint."""
    parser = argparse.ArgumentParser(
        description="Set up Slack channels for Lambda services",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Create channels from config
  python -m lambda_shared_utils.slack_setup_cli --config scripts/channel_config.yaml
  
  # Check existing channels only
  python -m lambda_shared_utils.slack_setup_cli --config scripts/channel_config.yaml --check-only
  
  # Generate serverless.yml snippet
  python -m lambda_shared_utils.slack_setup_cli --config scripts/channel_config.yaml --output serverless-channels.yml
  
  # Use specific token
  SLACK_BOT_TOKEN=xoxb-... python -m lambda_shared_utils.slack_setup_cli --config channel_config.yaml
        """,
    )

    parser.add_argument("--config", required=True, help="Path to channel configuration YAML file")

    parser.add_argument("--token", help="Slack bot token (or use SLACK_BOT_TOKEN env var)")

    parser.add_argument("--check-only", action="store_true", help="Only check existing channels, do not create")

    parser.add_argument("--output", help="Output file for serverless.yml configuration")

    parser.add_argument(
        "--output-format",
        choices=["yaml", "env"],
        default="yaml",
        help="Output format for configuration (default: yaml)",
    )

    parser.add_argument("--no-interactive", action="store_true", help="Skip interactive confirmations")

    parser.add_argument("--validate-only", action="store_true", help="Only validate channel names, do not create")

    parser.add_argument("--test-access", action="store_true", help="Test bot access to created channels")

    args = parser.parse_args()

    try:
        # Load channel configuration
        log.info(f"Loading configuration from {args.config}")
        definitions = load_channel_config(args.config)

        if not definitions:
            log.error("No channel definitions found in config")
            return 1

        # Extract service name from first definition or config path
        service_name = definitions[0].service or Path(args.config).parent.parent.name

        print(f"\n🚀 Slack Setup for {service_name}")
        print("=" * 60)

        # Validate channel names
        errors = validate_channel_names(definitions)
        if errors:
            log.error("Channel name validation failed:")
            for error in errors:
                print(f"  ❌ {error}")
            return 1

        if args.validate_only:
            print("✅ All channel names are valid")
            return 0

        # Get Slack token
        token = args.token or os.environ.get("SLACK_BOT_TOKEN")
        if not token and not args.check_only:
            token = prompt_for_token()
            os.environ["SLACK_BOT_TOKEN"] = token

        # Initialize channel creator
        creator = ChannelCreator(token)
        helper = SlackSetupHelper(token)

        # Check bot authentication
        auth_info = helper.validate_bot_permissions()
        if auth_info.get("authenticated"):
            print(f"\n✅ Authenticated as: {auth_info['bot_name']} (@{auth_info['bot_id']})")
            print(f"   Team: {auth_info['team']}")
        else:
            log.error(f"Authentication failed: {auth_info.get('error')}")
            return 1

        # Check existing channels
        channel_names = [d.name for d in definitions]
        existing_channels = creator.check_existing_channels(channel_names)

        print(f"\n📊 Channel Status:")
        for name, channel_id in existing_channels.items():
            if channel_id:
                print(f"  ✅ #{name} exists (ID: {channel_id})")
            else:
                print(f"  ❌ #{name} does not exist")

        if args.check_only:
            return 0

        # Confirm creation
        if not args.no_interactive:
            if not confirm_channel_creation(definitions, existing_channels):
                print("\nChannel creation cancelled")
                return 0

        # Create/configure channels
        print("\n🔨 Setting up channels...")
        channel_map = creator.create_channels(definitions)

        if not channel_map:
            log.error("No channels were created")
            return 1

        # Test access if requested
        if args.test_access:
            print("\n🧪 Testing channel access...")
            test_results = helper.test_channel_access(list(channel_map.values()))
            for channel_id, success in test_results.items():
                channel_name = [k for k, v in channel_map.items() if v == channel_id][0]
                if success:
                    print(f"  ✅ Can post to #{channel_name}")
                else:
                    print(f"  ❌ Cannot post to #{channel_name}")

        # Generate configuration
        if args.output or not args.no_interactive:
            config_output = generate_serverless_config(channel_map, service_name, args.output_format)

            if args.output:
                with open(args.output, "w") as f:
                    f.write(config_output)
                print(f"\n✅ Configuration written to {args.output}")
            else:
                print("\n" + "=" * 60)
                print("Configuration Output:")
                print("=" * 60)
                print(config_output)

        # Print summary
        print_channel_summary(channel_map, service_name)

        return 0

    except FileNotFoundError as e:
        log.error(f"Configuration file not found: {e}")
        return 1
    except ValueError as e:
        log.error(f"Configuration error: {e}")
        return 1
    except KeyboardInterrupt:
        print("\n\nSetup cancelled by user")
        return 130
    except Exception as e:
        log.error(f"Unexpected error: {e}", exc_info=True)
        return 1


if __name__ == "__main__":
    sys.exit(main())
