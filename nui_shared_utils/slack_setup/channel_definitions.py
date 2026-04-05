"""
Channel definition models and configuration parser.
"""

import os
import yaml
from typing import List, Dict, Optional, Any
from dataclasses import dataclass, field


@dataclass
class ChannelDefinition:
    """Represents a Slack channel configuration."""

    name: str
    purpose: str
    description: str
    topic: str
    invite_users: List[str] = field(default_factory=list)
    service: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary representation."""
        return {
            "name": self.name,
            "purpose": self.purpose,
            "description": self.description,
            "topic": self.topic,
            "invite_users": self.invite_users,
            "service": self.service,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any], service: Optional[str] = None) -> "ChannelDefinition":
        """Create from dictionary."""
        return cls(
            name=data["name"],
            purpose=data["purpose"],
            description=data["description"],
            topic=data["topic"],
            invite_users=data.get("invite_users", []),
            service=service or data.get("service"),
        )


def load_channel_config(config_path: str) -> List[ChannelDefinition]:
    """
    Load channel definitions from YAML config file.

    Args:
        config_path: Path to YAML config file

    Returns:
        List of channel definitions

    Example YAML:
        service: business-insights
        default_invite_users:
          - tim
        channels:
          - name: insights-daily
            purpose: Daily operational metrics
            description: Daily business insights for platform operations
            topic: 📊 Daily business metrics
          - name: insights-executive
            purpose: Executive summaries
            description: Weekly executive reports
            topic: 🎯 Weekly executive summaries
            invite_users:
              - tim
              - john
    """
    if not os.path.exists(config_path):
        raise FileNotFoundError(f"Config file not found: {config_path}")

    with open(config_path, "r") as f:
        config = yaml.safe_load(f)

    if not config or "channels" not in config:
        raise ValueError("Invalid config file: missing 'channels' section")

    service = config.get("service")
    default_invite_users = config.get("default_invite_users", [])

    definitions = []
    for channel_data in config["channels"]:
        # Apply defaults
        if "invite_users" not in channel_data and default_invite_users:
            channel_data["invite_users"] = default_invite_users

        definition = ChannelDefinition.from_dict(channel_data, service)
        definitions.append(definition)

    return definitions


def generate_serverless_config(channel_map: Dict[str, str], service_name: str, output_format: str = "yaml") -> str:
    """
    Generate serverless.yml configuration snippet.

    Args:
        channel_map: Dict mapping channel names to IDs
        service_name: Name of the service
        output_format: 'yaml' or 'env'

    Returns:
        Configuration snippet
    """
    if output_format == "yaml":
        lines = ["# Add this to your serverless.yml custom section:", "custom:", "  slack:", "    channels:"]

        # Map channel names to config keys
        key_mapping = {
            "alerts": "alerts",
            "health": "health",
            "debug": "debug",
            "daily": "daily",
            "weekly": "weekly",
            "executive": "executive",
            "insights": "insights",
            "operations": "operations",
            "activity": "activity",
        }

        for channel_name, channel_id in channel_map.items():
            # Extract key from channel name
            key = None
            for keyword, config_key in key_mapping.items():
                if keyword in channel_name:
                    key = config_key
                    break

            if not key:
                # Default to last part of channel name
                key = channel_name.split("-")[-1]

            lines.append(f'      {key}: "{channel_id}"  # {channel_name}')

        return "\n".join(lines)

    elif output_format == "env":
        lines = [
            "# Environment variables for your application:",
        ]

        for channel_name, channel_id in channel_map.items():
            env_key = channel_name.upper().replace("-", "_") + "_CHANNEL"
            lines.append(f"{env_key}={channel_id}")

        return "\n".join(lines)

    else:
        raise ValueError(f"Unknown output format: {output_format}")


def validate_channel_names(definitions: List[ChannelDefinition]) -> List[str]:
    """
    Validate channel names according to Slack rules.

    Args:
        definitions: List of channel definitions

    Returns:
        List of validation errors (empty if all valid)
    """
    errors = []

    for definition in definitions:
        name = definition.name

        # Check length
        if len(name) > 80:
            errors.append(f"{name}: Channel name too long (max 80 chars)")

        # Check for valid characters
        if not all(c.isalnum() or c in "-_" for c in name):
            errors.append(f"{name}: Invalid characters (use only letters, numbers, hyphens, underscores)")

        # Check lowercase
        if name != name.lower():
            errors.append(f"{name}: Channel names must be lowercase")

        # Check doesn't start with special chars
        if name and name[0] in "-_":
            errors.append(f"{name}: Channel name cannot start with hyphen or underscore")

    return errors
