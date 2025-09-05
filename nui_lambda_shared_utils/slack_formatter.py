"""
Slack message formatting utilities for consistent block formatting across Lambda services.
Provides a builder pattern for creating Slack Block Kit messages.
"""

from typing import Dict, List, Any, Optional, Union
from datetime import datetime, timedelta
import pytz

# Service emoji mapping
SERVICE_EMOJI = {
    "auth": "🔐",
    "order": "📦",
    "records": "📦",
    "product": "📋",
    "processing": "⚙️",
    "surplus": "📊",
    "gateway": "🌐",
    "app": "📱",
    "tender": "🎯",
    "insights": "📈",
    "monitor": "👁️",
}

# Severity emoji mapping
SEVERITY_EMOJI = {"critical": "🚨", "warning": "⚠️", "info": "ℹ️", "success": "✅", "error": "❌"}

# Status emoji mapping
STATUS_EMOJI = {
    "active": "🟢",
    "pending": "🟡",
    "completed": "✅",
    "failed": "❌",
    "cancelled": "🚫",
    "ending_soon": "⏰",
}


# Number formatting helpers
def format_currency(value: float, currency: str = "NZD") -> str:
    """Format a number as currency."""
    return f"${value:,.2f} {currency}"


def format_percentage(value: float, decimals: int = 1) -> str:
    """Format a number as percentage."""
    return f"{value:.{decimals}f}%"


def format_number(value: Union[int, float], decimals: int = 0) -> str:
    """Format a number with thousands separators."""
    if isinstance(value, int) or decimals == 0:
        return f"{int(value):,}"
    return f"{value:,.{decimals}f}"


def format_nz_time(dt: Optional[datetime] = None) -> str:
    """Format datetime in NZ timezone."""
    if dt is None:
        dt = datetime.utcnow()
    elif not dt.tzinfo:
        dt = dt.replace(tzinfo=pytz.UTC)

    nz_tz = pytz.timezone("Pacific/Auckland")
    nz_time = dt.astimezone(nz_tz)
    return nz_time.strftime("%I:%M %p %Z")


def format_date_range(start: datetime, end: datetime) -> str:
    """Format a date range in NZ timezone."""
    nz_tz = pytz.timezone("Pacific/Auckland")
    if not start.tzinfo:
        start = start.replace(tzinfo=pytz.UTC)
    if not end.tzinfo:
        end = end.replace(tzinfo=pytz.UTC)

    start_nz = start.astimezone(nz_tz)
    end_nz = end.astimezone(nz_tz)

    if start_nz.date() == end_nz.date():
        return f"{start_nz.strftime('%b %d')} {start_nz.strftime('%I:%M %p')} - {end_nz.strftime('%I:%M %p %Z')}"
    else:
        return f"{start_nz.strftime('%b %d %I:%M %p')} - {end_nz.strftime('%b %d %I:%M %p %Z')}"


class SlackBlockBuilder:
    """
    Builder for creating Slack Block Kit messages with consistent formatting.

    Example:
        builder = SlackBlockBuilder()
        blocks = (builder
            .add_header("Daily Report", emoji="📊")
            .add_context(f"Generated at {format_nz_time()}")
            .add_divider()
            .add_section("Total Records", format_number(150))
            .add_fields([
                ("Revenue", format_currency(25000)),
                ("Growth", format_percentage(15.5))
            ])
            .build()
        )
    """

    def __init__(self):
        self.blocks = []

    def add_header(self, text: str, emoji: Optional[str] = None) -> "SlackBlockBuilder":
        """Add a header block."""
        header_text = f"{emoji} {text}" if emoji else text
        self.blocks.append({"type": "header", "text": {"type": "plain_text", "text": header_text}})
        return self

    def add_section(self, text: str, value: Optional[str] = None, emoji: Optional[str] = None) -> "SlackBlockBuilder":
        """Add a section block with optional value."""
        if value:
            section_text = f"*{text}:* {value}"
        else:
            section_text = text

        if emoji:
            section_text = f"{emoji} {section_text}"

        self.blocks.append({"type": "section", "text": {"type": "mrkdwn", "text": section_text}})
        return self

    def add_fields(self, fields: List[tuple], columns: int = 2) -> "SlackBlockBuilder":
        """Add a section with multiple fields."""
        field_blocks = []
        for label, value in fields:
            field_blocks.append({"type": "mrkdwn", "text": f"*{label}:*\n{value}"})

        # Ensure even number of fields for proper layout
        while len(field_blocks) % columns != 0:
            field_blocks.append({"type": "mrkdwn", "text": " "})

        self.blocks.append({"type": "section", "fields": field_blocks[:10]})  # Slack limit
        return self

    def add_context(self, text: str) -> "SlackBlockBuilder":
        """Add a context block."""
        self.blocks.append({"type": "context", "elements": [{"type": "mrkdwn", "text": text}]})
        return self

    def add_divider(self) -> "SlackBlockBuilder":
        """Add a divider block."""
        self.blocks.append({"type": "divider"})
        return self

    def add_metrics_list(self, metrics: List[Dict[str, Any]]) -> "SlackBlockBuilder":
        """Add a formatted list of metrics."""
        for metric in metrics:
            text = f"• *{metric['label']}:* {metric['value']}"
            if "change" in metric:
                change_emoji = "📈" if metric["change"] > 0 else "📉"
                text += f" {change_emoji} {format_percentage(metric['change'])}"

            self.blocks.append({"type": "section", "text": {"type": "mrkdwn", "text": text}})
        return self

    def add_activity_meter(self, value: int, max_value: int = 100, width: int = 10) -> "SlackBlockBuilder":
        """Add a visual activity meter."""
        filled = int((value / max_value) * width)
        meter = "█" * filled + "░" * (width - filled)
        percentage = (value / max_value) * 100

        self.blocks.append(
            {
                "type": "section",
                "text": {"type": "mrkdwn", "text": f"Activity Level: {meter} {format_percentage(percentage)}"},
            }
        )
        return self

    def add_error_summary(self, errors: List[Dict[str, Any]], limit: int = 3) -> "SlackBlockBuilder":
        """Add a formatted error summary."""
        if not errors:
            self.add_section("No errors detected", emoji="✅")
            return self

        error_text = f"*Top {min(len(errors), limit)} Errors:*\n"
        for error in errors[:limit]:
            error_text += f"• `{error.get('key', 'Unknown')}` - {error.get('doc_count', 0)} occurrences\n"

        self.blocks.append({"type": "section", "text": {"type": "mrkdwn", "text": error_text}})
        return self

    def add_chart(
        self, title: str, data_points: List[float], labels: Optional[List[str]] = None
    ) -> "SlackBlockBuilder":
        """Add a simple ASCII chart."""
        max_val = max(data_points) if data_points else 1
        chart_height = 5

        chart_text = f"*{title}*\n```\n"

        # Create the chart
        for row in range(chart_height, 0, -1):
            threshold = (row / chart_height) * max_val
            line = ""
            for val in data_points:
                if val >= threshold:
                    line += "█ "
                else:
                    line += "  "
            chart_text += line + "\n"

        # Add labels if provided
        if labels:
            chart_text += "-" * (len(data_points) * 2) + "\n"
            label_line = ""
            for i, label in enumerate(labels[: len(data_points)]):
                if i < len(data_points):
                    label_line += label[:1] + " "
            chart_text += label_line + "\n"

        chart_text += "```"

        self.blocks.append({"type": "section", "text": {"type": "mrkdwn", "text": chart_text}})
        return self

    def add_alert(
        self, severity: str, service: str, message: str, details: Optional[Dict] = None
    ) -> "SlackBlockBuilder":
        """Add a formatted alert block."""
        severity_emoji = SEVERITY_EMOJI.get(severity.lower(), "❓")
        service_emoji = SERVICE_EMOJI.get(service.lower(), "🔧")

        self.add_header(f"Alert - {severity.upper()}", emoji=severity_emoji)
        self.add_fields(
            [
                ("Service", f"{service_emoji} {service.upper()}"),
                ("Time", format_nz_time()),
                ("Environment", "Production"),
                ("Severity", severity.title()),
            ]
        )
        self.add_section(message)

        if details:
            detail_text = "*Details:*\n"
            for key, value in details.items():
                detail_text += f"• {key}: {value}\n"
            self.add_section(detail_text)

        return self

    def add_summary_stats(self, stats: Dict[str, Any]) -> "SlackBlockBuilder":
        """Add a formatted summary statistics section."""
        self.add_section("📊 *Summary Statistics*")

        fields = []
        for key, value in stats.items():
            label = key.replace("_", " ").title()
            if isinstance(value, (int, float)):
                if "percent" in key or "rate" in key:
                    formatted_value = format_percentage(value)
                elif "amount" in key or "revenue" in key or "value" in key:
                    formatted_value = format_currency(value)
                else:
                    formatted_value = format_number(value)
            else:
                formatted_value = str(value)

            fields.append((label, formatted_value))

        self.add_fields(fields)
        return self

    def add_code_block(self, code: str, language: str = "") -> "SlackBlockBuilder":
        """Add a code block."""
        self.blocks.append({"type": "section", "text": {"type": "mrkdwn", "text": f"```{language}\n{code}\n```"}})
        return self

    def build(self) -> List[Dict]:
        """Build and return the blocks list."""
        # Ensure we don't exceed Slack's 50 block limit
        return self.blocks[:50]

    def clear(self) -> "SlackBlockBuilder":
        """Clear all blocks and start fresh."""
        self.blocks = []
        return self


# Convenience functions for common patterns
def format_daily_header(report_name: str, time_window: Optional[Dict] = None) -> List[Dict]:
    """Create a standard daily report header."""
    builder = SlackBlockBuilder()
    builder.add_header(f"Daily {report_name}", emoji="📈")

    if time_window:
        builder.add_context(f"*Period:* {time_window.get('start', 'N/A')} - {time_window.get('end', 'N/A')}")
    else:
        builder.add_context(f"*Generated:* {format_nz_time()}")

    builder.add_divider()
    return builder.build()


def format_weekly_header(report_name: str, week_start: datetime) -> List[Dict]:
    """Create a standard weekly report header."""
    builder = SlackBlockBuilder()
    builder.add_header(f"Weekly {report_name}", emoji="📊")

    week_end = week_start + timedelta(days=6)
    builder.add_context(f"*Week of:* {format_date_range(week_start, week_end)}")
    builder.add_divider()
    return builder.build()


def format_error_alert(service: str, error_rate: float, top_errors: List[Dict]) -> List[Dict]:
    """Create a standard error alert."""
    builder = SlackBlockBuilder()
    severity = "critical" if error_rate > 20 else "warning"

    builder.add_alert(
        severity=severity,
        service=service,
        message=f"Error rate {format_percentage(error_rate)} exceeds threshold",
        details={"threshold": "10%", "current": format_percentage(error_rate)},
    )
    builder.add_error_summary(top_errors)

    return builder.build()
