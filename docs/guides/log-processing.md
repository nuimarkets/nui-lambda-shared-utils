# Log Processing Guide

This guide covers the log processing utilities for Lambda functions that stream
CloudWatch logs to Elasticsearch via Kinesis.

## Overview

The `log_processors` module provides utilities for:

- Extracting CloudWatch logs from Kinesis stream records
- Deriving Elasticsearch index names from log metadata
- Type definitions for CloudWatch log structures

## Quick Start

### Basic Usage

```python
from elasticsearch.helpers import streaming_bulk
from nui_lambda_shared_utils.log_processors import (
    extract_cloudwatch_logs_from_kinesis,
    derive_index_name,
)
from datetime import datetime, timezone


def process_log_events(log_group: str, log_stream: str, log_events: list):
    """Process log events and yield ES documents."""
    for event in log_events:
        ts = datetime.fromtimestamp(event["timestamp"] / 1000.0, tz=timezone.utc)

        yield {
            "_index": derive_index_name(log_group, ts),
            "_id": event["id"],
            "_source": {
                "message": event["message"],
                "@timestamp": ts.isoformat(),
                "log": {"group": log_group, "stream": log_stream},
            }
        }


def handler(event, context):
    """Lambda handler for Kinesis -> ES streaming."""
    es = get_elasticsearch_client()

    for ok, response in streaming_bulk(
        client=es,
        actions=extract_cloudwatch_logs_from_kinesis(
            event["Records"],
            process_fn=process_log_events
        ),
        chunk_size=100,
        raise_on_error=True,
    ):
        if not ok:
            logger.error(f"Document indexing failed: {response}")
```

### Error Handling

Provide an `on_error` callback to handle failures without stopping the entire batch:

```python
def handle_processing_error(exception: Exception, record_data: dict):
    """Log errors but continue processing."""
    logger.error(f"Failed to process record: {exception}")
    # Optionally send to dead letter queue, metrics, etc.


for doc in extract_cloudwatch_logs_from_kinesis(
    event["Records"],
    process_fn=process_log_events,
    on_error=handle_processing_error
):
    # Documents from successfully processed records
    pass
```

### Custom Index Naming

Override the default index naming pattern:

```python
from nui_lambda_shared_utils.log_processors import derive_index_name

# Default: log-{service}-{YYYY}-m{MM}
derive_index_name("/aws/lambda/orders", ts)
# -> "log-orders-2025-m01"

# Custom target
derive_index_name("/aws/lambda/orders", ts, target_override="order-service")
# -> "log-order-service-2025-m01"

# Custom prefix and date format
derive_index_name("/aws/lambda/orders", ts, prefix="logs", date_format="%Y-%m-%d")
# -> "logs-orders-2025-01-15"
```

## Migration Guide

### From inline Kinesis extraction

Replace:

```python
# Before
def extract_logs(records):
    for row in records:
        raw_data = row["kinesis"]["data"]
        data = json.loads(
            zlib.decompress(base64.b64decode(raw_data), 16 + zlib.MAX_WBITS).decode("utf-8")
        )
        if data["messageType"] == "CONTROL_MESSAGE":
            continue
        for item in process_log_events(...):
            yield item
```

With:

```python
# After
from nui_lambda_shared_utils.log_processors import extract_cloudwatch_logs_from_kinesis

for doc in extract_cloudwatch_logs_from_kinesis(event["Records"], process_log_events):
    yield doc
```

## API Reference

### `extract_cloudwatch_logs_from_kinesis()`

Extract CloudWatch logs from Kinesis stream records.

**Parameters:**

- `records`: List of Kinesis event records (`event["Records"]`)
- `process_fn`: Callback to process log events
- `on_error`: Optional error handler (if None, exceptions are raised)

**Yields:** Dict documents ready for `streaming_bulk()`

### `derive_index_name()`

Derive Elasticsearch index name from log metadata.

**Parameters:**

- `log_group`: CloudWatch log group name
- `timestamp`: Event timestamp for date suffix
- `prefix`: Index name prefix (default: "log")
- `date_format`: strftime format (default: "%Y-m%m")
- `target_override`: Custom service name (optional)

**Returns:** Index name string
