# Elasticsearch Integration Guide

Comprehensive guide for using Elasticsearch utilities in `nui-lambda-shared-utils`.

**Last Updated**: 2026-01-30

## Overview

The package provides Elasticsearch integration through:

- **ElasticsearchClient** - Search, aggregations, bulk indexing, health checks
- **ElasticsearchQueryBuilder** - Fluent query construction

## Quick Start

```python
import nui_lambda_shared_utils as nui

# Configure Elasticsearch credentials
nui.configure(es_credentials_secret="prod/elasticsearch-credentials")

# Create client and search
es = nui.ElasticsearchClient()
results = es.search(
    index="logs-*",
    body={"query": {"match": {"level": "error"}}}
)
```

## Installation

Install with the elasticsearch extra:

```bash
pip install nui-lambda-shared-utils[elasticsearch]
```

## Configuration

### AWS Secrets Manager Setup

Create a secret with your Elasticsearch credentials:

```bash
aws secretsmanager create-secret \
  --name "elasticsearch-credentials" \
  --description "Elasticsearch credentials" \
  --secret-string '{"username":"elastic","password":"YOUR_PASSWORD"}'
```

**Secret Format:**

```json
{
  "username": "elastic",
  "password": "YOUR_PASSWORD"
}
```

### Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `ES_HOST` | Elasticsearch host | `localhost:9200` |
| `ES_CREDENTIALS_SECRET` | Secret name for credentials | `elasticsearch-credentials` |

### Programmatic Configuration

```python
import nui_lambda_shared_utils as nui

# Configure at startup
nui.configure(
    es_host="elasticsearch.example.com:9200",
    es_credentials_secret="prod/es-creds"
)

# Or pass directly to client
client = nui.ElasticsearchClient(
    host="elasticsearch.example.com:9200",
    secret_name="prod/es-creds"
)
```

## Basic Operations

### Search

```python
from nui_lambda_shared_utils import ElasticsearchClient

es = ElasticsearchClient()

# Simple search
results = es.search(
    index="logs-*",
    body={"query": {"match_all": {}}},
    size=100
)

for doc in results:
    print(doc["message"])
```

### Aggregations

```python
# Get aggregation results
aggs = es.aggregate(
    index="logs-*",
    body={
        "query": {"range": {"@timestamp": {"gte": "now-1h"}}},
        "aggs": {
            "by_level": {"terms": {"field": "level.keyword"}},
            "avg_duration": {"avg": {"field": "duration"}}
        }
    }
)

print(aggs["by_level"]["buckets"])
```

### Count Documents

```python
# Count all documents
total = es.count(index="logs-*")

# Count with query
errors = es.count(
    index="logs-*",
    body={"query": {"term": {"level": "error"}}}
)
```

## Bulk Indexing

### streaming_bulk Method

For efficient bulk indexing of documents, use the `streaming_bulk` method:

```python
from nui_lambda_shared_utils import ElasticsearchClient

es = ElasticsearchClient()

def generate_documents():
    """Yield documents to index."""
    for item in items:
        yield {
            "_index": "my-index",
            "_source": {
                "field1": item.field1,
                "field2": item.field2,
                "@timestamp": item.timestamp.isoformat()
            }
        }

# Index documents with automatic error handling
success, failed = es.streaming_bulk(
    actions=generate_documents(),
    chunk_size=100,
    max_retries=2
)

print(f"Indexed {success} documents, {failed} failures")
```

### Parameters

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `actions` | Iterator[Dict] | required | Iterator yielding action dictionaries |
| `chunk_size` | int | 100 | Documents per batch |
| `max_retries` | int | 2 | Retries for failed documents |
| `raise_on_error` | bool | False | Raise exception on first error |

### Action Dictionary Format

Each yielded action should contain:

```python
{
    "_index": "target-index-name",
    "_source": {
        # Your document fields
    },
    # Optional fields:
    "_id": "custom-id",  # Auto-generated if not provided
    "_op_type": "index"  # "index", "create", "update", "delete"
}
```

### Error Handling

By default, `streaming_bulk` logs errors but continues processing:

```python
# Default: log errors, continue processing
success, failed = es.streaming_bulk(generate_docs())
if failed > 0:
    logger.warning(f"{failed} documents failed to index")

# Strict mode: raise on first error
try:
    success, failed = es.streaming_bulk(
        generate_docs(),
        raise_on_error=True
    )
except Exception as e:
    logger.error(f"Bulk indexing failed: {e}")
```

### Integration with Log Processors

The `streaming_bulk` method pairs well with log extraction utilities:

```python
from nui_lambda_shared_utils import ElasticsearchClient

es = ElasticsearchClient()

def extract_logs_from_kinesis(records):
    """Extract logs from Kinesis records."""
    for record in records:
        # Your log extraction logic
        yield {
            "_index": f"logs-{service_name}-{date}",
            "_source": log_data
        }

def handler(event, context):
    success, failed = es.streaming_bulk(
        actions=extract_logs_from_kinesis(event["Records"]),
        chunk_size=200
    )
    return {"indexed": success, "failed": failed}
```

## Service Statistics

Get comprehensive service statistics:

```python
stats = es.get_service_stats(
    service="order",
    hours=24,
    index_prefix="logs"
)

print(f"Total requests: {stats['total_count']}")
print(f"Error rate: {stats['error_rate']:.2f}%")
print(f"P95 latency: {stats['p95_response_time']}ms")
```

## Recent Errors

Retrieve recent error logs:

```python
errors = es.get_recent_errors(
    service="auth",
    hours=1,
    limit=10
)

for error in errors:
    print(f"{error['@timestamp']}: {error['message']}")
```

## Health Checks

### Cluster Health

```python
# Get cluster info
info = es.get_cluster_info()
print(f"Cluster: {info['cluster_name']}, Status: {info['cluster_status']}")

# Check health (raises on failure)
health = es.check_health()
```

### Index Information

```python
indices = es.get_indices_info(pattern="logs-*")
for idx in indices:
    print(f"{idx['index']}: {idx['docs.count']} docs, {idx['store.size']}")
```

## Query Builder

For complex queries, use the query builder:

```python
from nui_lambda_shared_utils import ElasticsearchQueryBuilder

query = (
    ElasticsearchQueryBuilder()
    .must_match("service", "order")
    .must_range("@timestamp", gte="now-1h")
    .filter_term("level", "error")
    .sort("@timestamp", "desc")
    .build()
)

results = es.search(index="logs-*", body=query)
```

## Lambda Handler Pattern

Recommended pattern for Lambda functions:

```python
import os
import nui_lambda_shared_utils as nui
from nui_lambda_shared_utils import (
    ElasticsearchClient,
    get_powertools_logger,
    powertools_handler
)

# Configure once at module level
nui.configure(
    es_host=os.environ.get("ES_HOST"),
    es_credentials_secret=os.environ.get("ES_CREDENTIALS_SECRET")
)

logger = get_powertools_logger("my-service")


@powertools_handler(service_name="my-service")
def handler(event, context):
    es = ElasticsearchClient()

    # Your indexing logic
    success, failed = es.streaming_bulk(
        actions=process_records(event["Records"])
    )

    logger.info(f"Indexed {success} documents, {failed} failures")
    return {"statusCode": 200, "body": f"Processed {success} documents"}
```

## Troubleshooting

### Connection Issues

```python
# Test connectivity
try:
    es = ElasticsearchClient()
    info = es.get_cluster_info()
    print(f"Connected to: {info['cluster_name']}")
except Exception as e:
    print(f"Connection failed: {e}")
```

### Common Errors

| Error | Cause | Solution |
|-------|-------|----------|
| `AuthenticationException` | Invalid credentials | Check secret values |
| `ConnectionError` | Host unreachable | Verify `ES_HOST` and network |
| `TransportError(403)` | Missing permissions | Check index permissions |

### Debug Logging

Enable debug logging for troubleshooting:

```python
import logging
logging.getLogger("elasticsearch").setLevel(logging.DEBUG)
```
