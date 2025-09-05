"""
Shared Elasticsearch client for AWS Lambda functions.
"""

import os
import logging
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any
from elasticsearch import Elasticsearch

from .secrets_helper import get_secret
from .config import get_config

log = logging.getLogger(__name__)


class ElasticsearchClient:
    def __init__(self, host: Optional[str] = None, secret_name: Optional[str] = None):
        """
        Initialize Elasticsearch client.

        Args:
            host: Override default ES host (if not provided, uses config or env vars)
            secret_name: Override default secret name (if not provided, uses config or env vars)
        """
        config = get_config()

        # Use parameter > environment > config defaults
        self.host = host or os.environ.get("ES_HOST") or config.es_host
        secret = secret_name or os.environ.get("ES_CREDENTIALS_SECRET") or config.es_credentials_secret

        es_credentials = get_secret(secret)

        # Handle host with or without port
        if ":" in self.host:
            es_url = f"http://{self.host}"
        else:
            es_url = f"http://{self.host}:9200"

        self.client = Elasticsearch(
            [es_url],
            basic_auth=(es_credentials["username"], es_credentials["password"]),
            request_timeout=30,
            max_retries=3,
            retry_on_timeout=True,
        )

    def search(self, index: str, body: Dict, size: int = 100) -> List[Dict]:
        """
        Execute search query and return results.

        Args:
            index: Index pattern to search
            body: Elasticsearch query body
            size: Maximum results to return

        Returns:
            List of hit documents
        """
        try:
            response = self.client.search(index=index, body=body, size=size, ignore_unavailable=True)

            return [hit["_source"] for hit in response["hits"]["hits"]]

        except Exception as e:
            log.error(f"Elasticsearch search error: {e}", exc_info=True)
            return []

    def aggregate(self, index: str, body: Dict) -> Dict[str, Any]:
        """
        Execute aggregation query and return results.

        Args:
            index: Index pattern to search
            body: Elasticsearch query body with aggregations

        Returns:
            Aggregation results
        """
        try:
            response = self.client.search(
                index=index, body=body, size=0, ignore_unavailable=True  # Only need aggregations
            )

            return response.get("aggregations", {})

        except Exception as e:
            log.error(f"Elasticsearch aggregation error: {e}", exc_info=True)
            return {}

    def count(self, index: str, body: Optional[Dict] = None) -> int:
        """
        Count documents matching query.

        Args:
            index: Index pattern to search
            body: Optional query body

        Returns:
            Document count
        """
        try:
            response = self.client.count(index=index, body=body, ignore_unavailable=True)

            return response.get("count", 0)

        except Exception as e:
            log.error(f"Elasticsearch count error: {e}", exc_info=True)
            return 0

    def get_service_stats(self, service: str, hours: int = 24, index_prefix: str = "logs") -> Dict[str, Any]:
        """
        Get stats for a specific service.

        Args:
            service: Service name (auth, order, product, etc.)
            hours: Time window to analyze
            index_prefix: Index prefix pattern (default: "logs")

        Returns:
            Dict with error_count, total_count, error_rate, p95_response_time
        """
        now = datetime.utcnow()
        start_time = now - timedelta(hours=hours)

        index = f"{index_prefix}-{service}-*"

        body = {
            "query": {
                "bool": {"filter": [{"range": {"@timestamp": {"gte": start_time.isoformat(), "lte": now.isoformat()}}}]}
            },
            "aggs": {
                "total": {"cardinality": {"field": "request_id.keyword"}},
                "errors": {
                    "filter": {"range": {"response_code": {"gte": 400}}},
                    "aggs": {"count": {"cardinality": {"field": "request_id.keyword"}}},
                },
                "response_times": {"percentiles": {"field": "response_time", "percents": [50, 95, 99]}},
            },
        }

        aggs = self.aggregate(index, body)

        total = aggs.get("total", {}).get("value", 0)
        errors = aggs.get("errors", {}).get("count", {}).get("value", 0)
        p95 = aggs.get("response_times", {}).get("values", {}).get("95.0", 0)

        return {
            "total_count": total,
            "error_count": errors,
            "error_rate": (errors / total * 100) if total > 0 else 0,
            "p95_response_time": p95,
        }
