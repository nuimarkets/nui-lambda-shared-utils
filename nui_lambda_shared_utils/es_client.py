"""
Refactored Elasticsearch client using BaseClient for DRY code patterns.
"""

import logging
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any
from urllib.parse import urlparse
from elasticsearch import Elasticsearch

from .base_client import BaseClient, ServiceHealthMixin
from .utils import handle_client_errors, resolve_config_value

log = logging.getLogger(__name__)


class ElasticsearchClient(BaseClient, ServiceHealthMixin):
    """
    Refactored Elasticsearch client with standardized patterns.
    """

    def __init__(self, host: Optional[str] = None, secret_name: Optional[str] = None, **kwargs):
        """
        Initialize Elasticsearch client.
        
        Args:
            host: Override ES host
            secret_name: Override secret name
            **kwargs: Additional ES client configuration
        """
        # Store host for later use in service client creation
        self._host_override = host
        super().__init__(secret_name=secret_name, **kwargs)

    def _get_default_config_prefix(self) -> str:
        """Return configuration prefix for Elasticsearch."""
        return "es"

    def _get_default_secret_name(self) -> str:
        """Return default secret name for ES credentials."""
        return "elasticsearch-credentials"

    def _create_service_client(self) -> Elasticsearch:
        """Create Elasticsearch client with resolved configuration."""
        # Resolve host using utility
        host = resolve_config_value(
            self._host_override,
            ["ES_HOST", "ELASTICSEARCH_HOST"],
            getattr(self.config, "es_host", "localhost:9200")
        )

        parsed = urlparse(host)
        if parsed.scheme and parsed.netloc:  # Valid URL with scheme://netloc
            es_url = host
        else:
            if ":" not in host:
                host = f"{host}:9200"
            scheme = self.client_config.get("scheme", "http")
            es_url = f"{scheme}://{host}"

        # Get credentials
        username = self.credentials.get("username", "elastic")
        password = self.credentials.get("password")
        
        if not password:
            raise ValueError("Elasticsearch credentials must include 'password'")

        # Create client with configuration
        return Elasticsearch(
            [es_url],
            basic_auth=(username, password),
            request_timeout=self.client_config.get("request_timeout", 30),
            max_retries=self.client_config.get("max_retries", 3),
            retry_on_timeout=self.client_config.get("retry_on_timeout", True),
        )

    @handle_client_errors(default_return=[])
    def search(self, index: str, body: Dict, size: int = 100) -> List[Dict]:
        """
        Execute search query with error handling.
        
        Args:
            index: Index pattern to search
            body: Elasticsearch query body
            size: Maximum results to return
            
        Returns:
            List of hit documents
        """
        def _search_operation():
            response = self._service_client.search(
                index=index,
                body=body,
                size=size,
                ignore_unavailable=True
            )
            return [hit["_source"] for hit in response["hits"]["hits"]]

        return self._execute_with_error_handling(
            "search",
            _search_operation,
            index=index,
            size=size
        )

    @handle_client_errors(default_return={})
    def aggregate(self, index: str, body: Dict) -> Dict[str, Any]:
        """
        Execute aggregation query with error handling.
        
        Args:
            index: Index pattern to search
            body: Elasticsearch query body with aggregations
            
        Returns:
            Aggregation results
        """
        def _aggregate_operation():
            response = self._service_client.search(
                index=index,
                body=body,
                size=0,  # Only need aggregations
                ignore_unavailable=True
            )
            return response.get("aggregations", {})

        return self._execute_with_error_handling(
            "aggregate",
            _aggregate_operation,
            index=index
        )

    @handle_client_errors(default_return=0)
    def count(self, index: str, body: Optional[Dict] = None) -> int:
        """
        Count documents with error handling.
        
        Args:
            index: Index pattern to search
            body: Optional query body
            
        Returns:
            Document count
        """
        def _count_operation():
            response = self._service_client.count(
                index=index,
                body=body,
                ignore_unavailable=True
            )
            return response.get("count", 0)

        return self._execute_with_error_handling(
            "count",
            _count_operation,
            index=index
        )

    @handle_client_errors(default_return={})
    def get_service_stats(
        self,
        service: str,
        hours: int = 24,
        index_prefix: str = "logs"
    ) -> Dict[str, Any]:
        """
        Get comprehensive service statistics.
        
        Args:
            service: Service name
            hours: Time window to analyze
            index_prefix: Index prefix pattern
            
        Returns:
            Dictionary with service statistics
        """
        def _stats_operation():
            now = datetime.utcnow()
            start_time = now - timedelta(hours=hours)
            index = f"{index_prefix}-{service}-*"

            # Build comprehensive stats query
            body = {
                "query": {
                    "bool": {
                        "filter": [{
                            "range": {
                                "@timestamp": {
                                    "gte": start_time.isoformat(),
                                    "lte": now.isoformat()
                                }
                            }
                        }]
                    }
                },
                "aggs": {
                    "total": {
                        "cardinality": {"field": "request_id.keyword"}
                    },
                    "errors": {
                        "filter": {"range": {"response_code": {"gte": 400}}},
                        "aggs": {
                            "count": {
                                "cardinality": {"field": "request_id.keyword"}
                            }
                        }
                    },
                    "response_times": {
                        "percentiles": {
                            "field": "response_time",
                            "percents": [50, 95, 99]
                        }
                    }
                }
            }

            aggs = self.aggregate(index, body)

            total = aggs.get("total", {}).get("value", 0)
            errors = aggs.get("errors", {}).get("count", {}).get("value", 0)
            percentiles = aggs.get("response_times", {}).get("values", {})

            return {
                "service": service,
                "time_window_hours": hours,
                "total_count": total,
                "error_count": errors,
                "error_rate": (errors / total * 100) if total > 0 else 0,
                "p50_response_time": percentiles.get("50.0", 0),
                "p95_response_time": percentiles.get("95.0", 0),
                "p99_response_time": percentiles.get("99.0", 0),
            }

        return self._execute_with_error_handling(
            "get_service_stats",
            _stats_operation,
            service=service,
            hours=hours
        )

    @handle_client_errors(default_return=[])
    def get_recent_errors(
        self,
        service: str,
        hours: int = 1,
        limit: int = 10,
        index_prefix: str = "logs"
    ) -> List[Dict]:
        """
        Get recent error logs for a service.
        
        Args:
            service: Service name
            hours: Time window
            limit: Maximum number of errors
            index_prefix: Index prefix
            
        Returns:
            List of recent error documents
        """
        def _errors_operation():
            now = datetime.utcnow()
            start_time = now - timedelta(hours=hours)
            index = f"{index_prefix}-{service}-*"

            body = {
                "query": {
                    "bool": {
                        "filter": [
                            {
                                "range": {
                                    "@timestamp": {
                                        "gte": start_time.isoformat(),
                                        "lte": now.isoformat()
                                    }
                                }
                            },
                            {
                                "range": {"response_code": {"gte": 400}}
                            }
                        ]
                    }
                },
                "sort": [{"@timestamp": {"order": "desc"}}]
            }

            return self.search(index, body, size=limit)

        return self._execute_with_error_handling(
            "get_recent_errors",
            _errors_operation,
            service=service,
            hours=hours,
            limit=limit
        )

    def _perform_health_check(self):
        """Perform Elasticsearch health check."""
        try:
            # Try to get cluster info
            info = self._service_client.info()
            if not info.get("version"):
                raise Exception("Elasticsearch info response invalid")
                
            # Check cluster health
            health = self._service_client.cluster.health()
            if health.get("status") == "red":
                raise Exception(f"Elasticsearch cluster is red: {health}")
                
        except Exception as e:
            raise Exception(f"Elasticsearch health check failed: {e}")

    def get_cluster_info(self) -> Dict:
        """
        Get Elasticsearch cluster information.
        
        Returns:
            Cluster info dictionary
        """
        try:
            info = self._service_client.info()
            health = self._service_client.cluster.health()
            
            return {
                "version": info.get("version", {}).get("number"),
                "cluster_name": info.get("cluster_name"),
                "cluster_status": health.get("status"),
                "number_of_nodes": health.get("number_of_nodes"),
                "number_of_data_nodes": health.get("number_of_data_nodes"),
                "active_primary_shards": health.get("active_primary_shards"),
                "active_shards": health.get("active_shards"),
            }
        except Exception as e:
            log.error(f"Failed to get cluster info: {e}")
            return {"error": str(e)}

    @handle_client_errors(default_return=[])
    def get_indices_info(self, pattern: str = "*") -> List[Dict]:
        """
        Get information about indices.
        
        Args:
            pattern: Index pattern to match
            
        Returns:
            List of index information dictionaries
        """
        def _indices_operation():
            response = self._service_client.cat.indices(
                index=pattern,
                format="json",
                h="index,health,status,docs.count,store.size"
            )
            return response or []

        return self._execute_with_error_handling(
            "get_indices_info",
            _indices_operation,
            pattern=pattern
        )