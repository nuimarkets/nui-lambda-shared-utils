"""
Elasticsearch query builder utilities for consistent query patterns across Lambda services.
Provides helper functions for building common ES queries used in application monitoring.
"""

from typing import Dict, List, Union
from datetime import datetime, timedelta


class ESQueryBuilder:
    """
    Builder for creating Elasticsearch queries with common patterns.

    Example:
        builder = ESQueryBuilder()
        query = (builder
            .with_time_range(start_time, end_time)
            .with_term('environment', 'prod')
            .with_service('order-service')
            .add_aggregation('error_rate', 'avg', 'response.status')
            .build()
        )
    """

    def __init__(self):
        self.query = {"bool": {"must": [], "must_not": [], "should": [], "filter": []}}
        self.aggregations = {}
        self.size = 0  # Default to aggregation-only queries
        self.sort = []

    def with_time_range(self, start: datetime, end: datetime, field: str = "@timestamp") -> "ESQueryBuilder":
        """Add time range filter."""
        self.query["bool"]["must"].append(
            {
                "range": {
                    field: {
                        "gte": start.isoformat() if hasattr(start, "isoformat") else start,
                        "lte": end.isoformat() if hasattr(end, "isoformat") else end,
                    }
                }
            }
        )
        return self

    def with_term(self, field: str, value: Union[str, int, bool]) -> "ESQueryBuilder":
        """Add exact term match."""
        self.query["bool"]["must"].append({"term": {field: value}})
        return self

    def with_terms(self, field: str, values: List[Union[str, int]]) -> "ESQueryBuilder":
        """Add terms match (OR condition for multiple values)."""
        self.query["bool"]["must"].append({"terms": {field: values}})
        return self

    def with_service(self, service: str) -> "ESQueryBuilder":
        """Add service name filter."""
        return self.with_term("service_name", service)

    def with_environment(self, env: str = "prod") -> "ESQueryBuilder":
        """Add environment filter."""
        return self.with_term("environment", env)

    def with_error_filter(self, min_status: int = 400) -> "ESQueryBuilder":
        """Add filter for error responses."""
        self.query["bool"]["must"].append({"range": {"response.status": {"gte": min_status}}})
        return self

    def exclude_pattern(self, field: str, pattern: str) -> "ESQueryBuilder":
        """Exclude documents matching a pattern."""
        self.query["bool"]["must_not"].append({"wildcard": {field: pattern}})
        return self

    def with_prefix(self, field: str, prefix: str) -> "ESQueryBuilder":
        """Add prefix match."""
        self.query["bool"]["must"].append({"prefix": {field: prefix}})
        return self

    def add_aggregation(self, name: str, agg_type: str, field: str, **kwargs) -> "ESQueryBuilder":
        """Add a simple aggregation."""
        self.aggregations[name] = {agg_type: {"field": field, **kwargs}}
        return self

    def add_date_histogram(
        self, name: str, field: str = "@timestamp", interval: str = "5m", **kwargs
    ) -> "ESQueryBuilder":
        """Add date histogram aggregation."""
        self.aggregations[name] = {
            "date_histogram": {"field": field, "fixed_interval": interval, "min_doc_count": 0, **kwargs}
        }
        return self

    def add_terms_aggregation(self, name: str, field: str, size: int = 10, **kwargs) -> "ESQueryBuilder":
        """Add terms aggregation for top values."""
        self.aggregations[name] = {"terms": {"field": field, "size": size, **kwargs}}
        return self

    def add_percentiles(self, name: str, field: str, percents: List[float] = None) -> "ESQueryBuilder":
        """Add percentiles aggregation."""
        if percents is None:
            percents = [50, 95, 99]

        self.aggregations[name] = {"percentiles": {"field": field, "percents": percents}}
        return self

    def add_nested_aggregation(self, parent_name: str, child_aggs: Dict) -> "ESQueryBuilder":
        """Add nested aggregations."""
        if parent_name not in self.aggregations:
            raise ValueError(f"Parent aggregation '{parent_name}' not found")

        self.aggregations[parent_name]["aggs"] = child_aggs
        return self

    def with_size(self, size: int) -> "ESQueryBuilder":
        """Set number of documents to return."""
        self.size = size
        return self

    def add_sort(self, field: str, order: str = "desc") -> "ESQueryBuilder":
        """Add sort criteria."""
        self.sort.append({field: {"order": order}})
        return self

    def build(self) -> Dict:
        """Build the final query."""
        query = {"query": self.query, "size": self.size}

        if self.aggregations:
            query["aggs"] = self.aggregations

        if self.sort:
            query["sort"] = self.sort

        return query


# Pre-built query templates for common patterns
def build_error_rate_query(service: str, start_time: datetime, end_time: datetime, interval: str = "5m") -> Dict:
    """Build query for service error rate over time."""
    builder = ESQueryBuilder()
    return (
        builder.with_time_range(start_time, end_time)
        .with_service(service)
        .with_environment("prod")
        .add_date_histogram("error_timeline", interval=interval)
        .add_nested_aggregation(
            "error_timeline",
            {
                "total_requests": {"value_count": {"field": "request.id"}},
                "error_requests": {
                    "filter": {"range": {"response.status": {"gte": 400}}},
                    "aggs": {"count": {"value_count": {"field": "response.status"}}},
                },
                "error_rate": {
                    "bucket_script": {
                        "buckets_path": {"errors": "error_requests>count", "total": "total_requests"},
                        "script": "params.errors / params.total * 100",
                    }
                },
            },
        )
        .build()
    )


def build_top_errors_query(service: str, start_time: datetime, end_time: datetime, top_n: int = 10) -> Dict:
    """Build query for top error messages."""
    builder = ESQueryBuilder()
    return (
        builder.with_time_range(start_time, end_time)
        .with_service(service)
        .with_environment("prod")
        .with_error_filter()
        .add_terms_aggregation("top_errors", "error.keyword", size=top_n)
        .add_nested_aggregation(
            "top_errors",
            {
                "status_codes": {"terms": {"field": "response.status", "size": 5}},
                "sample_error": {"top_hits": {"size": 1, "_source": ["error", "request.path", "@timestamp"]}},
            },
        )
        .build()
    )


def build_response_time_query(service: str, start_time: datetime, end_time: datetime) -> Dict:
    """Build query for response time metrics."""
    builder = ESQueryBuilder()
    return (
        builder.with_time_range(start_time, end_time)
        .with_service(service)
        .with_environment("prod")
        .add_percentiles("response_times", "response.time", [50, 90, 95, 99])
        .add_aggregation("avg_response_time", "avg", "response.time")
        .add_aggregation("max_response_time", "max", "response.time")
        .add_date_histogram("response_timeline", interval="5m")
        .add_nested_aggregation(
            "response_timeline",
            {
                "avg_time": {"avg": {"field": "response.time"}},
                "p95_time": {"percentiles": {"field": "response.time", "percents": [95]}},
            },
        )
        .build()
    )


def build_service_volume_query(services: List[str], start_time: datetime, end_time: datetime) -> Dict:
    """Build query for request volume across multiple services."""
    builder = ESQueryBuilder()
    return (
        builder.with_time_range(start_time, end_time)
        .with_terms("service_name", services)
        .with_environment("prod")
        .add_terms_aggregation("service_breakdown", "service_name", size=20)
        .add_nested_aggregation(
            "service_breakdown",
            {
                "request_count": {"value_count": {"field": "request.id"}},
                "error_count": {
                    "filter": {"range": {"response.status": {"gte": 400}}},
                    "aggs": {"count": {"value_count": {"field": "response.status"}}},
                },
                "avg_response_time": {"avg": {"field": "response.time"}},
            },
        )
        .build()
    )


def build_user_activity_query(start_time: datetime, end_time: datetime, user_field: str = "user.id") -> Dict:
    """Build query for user activity metrics."""
    builder = ESQueryBuilder()
    return (
        builder.with_time_range(start_time, end_time)
        .with_environment("prod")
        .add_aggregation("unique_users", "cardinality", user_field)
        .add_terms_aggregation("top_users", user_field, size=20)
        .add_nested_aggregation(
            "top_users",
            {
                "request_count": {"value_count": {"field": "request.id"}},
                "services_used": {"cardinality": {"field": "service_name"}},
                "last_activity": {"max": {"field": "@timestamp"}},
            },
        )
        .add_date_histogram("user_timeline", interval="1h")
        .add_nested_aggregation("user_timeline", {"active_users": {"cardinality": {"field": user_field}}})
        .build()
    )


def build_pattern_detection_query(
    pattern: str, field: str = "message", start_time: datetime = None, hours_back: int = 24
) -> Dict:
    """Build query to detect specific patterns in logs."""
    if not start_time:
        start_time = datetime.utcnow() - timedelta(hours=hours_back)
    end_time = datetime.utcnow()

    return {
        "query": {
            "bool": {
                "must": [
                    {"wildcard": {field: f"*{pattern}*"}},
                    {"range": {"@timestamp": {"gte": start_time.isoformat(), "lte": end_time.isoformat()}}},
                ]
            }
        },
        "size": 100,
        "sort": [{"@timestamp": {"order": "desc"}}],
        "aggs": {
            "service_breakdown": {"terms": {"field": "service_name", "size": 10}},
            "timeline": {"date_histogram": {"field": "@timestamp", "fixed_interval": "1h", "min_doc_count": 1}},
        },
    }


def build_tender_participant_query(tender_id: str, start_time: datetime, end_time: datetime) -> Dict:
    """Build query for tender participant analysis."""
    # Expand time range for pre-tender activity
    expanded_start = start_time - timedelta(hours=2)
    expanded_end = end_time + timedelta(minutes=30)

    return {
        "query": {
            "bool": {
                "must": [
                    {"term": {"tender.id": tender_id}},
                    {"range": {"created": {"gte": expanded_start.isoformat(), "lte": expanded_end.isoformat()}}},
                ]
            }
        },
        "size": 0,
        "aggs": {
            "participants": {
                "terms": {"field": "division.id", "size": 100},
                "aggs": {
                    "participant_details": {"top_hits": {"size": 1, "_source": ["division.name", "company.name"]}},
                    "bid_count": {"value_count": {"field": "created"}},
                    "first_bid": {"min": {"field": "created"}},
                    "last_bid": {"max": {"field": "created"}},
                    "bid_values": {"stats": {"field": "price"}},
                },
            },
            "total_bids": {"value_count": {"field": "created"}},
            "bid_timeline": {
                "date_histogram": {
                    "field": "created",
                    "fixed_interval": "1m",
                    "min_doc_count": 0,
                    "extended_bounds": {"min": start_time.isoformat(), "max": end_time.isoformat()},
                }
            },
        },
    }
