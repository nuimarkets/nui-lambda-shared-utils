"""
Tests for es_query_builder module.
"""

import pytest
from unittest.mock import patch
from datetime import datetime, timedelta
import pytz

from nui_lambda_shared_utils.es_query_builder import (
    ESQueryBuilder,
    build_error_rate_query,
    build_top_errors_query,
    build_response_time_query,
    build_service_volume_query,
    build_user_activity_query,
    build_pattern_detection_query,
    build_tender_participant_query,
)


class TestESQueryBuilder:
    """Tests for ESQueryBuilder class."""

    def test_init(self):
        """Test builder initialization."""
        builder = ESQueryBuilder()

        assert builder.query == {"bool": {"must": [], "must_not": [], "should": [], "filter": []}}
        assert builder.aggregations == {}
        assert builder.size == 0
        assert builder.sort == []

    def test_with_time_range_datetime_objects(self):
        """Test adding time range with datetime objects."""
        builder = ESQueryBuilder()
        start_time = datetime(2023, 6, 15, 10, 0, 0, tzinfo=pytz.UTC)
        end_time = datetime(2023, 6, 15, 14, 0, 0, tzinfo=pytz.UTC)

        result = builder.with_time_range(start_time, end_time)

        assert result == builder  # Should return self for chaining
        assert len(builder.query["bool"]["must"]) == 1

        time_range = builder.query["bool"]["must"][0]
        assert time_range["range"]["@timestamp"]["gte"] == start_time.isoformat()
        assert time_range["range"]["@timestamp"]["lte"] == end_time.isoformat()

    def test_with_time_range_custom_field(self):
        """Test adding time range with custom field."""
        builder = ESQueryBuilder()
        start_time = datetime(2023, 6, 15, 10, 0, 0)
        end_time = datetime(2023, 6, 15, 14, 0, 0)

        builder.with_time_range(start_time, end_time, field="created")

        time_range = builder.query["bool"]["must"][0]
        assert "created" in time_range["range"]
        assert time_range["range"]["created"]["gte"] == start_time.isoformat()
        assert time_range["range"]["created"]["lte"] == end_time.isoformat()

    def test_with_time_range_string_values(self):
        """Test adding time range with string values."""
        builder = ESQueryBuilder()
        start_str = "2023-06-15T10:00:00Z"
        end_str = "2023-06-15T14:00:00Z"

        builder.with_time_range(start_str, end_str)

        time_range = builder.query["bool"]["must"][0]
        assert time_range["range"]["@timestamp"]["gte"] == start_str
        assert time_range["range"]["@timestamp"]["lte"] == end_str

    def test_with_term_string(self):
        """Test adding term filter with string value."""
        builder = ESQueryBuilder()

        result = builder.with_term("service_name", "connect-order")

        assert result == builder
        assert len(builder.query["bool"]["must"]) == 1
        assert builder.query["bool"]["must"][0] == {"term": {"service_name": "connect-order"}}

    def test_with_term_integer(self):
        """Test adding term filter with integer value."""
        builder = ESQueryBuilder()

        builder.with_term("response.status", 200)

        assert builder.query["bool"]["must"][0] == {"term": {"response.status": 200}}

    def test_with_term_boolean(self):
        """Test adding term filter with boolean value."""
        builder = ESQueryBuilder()

        builder.with_term("is_error", True)

        assert builder.query["bool"]["must"][0] == {"term": {"is_error": True}}

    def test_with_terms(self):
        """Test adding terms filter."""
        builder = ESQueryBuilder()

        result = builder.with_terms("status", [200, 201, 204])

        assert result == builder
        assert len(builder.query["bool"]["must"]) == 1
        assert builder.query["bool"]["must"][0] == {"terms": {"status": [200, 201, 204]}}

    def test_with_service(self):
        """Test adding service filter."""
        builder = ESQueryBuilder()

        result = builder.with_service("connect-auth")

        assert result == builder
        assert len(builder.query["bool"]["must"]) == 1
        assert builder.query["bool"]["must"][0] == {"term": {"service_name": "connect-auth"}}

    def test_with_environment_default(self):
        """Test adding environment filter with default."""
        builder = ESQueryBuilder()

        result = builder.with_environment()

        assert result == builder
        assert len(builder.query["bool"]["must"]) == 1
        assert builder.query["bool"]["must"][0] == {"term": {"environment": "prod"}}

    def test_with_environment_custom(self):
        """Test adding environment filter with custom value."""
        builder = ESQueryBuilder()

        builder.with_environment("dev")

        assert builder.query["bool"]["must"][0] == {"term": {"environment": "dev"}}

    def test_with_error_filter_default(self):
        """Test adding error filter with default status."""
        builder = ESQueryBuilder()

        result = builder.with_error_filter()

        assert result == builder
        assert len(builder.query["bool"]["must"]) == 1
        assert builder.query["bool"]["must"][0] == {"range": {"response.status": {"gte": 400}}}

    def test_with_error_filter_custom(self):
        """Test adding error filter with custom status."""
        builder = ESQueryBuilder()

        builder.with_error_filter(500)

        assert builder.query["bool"]["must"][0] == {"range": {"response.status": {"gte": 500}}}

    def test_exclude_pattern(self):
        """Test excluding pattern."""
        builder = ESQueryBuilder()

        result = builder.exclude_pattern("request.path", "/health*")

        assert result == builder
        assert len(builder.query["bool"]["must_not"]) == 1
        assert builder.query["bool"]["must_not"][0] == {"wildcard": {"request.path": "/health*"}}

    def test_with_prefix(self):
        """Test adding prefix filter."""
        builder = ESQueryBuilder()

        result = builder.with_prefix("log.level", "ERROR")

        assert result == builder
        assert len(builder.query["bool"]["must"]) == 1
        assert builder.query["bool"]["must"][0] == {"prefix": {"log.level": "ERROR"}}

    def test_add_aggregation_basic(self):
        """Test adding basic aggregation."""
        builder = ESQueryBuilder()

        result = builder.add_aggregation("avg_response", "avg", "response.time")

        assert result == builder
        assert "avg_response" in builder.aggregations
        assert builder.aggregations["avg_response"] == {"avg": {"field": "response.time"}}

    def test_add_aggregation_with_kwargs(self):
        """Test adding aggregation with extra parameters."""
        builder = ESQueryBuilder()

        builder.add_aggregation("percentile_response", "percentiles", "response.time", percents=[50, 95])

        assert builder.aggregations["percentile_response"] == {
            "percentiles": {"field": "response.time", "percents": [50, 95]}
        }

    def test_add_date_histogram_default(self):
        """Test adding date histogram with defaults."""
        builder = ESQueryBuilder()

        result = builder.add_date_histogram("timeline")

        assert result == builder
        assert "timeline" in builder.aggregations
        assert builder.aggregations["timeline"] == {
            "date_histogram": {"field": "@timestamp", "fixed_interval": "5m", "min_doc_count": 0}
        }

    def test_add_date_histogram_custom(self):
        """Test adding date histogram with custom parameters."""
        builder = ESQueryBuilder()

        builder.add_date_histogram("hourly_timeline", field="created", interval="1h", min_doc_count=1)

        assert builder.aggregations["hourly_timeline"] == {
            "date_histogram": {"field": "created", "fixed_interval": "1h", "min_doc_count": 1}
        }

    def test_add_terms_aggregation_default(self):
        """Test adding terms aggregation with defaults."""
        builder = ESQueryBuilder()

        result = builder.add_terms_aggregation("top_services", "service_name")

        assert result == builder
        assert "top_services" in builder.aggregations
        assert builder.aggregations["top_services"] == {"terms": {"field": "service_name", "size": 10}}

    def test_add_terms_aggregation_custom(self):
        """Test adding terms aggregation with custom parameters."""
        builder = ESQueryBuilder()

        builder.add_terms_aggregation("top_errors", "error.keyword", size=20, order={"_count": "desc"})

        assert builder.aggregations["top_errors"] == {
            "terms": {"field": "error.keyword", "size": 20, "order": {"_count": "desc"}}
        }

    def test_add_percentiles_default(self):
        """Test adding percentiles with defaults."""
        builder = ESQueryBuilder()

        result = builder.add_percentiles("response_percentiles", "response.time")

        assert result == builder
        assert "response_percentiles" in builder.aggregations
        assert builder.aggregations["response_percentiles"] == {
            "percentiles": {"field": "response.time", "percents": [50, 95, 99]}
        }

    def test_add_percentiles_custom(self):
        """Test adding percentiles with custom percentiles."""
        builder = ESQueryBuilder()

        builder.add_percentiles("custom_percentiles", "response.time", percents=[90, 99])

        assert builder.aggregations["custom_percentiles"] == {
            "percentiles": {"field": "response.time", "percents": [90, 99]}
        }

    def test_add_nested_aggregation_success(self):
        """Test adding nested aggregation successfully."""
        builder = ESQueryBuilder()

        # First add a parent aggregation
        builder.add_terms_aggregation("services", "service_name")

        # Then add nested aggregation
        child_aggs = {
            "avg_response": {"avg": {"field": "response.time"}},
            "error_count": {"filter": {"range": {"response.status": {"gte": 400}}}},
        }

        result = builder.add_nested_aggregation("services", child_aggs)

        assert result == builder
        assert "aggs" in builder.aggregations["services"]
        assert builder.aggregations["services"]["aggs"] == child_aggs

    def test_add_nested_aggregation_parent_not_found(self):
        """Test adding nested aggregation when parent doesn't exist."""
        builder = ESQueryBuilder()

        child_aggs = {"avg_response": {"avg": {"field": "response.time"}}}

        with pytest.raises(ValueError, match="Parent aggregation 'nonexistent' not found"):
            builder.add_nested_aggregation("nonexistent", child_aggs)

    def test_with_size(self):
        """Test setting size."""
        builder = ESQueryBuilder()

        result = builder.with_size(100)

        assert result == builder
        assert builder.size == 100

    def test_add_sort_default(self):
        """Test adding sort with default order."""
        builder = ESQueryBuilder()

        result = builder.add_sort("@timestamp")

        assert result == builder
        assert len(builder.sort) == 1
        assert builder.sort[0] == {"@timestamp": {"order": "desc"}}

    def test_add_sort_custom(self):
        """Test adding sort with custom order."""
        builder = ESQueryBuilder()

        builder.add_sort("response.time", "asc")

        assert builder.sort[0] == {"response.time": {"order": "asc"}}

    def test_add_multiple_sorts(self):
        """Test adding multiple sorts."""
        builder = ESQueryBuilder()

        builder.add_sort("@timestamp").add_sort("response.time", "asc")

        assert len(builder.sort) == 2
        assert builder.sort[0] == {"@timestamp": {"order": "desc"}}
        assert builder.sort[1] == {"response.time": {"order": "asc"}}

    def test_build_basic_query(self):
        """Test building basic query."""
        builder = ESQueryBuilder()

        query = builder.build()

        assert query["query"] == {"bool": {"must": [], "must_not": [], "should": [], "filter": []}}
        assert query["size"] == 0
        assert "aggs" not in query
        assert "sort" not in query

    def test_build_query_with_filters(self):
        """Test building query with filters."""
        builder = ESQueryBuilder()

        builder.with_term("service_name", "connect-order").with_environment("prod")

        query = builder.build()

        assert len(query["query"]["bool"]["must"]) == 2
        assert {"term": {"service_name": "connect-order"}} in query["query"]["bool"]["must"]
        assert {"term": {"environment": "prod"}} in query["query"]["bool"]["must"]

    def test_build_query_with_aggregations(self):
        """Test building query with aggregations."""
        builder = ESQueryBuilder()

        builder.add_aggregation("avg_response", "avg", "response.time")
        builder.add_terms_aggregation("top_services", "service_name")

        query = builder.build()

        assert "aggs" in query
        assert "avg_response" in query["aggs"]
        assert "top_services" in query["aggs"]

    def test_build_query_with_sort(self):
        """Test building query with sort."""
        builder = ESQueryBuilder()

        builder.add_sort("@timestamp").with_size(50)

        query = builder.build()

        assert "sort" in query
        assert query["sort"] == [{"@timestamp": {"order": "desc"}}]
        assert query["size"] == 50

    def test_method_chaining(self):
        """Test method chaining."""
        builder = ESQueryBuilder()

        result = (
            builder.with_service("connect-auth")
            .with_environment("prod")
            .with_error_filter()
            .add_aggregation("avg_response", "avg", "response.time")
            .add_sort("@timestamp")
            .with_size(100)
        )

        assert result == builder
        assert len(builder.query["bool"]["must"]) == 3
        assert len(builder.aggregations) == 1
        assert len(builder.sort) == 1
        assert builder.size == 100


class TestPrebuiltQueries:
    """Tests for pre-built query functions."""

    def test_build_error_rate_query(self):
        """Test building error rate query."""
        service = "connect-order"
        start_time = datetime(2023, 6, 15, 10, 0, 0, tzinfo=pytz.UTC)
        end_time = datetime(2023, 6, 15, 14, 0, 0, tzinfo=pytz.UTC)

        query = build_error_rate_query(service, start_time, end_time, interval="10m")

        # Check basic structure
        assert "query" in query
        assert "aggs" in query
        assert query["size"] == 0

        # Check filters
        must_clauses = query["query"]["bool"]["must"]
        assert len(must_clauses) == 3  # time range, service, environment

        # Check time range
        time_range = next(clause for clause in must_clauses if "range" in clause)
        assert time_range["range"]["@timestamp"]["gte"] == start_time.isoformat()
        assert time_range["range"]["@timestamp"]["lte"] == end_time.isoformat()

        # Check service filter
        service_filter = next(
            clause for clause in must_clauses if "term" in clause and "service_name" in clause["term"]
        )
        assert service_filter["term"]["service_name"] == service

        # Check environment filter
        env_filter = next(clause for clause in must_clauses if "term" in clause and "environment" in clause["term"])
        assert env_filter["term"]["environment"] == "prod"

        # Check aggregations
        assert "error_timeline" in query["aggs"]
        assert query["aggs"]["error_timeline"]["date_histogram"]["fixed_interval"] == "10m"

        # Check nested aggregations
        nested_aggs = query["aggs"]["error_timeline"]["aggs"]
        assert "total_requests" in nested_aggs
        assert "error_requests" in nested_aggs
        assert "error_rate" in nested_aggs

    def test_build_top_errors_query(self):
        """Test building top errors query."""
        service = "connect-auth"
        start_time = datetime(2023, 6, 15, 10, 0, 0, tzinfo=pytz.UTC)
        end_time = datetime(2023, 6, 15, 14, 0, 0, tzinfo=pytz.UTC)

        query = build_top_errors_query(service, start_time, end_time, top_n=20)

        # Check basic structure
        assert "query" in query
        assert "aggs" in query
        assert query["size"] == 0

        # Check filters
        must_clauses = query["query"]["bool"]["must"]
        assert len(must_clauses) == 4  # time range, service, environment, error filter

        # Check error filter
        error_filter = next(
            clause for clause in must_clauses if "range" in clause and "response.status" in clause["range"]
        )
        assert error_filter["range"]["response.status"]["gte"] == 400

        # Check aggregations
        assert "top_errors" in query["aggs"]
        assert query["aggs"]["top_errors"]["terms"]["field"] == "error.keyword"
        assert query["aggs"]["top_errors"]["terms"]["size"] == 20

        # Check nested aggregations
        nested_aggs = query["aggs"]["top_errors"]["aggs"]
        assert "status_codes" in nested_aggs
        assert "sample_error" in nested_aggs

    def test_build_response_time_query(self):
        """Test building response time query."""
        service = "connect-product"
        start_time = datetime(2023, 6, 15, 10, 0, 0, tzinfo=pytz.UTC)
        end_time = datetime(2023, 6, 15, 14, 0, 0, tzinfo=pytz.UTC)

        query = build_response_time_query(service, start_time, end_time)

        # Check basic structure
        assert "query" in query
        assert "aggs" in query
        assert query["size"] == 0

        # Check filters
        must_clauses = query["query"]["bool"]["must"]
        assert len(must_clauses) == 3  # time range, service, environment

        # Check aggregations
        assert "response_times" in query["aggs"]
        assert "avg_response_time" in query["aggs"]
        assert "max_response_time" in query["aggs"]
        assert "response_timeline" in query["aggs"]

        # Check percentiles
        percentiles = query["aggs"]["response_times"]["percentiles"]
        assert percentiles["field"] == "response.time"
        assert percentiles["percents"] == [50, 90, 95, 99]

        # Check nested timeline aggregations
        timeline_aggs = query["aggs"]["response_timeline"]["aggs"]
        assert "avg_time" in timeline_aggs
        assert "p95_time" in timeline_aggs

    def test_build_service_volume_query(self):
        """Test building service volume query."""
        services = ["connect-order", "connect-auth", "connect-product"]
        start_time = datetime(2023, 6, 15, 10, 0, 0, tzinfo=pytz.UTC)
        end_time = datetime(2023, 6, 15, 14, 0, 0, tzinfo=pytz.UTC)

        query = build_service_volume_query(services, start_time, end_time)

        # Check basic structure
        assert "query" in query
        assert "aggs" in query
        assert query["size"] == 0

        # Check filters
        must_clauses = query["query"]["bool"]["must"]
        assert len(must_clauses) == 3  # time range, services, environment

        # Check services filter
        services_filter = next(clause for clause in must_clauses if "terms" in clause)
        assert services_filter["terms"]["service_name"] == services

        # Check aggregations
        assert "service_breakdown" in query["aggs"]
        assert query["aggs"]["service_breakdown"]["terms"]["field"] == "service_name"
        assert query["aggs"]["service_breakdown"]["terms"]["size"] == 20

        # Check nested aggregations
        nested_aggs = query["aggs"]["service_breakdown"]["aggs"]
        assert "request_count" in nested_aggs
        assert "error_count" in nested_aggs
        assert "avg_response_time" in nested_aggs

    def test_build_user_activity_query(self):
        """Test building user activity query."""
        start_time = datetime(2023, 6, 15, 10, 0, 0, tzinfo=pytz.UTC)
        end_time = datetime(2023, 6, 15, 14, 0, 0, tzinfo=pytz.UTC)

        query = build_user_activity_query(start_time, end_time, user_field="user.email")

        # Check basic structure
        assert "query" in query
        assert "aggs" in query
        assert query["size"] == 0

        # Check filters
        must_clauses = query["query"]["bool"]["must"]
        assert len(must_clauses) == 2  # time range, environment

        # Check aggregations
        assert "unique_users" in query["aggs"]
        assert "top_users" in query["aggs"]
        assert "user_timeline" in query["aggs"]

        # Check unique users aggregation
        unique_users = query["aggs"]["unique_users"]["cardinality"]
        assert unique_users["field"] == "user.email"

        # Check top users aggregation
        top_users = query["aggs"]["top_users"]["terms"]
        assert top_users["field"] == "user.email"
        assert top_users["size"] == 20

        # Check nested aggregations
        top_users_aggs = query["aggs"]["top_users"]["aggs"]
        assert "request_count" in top_users_aggs
        assert "services_used" in top_users_aggs
        assert "last_activity" in top_users_aggs

        # Check timeline aggregations
        timeline_aggs = query["aggs"]["user_timeline"]["aggs"]
        assert "active_users" in timeline_aggs
        assert timeline_aggs["active_users"]["cardinality"]["field"] == "user.email"

    @patch("nui_lambda_shared_utils.es_query_builder.datetime")
    def test_build_pattern_detection_query_with_start_time(self, mock_datetime):
        """Test building pattern detection query with start time."""
        mock_utcnow = datetime(2023, 6, 15, 14, 0, 0, tzinfo=pytz.UTC)
        mock_datetime.utcnow.return_value = mock_utcnow

        pattern = "database timeout"
        start_time = datetime(2023, 6, 15, 10, 0, 0, tzinfo=pytz.UTC)

        query = build_pattern_detection_query(pattern, field="error.message", start_time=start_time)

        # Check basic structure
        assert "query" in query
        assert "aggs" in query
        assert query["size"] == 100
        assert "sort" in query

        # Check filters
        must_clauses = query["query"]["bool"]["must"]
        assert len(must_clauses) == 2  # wildcard pattern, time range

        # Check pattern filter
        pattern_filter = next(clause for clause in must_clauses if "wildcard" in clause)
        assert pattern_filter["wildcard"]["error.message"] == f"*{pattern}*"

        # Check time range
        time_range = next(clause for clause in must_clauses if "range" in clause)
        assert time_range["range"]["@timestamp"]["gte"] == start_time.isoformat()
        assert time_range["range"]["@timestamp"]["lte"] == mock_utcnow.isoformat()

        # Check aggregations
        assert "service_breakdown" in query["aggs"]
        assert "timeline" in query["aggs"]

        # Check sort
        assert query["sort"] == [{"@timestamp": {"order": "desc"}}]

    @patch("nui_lambda_shared_utils.es_query_builder.datetime")
    def test_build_pattern_detection_query_without_start_time(self, mock_datetime):
        """Test building pattern detection query without start time."""
        mock_utcnow = datetime(2023, 6, 15, 14, 0, 0, tzinfo=pytz.UTC)
        mock_datetime.utcnow.return_value = mock_utcnow

        pattern = "connection failed"

        query = build_pattern_detection_query(pattern, hours_back=12)

        # Check that start time is calculated
        must_clauses = query["query"]["bool"]["must"]
        time_range = next(clause for clause in must_clauses if "range" in clause)

        # Should be 12 hours back from mock_utcnow
        expected_start = mock_utcnow - timedelta(hours=12)
        assert time_range["range"]["@timestamp"]["gte"] == expected_start.isoformat()
        assert time_range["range"]["@timestamp"]["lte"] == mock_utcnow.isoformat()

        # Check pattern filter
        pattern_filter = next(clause for clause in must_clauses if "wildcard" in clause)
        assert pattern_filter["wildcard"]["message"] == f"*{pattern}*"  # Default field

    def test_build_tender_participant_query(self):
        """Test building tender participant query."""
        tender_id = "tender-12345"
        start_time = datetime(2023, 6, 15, 10, 0, 0, tzinfo=pytz.UTC)
        end_time = datetime(2023, 6, 15, 14, 0, 0, tzinfo=pytz.UTC)

        query = build_tender_participant_query(tender_id, start_time, end_time)

        # Check basic structure
        assert "query" in query
        assert "aggs" in query
        assert query["size"] == 0

        # Check filters
        must_clauses = query["query"]["bool"]["must"]
        assert len(must_clauses) == 2  # tender ID, expanded time range

        # Check tender ID filter
        tender_filter = next(clause for clause in must_clauses if "term" in clause and "tender.id" in clause["term"])
        assert tender_filter["term"]["tender.id"] == tender_id

        # Check expanded time range
        time_range = next(clause for clause in must_clauses if "range" in clause)
        expected_start = start_time - timedelta(hours=2)
        expected_end = end_time + timedelta(minutes=30)
        assert time_range["range"]["created"]["gte"] == expected_start.isoformat()
        assert time_range["range"]["created"]["lte"] == expected_end.isoformat()

        # Check aggregations
        assert "participants" in query["aggs"]
        assert "total_bids" in query["aggs"]
        assert "bid_timeline" in query["aggs"]

        # Check participants aggregation
        participants = query["aggs"]["participants"]
        assert participants["terms"]["field"] == "division.id"
        assert participants["terms"]["size"] == 100

        # Check participant nested aggregations
        participant_aggs = participants["aggs"]
        assert "participant_details" in participant_aggs
        assert "bid_count" in participant_aggs
        assert "first_bid" in participant_aggs
        assert "last_bid" in participant_aggs
        assert "bid_values" in participant_aggs

        # Check bid timeline
        bid_timeline = query["aggs"]["bid_timeline"]["date_histogram"]
        assert bid_timeline["field"] == "created"
        assert bid_timeline["fixed_interval"] == "1m"
        assert bid_timeline["min_doc_count"] == 0
        assert bid_timeline["extended_bounds"]["min"] == start_time.isoformat()
        assert bid_timeline["extended_bounds"]["max"] == end_time.isoformat()

    def test_build_error_rate_query_default_interval(self):
        """Test error rate query with default interval."""
        service = "connect-order"
        start_time = datetime(2023, 6, 15, 10, 0, 0, tzinfo=pytz.UTC)
        end_time = datetime(2023, 6, 15, 14, 0, 0, tzinfo=pytz.UTC)

        query = build_error_rate_query(service, start_time, end_time)

        # Check default interval
        assert query["aggs"]["error_timeline"]["date_histogram"]["fixed_interval"] == "5m"

    def test_build_top_errors_query_default_top_n(self):
        """Test top errors query with default top_n."""
        service = "connect-auth"
        start_time = datetime(2023, 6, 15, 10, 0, 0, tzinfo=pytz.UTC)
        end_time = datetime(2023, 6, 15, 14, 0, 0, tzinfo=pytz.UTC)

        query = build_top_errors_query(service, start_time, end_time)

        # Check default size
        assert query["aggs"]["top_errors"]["terms"]["size"] == 10

    def test_build_user_activity_query_default_user_field(self):
        """Test user activity query with default user field."""
        start_time = datetime(2023, 6, 15, 10, 0, 0, tzinfo=pytz.UTC)
        end_time = datetime(2023, 6, 15, 14, 0, 0, tzinfo=pytz.UTC)

        query = build_user_activity_query(start_time, end_time)

        # Check default user field
        assert query["aggs"]["unique_users"]["cardinality"]["field"] == "user.id"
        assert query["aggs"]["top_users"]["terms"]["field"] == "user.id"
        assert query["aggs"]["user_timeline"]["aggs"]["active_users"]["cardinality"]["field"] == "user.id"
