"""
Tests for es_client module.
"""

import pytest
from datetime import datetime, timedelta
from unittest.mock import patch, Mock
from elasticsearch import Elasticsearch
from nui_lambda_shared_utils.es_client import ElasticsearchClient


class TestElasticsearchClient:
    """Tests for ElasticsearchClient class."""

    @patch.dict("os.environ", {}, clear=True)
    @patch("nui_lambda_shared_utils.es_client.resolve_config_value")
    @patch("nui_lambda_shared_utils.base_client.get_secret")
    @patch("nui_lambda_shared_utils.es_client.Elasticsearch")
    def test_init_default_values(self, mock_es, mock_get_secret, mock_resolve_config_value):
        """Test initialization with default values."""
        # Mock resolve_config_value to return localhost for host resolution
        mock_resolve_config_value.return_value = "localhost:9200"
        mock_get_secret.return_value = {"username": "elastic", "password": "test_password"}

        client = ElasticsearchClient()

        # Verify secret was retrieved
        mock_get_secret.assert_called_once_with("elasticsearch-credentials")
        mock_es.assert_called_once_with(
            ["http://localhost:9200"],
            basic_auth=("elastic", "test_password"),
            request_timeout=30,
            max_retries=3,
            retry_on_timeout=True,
        )

    @patch("nui_lambda_shared_utils.base_client.get_secret")
    @patch("nui_lambda_shared_utils.es_client.Elasticsearch")
    def test_init_custom_host(self, mock_es, mock_get_secret):
        """Test initialization with custom host."""
        mock_get_secret.return_value = {"username": "elastic", "password": "test_password"}

        client = ElasticsearchClient(host="10.0.0.1")

        # Verify custom host was used in client creation
        mock_es.assert_called_once_with(
            ["http://10.0.0.1:9200"],
            basic_auth=("elastic", "test_password"),
            request_timeout=30,
            max_retries=3,
            retry_on_timeout=True,
        )

    @patch("nui_lambda_shared_utils.base_client.get_secret")
    @patch("nui_lambda_shared_utils.es_client.Elasticsearch")
    def test_init_env_vars(self, mock_es, mock_get_secret):
        """Test initialization with environment variables."""
        mock_get_secret.return_value = {"username": "elastic", "password": "test_password"}

        with patch.dict("os.environ", {"ES_HOST": "es.example.com", "ES_CREDENTIALS_SECRET": "custom-es-secret"}):
            client = ElasticsearchClient()

        # Verify environment variable was used for host and secret
        mock_get_secret.assert_called_once_with("custom-es-secret")
        mock_es.assert_called_once_with(
            ["http://es.example.com:9200"],
            basic_auth=("elastic", "test_password"),
            request_timeout=30,
            max_retries=3,
            retry_on_timeout=True,
        )


class TestSearch:
    """Tests for search method."""

    @patch("nui_lambda_shared_utils.base_client.get_secret")
    @patch("nui_lambda_shared_utils.es_client.Elasticsearch")
    def test_search_success(self, mock_es, mock_get_secret):
        """Test successful search."""
        mock_get_secret.return_value = {"username": "elastic", "password": "pass"}
        mock_client = Mock()
        mock_es.return_value = mock_client

        mock_client.search.return_value = {
            "hits": {"hits": [{"_source": {"field1": "value1"}}, {"_source": {"field2": "value2"}}]}
        }

        client = ElasticsearchClient()
        results = client.search("test-index", {"query": {"match_all": {}}})

        assert len(results) == 2
        assert results[0] == {"field1": "value1"}
        assert results[1] == {"field2": "value2"}

        mock_client.search.assert_called_once_with(
            index="test-index", body={"query": {"match_all": {}}}, size=100, ignore_unavailable=True
        )

    @patch("nui_lambda_shared_utils.base_client.get_secret")
    @patch("nui_lambda_shared_utils.es_client.Elasticsearch")
    def test_search_custom_size(self, mock_es, mock_get_secret):
        """Test search with custom size parameter."""
        mock_get_secret.return_value = {"username": "elastic", "password": "pass"}
        mock_client = Mock()
        mock_es.return_value = mock_client
        mock_client.search.return_value = {"hits": {"hits": []}}

        client = ElasticsearchClient()
        client.search("test-index", {}, size=500)

        mock_client.search.assert_called_once_with(index="test-index", body={}, size=500, ignore_unavailable=True)

    @patch("nui_lambda_shared_utils.base_client.get_secret")
    @patch("nui_lambda_shared_utils.es_client.Elasticsearch")
    def test_search_error_handling(self, mock_es, mock_get_secret):
        """Test search error handling."""
        mock_get_secret.return_value = {"username": "elastic", "password": "pass"}
        mock_client = Mock()
        mock_es.return_value = mock_client
        mock_client.search.side_effect = Exception("Connection error")

        client = ElasticsearchClient()
        results = client.search("test-index", {})

        assert results == []  # Should return empty list on error


class TestAggregate:
    """Tests for aggregate method."""

    @patch("nui_lambda_shared_utils.base_client.get_secret")
    @patch("nui_lambda_shared_utils.es_client.Elasticsearch")
    def test_aggregate_success(self, mock_es, mock_get_secret):
        """Test successful aggregation."""
        mock_get_secret.return_value = {"username": "elastic", "password": "pass"}
        mock_client = Mock()
        mock_es.return_value = mock_client

        mock_client.search.return_value = {
            "aggregations": {"total_count": {"value": 100}, "avg_value": {"value": 50.5}}
        }

        client = ElasticsearchClient()
        aggs = client.aggregate(
            "test-index",
            {"aggs": {"total_count": {"sum": {"field": "count"}}, "avg_value": {"avg": {"field": "value"}}}},
        )

        assert aggs["total_count"]["value"] == 100
        assert aggs["avg_value"]["value"] == 50.5

        mock_client.search.assert_called_once_with(
            index="test-index",
            body={"aggs": {"total_count": {"sum": {"field": "count"}}, "avg_value": {"avg": {"field": "value"}}}},
            size=0,
            ignore_unavailable=True,
        )

    @patch("nui_lambda_shared_utils.base_client.get_secret")
    @patch("nui_lambda_shared_utils.es_client.Elasticsearch")
    def test_aggregate_error_handling(self, mock_es, mock_get_secret):
        """Test aggregation error handling."""
        mock_get_secret.return_value = {"username": "elastic", "password": "pass"}
        mock_client = Mock()
        mock_es.return_value = mock_client
        mock_client.search.side_effect = Exception("Aggregation error")

        client = ElasticsearchClient()
        aggs = client.aggregate("test-index", {})

        assert aggs == {}  # Should return empty dict on error


class TestCount:
    """Tests for count method."""

    @patch("nui_lambda_shared_utils.base_client.get_secret")
    @patch("nui_lambda_shared_utils.es_client.Elasticsearch")
    def test_count_success(self, mock_es, mock_get_secret):
        """Test successful document count."""
        mock_get_secret.return_value = {"username": "elastic", "password": "pass"}
        mock_client = Mock()
        mock_es.return_value = mock_client
        mock_client.count.return_value = {"count": 42}

        client = ElasticsearchClient()
        count = client.count("test-index")

        assert count == 42
        mock_client.count.assert_called_once_with(index="test-index", body=None, ignore_unavailable=True)

    @patch("nui_lambda_shared_utils.base_client.get_secret")
    @patch("nui_lambda_shared_utils.es_client.Elasticsearch")
    def test_count_with_query(self, mock_es, mock_get_secret):
        """Test count with query body."""
        mock_get_secret.return_value = {"username": "elastic", "password": "pass"}
        mock_client = Mock()
        mock_es.return_value = mock_client
        mock_client.count.return_value = {"count": 10}

        query = {"query": {"match": {"status": "error"}}}

        client = ElasticsearchClient()
        count = client.count("test-index", query)

        assert count == 10
        mock_client.count.assert_called_once_with(index="test-index", body=query, ignore_unavailable=True)

    @patch("nui_lambda_shared_utils.base_client.get_secret")
    @patch("nui_lambda_shared_utils.es_client.Elasticsearch")
    def test_count_error_handling(self, mock_es, mock_get_secret):
        """Test count error handling."""
        mock_get_secret.return_value = {"username": "elastic", "password": "pass"}
        mock_client = Mock()
        mock_es.return_value = mock_client
        mock_client.count.side_effect = Exception("Count error")

        client = ElasticsearchClient()
        count = client.count("test-index")

        assert count == 0  # Should return 0 on error


class TestGetServiceStats:
    """Tests for get_service_stats method."""

    @patch("nui_lambda_shared_utils.base_client.get_secret")
    @patch("nui_lambda_shared_utils.es_client.Elasticsearch")
    def test_get_service_stats_success(self, mock_es, mock_get_secret):
        """Test successful service stats retrieval."""
        mock_get_secret.return_value = {"username": "elastic", "password": "pass"}
        mock_client = Mock()
        mock_es.return_value = mock_client

        # Mock aggregation response
        mock_client.search.return_value = {
            "aggregations": {
                "total": {"value": 1000},
                "errors": {"count": {"value": 50}},
                "response_times": {"values": {"50.0": 100, "95.0": 500, "99.0": 1000}},
            }
        }

        client = ElasticsearchClient()
        stats = client.get_service_stats("order", hours=12)

        assert stats["total_count"] == 1000
        assert stats["error_count"] == 50
        assert stats["error_rate"] == 5.0  # 50/1000 * 100
        assert stats["p95_response_time"] == 500

        # Verify the search was called with correct parameters
        call_args = mock_client.search.call_args
        assert call_args[1]["index"] == "logs-order-*"
        assert call_args[1]["size"] == 0

        # Verify time range in query
        query = call_args[1]["body"]["query"]["bool"]["filter"][0]["range"]["@timestamp"]
        assert "gte" in query
        assert "lte" in query

    @patch("nui_lambda_shared_utils.base_client.get_secret")
    @patch("nui_lambda_shared_utils.es_client.Elasticsearch")
    def test_get_service_stats_no_data(self, mock_es, mock_get_secret):
        """Test service stats with no data."""
        mock_get_secret.return_value = {"username": "elastic", "password": "pass"}
        mock_client = Mock()
        mock_es.return_value = mock_client

        # Mock empty aggregation response
        mock_client.search.return_value = {
            "aggregations": {"total": {"value": 0}, "errors": {"count": {"value": 0}}, "response_times": {"values": {}}}
        }

        client = ElasticsearchClient()
        stats = client.get_service_stats("auth")

        assert stats["total_count"] == 0
        assert stats["error_count"] == 0
        assert stats["error_rate"] == 0  # Should handle division by zero
        assert stats["p95_response_time"] == 0

    @patch("nui_lambda_shared_utils.base_client.get_secret")
    @patch("nui_lambda_shared_utils.es_client.Elasticsearch")
    @patch("nui_lambda_shared_utils.es_client.datetime")
    def test_get_service_stats_time_window(self, mock_datetime, mock_es, mock_get_secret):
        """Test service stats with custom time window."""
        mock_get_secret.return_value = {"username": "elastic", "password": "pass"}
        mock_client = Mock()
        mock_es.return_value = mock_client

        # Mock datetime
        mock_now = datetime(2024, 1, 30, 12, 0, 0)
        mock_datetime.utcnow.return_value = mock_now

        mock_client.search.return_value = {
            "aggregations": {
                "total": {"value": 100},
                "errors": {"count": {"value": 10}},
                "response_times": {"values": {"95.0": 200}},
            }
        }

        client = ElasticsearchClient()
        stats = client.get_service_stats("product", hours=48)

        # Verify time calculation
        call_args = mock_client.search.call_args
        query = call_args[1]["body"]["query"]["bool"]["filter"][0]["range"]["@timestamp"]

        # Should be 48 hours ago
        expected_start = (mock_now - timedelta(hours=48)).isoformat()
        assert query["gte"] == expected_start
        assert query["lte"] == mock_now.isoformat()
