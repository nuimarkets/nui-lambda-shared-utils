"""Compatibility tests for es_client against the installed elasticsearch-py client.

The other ES tests replace ``Elasticsearch`` with a ``Mock``, which pins the call
shape we send but cannot tell whether the installed client accepts it. These drive
the *real* client with a stubbed transport (no server, no network), so they fail if
our call shape stops being valid on the installed major.

Supported majors: 7.17, 8.x and 9.x. The CI ``es-compat`` job runs this file
against each in turn.
"""

import json
import warnings

import pytest

pytestmark = pytest.mark.unit

import elasticsearch

from nui_shared_utils.es_client import ElasticsearchClient

ES_MAJOR = elasticsearch.__version__[0]

SEARCH_PAYLOAD = {
    "hits": {"hits": [{"_source": {"field1": "value1"}}, {"_source": {"field2": "value2"}}]},
    "aggregations": {"total": {"value": 3}},
}


class RequestRecorder:
    """Stub transport that records requests and replays a canned payload."""

    def __init__(self, payload):
        self.payload = payload
        self.requests = []

    def __call__(self, *args, **kwargs):
        method, target = args[0], args[1]
        body = kwargs.get("body", args[4] if len(args) > 4 else None)
        self.requests.append({"method": method, "target": target, "body": body})
        if ES_MAJOR >= 8:
            from elastic_transport import ApiResponseMeta, TransportApiResponse

            meta = ApiResponseMeta(
                status=200,
                http_version="1.1",
                headers={"x-elastic-product": "Elasticsearch"},
                duration=0.0,
                node=None,
            )
            return TransportApiResponse(meta, self.payload)
        return self.payload

    @property
    def last(self):
        return self.requests[-1]

    def sent_body(self, index=-1):
        """Return the request body as a dict, whichever form the client serialised it in."""
        body = self.requests[index]["body"]
        if isinstance(body, (bytes, str)):
            return json.loads(body)
        return body or {}


def build_client(payload):
    """Real ElasticsearchClient wired to a stub transport."""
    client = ElasticsearchClient(
        host="localhost:9200",
        credentials={"username": "elastic", "password": "pass"},
    )
    recorder = RequestRecorder(payload)
    client._service_client.transport.perform_request = recorder
    return client, recorder


@pytest.fixture
def no_mixed_body_warning():
    """Fail on the 8.x/9.x warning raised when body= is mixed with body-field keywords.

    Narrow by design: it only catches the warning form. The 8.x/9.x hard failure
    (``ValueError: Received multiple values for 'size'``) is swallowed by
    ``handle_client_errors``, so the result assertions in each test catch that.
    """
    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always")
        yield
    offenders = [
        str(w.message)
        for w in caught
        if "in the presence of a 'body' parameter" in str(w.message) or "Received multiple values" in str(w.message)
    ]
    assert not offenders, f"call shape mixes body and body-field keywords: {offenders}"


class TestInstalledClientAcceptsOurCalls:
    """Every call es_client makes must be valid on the installed client major."""

    def test_constructor_kwargs_accepted(self):
        client, _ = build_client(SEARCH_PAYLOAD)
        assert isinstance(client._service_client, elasticsearch.Elasticsearch)

    def test_search(self, no_mixed_body_warning):
        client, recorder = build_client(SEARCH_PAYLOAD)

        results = client.search("test-index-*", {"query": {"match_all": {}}}, size=25)

        # An empty list means the client rejected the call: handle_client_errors
        # swallows the exception and returns the default.
        assert results == [{"field1": "value1"}, {"field2": "value2"}]
        assert recorder.sent_body()["size"] == 25
        assert "test-index-*" in recorder.last["target"]

    def test_search_reuses_the_same_body_dict(self, no_mixed_body_warning):
        """Two searches from one body dict: mutating clients break the second call."""
        client, recorder = build_client(SEARCH_PAYLOAD)
        body = {"query": {"match_all": {}}}

        first = client.search("test-index-*", body, size=10)
        second = client.search("test-index-*", body, size=20)

        assert first and second
        assert recorder.sent_body(0)["size"] == 10
        assert recorder.sent_body(1)["size"] == 20
        assert body == {"query": {"match_all": {}}}, "caller's body dict was mutated"

    def test_aggregate(self, no_mixed_body_warning):
        client, recorder = build_client(SEARCH_PAYLOAD)

        aggs = client.aggregate("test-index-*", {"aggs": {"total": {"cardinality": {"field": "id"}}}})

        assert aggs == {"total": {"value": 3}}
        assert recorder.sent_body()["size"] == 0

    def test_count(self, no_mixed_body_warning):
        client, recorder = build_client({"count": 42})

        assert client.count("test-index-*", {"query": {"match_all": {}}}) == 42
        assert recorder.sent_body() == {"query": {"match_all": {}}}

        assert client.count("test-index-*") == 42  # body=None

    def test_get_indices_info_returns_plain_list(self):
        client, _ = build_client([{"index": "test-index", "health": "green"}])

        indices = client.get_indices_info("test-*")

        assert type(indices) is list
        assert indices == [{"index": "test-index", "health": "green"}]

    def test_get_cluster_info(self):
        client, _ = build_client({"version": {"number": "8.19.0"}, "cluster_name": "c", "status": "green"})

        info = client.get_cluster_info()

        assert info["version"] == "8.19.0"
        assert info["cluster_status"] == "green"
        assert "error" not in info
