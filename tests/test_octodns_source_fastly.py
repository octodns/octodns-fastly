from unittest import TestCase
from unittest.mock import MagicMock, patch

from fastly.api.tls_subscriptions_api import TlsSubscriptionsApi
from octodns.zone import Zone

from octodns_fastly import FastlyAcmeSource


class FastlyAcmeSourceTestCase(TestCase):
    def test_init(self):
        source = FastlyAcmeSource("test_id", "test_token")
        assert source.id == "test_id"
        assert source.ttl == 3600
        assert source._token == "test_token"

    @patch("octodns_fastly.requests")
    def test_custom_default_ttl(self, mock_requests):
        zone = Zone("example.net.", [])
        source = FastlyAcmeSource("test_id", "test_token", default_ttl=60)

        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "data": [],
            "included": [
                {
                    "id": "1234567890abcdefghijkl",
                    "type": "tls_authorization",
                    "attributes": {
                        "challenges": [
                            {
                                "type": "managed-dns",
                                "record_type": "CNAME",
                                "record_name": "_acme-challenge.example.net",
                                "values": ["1234567890abcdef.fastly-validations.com"],
                            }
                        ]
                    },
                }
            ],
            "meta": {"total_pages": 1},
        }
        mock_requests.get.return_value = mock_response

        source.populate(zone)

        assert len(zone.records) == 1

        records = {(r.name, r._type): r for r in zone.records}

        print(records)

        assert 60 == records[("_acme-challenge", "CNAME")].ttl

    @patch("octodns_fastly.requests")
    def test_challanges_filters_by_zone(self, mock_requests):
        zone = Zone("example.net.", [])
        source = FastlyAcmeSource("test_id", "test_token")

        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "data": [],
            "included": [],
            "meta": {"total_pages": 1},
        }
        mock_requests.get.return_value = mock_response

        source.populate(zone)

        assert len(zone.records) == 0
        mock_requests.get.assert_called_with(
            "https://api.fastly.com/tls/subscriptions?include=tls_authorizations&filter[tls_domains.id]=example.net",
            headers={"Fastly-Key": "test_token"},
        )

    @patch("octodns_fastly.requests")
    def test_populate_with_no_tls_subscriptions(self, mock_requests):
        zone = Zone("example.com.", [])
        source = FastlyAcmeSource("test_id", "test_token")

        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "data": [],
            "included": [],
            "meta": {"total_pages": 1},
        }
        mock_requests.get.return_value = mock_response

        source.populate(zone)

        assert len(zone.records) == 0

    @patch("octodns_fastly.requests")
    def test_populate_with_single_tls_challenge(self, mock_requests):
        zone = Zone("example.com.", [])
        source = FastlyAcmeSource("test_id", "test_token")

        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "data": [],
            "included": [
                {
                    "id": "1234567890abcdefghijkl",
                    "type": "tls_authorization",
                    "attributes": {
                        "challenges": [
                            {
                                "type": "managed-dns",
                                "record_type": "CNAME",
                                "record_name": "_acme-challenge.www.example.com",
                                "values": ["1234567890abcdef.fastly-validations.com"],
                            }
                        ]
                    },
                }
            ],
            "meta": {"total_pages": 1},
        }
        mock_requests.get.return_value = mock_response

        source.populate(zone)

        records = {(r.name, r._type): r for r in zone.records}
        record = records[("_acme-challenge.www", "CNAME")]

        assert len(zone.records) == 1
        assert "_acme-challenge.www" == record.name
        assert "CNAME" == record._type
        assert "1234567890abcdef.fastly-validations.com." == record.value
        assert 3600 == record.ttl

    @patch("octodns_fastly.requests")
    def test_populate_with_multiple_tls_challenges(self, mock_requests):
        zone = Zone("example.com.", [])
        source = FastlyAcmeSource("test_id", "test_token")

        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "data": [],
            "included": [
                {
                    "id": "1234567890abcdefghijkl",
                    "type": "tls_authorization",
                    "attributes": {
                        "challenges": [
                            {
                                "type": "managed-dns",
                                "record_type": "CNAME",
                                "record_name": "_acme-challenge.example.com",
                                "values": ["1234567890abcdef.fastly-validations.com"],
                            },
                            {
                                "type": "managed-dns",
                                "record_type": "CNAME",
                                "record_name": "_acme-challenge.www.example.com",
                                "values": ["fedcba0987654321.fastly-validations.com"],
                            },
                        ]
                    },
                }
            ],
            "meta": {"total_pages": 1},
        }
        mock_requests.get.return_value = mock_response

        source.populate(zone)

        records = {(r.name, r._type): r for r in zone.records}

        assert len(zone.records) == 2

        record = records[("_acme-challenge", "CNAME")]
        assert "_acme-challenge" == record.name
        assert "CNAME" == record._type
        assert "1234567890abcdef.fastly-validations.com." == record.value
        assert 3600 == record.ttl

        record = records[("_acme-challenge.www", "CNAME")]
        assert "_acme-challenge.www" == record.name
        assert "CNAME" == record._type
        assert "fedcba0987654321.fastly-validations.com." == record.value
        assert 3600 == record.ttl

    # TLS subscriptions can contain a mix of domains, so we need to filter out any
    # that don't match the zone we're populating.
    @patch("octodns_fastly.requests")
    def test_populate_with_mixed_domains_in_tls_subscription(self, mock_requests):
        zone = Zone("example.com.", [])
        source = FastlyAcmeSource("test_id", "test_token")

        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "data": [],
            "included": [
                {
                    "id": "1234567890abcdefghijkl",
                    "type": "tls_authorization",
                    "attributes": {
                        "challenges": [
                            {
                                "type": "managed-dns",
                                "record_type": "CNAME",
                                "record_name": "_acme-challenge.example.com",
                                "values": ["1234567890abcdef.fastly-validations.com"],
                            },
                            {
                                "type": "managed-dns",
                                "record_type": "CNAME",
                                "record_name": "_acme-challenge.example.net",
                                "values": ["fedcba0987654321.fastly-validations.com"],
                            },
                        ]
                    },
                }
            ],
            "meta": {"total_pages": 1},
        }
        mock_requests.get.return_value = mock_response

        source.populate(zone)

        records = {(r.name, r._type): r for r in zone.records}

        assert len(zone.records) == 1

        record = records[("_acme-challenge", "CNAME")]
        assert "_acme-challenge" == record.name
        assert "CNAME" == record._type
        assert "1234567890abcdef.fastly-validations.com." == record.value
        assert 3600 == record.ttl

    # When a TLS subscription contains a wildcard and root domain (e.g. example.com and *.example.com)
    # the challenge record is listed twice in the API response with the same record_name and values.
    @patch("octodns_fastly.requests")
    def test_populate_dedups_wildcard_and_root_domain_challenges(self, mock_requests):
        zone = Zone("example.com.", [])
        source = FastlyAcmeSource("test_id", "test_token")

        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "data": [],
            "included": [
                {
                    "id": "1234567890abcdefghijkl",
                    "type": "tls_authorization",
                    "attributes": {
                        "challenges": [
                            {
                                "type": "managed-dns",
                                "record_type": "CNAME",
                                "record_name": "_acme-challenge.example.com",
                                "values": ["1234567890abcdef.fastly-validations.com"],
                            },
                            {
                                "type": "managed-dns",
                                "record_type": "CNAME",
                                "record_name": "_acme-challenge.example.com",
                                "values": ["1234567890abcdef.fastly-validations.com"],
                            },
                        ]
                    },
                }
            ],
            "meta": {"total_pages": 1},
        }
        mock_requests.get.return_value = mock_response

        source.populate(zone)

        records = {(r.name, r._type): r for r in zone.records}

        assert len(zone.records) == 1

        record = records[("_acme-challenge", "CNAME")]
        assert "_acme-challenge" == record.name
        assert "CNAME" == record._type
        assert "1234567890abcdef.fastly-validations.com." == record.value
        assert 3600 == record.ttl

    # The TLS subscription list API endpoint is paginated. We only support a single page of results.
    @patch("octodns_fastly.requests")
    def test_populate_errors_on_too_many_subscriptions(self, mock_requests):
        zone = Zone("example.com.", [])
        source = FastlyAcmeSource("test_id", "test_token")

        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"data": [], "included": [], "meta": {"total_pages": 2}}
        mock_requests.get.return_value = mock_response

        with self.assertRaises(NotImplementedError) as context:
            source.populate(zone)

        assert "More than one page of TLS subscriptions is not supported" in str(context.exception)
