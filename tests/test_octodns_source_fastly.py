from unittest import TestCase, skip
from unittest.mock import MagicMock, call, patch

from requests.exceptions import HTTPError

from octodns.zone import Zone

from octodns_fastly import FastlyAcmeSource


class FastlyAcmeSourceTestCase(TestCase):
    def test_init(self):
        source = FastlyAcmeSource("test_id", "test_token")
        assert source.id == "test_id"
        assert source._ttl == 3600
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
                                "values": [
                                    "1234567890abcdef.fastly-validations.com"
                                ],
                            }
                        ]
                    },
                }
            ],
            "meta": {"current_page": 1, "total_pages": 1},
        }
        source._session = mock_requests
        mock_requests.get.return_value = mock_response

        source.populate(zone)

        assert len(zone.records) == 1

        records = {(r.name, r._type): r for r in zone.records}

        print(records)

        assert 60 == records[("_acme-challenge", "CNAME")].ttl

    @skip(reason="domain filter does not work when given a subzone")
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
        source._session = mock_requests
        mock_requests.get.return_value = mock_response

        source.populate(zone)

        assert len(zone.records) == 0
        mock_requests.get.assert_called_with(
            "https://api.fastly.com/tls/subscriptions?include=tls_authorizations&filter[tls_domains.id]=example.net",
            headers={"Fastly-Key": "test_token"},
        )

    @patch("octodns_fastly.requests")
    def test_populate_filters_non_tls_authorizations(self, mock_requests):
        zone = Zone("example.com.", [])
        source = FastlyAcmeSource("test_id", "test_token")

        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "data": [],
            "included": [],
            "meta": {"current_page": 1, "total_pages": 1},
        }
        source._session = mock_requests
        mock_requests.get.return_value = mock_response

        source.populate(zone)

        assert len(zone.records) == 0

    @patch("octodns_fastly.requests")
    def test_populate_with_no_tls_subscriptions(self, mock_requests):
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
                                "values": [
                                    "1234567890abcdef.fastly-validations.com"
                                ],
                            }
                        ]
                    },
                },
                {"id": "1111111111111111111111", "type": "tls_other"},
            ],
            "meta": {"current_page": 1, "total_pages": 1},
        }
        source._session = mock_requests
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
                                "values": [
                                    "1234567890abcdef.fastly-validations.com"
                                ],
                            }
                        ]
                    },
                }
            ],
            "meta": {"current_page": 1, "total_pages": 1},
        }
        source._session = mock_requests
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
                                "values": [
                                    "1234567890abcdef.fastly-validations.com"
                                ],
                            },
                            {
                                "type": "managed-dns",
                                "record_type": "CNAME",
                                "record_name": "_acme-challenge.www.example.com",
                                "values": [
                                    "fedcba0987654321.fastly-validations.com"
                                ],
                            },
                        ]
                    },
                }
            ],
            "meta": {"current_page": 1, "total_pages": 1},
        }
        source._session = mock_requests
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
    def test_populate_with_mixed_domains_in_tls_subscription(
        self, mock_requests
    ):
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
                                "values": [
                                    "1234567890abcdef.fastly-validations.com"
                                ],
                            },
                            {
                                "type": "managed-dns",
                                "record_type": "CNAME",
                                "record_name": "_acme-challenge.example.net",
                                "values": [
                                    "fedcba0987654321.fastly-validations.com"
                                ],
                            },
                        ]
                    },
                }
            ],
            "meta": {"current_page": 1, "total_pages": 1},
        }
        source._session = mock_requests
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
    def test_populate_dedups_wildcard_and_root_domain_challenges(
        self, mock_requests
    ):
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
                                "values": [
                                    "1234567890abcdef.fastly-validations.com"
                                ],
                            },
                            {
                                "type": "managed-dns",
                                "record_type": "CNAME",
                                "record_name": "_acme-challenge.example.com",
                                "values": [
                                    "1234567890abcdef.fastly-validations.com"
                                ],
                            },
                        ]
                    },
                }
            ],
            "meta": {"current_page": 1, "total_pages": 1},
        }
        source._session = mock_requests
        mock_requests.get.return_value = mock_response

        source.populate(zone)

        records = {(r.name, r._type): r for r in zone.records}

        assert len(zone.records) == 1

        record = records[("_acme-challenge", "CNAME")]
        assert "_acme-challenge" == record.name
        assert "CNAME" == record._type
        assert "1234567890abcdef.fastly-validations.com." == record.value
        assert 3600 == record.ttl

    @patch("octodns_fastly.requests")
    def test_populate_with_subzone(self, mock_requests):
        zone = Zone("example.com.", ["internal"])
        subzone = Zone("internal.example.com.", [])
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
                                "values": [
                                    "1234567890abcdef.fastly-validations.com"
                                ],
                            },
                            {
                                "type": "managed-dns",
                                "record_type": "CNAME",
                                "record_name": "_acme-challenge.www.internal.example.com",
                                "values": [
                                    "1234567890abcdef.fastly-validations.com"
                                ],
                            },
                        ]
                    },
                }
            ],
            "meta": {"current_page": 1, "total_pages": 1},
        }
        source._session = mock_requests
        mock_requests.get.return_value = mock_response

        source.populate(zone)

        records = {(r.name, r._type): r for r in zone.records}

        assert len(zone.records) == 1

        record = records[("_acme-challenge.www", "CNAME")]
        assert "_acme-challenge.www" == record.name
        assert "CNAME" == record._type
        assert "1234567890abcdef.fastly-validations.com." == record.value
        assert 3600 == record.ttl

        source.populate(subzone)

        records = {(r.name, r._type): r for r in subzone.records}

        assert len(subzone.records) == 1

        record = records[("_acme-challenge.www", "CNAME")]
        assert "_acme-challenge.www" == record.name
        assert "CNAME" == record._type
        assert "1234567890abcdef.fastly-validations.com." == record.value
        assert 3600 == record.ttl

    # The TLS subscription list API endpoint is paginated.
    @patch("octodns_fastly.requests")
    def test_populate_supports_api_pagination(self, mock_requests):
        zone = Zone("example.com.", [])
        source = FastlyAcmeSource("test_id", "test_token")

        mock_page_one_response = MagicMock()
        mock_page_one_response.status_code = 200
        mock_page_one_response.json.return_value = {
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
                                "values": [
                                    "1234567890abcdef.fastly-validations.com"
                                ],
                            }
                        ]
                    },
                }
            ],
            "meta": {"current_page": 1, "total_pages": 3},
        }

        mock_page_two_response = MagicMock()
        mock_page_two_response.status_code = 200
        mock_page_two_response.json.return_value = {
            "data": [],
            "included": [
                {
                    "id": "lkjihgfedcba0987654321",
                    "type": "tls_authorization",
                    "attributes": {
                        "challenges": [
                            {
                                "type": "managed-dns",
                                "record_type": "CNAME",
                                "record_name": "_acme-challenge.www.example.com",
                                "values": [
                                    "fedcba0987654321.fastly-validations.com"
                                ],
                            }
                        ]
                    },
                }
            ],
            "meta": {"current_page": 2, "total_pages": 3},
        }

        mock_page_three_response = MagicMock()
        mock_page_three_response.status_code = 200
        mock_page_three_response.json.return_value = {
            "data": [],
            "included": [
                {
                    "id": "lkjihgfedcba1234567890",
                    "type": "tls_authorization",
                    "attributes": {
                        "challenges": [
                            {
                                "type": "managed-dns",
                                "record_type": "CNAME",
                                "record_name": "_acme-challenge.internal.example.com",
                                "values": [
                                    "aaaaaaaaaaaaaaaa.fastly-validations.com"
                                ],
                            }
                        ]
                    },
                }
            ],
            "meta": {"current_page": 3, "total_pages": 3},
        }

        source._session = mock_requests
        mock_requests.get.side_effect = [
            mock_page_one_response,
            mock_page_two_response,
            mock_page_three_response,
        ]

        source.populate(zone)

        records = {(r.name, r._type): r for r in zone.records}

        assert len(zone.records) == 3

        mock_requests.get.assert_has_calls(
            [
                call(
                    "https://api.fastly.com/tls/subscriptions",
                    params={"include": "tls_authorizations", "page[number]": 1},
                    headers={"Fastly-Key": "test_token"},
                ),
                call(
                    "https://api.fastly.com/tls/subscriptions",
                    params={"include": "tls_authorizations", "page[number]": 2},
                    headers={"Fastly-Key": "test_token"},
                ),
                call(
                    "https://api.fastly.com/tls/subscriptions",
                    params={"include": "tls_authorizations", "page[number]": 3},
                    headers={"Fastly-Key": "test_token"},
                ),
            ]
        )

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

        record = records[("_acme-challenge.internal", "CNAME")]
        assert "_acme-challenge.internal" == record.name
        assert "CNAME" == record._type
        assert "aaaaaaaaaaaaaaaa.fastly-validations.com." == record.value
        assert 3600 == record.ttl

    @patch("octodns_fastly.requests")
    def test_populate_api_pagination_with_wildcard_and_root(
        self, mock_requests
    ):
        zone = Zone("example.com.", [])
        source = FastlyAcmeSource("test_id", "test_token")

        mock_page_one_response = MagicMock()
        mock_page_one_response.status_code = 200
        mock_page_one_response.json.return_value = {
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
                                "values": [
                                    "1234567890abcdef.fastly-validations.com"
                                ],
                            }
                        ]
                    },
                }
            ],
            "meta": {"current_page": 1, "total_pages": 2},
        }

        mock_page_two_response = MagicMock()
        mock_page_two_response.status_code = 200
        mock_page_two_response.json.return_value = {
            "data": [],
            "included": [
                {
                    "id": "lkjihgfedcba0987654321",
                    "type": "tls_authorization",
                    "attributes": {
                        "challenges": [
                            {
                                "type": "managed-dns",
                                "record_type": "CNAME",
                                "record_name": "_acme-challenge.example.com",
                                "values": [
                                    "1234567890abcdef.fastly-validations.com"
                                ],
                            }
                        ]
                    },
                }
            ],
            "meta": {"current_page": 2, "total_pages": 2},
        }
        source._session = mock_requests
        mock_requests.get.side_effect = [
            mock_page_one_response,
            mock_page_two_response,
        ]

        source.populate(zone)

        records = {(r.name, r._type): r for r in zone.records}

        assert len(zone.records) == 1

        record = records[("_acme-challenge", "CNAME")]
        assert "_acme-challenge" == record.name
        assert "CNAME" == record._type
        assert "1234567890abcdef.fastly-validations.com." == record.value
        assert 3600 == record.ttl

    @patch("octodns_fastly.requests")
    def test_populate_errors_with_invalid_api_key(self, mock_requests):
        zone = Zone("example.com.", [])
        source = FastlyAcmeSource("test_id", "test_token")

        mock_response = MagicMock()
        mock_response.status_code = 401
        mock_response.json.return_value = {
            "msg": "Provided credentials are missing or invalid"
        }
        source._session = mock_requests
        mock_requests.get.return_value = mock_response

        mock_response.raise_for_status.side_effect = HTTPError()

        with self.assertRaises(HTTPError):
            source.populate(zone)
