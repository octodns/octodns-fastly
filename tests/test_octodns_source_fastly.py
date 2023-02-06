from unittest import TestCase
from unittest.mock import patch

from fastly.api.tls_subscriptions_api import TlsSubscriptionsApi
from octodns.zone import Zone

from octodns_fastly import FastlyAcmeSource


class FastlyAcmeSourceTestCase(TestCase):
    def test_init(self):
        source = FastlyAcmeSource("test_id", "test_token")
        assert source.id == "test_id"
        assert source.ttl == 3600
        assert source._config.api_token == "test_token"

    def test_custom_default_ttl(self):
        zone = Zone("example.com.", [])
        source = FastlyAcmeSource("test_id", "test_token", ttl=60)

        with patch.object(TlsSubscriptionsApi, "list_tls_subs") as mock:
            mock.return_value = {
                "data": [],
                "included": [
                    {
                        "type": "tls_authorization",
                        "attributes": {
                            "challenges": [
                                {
                                    "type": "managed-dns",
                                    "record_type": "CNAME",
                                    "record_name": "_acme-challenge.example.com",
                                    "values": ["1234567890abcdef.fastly-validations.com"],
                                }
                            ]
                        },
                    }
                ],
                "meta": {"total_pages": 1},
            }

            source.populate(zone)

            assert len(zone.records) == 1

            records = {(r.name, r._type): r for r in zone.records}

            assert 60 == records[("_acme-challenge", "CNAME")].ttl

    def test_challanges_filters_by_zone(self):
        zone = Zone("example.net.", [])
        source = FastlyAcmeSource("test_id", "test_token", ttl=60)

        with patch.object(TlsSubscriptionsApi, "list_tls_subs") as mock:
            mock.return_value = {
                "data": [],
                "included": [],
                "meta": {"total_pages": 1},
            }

            source.populate(zone)

            assert len(zone.records) == 0
            mock.assert_called_with(include="tls_authorizations", filter_tls_domains_id="example.net")

    def test_populate_with_no_tls_subscriptions(self):
        zone = Zone("example.com.", [])
        source = FastlyAcmeSource("test_id", "test_token", ttl=60)

        with patch.object(TlsSubscriptionsApi, "list_tls_subs") as mock:
            mock.return_value = {
                "data": [],
                "included": [],
                "meta": {"total_pages": 1},
            }

            source.populate(zone)

            assert len(zone.records) == 0

    def test_populate_with_single_tls_challenge(self):
        zone = Zone("example.com.", [])
        source = FastlyAcmeSource("test_id", "test_token")

        with patch.object(TlsSubscriptionsApi, "list_tls_subs") as mock:
            mock.return_value = {
                "data": [],
                "included": [
                    {
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

            source.populate(zone)

            records = {(r.name, r._type): r for r in zone.records}
            record = records[("_acme-challenge.www", "CNAME")]

            assert len(zone.records) == 1
            assert "_acme-challenge.www" == record.name
            assert "CNAME" == record._type
            assert "1234567890abcdef.fastly-validations.com." == record.value
            assert 3600 == record.ttl

    def test_populate_with_multiple_tls_challenges(self):
        zone = Zone("example.com.", [])
        source = FastlyAcmeSource("test_id", "test_token")

        with patch.object(TlsSubscriptionsApi, "list_tls_subs") as mock:
            mock.return_value = {
                "data": [],
                "included": [
                    {
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

    def test_populate_with_multiple_tls_subscriptions(self):
        zone = Zone("example.com.", [])
        source = FastlyAcmeSource("test_id", "test_token")

        with patch.object(TlsSubscriptionsApi, "list_tls_subs") as mock:
            mock.return_value = {
                "data": [],
                "included": [
                    {
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

            source.populate(zone)

            records = {(r.name, r._type): r for r in zone.records}
            record = records[("_acme-challenge.www", "CNAME")]

            assert len(zone.records) == 1
            assert "_acme-challenge.www" == record.name
            assert "CNAME" == record._type
            assert "1234567890abcdef.fastly-validations.com." == record.value
            assert 3600 == record.ttl

    def test_populate_errors_on_too_many_subscriptions(self):
        zone = Zone("example.com.", [])
        source = FastlyAcmeSource("test_id", "test_token")

        with patch.object(TlsSubscriptionsApi, "list_tls_subs") as mock:
            mock.return_value = {"data": [], "included": [], "meta": {"total_pages": 2}}

            with self.assertRaises(NotImplementedError) as context:
                source.populate(zone)

            assert "More than one page of TLS subscriptions is not supported" in str(context.exception)
