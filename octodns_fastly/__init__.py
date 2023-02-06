"""
A Fastly source for OctoDNS.

Automatically create ACME CNAME records for verifying domains in Fastly TLS subscriptions.
"""

import logging

import fastly
from fastly.api.tls_subscriptions_api import TlsSubscriptionsApi
from octodns.record import Record
from octodns.source.base import BaseSource
from octodns.zone import Zone


class FastlyAcmeSource(BaseSource):
    """
    Fastly Acme Source

    ```yaml
    fastly:
      class: octodns_fastly.FastlyAcmeSource
      token: env/FASTLY_API_TOKEN

    zones:
      example.com.:
        sources:
          - yaml
          - fastly
        targets:
          - route53
    ```
    """

    SUPPORTS_GEO = False
    SUPPORTS_DYNAMIC = False
    SUPPORTS = set(("CNAME"))

    DEFAULT_TTL = 3600

    def __init__(self, id: str, token: str, ttl: int = DEFAULT_TTL):
        klass = self.__class__.__name__
        self.log = logging.getLogger(f"{klass}[{id}]")
        self.log.debug("__init__: id=%s, ttl=%d", id, ttl)

        super().__init__(id)

        self.ttl = ttl
        self._config = fastly.Configuration()
        self._config.api_token = token

        self._challenges = None

    def challenges(self, zone: Zone):
        if self._challenges is None:
            with fastly.ApiClient(self._config) as client:
                instance = TlsSubscriptionsApi(client)
                subscriptions = instance.list_tls_subs(
                    include="tls_authorizations", filter_tls_domains_id=zone.name.removesuffix(".")
                )

                if subscriptions["meta"]["total_pages"] > 1:
                    raise NotImplementedError("More than one page of TLS subscriptions is not supported")

                # Ensure we only have a list of authorizations
                authorizations = [
                    authorization
                    for authorization in subscriptions["included"]
                    if authorization["type"] == "tls_authorization"
                ]

                challenges = []

                for authorization in authorizations:
                    for challenge in authorization["attributes"]["challenges"]:
                        if challenge["type"] == "managed-dns":
                            challenges.append(
                                {
                                    "name": challenge["record_name"].removesuffix(".example.com"),
                                    "value": "%s." % challenge["values"][0],
                                }
                            )

                self._challenges = challenges

        return self._challenges

    def populate(self, zone: Zone, target=False, lenient=False):
        self.log.debug(
            "populate: name=%s, target=%s, lenient=%s",
            zone.name,
            target,
            lenient,
        )

        before = len(zone.records)

        for challange in self.challenges(zone):
            record = Record.new(
                zone,
                challange["name"],
                {
                    "type": "CNAME",
                    "ttl": self.ttl,
                    "value": challange["value"],
                },
            )
            zone.add_record(record)

        self.log.info("populate:   found %s records", len(zone.records) - before)
