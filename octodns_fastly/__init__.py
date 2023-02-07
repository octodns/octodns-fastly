"""
A Fastly source for OctoDNS.

Automatically create ACME CNAME records for verifying domains in Fastly TLS subscriptions.
"""

import logging

import requests
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
      default_ttl: 86400

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

    def __init__(self, id: str, token: str, default_ttl: int = DEFAULT_TTL):
        klass = self.__class__.__name__
        self.log = logging.getLogger(f"{klass}[{id}]")
        self.log.debug("__init__: id=%s, default_ttl=%d", id, default_ttl)

        super().__init__(id)

        self.ttl = default_ttl
        self._token = token

    def _challenges(self, zone: Zone):
        domain = zone.name.removesuffix(".")

        resp = requests.get(
            "https://api.fastly.com/tls/subscriptions?include=tls_authorizations&filter[tls_domains.id]=%s" % domain,
            headers={"Fastly-Key": self._token},
        )

        subscriptions = resp.json()

        if subscriptions["meta"]["total_pages"] > 1:
            raise NotImplementedError("More than one page of TLS subscriptions is not supported")

        # Ensure we only have a list of authorizations
        authorizations = [
            authorization for authorization in subscriptions["included"] if authorization["type"] == "tls_authorization"
        ]

        self.log.debug("_challenges: recieved %d authorizations", len(authorizations))

        # Use a set to deduplicate identical challenges
        challenges = set()

        for authorization in authorizations:
            self.log.debug(
                "_challenges: recieved %d challenges for authorization %s",
                len(authorization["attributes"]["challenges"]),
                authorization["id"],
            )

            for challenge in authorization["attributes"]["challenges"]:
                if challenge["type"] == "managed-dns" and challenge["record_name"].endswith("." + domain):
                    challenges.add(
                        (
                            challenge["record_name"].removesuffix("." + domain),
                            "%s." % challenge["values"][0],
                        )
                    )

        self.log.debug("_challenges: filtered to %d challenges", len(challenges))

        return [{"name": name, "value": value} for name, value in challenges]

    def populate(self, zone: Zone, target=False, lenient=False):
        self.log.debug(
            "populate: name=%s, target=%s, lenient=%s",
            zone.name,
            target,
            lenient,
        )

        before = len(zone.records)

        for challange in self._challenges(zone):
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
