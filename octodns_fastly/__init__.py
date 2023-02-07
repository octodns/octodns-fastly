"""
A Fastly source for OctoDNS.

Automatically create ACME CNAME records for verifying domains in Fastly TLS subscriptions.
"""

import logging

import requests
from octodns.record import Record
from octodns.source.base import BaseSource
from octodns.zone import SubzoneRecordException, Zone


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

        self._ttl = default_ttl
        self._token = token

    def _list_tls_subscriptions(self):
        url = "https://api.fastly.com/tls/subscriptions?include=tls_authorizations"

        while True:
            resp = requests.get(
                url,
                headers={"Fastly-Key": self._token},
            )
            resp.raise_for_status()  # Error on non-200 responses

            subscriptions = resp.json()
            yield subscriptions

            self.log.debug(
                "_list_tls_subscriptions: recieved tls subscription page %d of %d",
                subscriptions["meta"]["current_page"],
                subscriptions["meta"]["total_pages"],
            )

            if subscriptions["meta"]["current_page"] == subscriptions["meta"]["total_pages"]:
                break

            url = "%s&page[number]=%d" % (url, subscriptions["meta"]["current_page"] + 1)

    def _challenges(self, zone: Zone):
        domain = zone.name.removesuffix(".")

        # Use a set to deduplicate identical challenges
        challenges = set()

        for subscriptions in self._list_tls_subscriptions():
            # Ensure we only have a list of authorizations
            authorizations = [
                authorization for authorization in subscriptions["included"] if authorization["type"] == "tls_authorization"
            ]

            self.log.debug("_challenges: recieved %d authorizations", len(authorizations))

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
                    "ttl": self._ttl,
                    "value": challange["value"],
                },
            )

            try:
                zone.add_record(record)
            except SubzoneRecordException:
                self.log.debug(
                    "populate: skipping subzone record=%s",
                    record,
                )

        self.log.info("populate:   found %s records", len(zone.records) - before)
