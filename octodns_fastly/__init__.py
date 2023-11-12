import logging
from functools import lru_cache

import requests

from octodns.record import Record
from octodns.source.base import BaseSource
from octodns.zone import SubzoneRecordException, Zone

__version__ = __VERSION__ = '0.0.1'


class FastlyAcmeSource(BaseSource):
    """
    An OctoDNS source for Fastly ACME DNS challenges.

    Uses the [List TLS Subscriptions API endpoint](https://developer.fastly.com/reference/api/tls/subs/#list-tls-subs) to build a list
    of [ACME DNS challenge records](https://docs.fastly.com/en/guides/serving-https-traffic-using-fastly-managed-certificates#using-the-acme-dns-challenge-to-verify-domain-ownership)
    to create in a zone.

    e.g. `_acme-challenge.example.com. CNAME 1234567890.fastly-validations.com.`

    Configure this source:

    ```yaml
    providers:
      fastly:
        class: octodns_fastly.FastlyAcmeSource
        token: env/FASTLY_API_TOKEN

    zones:
      example.com.:
        sources:
          - fastly
    ```
    """  # noqa E501

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
        self._session = requests.Session()

    @lru_cache(maxsize=None)
    def _list_tls_authorizations(self):
        """
        Fetch TLS subscriptions and return a list of TLS authorizations.

        This method uses `@cache` to avoid making multiple requests to the Fastly API
        on every call to populate a zone when the responses will be the same per Fastly account.
        """
        page = 1
        authorizations = []
        while True:
            resp = self._session.get(
                "https://api.fastly.com/tls/subscriptions",
                params={"include": "tls_authorizations", "page[number]": page},
                headers={"Fastly-Key": self._token},
            )
            resp.raise_for_status()  # Error on non-200 responses

            page = resp.json()

            self.log.debug(
                "_list_tls_authorizations: received tls subscription page %d of %d",
                page["meta"]["current_page"],
                page["meta"]["total_pages"],
            )

            previous_count = len(authorizations)

            authorizations.extend(
                # Ensure we only have a list of authorizations
                [
                    authorization
                    for authorization in page["included"]
                    if authorization["type"] == "tls_authorization"
                ]
            )

            self.log.debug(
                "_list_tls_authorizations: found %d authorizations on page %d",
                len(authorizations) - previous_count,
                page["meta"]["current_page"],
            )

            if page["meta"]["current_page"] == page["meta"]["total_pages"]:
                self.log.debug(
                    "_list_tls_authorizations: found %d authorizations total",
                    len(authorizations),
                )
                return authorizations

            page = page["meta"]["current_page"] + 1

    def _list_challenges(self):
        """
        Fetch a list of ACME DNS challenges out of the TLS authorizations.
        """
        for authorization in self._list_tls_authorizations():
            for challenge in authorization["attributes"]["challenges"]:
                yield challenge

    def _challenges(self, zone: Zone):
        """
        List ACME DNS challenges for the given zone.

        When certificates are requested for the root of a domain and it's wildcard (`*.example.com`),
        Fastly returns two challenges with the same record name and value which need to be deduplicated.
        """
        suffix = "." + zone.name[:-1]
        # Filter out duplicate challenges included in the TLS subscriptions response
        challenges = set()
        for challenge in self._list_challenges():
            if challenge["type"] == "managed-dns" and challenge[
                "record_name"
            ].endswith(suffix):
                name = challenge["record_name"][: -len(suffix)]
                value = f"{challenge['values'][0]}."  # Append a trailing dot
                if (name, value) not in challenges:
                    challenges.add((name, value))
                    yield (name, value)
                else:
                    self.log.debug(
                        f"_challenges: skipping duplicate challenge {name}.{zone.name}"
                    )

    def populate(self, zone: Zone, target=False, lenient=False):
        self.log.debug(
            f"populate: name={zone.name}, target={target}, lenient={lenient}"
        )

        before = len(zone.records)

        for name, value in self._challenges(zone):
            record = Record.new(
                zone,
                name,
                {"type": "CNAME", "ttl": self._ttl, "value": value},
                source=self,
                lenient=lenient,
            )

            try:
                zone.add_record(record, lenient=lenient)
            except SubzoneRecordException:
                self.log.debug("populate:   skipping subzone record %s", record)

        self.log.info(
            "populate:   found %s records", len(zone.records) - before
        )
