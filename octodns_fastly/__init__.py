"""
A Fastly source for OctoDNS.

Automatically create ACME CNAME records for verifying domains in Fastly TLS subscriptions.
"""

import logging
from functools import cache

import requests
from octodns.record import Record
from octodns.source.base import BaseSource
from octodns.zone import DuplicateRecordException, SubzoneRecordException, Zone


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
        self._session = requests.Session()

    @cache
    def _list_tls_authorizations(self):
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
                [authorization for authorization in page["included"] if authorization["type"] == "tls_authorization"]
            )

            self.log.debug(
                "_list_tls_authorizations: found %d authorizations on page %d",
                len(authorizations) - previous_count,
                page["meta"]["current_page"],
            )

            if page["meta"]["current_page"] == page["meta"]["total_pages"]:
                self.log.debug("_list_tls_authorizations: found %d authorizations total", len(authorizations))
                return authorizations

            page = page["meta"]["current_page"] + 1

    def _challenges(self, zone: Zone):
        for authorization in self._list_tls_authorizations():
            for challenge in authorization["attributes"]["challenges"]:
                suffix = "." + zone.name.removesuffix(".")
                if challenge["type"] == "managed-dns" and challenge["record_name"].endswith(suffix):
                    name = challenge["record_name"].removesuffix(suffix)
                    value = f"{challenge['values'][0]}."  # Append a trailing dot
                    yield (name, value)

    def populate(self, zone: Zone, target=False, lenient=False):
        self.log.debug(
            "populate: name=%s, target=%s, lenient=%s",
            zone.name,
            target,
            lenient,
        )

        before = len(zone.records)

        for name, value in self._challenges(zone):
            record = Record.new(
                zone,
                name,
                {
                    "type": "CNAME",
                    "ttl": self._ttl,
                    "value": value,
                },
            )

            try:
                zone.add_record(record)
            except SubzoneRecordException:
                self.log.debug(
                    "populate:   skipping subzone record %s",
                    record,
                )
            except DuplicateRecordException:
                self.log.warning("populate:   skipping duplicate ACME DNS challenge record %s" % record)

        self.log.info("populate:   found %s records", len(zone.records) - before)
