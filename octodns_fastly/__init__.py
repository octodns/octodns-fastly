#
#
#

import logging

import fastly
from octodns.record import Record
from octodns.source.base import BaseSource


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

    def __init__(self, id, token):
        klass = self.__class__.__name__
        self.log = logging.getLogger(f"{klass}[{id}]")
        self.log.debug("__init__: id=%s", id)
        super().__init__(id)

        self._config = fastly.Configuration()
        self._config.api_token = token

    def populate(self, zone, target=False, lenient=False):
        self.log.debug(
            "populate: name=%s, target=%s, lenient=%s",
            zone.name,
            target,
            lenient,
        )

        before = len(zone.records)

        # with fastly.ApiClient(self._config) as client:
        #     instance = fastly.api.TlsSubscriptionsApi(client)
        #     try:
        #         subscriptions = instance.list_tls_subs()
        #     except fastly.ApiException as e:
        #         self.log.error("populate:   error=%s", e)

        record = Record.new(
            zone,
            "_acme-challenge",
            {"ttl": 60, "type": "CNAME", "value": "example.com"},
            source=self,
        )
        zone.add_record(record)

        self.log.info("populate:   found %s records", len(zone.records) - before)
