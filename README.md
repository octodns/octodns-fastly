# Fastly source for OctoDNS

An [OctoDNS source](https://github.com/octodns/octodns#dynamic-sources) source for [Fastly](https://www.fastly.com).

Supports:

* [ACME DNS challenges](https://docs.fastly.com/en/guides/serving-https-traffic-using-fastly-managed-certificates#verifying-domain-ownership) with `FastlyAcmeSource`

    ```yml
    fastly:
      class: octodns_fastly.FastlyAcmeSource
      token: env/FASTLY_API_TOKEN

    zones:
      example.com.:
        sources:
          - fastly
        targets:
          - route53
    ```

Related links:

* https://docs.fastly.com/en/guides/serving-https-traffic-using-fastly-managed-certificates#using-the-acme-dns-challenge-to-verify-domain-ownership
* https://developer.fastly.com/reference/api/tls/subs/#list-tls-subs
* https://letsencrypt.org/docs/challenge-types/#dns-01-challenge
