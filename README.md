# OctoDNS Fastly

An [OctoDNS source](https://github.com/octodns/octodns#dynamic-sources) for [Fastly](https://www.fastly.com).

**Sources**

`FastlyAcmeSource` will create [ACME DNS challenge](https://docs.fastly.com/en/guides/serving-https-traffic-using-fastly-managed-certificates#verifying-domain-ownership) CNAME records such as `_acme-challange.www.example.com` based on TLS subscriptions.

OctoDNS configuration:

```yml
providers:
  fastly:
    class: octodns_fastly.FastlyAcmeSource
    token: env/FASTLY_API_TOKEN

zones:
  example.com.:
    sources:
      - fastly
```

## Install

**Pipenv**

```console
$ pipenv install -e git+https://github.com/Financial-Times/octodns-fastly.git@main#egg=octodns-fastly
```
