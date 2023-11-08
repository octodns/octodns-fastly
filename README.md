## Fastly ACME source for octoDNS

An [OctoDNS source](https://github.com/octodns/octodns#dynamic-sources) for [Fastly](https://www.fastly.com).

### Installation

#### Command line

```
pip install octodns-fastly
```

#### requirements.txt/setup.py

Pinning specific versions or SHAs is recommended to avoid unplanned upgrades.

##### Versions

```
# Start with the latest versions and don't just copy what's here
octodns==0.9.14
octodns-fastly==0.0.1
```

##### SHAs

```
# Start with the latest/specific versions and don't just copy what's here
-e git+https://git@github.com/octodns/octodns.git@9da19749e28f68407a1c246dfdf65663cdc1c422#egg=octodns
-e git+https://git@github.com/octodns/octodns-fastly.git@ec9661f8b335241ae4746eea467a8509205e6a30#egg=octodns_fastly
```

### Configuration

`FastlyAcmeSource` will create [ACME DNS challenge](https://docs.fastly.com/en/guides/serving-https-traffic-using-fastly-managed-certificates#verifying-domain-ownership) CNAME records such as `_acme-challenge.www.example.com` based on TLS subscriptions.

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

### Support Information

#### Records

CNAME

#### Dynamic

FastlyProvider does not support dynamic records.

### Development

See the [/script/](/script/) directory for some tools to help with the development process. They generally follow the [Script to rule them all](https://github.com/github/scripts-to-rule-them-all) pattern. Most useful is `./script/bootstrap` which will create a venv and install both the runtime and development related requirements. It will also hook up a pre-commit hook that covers most of what's run by CI.
