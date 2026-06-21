# Developer Agent Guide for octoDNS Fastly Source

This repository contains the Fastly ACME DNS source for octoDNS. Unlike standard DNS providers, it is a read-only source that queries Fastly APIs to dynamically compile ACME DNS validation challenge CNAME records for domain ownership verification.

> [!IMPORTANT]
> **Core Workflow and Guidelines**
>
> All agents working on this repository must read and follow the general instructions and workflow guidelines defined in the core octoDNS `AGENTS.md` file.
> - **Local check**: Look for the file at `../octodns/AGENTS.md`.
> - **Remote check**: If the local file is not available, fetch it from GitHub: [octoDNS Core AGENTS.md](https://github.com/octodns/octodns/raw/refs/heads/main/AGENTS.md).
>
> You must align your code structure, style, pull request guidelines, and overall development workflows with the instructions specified there.

## Repository & Module Information

### Key Components

- **Source Class**: [FastlyAcmeSource](file:///home/ross/octodns/octodns-fastly/octodns_fastly/__init__.py#L13-L160) (defined in [octodns_fastly/__init__.py](file:///home/ross/octodns/octodns-fastly/octodns_fastly/__init__.py)). This class connects to Fastly's API to construct validation challenges.
- **LRU Cache Optimization**: The method [_list_tls_authorizations](file:///home/ross/octodns/octodns-fastly/octodns_fastly/__init__.py#L55-L101) uses `@lru_cache(maxsize=None)` to cache API responses and avoid duplicated HTTP request overhead when populating multiple subdomains in the same zone.

### Key Workflows & Features

1. **Supported Record Types**: `CNAME` only.
2. **ACME Challenge Generation**: Queries Fastly's `https://api.fastly.com/tls/subscriptions` (filtering for `tls_authorization` types in responses) to construct challenges. It outputs records named `_acme-challenge.<domain>` mapped to target fastly validation endpoints (e.g. `<challenge-id>.fastly-validations.com.`).
3. **Authentication**: Uses Fastly API token header verification via the `Fastly-Key` header, configured through the `token` parameter.
4. **Dynamic Routing**: Not supported (`SUPPORTS_DYNAMIC=False`, `SUPPORTS_GEO=False`).
5. **Non-Provider nature**: `FastlyAcmeSource` is a read-only source. It cannot plan changes, delete records, or write values. It must always be utilized alongside a target DNS provider in octoDNS configurations.

## Development & Testing

- **Setup Script**: Run `./script/bootstrap` to create a virtual environment, install runtime and development dependencies (including `black`, `isort`, `pyflakes`, and `pytest`), and configure pre-commit hooks.
- **Test Suite**: Run unit tests using `pytest` via `./script/test` (or `pytest tests/`). Test files are located in [tests/](file:///home/ross/octodns/octodns-fastly/tests).
- **Code Coverage**: Verify code coverage using `./script/coverage`.

## Key Constraints & Behaviors

- **Python Version**: Targets Python `>=3.9`.
- **Formatting**: Code formatting is enforced via `black` (version `>=26.0.0,<27.0.0`) and `isort`.
