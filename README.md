# cors-misconfig-scanner

A defensive CORS misconfiguration scanner for Python — sends the same
GET/OPTIONS requests a browser would during a cross-origin request, with
varying `Origin` headers, and flags known CORS misconfigurations.

## What this is

Tests a URL **you own or have explicit permission to test** by sending
ordinary HTTP GET/OPTIONS requests with different `Origin` header values
and inspecting the `Access-Control-Allow-*` response headers. It performs
no exploitation, no state mutation, and sends no credentials.

### What it checks

| Finding | Severity | What it means |
|---|---|---|
| `ORIGIN_REFLECTED` | critical / high | Server reflects an arbitrary `Origin` back in `Access-Control-Allow-Origin` (critical if combined with `Allow-Credentials: true`) |
| `WILDCARD_WITH_CREDENTIALS` | high | `Access-Control-Allow-Origin: *` + `Access-Control-Allow-Credentials: true` together — forbidden by spec, indicates broken config |
| `NULL_ORIGIN_ALLOWED` | critical / high | Server explicitly allows `Origin: null` (easy to spoof via sandboxed iframes/local files) |
| `SUBDOMAIN_BYPASS` | critical / high | With `--baseline-domain`, checks whether a lookalike origin (`evil.trusted.com`, `trusted.com.evil.com`) is accepted |
| `PERMISSIVE_METHODS` | high / medium | `Access-Control-Allow-Methods` includes `DELETE`/`PUT`/`PATCH` — severity bumped to high if combined with a wildcard origin |

## Installation

```bash
git clone https://github.com/m2xdev/cors-misconfig-scanner
cd cors-misconfig-scanner
pip install -r requirements.txt
```

## Usage

```bash
# Scan a single URL
python cors_scanner.py --url https://yourapp.com/api/endpoint

# Also test subdomain/suffix bypass against a trusted baseline domain
python cors_scanner.py --url https://yourapp.com/api/endpoint --baseline-domain yourapp.com

# JSON output
python cors_scanner.py --url https://yourapp.com/api/endpoint --json

# Offline self-test (no network)
python cors_scanner.py --self-test
```

## Running self-tests

```bash
python cors_scanner.py --self-test
```

All HTTP calls are mocked (`_FakeSession`) — no real network requests.
Covers every finding type individually, a clean-server negative case, and
two regression tests: that `Origin: null` produces exactly one finding
(not a duplicate with `ORIGIN_REFLECTED`), and that `PERMISSIVE_METHODS`
severity is correctly bumped to `high` under a wildcard origin.

## ⚠️ Disclaimer

This tool is intended only for auditing applications and sites that you
own or have explicit permission to test. It performs one ordinary HTTP
request per Origin (GET and OPTIONS) — exactly what a browser does during
a cross-origin request. It does not exploit, mutate state, or send
credentials.

The software is provided **"AS IS"**, without warranty of any kind,
express or implied. By using this code, you are solely responsible for
its use. The author is not liable for any damages arising from the use of
this software.

## Related projects

- [header-scan](https://github.com/m2xdev/header-scan)
- [jwt-auditor](https://github.com/m2xdev/jwt-auditor)
- [ssrf-shield](https://github.com/m2xdev/ssrf-shield) / [ssrf-lab](https://github.com/m2xdev/ssrf-lab)
- [csrf-shield](https://github.com/m2xdev/csrf-shield) / [csrf-lab](https://github.com/m2xdev/csrf-lab)