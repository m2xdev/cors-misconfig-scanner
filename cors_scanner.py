#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
cors_scanner.py — defensive CORS misconfiguration scanner.

Sends the same HTTP GET/OPTIONS requests a browser would send during a
cross-origin request, with varying Origin headers, and inspects the CORS
response headers for known misconfigurations.

MIT License

Copyright (c) 2026

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.

DISCLAIMER
----------
This tool is intended ONLY for auditing applications and sites that you own
or that you have explicit permission to test. It performs one ordinary HTTP
request per Origin (GET and OPTIONS) — exactly what a browser would do
during a cross-origin request. It does not exploit, mutate state, or send
credentials. The author assumes no liability for misuse.
"""

from __future__ import annotations

import argparse
import json
import logging
import sys
from dataclasses import dataclass, field, asdict
from typing import Any, Dict, List, Optional

import requests

logger = logging.getLogger("cors_scanner")
logger.addHandler(logging.NullHandler())


# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------
@dataclass
class Finding:
    code: str
    severity: str
    title: str
    detail: str
    origin_tested: Optional[str] = None


@dataclass
class CORSReport:
    url: str
    findings: List[Finding] = field(default_factory=list)
    raw_headers: Dict[str, Dict[str, Any]] = field(default_factory=dict)
    error: Optional[str] = None

    def add(self, code: str, severity: str, title: str,
            detail: str, origin: Optional[str] = None) -> None:
        self.findings.append(Finding(code, severity, title, detail, origin))

    def to_dict(self) -> Dict[str, Any]:
        return {
            "url": self.url,
            "error": self.error,
            "findings": [asdict(f) for f in self.findings],
            "raw_headers": self.raw_headers,
        }

    def pretty(self) -> str:
        lines = [f"=== CORS Scan Report ===", f"url    : {self.url}"]
        if self.error:
            lines.append(f"error  : {self.error}")
        lines.append(f"findings: {len(self.findings)}")
        for f in self.findings:
            origin = f" (origin={f.origin_tested})" if f.origin_tested else ""
            lines.append(f"  [{f.severity.upper():8}] {f.code}: {f.title}{origin}")
            lines.append(f"             {f.detail}")
        lines.append("raw headers:")
        for origin, hdrs in self.raw_headers.items():
            lines.append(f"  origin={origin}")
            for k, v in hdrs.items():
                lines.append(f"    {k}: {v}")
        return "\n".join(lines)


# ---------------------------------------------------------------------------
# Header extraction
# ---------------------------------------------------------------------------
_CORS_HEADERS = (
    "Access-Control-Allow-Origin",
    "Access-Control-Allow-Credentials",
    "Access-Control-Allow-Methods",
    "Access-Control-Allow-Headers",
    "Access-Control-Expose-Headers",
    "Vary",
)


def _extract_cors_headers(resp: requests.Response) -> Dict[str, str]:
    """Return CORS-related headers from a response (case-insensitive)."""
    out: Dict[str, str] = {}
    lower_map = {k.lower(): v for k, v in resp.headers.items()}
    for name in _CORS_HEADERS:
        value = lower_map.get(name.lower())
        if value is not None:
            out[name] = value
    return out


# ---------------------------------------------------------------------------
# Scanner
# ---------------------------------------------------------------------------
DEFAULT_TEST_ORIGIN = "https://example-attacker-test.com"
NULL_ORIGIN = "null"


class CORSScanner:
    """Scan a URL for CORS misconfigurations using only GET/OPTIONS."""

    def __init__(self, timeout: float = 10.0,
                 session: Optional[requests.Session] = None) -> None:
        self.timeout = timeout
        self._session = session or requests.Session()

    # ---- low-level probing ------------------------------------------------
    def _probe_get(self, url: str, origin: str) -> Dict[str, Any]:
        try:
            resp = self._session.get(
                url,
                headers={"Origin": origin},
                timeout=self.timeout,
                allow_redirects=False,
            )
        except requests.RequestException as exc:
            logger.warning("GET failed for origin=%s: %s", origin, exc)
            return {"error": str(exc)}
        hdrs = _extract_cors_headers(resp)
        hdrs["_status"] = resp.status_code
        return hdrs

    def _probe_options(self, url: str, origin: str) -> Dict[str, Any]:
        try:
            resp = self._session.options(
                url,
                headers={
                    "Origin": origin,
                    "Access-Control-Request-Method": "GET",
                },
                timeout=self.timeout,
                allow_redirects=False,
            )
        except requests.RequestException as exc:
            logger.warning("OPTIONS failed for origin=%s: %s", origin, exc)
            return {"error": str(exc)}
        hdrs = _extract_cors_headers(resp)
        hdrs["_status"] = resp.status_code
        return hdrs

    # ---- main entry -------------------------------------------------------
    def scan(self, url: str, baseline_domain: Optional[str] = None) -> CORSReport:
        report = CORSReport(url=url)

        # Build the list of Origins to test.
        origins: List[str] = [DEFAULT_TEST_ORIGIN, NULL_ORIGIN]
        if baseline_domain:
            bd = baseline_domain.strip().lower().strip(".")
            origins.extend([
                f"https://evil.{bd}",
                f"https://{bd}.evil.com",
            ])

        for origin in origins:
            logger.info("probing origin=%s", origin)
            get_hdrs = self._probe_get(url, origin)
            opt_hdrs = self._probe_options(url, origin)
            report.raw_headers[origin] = {
                "GET": get_hdrs,
                "OPTIONS": opt_hdrs,
            }

            # Prefer OPTIONS headers if the server answered preflight, else GET.
            effective = opt_hdrs if opt_hdrs.get("Access-Control-Allow-Origin") \
                else get_hdrs

            self._check_origin_reflection(report, origin, effective)
            self._check_wildcard_with_credentials(report, origin, effective)
            self._check_null_origin(report, origin, effective)
            self._check_permissive_methods(report, origin, effective)
            if baseline_domain:
                self._check_subdomain_bypass(report, origin, effective,
                                             baseline_domain)

        return report

    # ---- checks -----------------------------------------------------------
    def _check_origin_reflection(self, report: CORSReport, origin: str,
                                 hdrs: Dict[str, Any]) -> None:
        if hdrs.get("error"):
            return
        if origin == NULL_ORIGIN:
            return  # handled separately by _check_null_origin
        acao = hdrs.get("Access-Control-Allow-Origin")
        acac = str(hdrs.get("Access-Control-Allow-Credentials", "")).lower()
        if acao is None:
            return
        if acao == "*":
            return
        if acao.strip().rstrip("/") == origin.strip().rstrip("/"):
            if acac == "true":
                report.add(
                    "ORIGIN_REFLECTED",
                    "critical",
                    "Arbitrary Origin reflected with credentials",
                    "Server reflects the supplied Origin in Access-Control-"
                    "Allow-Origin while allowing credentials. Any site can "
                    "make authenticated cross-origin requests on behalf of "
                    "the victim.",
                    origin,
                )
            else:
                report.add(
                    "ORIGIN_REFLECTED",
                    "high",
                    "Arbitrary Origin reflected",
                    "Server reflects the supplied Origin in Access-Control-"
                    "Allow-Origin. Without credentials the impact is lower, "
                    "but it still enables cross-origin reads of non-"
                    "credentialed responses.",
                    origin,
                )

    def _check_wildcard_with_credentials(self, report: CORSReport, origin: str,
                                         hdrs: Dict[str, Any]) -> None:
        if hdrs.get("error"):
            return
        acao = hdrs.get("Access-Control-Allow-Origin")
        acac = str(hdrs.get("Access-Control-Allow-Credentials", "")).lower()
        if acao == "*" and acac == "true":
            report.add(
                "WILDCARD_WITH_CREDENTIALS",
                "high",
                "Wildcard Origin combined with credentials",
                "Access-Control-Allow-Origin: * together with "
                "Access-Control-Allow-Credentials: true is forbidden by the "
                "specification; browsers will reject it, but its presence "
                "indicates a broken or over-permissive configuration.",
                origin,
            )

    def _check_null_origin(self, report: CORSReport, origin: str,
                           hdrs: Dict[str, Any]) -> None:
        if hdrs.get("error"):
            return
        if origin != NULL_ORIGIN:
            return
        acao = hdrs.get("Access-Control-Allow-Origin")
        if acao is None:
            return
        if acao == "null" or acao.strip().lower() == "null":
            acac = str(hdrs.get("Access-Control-Allow-Credentials", "")).lower()
            severity = "critical" if acac == "true" else "high"
            report.add(
                "NULL_ORIGIN_ALLOWED",
                severity,
                "Origin 'null' explicitly allowed",
                "Server grants access to Origin: null. Sandboxed iframes, "
                "data: URLs and local files send this Origin; allowing it "
                "widens the attack surface significantly.",
                origin,
            )

    def _check_permissive_methods(self, report: CORSReport, origin: str,
                                  hdrs: Dict[str, Any]) -> None:
        if hdrs.get("error"):
            return
        acao = hdrs.get("Access-Control-Allow-Origin")
        acam = hdrs.get("Access-Control-Allow-Methods")
        if not acao or not acam:
            return
        methods = {m.strip().upper() for m in acam.split(",") if m.strip()}
        write_methods = methods & {"DELETE", "PUT", "PATCH"}
        if not write_methods:
            return
        # Wildcard origin combined with cross-origin write methods is
        # materially worse than a permissive allowlist, so bump severity.
        if acao == "*":
            severity = "high"
            note = ("Access-Control-Allow-Origin: * combined with write "
                    "methods means any origin can attempt cross-origin "
                    "state changes; even though credentialed requests are "
                    "blocked by the browser under '*', any non-credentialed "
                    "endpoint that mutates state becomes reachable.")
        else:
            severity = "medium"
            note = ("Access-Control-Allow-Methods includes write methods. "
                    "If the Origin is also permissive, cross-origin state "
                    "changes become possible.")
        report.add(
            "PERMISSIVE_METHODS",
            severity,
            "Write methods allowed cross-origin",
            f"Access-Control-Allow-Methods includes {sorted(write_methods)}. {note}",
            origin,
        )

    def _check_subdomain_bypass(self, report: CORSReport, origin: str,
                                hdrs: Dict[str, Any],
                                baseline_domain: str) -> None:
        if hdrs.get("error"):
            return
        bd = baseline_domain.strip().lower().strip(".")
        candidates = {f"https://evil.{bd}", f"https://{bd}.evil.com"}
        if origin not in candidates:
            return
        acao = hdrs.get("Access-Control-Allow-Origin")
        if acao is None or acao == "*":
            return
        if acao.strip().rstrip("/") == origin.strip().rstrip("/"):
            acac = str(hdrs.get("Access-Control-Allow-Credentials", "")).lower()
            severity = "critical" if acac == "true" else "high"
            report.add(
                "SUBDOMAIN_BYPASS",
                severity,
                "Suspicious subdomain/prefix origin accepted",
                f"Server accepted Origin {origin!r} which uses the baseline "
                f"domain {bd!r} as a suffix or prefix. A naive 'endswith' or "
                "'startswith' check on the host allows attacker-controlled "
                "hosts to bypass the allowlist.",
                origin,
            )


# ---------------------------------------------------------------------------
# Self-test with mocked responses (no network).
# ---------------------------------------------------------------------------
def _make_fake_response(headers: Dict[str, str], status: int = 200):
    """Create a minimal object that quacks like requests.Response."""
    class _Resp:
        def __init__(self, h, s):
            self.headers = h
            self.status_code = s
    return _Resp(headers, status)


class _FakeSession:
    """Test double for requests.Session, keyed by (method, origin)."""
    def __init__(self, responses: Dict[tuple, Dict[str, str]]):
        self._responses = responses

    def get(self, url, headers=None, timeout=None, allow_redirects=None):
        origin = (headers or {}).get("Origin", "")
        hdrs = self._responses.get(("GET", origin), {})
        return _make_fake_response(hdrs)

    def options(self, url, headers=None, timeout=None, allow_redirects=None):
        origin = (headers or {}).get("Origin", "")
        hdrs = self._responses.get(("OPTIONS", origin), {})
        return _make_fake_response(hdrs)


def _run_self_test() -> int:
    failures = 0

    def check(name: str, cond: bool) -> None:
        nonlocal failures
        status = "ok" if cond else "FAIL"
        print(f"  [{status}] {name}")
        if not cond:
            failures += 1

    # ---- ORIGIN_REFLECTED (critical) ------------------------------------
    print("[self-test] ORIGIN_REFLECTED with credentials")
    origin = DEFAULT_TEST_ORIGIN
    sess = _FakeSession({
        ("GET", origin): {
            "Access-Control-Allow-Origin": origin,
            "Access-Control-Allow-Credentials": "true",
        },
        ("OPTIONS", origin): {
            "Access-Control-Allow-Origin": origin,
            "Access-Control-Allow-Credentials": "true",
        },
    })
    rep = CORSScanner(session=sess).scan("https://target.test/api")
    refl = [f for f in rep.findings if f.code == "ORIGIN_REFLECTED"]
    check("ORIGIN_REFLECTED reported", len(refl) >= 1)
    check("severity critical", refl and refl[0].severity == "critical")

    # ---- ORIGIN_REFLECTED (high, no credentials) ------------------------
    print("[self-test] ORIGIN_REFLECTED without credentials")
    sess = _FakeSession({
        ("GET", origin): {"Access-Control-Allow-Origin": origin},
        ("OPTIONS", origin): {"Access-Control-Allow-Origin": origin},
    })
    rep = CORSScanner(session=sess).scan("https://target.test/api")
    refl = [f for f in rep.findings if f.code == "ORIGIN_REFLECTED"]
    check("ORIGIN_REFLECTED reported", len(refl) >= 1)
    check("severity high", refl and refl[0].severity == "high")

    # ---- WILDCARD_WITH_CREDENTIALS --------------------------------------
    print("[self-test] WILDCARD_WITH_CREDENTIALS")
    sess = _FakeSession({
        ("GET", origin): {
            "Access-Control-Allow-Origin": "*",
            "Access-Control-Allow-Credentials": "true",
        },
        ("OPTIONS", origin): {},
    })
    rep = CORSScanner(session=sess).scan("https://target.test/api")
    check("WILDCARD_WITH_CREDENTIALS reported",
          any(f.code == "WILDCARD_WITH_CREDENTIALS" for f in rep.findings))

    # ---- NULL_ORIGIN_ALLOWED --------------------------------------------
    print("[self-test] NULL_ORIGIN_ALLOWED")
    sess = _FakeSession({
        ("GET", NULL_ORIGIN): {
            "Access-Control-Allow-Origin": "null",
            "Access-Control-Allow-Credentials": "true",
        },
        ("OPTIONS", NULL_ORIGIN): {},
    })
    rep = CORSScanner(session=sess).scan("https://target.test/api")
    null_f = [f for f in rep.findings if f.code == "NULL_ORIGIN_ALLOWED"]
    check("NULL_ORIGIN_ALLOWED reported", len(null_f) >= 1)
    check("severity critical",
          null_f and null_f[0].severity == "critical")

    # ---- SUBDOMAIN_BYPASS -----------------------------------------------
    print("[self-test] SUBDOMAIN_BYPASS")
    bd = "trusted.com"
    evil = f"https://evil.{bd}"
    sess = _FakeSession({
        ("GET", evil): {
            "Access-Control-Allow-Origin": evil,
            "Access-Control-Allow-Credentials": "true",
        },
        ("OPTIONS", evil): {},
    })
    rep = CORSScanner(session=sess).scan(
        "https://target.test/api", baseline_domain=bd)
    check("SUBDOMAIN_BYPASS reported",
          any(f.code == "SUBDOMAIN_BYPASS" for f in rep.findings))

    print("[self-test] SUBDOMAIN_BYPASS prefix case")
    evil2 = f"https://{bd}.evil.com"
    sess = _FakeSession({
        ("GET", evil2): {
            "Access-Control-Allow-Origin": evil2,
            "Access-Control-Allow-Credentials": "true",
        },
        ("OPTIONS", evil2): {},
    })
    rep = CORSScanner(session=sess).scan(
        "https://target.test/api", baseline_domain=bd)
    check("SUBDOMAIN_BYPASS reported (prefix form)",
          any(f.code == "SUBDOMAIN_BYPASS" for f in rep.findings))

    # ---- PERMISSIVE_METHODS ---------------------------------------------
    print("[self-test] PERMISSIVE_METHODS")
    sess = _FakeSession({
        ("GET", origin): {
            "Access-Control-Allow-Origin": origin,
            "Access-Control-Allow-Methods": "GET, PUT, DELETE, POST",
        },
        ("OPTIONS", origin): {
            "Access-Control-Allow-Origin": origin,
            "Access-Control-Allow-Methods": "GET, PUT, DELETE, POST",
        },
    })
    rep = CORSScanner(session=sess).scan("https://target.test/api")
    check("PERMISSIVE_METHODS reported",
          any(f.code == "PERMISSIVE_METHODS" for f in rep.findings))

    # ---- Clean response: no findings ------------------------------------
    print("[self-test] clean response -> no findings")
    sess = _FakeSession({
        ("GET", origin): {},
        ("OPTIONS", origin): {},
    })
    rep = CORSScanner(session=sess).scan("https://target.test/api")
    check("no findings on clean server", len(rep.findings) == 0)

    # ---- null origin must not double-report -----------------------------
    print("[self-test] Origin: null reflected -> exactly one finding (NULL_ORIGIN_ALLOWED)")
    sess = _FakeSession({
        ("GET", NULL_ORIGIN): {
            "Access-Control-Allow-Origin": "null",
            "Access-Control-Allow-Credentials": "true",
        },
        ("OPTIONS", NULL_ORIGIN): {},
    })
    rep = CORSScanner(session=sess).scan("https://target.test/api")
    null_findings = [f for f in rep.findings
                     if f.code in ("NULL_ORIGIN_ALLOWED", "ORIGIN_REFLECTED")]
    check("exactly one finding for Origin: null", len(null_findings) == 1)
    check("the finding is NULL_ORIGIN_ALLOWED",
          null_findings and null_findings[0].code == "NULL_ORIGIN_ALLOWED")
    check("no ORIGIN_REFLECTED for null",
          not any(f.code == "ORIGIN_REFLECTED" for f in rep.findings))

    # ---- wildcard + write methods bumps severity to high ----------------
    print("[self-test] PERMISSIVE_METHODS severity bumped for wildcard")
    sess = _FakeSession({
        ("GET", origin): {
            "Access-Control-Allow-Origin": "*",
            "Access-Control-Allow-Methods": "GET, DELETE",
        },
        ("OPTIONS", origin): {},
    })
    rep = CORSScanner(session=sess).scan("https://target.test/api")
    perm = [f for f in rep.findings if f.code == "PERMISSIVE_METHODS"]
    check("PERMISSIVE_METHODS reported", len(perm) >= 1)
    check("severity high under wildcard",
          perm and perm[0].severity == "high")

    # ---- raw_headers captured -------------------------------------------
    print("[self-test] raw_headers captured for each origin")
    sess = _FakeSession({
        ("GET", origin): {"Access-Control-Allow-Origin": origin},
        ("OPTIONS", origin): {},
    })
    rep = CORSScanner(session=sess).scan("https://target.test/api")
    check("raw_headers contains default origin",
          DEFAULT_TEST_ORIGIN in rep.raw_headers)
    check("raw_headers contains null origin",
          NULL_ORIGIN in rep.raw_headers)

    print()
    if failures:
        print(f"SELF-TEST FAILED: {failures} failure(s)")
        return 1
    print("SELF-TEST PASSED")
    return 0


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------
def _build_argparser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="cors_scanner",
        description="Scan a URL you own for CORS misconfigurations "
                    "(defensive use only).",
    )
    p.add_argument("--url", help="URL to scan (single target).")
    p.add_argument("--baseline-domain", default=None,
                   help="Trusted baseline domain to test subdomain bypass, "
                        "e.g. 'trusted.com'.")
    p.add_argument("--self-test", action="store_true",
                   help="Run offline self-tests (no network).")
    p.add_argument("--timeout", type=float, default=10.0,
                   help="HTTP timeout in seconds (default: 10).")
    p.add_argument("-v", "--verbose", action="store_true",
                   help="Verbose logging to stderr.")
    p.add_argument("--json", action="store_true",
                   help="Output the report as JSON.")
    return p


def main(argv: Optional[List[str]] = None) -> int:
    args = _build_argparser().parse_args(argv)

    if args.verbose:
        logging.basicConfig(level=logging.INFO,
                            format="%(levelname)s %(name)s: %(message)s")

    if args.self_test:
        return _run_self_test()

    if not args.url:
        _build_argparser().print_help()
        return 2

    scanner = CORSScanner(timeout=args.timeout)
    report = scanner.scan(args.url, baseline_domain=args.baseline_domain)

    if args.json:
        print(json.dumps(report.to_dict(), indent=2, ensure_ascii=False))
    else:
        print(report.pretty())
    return 0


if __name__ == "__main__":
    sys.exit(main())