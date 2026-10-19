from __future__ import annotations

import html
import ipaddress
import socket
import time
from datetime import datetime, timezone
from urllib.parse import urljoin, urlparse

import requests
from bs4 import BeautifulSoup

USER_AGENT = "WebGuardAI/0.1 (authorized low-impact security checks)"
TIMEOUT_SECONDS = 8
MAX_PAGES = 8
DELAY_SECONDS = 0.35
MAX_BODY_BYTES = 1_000_000

SECURITY_HEADERS = {
    "Content-Security-Policy": (
        "Missing Content-Security-Policy header",
        "A CSP can reduce the impact of some injection bugs when configured correctly.",
        [
            "Start with a report-only policy and review violations.",
            "Define trusted sources narrowly; avoid broad wildcards.",
            "Keep fixing unsafe output handling—CSP is an extra layer, not a substitute.",
        ],
    ),
    "X-Content-Type-Options": (
        "Missing X-Content-Type-Options header",
        "Browsers may MIME-sniff some responses without this protection.",
        [
            "Set X-Content-Type-Options: nosniff on appropriate responses.",
            "Serve each resource with the correct Content-Type.",
        ],
    ),
    "Referrer-Policy": (
        "Missing Referrer-Policy header",
        "Referrer information may be sent more broadly than intended.",
        [
            "Consider strict-origin-when-cross-origin as a practical baseline.",
            "Review whether sensitive URLs contain information that should never be in a URL.",
        ],
    ),
    "Permissions-Policy": (
        "Missing Permissions-Policy header",
        "The site has not explicitly declared restrictions for browser features using this header.",
        [
            "Set a policy appropriate to features the site actually uses.",
            "Do not disable features blindly; test the user experience after changes.",
        ],
    ),
}

def _is_public_address(hostname: str) -> bool:
    """Reject localhost and private/reserved IP destinations as a basic SSRF guard."""
    try:
        addresses = [ipaddress.ip_address(hostname)]
    except ValueError:
        try:
            answers = socket.getaddrinfo(hostname, None, type=socket.SOCK_STREAM)
            addresses = [ipaddress.ip_address(item[4][0]) for item in answers]
        except (socket.gaierror, OSError):
            return False
    return bool(addresses) and all(addr.is_global for addr in addresses)

def _validate_url(url: str) -> str:
    parsed = urlparse(url)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise ValueError("Please provide a valid http:// or https:// URL.")
    if parsed.username or parsed.password:
        raise ValueError("URLs containing embedded credentials are not accepted.")
    if not _is_public_address(parsed.hostname):
        raise ValueError("The target must resolve to a public address. Local/private targets are blocked in this starter.")
    return url

def _same_origin(a: str, b: str) -> bool:
    pa, pb = urlparse(a), urlparse(b)
    return (pa.scheme, pa.hostname, pa.port) == (pb.scheme, pb.hostname, pb.port)

def scan_site(start_url: str) -> dict:
    start_url = _validate_url(start_url.strip())
    session = requests.Session()
    session.headers.update({"User-Agent": USER_AGENT, "Accept": "text/html,application/xhtml+xml"})
    queue = [start_url]
    seen = set()
    findings = []
    page_count = 0
    start_origin = start_url

    while queue and page_count < MAX_PAGES:
        url = queue.pop(0)
        if url in seen:
            continue
        seen.add(url)

        # Revalidate every URL before requesting it; do not follow redirects automatically.
        _validate_url(url)
        response = session.get(
            url,
            timeout=TIMEOUT_SECONDS,
            allow_redirects=False,
            stream=True,
        )
        try:
            status = response.status_code
            headers = response.headers
            body = response.raw.read(MAX_BODY_BYTES, decode_content=True)
        finally:
            response.close()

        page_count += 1

        if status in {301, 302, 303, 307, 308}:
            location = headers.get("Location", "")
            if location:
                redirected = urljoin(url, location)
                if _same_origin(start_origin, redirected):
                    queue.append(redirected)
            time.sleep(DELAY_SECONDS)
            continue

        if url == start_url and urlparse(url).scheme == "http":
            findings.append({
                "title": "Website starts over HTTP",
                "severity": "Medium",
                "category": "Transport security",
                "confidence": "High",
                "description": "The submitted starting URL uses HTTP, so the initial connection is not encrypted.",
                "evidence": f"Starting URL scheme is {urlparse(url).scheme}.",
                "suggestions": [
                    "Serve the site over HTTPS with a valid certificate.",
                    "Redirect HTTP to HTTPS after confirming HTTPS works.",
                    "Consider HSTS only after HTTPS is correctly configured across the intended domain.",
                ],
            })

        for header, details in SECURITY_HEADERS.items():
            if header not in headers:
                title, description, suggestions = details
                findings.append({
                    "title": title,
                    "severity": "Low",
                    "category": "Security headers",
                    "confidence": "High",
                    "description": description,
                    "evidence": f"{header} was absent from the response for {url}.",
                    "suggestions": suggestions,
                })

        cookie_headers = response.headers.get("Set-Cookie", "")
        if cookie_headers:
            lower = cookie_headers.lower()
            missing = []
            if "secure" not in lower:
                missing.append("Secure")
            if "httponly" not in lower:
                missing.append("HttpOnly")
            if "samesite" not in lower:
                missing.append("SameSite")
            if missing:
                findings.append({
                    "title": "Cookie may be missing security attributes",
                    "severity": "Low",
                    "category": "Cookie configuration",
                    "confidence": "Medium",
                    "description": "At least one Set-Cookie header may not include all common security attributes. Requirements vary by cookie purpose.",
                    "evidence": "Potentially missing attributes: " + ", ".join(missing),
                    "suggestions": [
                        "Set Secure for cookies that should only travel over HTTPS.",
                        "Set HttpOnly for session cookies that do not need JavaScript access.",
                        "Choose an appropriate SameSite value and test login, SSO, and cross-site flows.",
                        "Review each cookie individually; attributes may differ by use case.",
                    ],
                })

        content_type = headers.get("Content-Type", "").lower()
        if "html" in content_type and body:
            soup = BeautifulSoup(body, "html.parser")
            for link in soup.find_all("a", href=True):
                candidate = urljoin(url, link["href"])
                parsed = urlparse(candidate)
                if parsed.scheme in {"http", "https"} and _same_origin(start_origin, candidate):
                    clean = parsed._replace(fragment="").geturl()
                    if clean not in seen and clean not in queue:
                        queue.append(clean)

        time.sleep(DELAY_SECONDS)

    # Deduplicate repeated findings by title + evidence.
    unique = []
    fingerprints = set()
    for item in findings:
        key = (item["title"], item["evidence"])
        if key not in fingerprints:
            fingerprints.add(key)
            unique.append(item)

    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
    report = {
        "tool": "WebGuard AI",
        "version": "0.1.0",
        "timestamp_utc": timestamp,
        "target": start_url,
        "summary": {"pages_checked": page_count, "findings": len(unique)},
        "findings": unique,
        "limitations": [
            "This is a limited, non-destructive checker, not a full penetration test.",
            "Missing headers are not necessarily exploitable vulnerabilities.",
            "No SQL injection, XSS, authentication, authorization, or business-logic exploit tests are run.",
            "A clean result does not mean the website is secure.",
        ],
    }
    report["html_report"] = _render_html(report)
    return report

def _render_html(report: dict) -> str:
    items = []
    for finding in report["findings"]:
        suggestions = "".join(f"<li>{html.escape(s)}</li>" for s in finding["suggestions"])
        items.append(
            "<section><h2>" + html.escape(finding["severity"] + " — " + finding["title"]) +
            "</h2><p>" + html.escape(finding["description"]) +
            "</p><p><b>Evidence:</b> " + html.escape(finding["evidence"]) +
            "</p><ul>" + suggestions + "</ul></section>"
        )
    body = "".join(items) or "<p>No issues detected by these limited checks.</p>"
    return (
        "<!doctype html><html lang='en'><meta charset='utf-8'><meta name='viewport' content='width=device-width'>"
        "<title>WebGuard AI Report</title><style>body{font:16px system-ui;max-width:900px;margin:2rem auto;padding:0 1rem}"
        "section{border:1px solid #ddd;border-radius:8px;padding:1rem;margin:1rem 0}</style><body>"
        "<h1>WebGuard AI Report</h1><p>Target: " + html.escape(report["target"]) +
        "</p><p>Generated (UTC): " + html.escape(report["timestamp_utc"]) + "</p>" +
        body + "<hr><p>This report is not a guarantee of security. Test only with authorization.</p></body></html>"
    )
