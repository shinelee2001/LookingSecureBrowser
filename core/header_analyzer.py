from dataclasses import dataclass
from http.cookies import SimpleCookie
from typing import Callable
from urllib.parse import urlparse

import httpx


@dataclass
class HeaderFinding:
    name: str
    status: str
    severity: str
    message: str
    recommendation: str
    score: int
    max_score: int
    evidence: str | None = None


@dataclass
class HeaderAnalysisContext:
    headers: dict[str, str]
    response: httpx.Response
    requested_url: str


HeaderRule = Callable[[HeaderAnalysisContext], HeaderFinding]


def get_header(context: HeaderAnalysisContext, name: str) -> str | None:
    return context.headers.get(name.lower())


def missing_finding(
    name: str,
    max_score: int,
    message: str,
    recommendation: str,
    severity: str = "MEDIUM",
) -> HeaderFinding:
    return HeaderFinding(
        name=name,
        status="MISSING",
        severity=severity,
        message=message,
        recommendation=recommendation,
        score=0,
        max_score=max_score,
    )


def present_finding(
    name: str,
    max_score: int,
    value: str,
    recommendation: str,
    status: str = "OK",
    severity: str = "INFO",
    score: int | None = None,
    message: str | None = None,
) -> HeaderFinding:
    final_score = max_score if score is None else score

    return HeaderFinding(
        name=name,
        status=status,
        severity=severity,
        message=message or f"{name} is present.",
        recommendation=recommendation,
        score=final_score,
        max_score=max_score,
        evidence=value,
    )


def parse_hsts_max_age(value: str) -> int | None:
    for directive in value.split(";"):
        key, _, raw_value = directive.strip().partition("=")

        if key.lower() != "max-age":
            continue

        try:
            return int(raw_value)
        except ValueError:
            return None

    return None


def analyze_hsts(context: HeaderAnalysisContext) -> HeaderFinding:
    name = "HSTS"
    max_score = 20
    value = get_header(context, "strict-transport-security")
    recommendation = (
        "Send Strict-Transport-Security with max-age of at least 31536000; "
        "includeSubDomains is recommended when all subdomains support HTTPS."
    )

    if not value:
        return missing_finding(
            name,
            max_score,
            "HSTS is missing. HTTPS downgrade and SSL stripping risks may increase.",
            recommendation,
            severity="HIGH",
        )

    max_age = parse_hsts_max_age(value)

    if max_age is None:
        return present_finding(
            name,
            max_score,
            value,
            recommendation,
            status="WARN",
            severity="MEDIUM",
            score=8,
            message="HSTS is present, but max-age could not be parsed.",
        )

    if max_age <= 0:
        return present_finding(
            name,
            max_score,
            value,
            recommendation,
            status="BAD",
            severity="HIGH",
            score=0,
            message="HSTS is present, but max-age disables the policy.",
        )

    if max_age < 31536000:
        return present_finding(
            name,
            max_score,
            value,
            recommendation,
            status="WARN",
            severity="MEDIUM",
            score=12,
            message="HSTS is present, but max-age is shorter than the recommended one year.",
        )

    return present_finding(
        name,
        max_score,
        value,
        recommendation,
        message="HSTS is present with a strong max-age.",
    )


def analyze_csp(context: HeaderAnalysisContext) -> HeaderFinding:
    name = "CSP"
    max_score = 30
    value = get_header(context, "content-security-policy")
    recommendation = (
        "Define a restrictive Content-Security-Policy, avoid wildcards and unsafe "
        "script directives, and include default-src as a fallback."
    )

    if not value:
        return missing_finding(
            name,
            max_score,
            "Content-Security-Policy is missing. XSS impact may be higher.",
            recommendation,
            severity="HIGH",
        )

    lowered = value.lower()
    score = max_score
    issues = []

    if "default-src" not in lowered:
        score -= 8
        issues.append("default-src is missing")
    if "'unsafe-inline'" in lowered:
        score -= 8
        issues.append("unsafe-inline is allowed")
    if "'unsafe-eval'" in lowered:
        score -= 6
        issues.append("unsafe-eval is allowed")
    if "*" in lowered:
        score -= 5
        issues.append("wildcard sources are allowed")

    score = max(0, score)

    if issues:
        return present_finding(
            name,
            max_score,
            value,
            recommendation,
            status="WARN",
            severity="MEDIUM",
            score=score,
            message=f"CSP is present, but weaker than recommended: {', '.join(issues)}.",
        )

    return present_finding(
        name,
        max_score,
        value,
        recommendation,
        message="CSP is present and does not contain the common high-risk directives checked here.",
    )


def analyze_x_frame_options(context: HeaderAnalysisContext) -> HeaderFinding:
    name = "X-Frame-Options"
    max_score = 10
    value = get_header(context, "x-frame-options")
    recommendation = (
        "Use DENY or SAMEORIGIN, or prefer CSP frame-ancestors for more flexible "
        "clickjacking protection."
    )

    if not value:
        return missing_finding(
            name,
            max_score,
            "X-Frame-Options is missing. Clickjacking protection may be weak.",
            recommendation,
        )

    normalized = value.strip().upper()

    if normalized in {"DENY", "SAMEORIGIN"}:
        return present_finding(
            name,
            max_score,
            value,
            recommendation,
            message="X-Frame-Options is present with a recognized protective value.",
        )

    return present_finding(
        name,
        max_score,
        value,
        recommendation,
        status="WARN",
        severity="MEDIUM",
        score=4,
        message="X-Frame-Options is present, but the value is not DENY or SAMEORIGIN.",
    )


def analyze_x_content_type_options(context: HeaderAnalysisContext) -> HeaderFinding:
    name = "X-Content-Type-Options"
    max_score = 10
    value = get_header(context, "x-content-type-options")
    recommendation = "Send X-Content-Type-Options: nosniff."

    if not value:
        return missing_finding(
            name,
            max_score,
            "X-Content-Type-Options is missing. MIME sniffing risk may exist.",
            recommendation,
        )

    if value.strip().lower() == "nosniff":
        return present_finding(
            name,
            max_score,
            value,
            recommendation,
            message="X-Content-Type-Options is present with nosniff.",
        )

    return present_finding(
        name,
        max_score,
        value,
        recommendation,
        status="WARN",
        severity="MEDIUM",
        score=3,
        message="X-Content-Type-Options is present, but the value is not nosniff.",
    )


def make_presence_rule(
    header_name: str,
    display_name: str,
    max_score: int,
    missing_message: str,
    recommendation: str,
) -> HeaderRule:
    def rule(context: HeaderAnalysisContext) -> HeaderFinding:
        value = get_header(context, header_name)

        if not value:
            return missing_finding(
                display_name,
                max_score,
                missing_message,
                recommendation,
            )

        return present_finding(
            display_name,
            max_score,
            value,
            recommendation,
            message=f"{display_name} is present.",
        )

    return rule


def get_set_cookie_headers(context: HeaderAnalysisContext) -> list[str]:
    try:
        return context.response.headers.get_list("set-cookie")
    except AttributeError:
        value = get_header(context, "set-cookie")
        return [value] if value else []


def parse_cookie_name(set_cookie_header: str) -> str:
    name, _, _ = set_cookie_header.partition("=")
    return name.strip() or "(unnamed cookie)"


def analyze_set_cookie(context: HeaderAnalysisContext) -> HeaderFinding:
    name = "Cookie Security"
    max_score = 10
    cookie_headers = get_set_cookie_headers(context)
    recommendation = (
        "Set session and sensitive cookies with Secure, HttpOnly, and an explicit "
        "SameSite value. SameSite=None cookies must also be Secure."
    )

    if not cookie_headers:
        return HeaderFinding(
            name=name,
            status="OK",
            severity="INFO",
            message="No Set-Cookie headers were observed on the final response.",
            recommendation="No cookie hardening is needed for this response unless cookies are added later.",
            score=max_score,
            max_score=max_score,
        )

    issues: list[str] = []
    parsed_count = 0

    for raw_cookie in cookie_headers:
        cookie_name = parse_cookie_name(raw_cookie)

        try:
            parsed = SimpleCookie(raw_cookie)
        except Exception:
            issues.append(f"{cookie_name}: could not parse cookie attributes")
            continue

        if not parsed:
            issues.append(f"{cookie_name}: could not parse cookie attributes")
            continue

        for morsel in parsed.values():
            parsed_count += 1
            cookie_label = morsel.key or cookie_name
            secure = bool(morsel["secure"])
            httponly = bool(morsel["httponly"])
            samesite = morsel["samesite"].strip().lower()

            if not secure:
                issues.append(f"{cookie_label}: missing Secure")
            if not httponly:
                issues.append(f"{cookie_label}: missing HttpOnly")
            if not samesite:
                issues.append(f"{cookie_label}: missing SameSite")
            elif samesite == "none" and not secure:
                issues.append(f"{cookie_label}: SameSite=None without Secure")

    if not issues:
        return HeaderFinding(
            name=name,
            status="OK",
            severity="INFO",
            message=f"{parsed_count} cookie(s) include the checked security attributes.",
            recommendation=recommendation,
            score=max_score,
            max_score=max_score,
            evidence=f"{len(cookie_headers)} Set-Cookie header(s)",
        )

    score = max(0, max_score - min(max_score, len(issues) * 2))
    status = "BAD" if score == 0 else "WARN"
    severity = "HIGH" if score <= 4 else "MEDIUM"
    evidence = "; ".join(issues[:5])

    if len(issues) > 5:
        evidence += f"; +{len(issues) - 5} more"

    return HeaderFinding(
        name=name,
        status=status,
        severity=severity,
        message=f"{len(issues)} cookie hardening issue(s) were found.",
        recommendation=recommendation,
        score=score,
        max_score=max_score,
        evidence=evidence,
    )


def analyze_cors(context: HeaderAnalysisContext) -> HeaderFinding:
    name = "CORS"
    max_score = 10
    allow_origin = get_header(context, "access-control-allow-origin")
    allow_credentials = get_header(context, "access-control-allow-credentials")
    recommendation = (
        "Allow only trusted origins in Access-Control-Allow-Origin, and avoid "
        "combining broad origins with credentialed requests."
    )

    if not allow_origin:
        return HeaderFinding(
            name=name,
            status="OK",
            severity="INFO",
            message="No Access-Control-Allow-Origin header was observed; cross-origin reads are not broadly enabled by this response.",
            recommendation=recommendation,
            score=max_score,
            max_score=max_score,
        )

    credentials_enabled = allow_credentials and allow_credentials.strip().lower() == "true"

    if allow_origin.strip() == "*" and credentials_enabled:
        return HeaderFinding(
            name=name,
            status="BAD",
            severity="HIGH",
            message="CORS allows every origin while also enabling credentials.",
            recommendation=recommendation,
            score=0,
            max_score=max_score,
            evidence=(
                f"Access-Control-Allow-Origin: {allow_origin}; "
                f"Access-Control-Allow-Credentials: {allow_credentials}"
            ),
        )

    if allow_origin.strip() == "*":
        return HeaderFinding(
            name=name,
            status="WARN",
            severity="MEDIUM",
            message="CORS allows every origin.",
            recommendation=recommendation,
            score=6,
            max_score=max_score,
            evidence=f"Access-Control-Allow-Origin: {allow_origin}",
        )

    return HeaderFinding(
        name=name,
        status="OK",
        severity="INFO",
        message="CORS is scoped to a specific origin.",
        recommendation=recommendation,
        score=max_score,
        max_score=max_score,
        evidence=f"Access-Control-Allow-Origin: {allow_origin}",
    )


def same_hostname(left: str, right: str) -> bool:
    return (urlparse(left).hostname or "").lower() == (urlparse(right).hostname or "").lower()


def analyze_redirect_chain(context: HeaderAnalysisContext) -> HeaderFinding:
    name = "Redirect Chain"
    max_score = 10
    requested_url = context.requested_url
    final_url = str(context.response.url)
    chain = [str(item.url) for item in context.response.history] + [final_url]
    recommendation = (
        "Redirect HTTP traffic directly to HTTPS, avoid HTTPS-to-HTTP downgrades, "
        "and keep cross-site redirects intentional and minimal."
    )

    if not context.response.history:
        return HeaderFinding(
            name=name,
            status="OK",
            severity="INFO",
            message="No redirects were followed.",
            recommendation=recommendation,
            score=max_score,
            max_score=max_score,
            evidence=final_url,
        )

    issues: list[str] = []
    parsed_chain = [urlparse(url) for url in chain]

    for before, after in zip(parsed_chain, parsed_chain[1:]):
        if before.scheme == "https" and after.scheme == "http":
            issues.append("HTTPS downgraded to HTTP")

    if urlparse(requested_url).scheme == "http" and urlparse(final_url).scheme != "https":
        issues.append("HTTP request did not end on HTTPS")

    if not same_hostname(requested_url, final_url):
        issues.append("final hostname differs from requested hostname")

    if len(context.response.history) > 3:
        issues.append("redirect chain is longer than three hops")

    evidence = " -> ".join(chain)

    if issues:
        score = max(0, max_score - min(max_score, len(issues) * 3))
        return HeaderFinding(
            name=name,
            status="WARN" if score > 0 else "BAD",
            severity="MEDIUM" if score > 0 else "HIGH",
            message=f"Redirect chain has {len(issues)} issue(s): {', '.join(issues)}.",
            recommendation=recommendation,
            score=score,
            max_score=max_score,
            evidence=evidence,
        )

    return HeaderFinding(
        name=name,
        status="OK",
        severity="INFO",
        message=f"Redirect chain completed cleanly in {len(context.response.history)} hop(s).",
        recommendation=recommendation,
        score=max_score,
        max_score=max_score,
        evidence=evidence,
    )


SECURITY_HEADERS: dict[str, HeaderRule] = {
    "strict-transport-security": analyze_hsts,
    "content-security-policy": analyze_csp,
    "x-frame-options": analyze_x_frame_options,
    "x-content-type-options": analyze_x_content_type_options,
    "referrer-policy": make_presence_rule(
        "referrer-policy",
        "Referrer-Policy",
        10,
        "Referrer-Policy is missing. Sensitive URL data may leak through referrers.",
        "Set a privacy-preserving policy such as strict-origin-when-cross-origin or no-referrer.",
    ),
    "permissions-policy": make_presence_rule(
        "permissions-policy",
        "Permissions-Policy",
        10,
        "Permissions-Policy is missing. Browser feature access is less restricted.",
        "Restrict sensitive browser features such as camera, microphone, and geolocation.",
    ),
    "cross-origin-opener-policy": make_presence_rule(
        "cross-origin-opener-policy",
        "COOP",
        5,
        "Cross-Origin-Opener-Policy is missing.",
        "Consider Cross-Origin-Opener-Policy: same-origin for pages that need stronger isolation.",
    ),
    "cross-origin-resource-policy": make_presence_rule(
        "cross-origin-resource-policy",
        "CORP",
        5,
        "Cross-Origin-Resource-Policy is missing.",
        "Consider Cross-Origin-Resource-Policy for resources that should not be embedded cross-origin.",
    ),
    "set-cookie": analyze_set_cookie,
    "access-control-allow-origin": analyze_cors,
    "redirect-chain": analyze_redirect_chain,
}


def grade_from_score(score: int) -> str:
    if score >= 90:
        return "A"
    if score >= 75:
        return "B"
    if score >= 60:
        return "C"
    if score >= 40:
        return "D"
    return "F"


def analyze_headers(url: str, timeout: float = 5.0) -> dict:
    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    findings: list[HeaderFinding] = []
    raw_score = 0
    max_score = 0

    try:
        with httpx.Client(
            follow_redirects=True,
            timeout=timeout,
            headers={"User-Agent": "SecBrowser-MVP/0.1"},
        ) as client:
            response = client.get(url)

        headers = {k.lower(): v for k, v in response.headers.items()}
        context = HeaderAnalysisContext(
            headers=headers,
            response=response,
            requested_url=url,
        )

        for rule in SECURITY_HEADERS.values():
            finding = rule(context)
            raw_score += finding.score
            max_score += finding.max_score
            findings.append(finding)

        total_score = round((raw_score / max_score) * 100) if max_score else 0

        return {
            "ok": True,
            "url": str(response.url),
            "status_code": response.status_code,
            "score": total_score,
            "raw_score": raw_score,
            "max_score": max_score,
            "grade": grade_from_score(total_score),
            "findings": findings,
            "headers": dict(response.headers),
            "redirect_chain": [str(item.url) for item in response.history]
            + [str(response.url)],
        }

    except Exception as e:
        return {
            "ok": False,
            "error": str(e),
            "score": 0,
            "raw_score": 0,
            "max_score": 0,
            "grade": "N/A",
            "findings": [],
            "headers": {},
            "redirect_chain": [],
        }
