import httpx
from dataclasses import dataclass


@dataclass
class HeaderFinding:
    name: str
    status: str
    message: str
    score: int


SECURITY_HEADERS = {
    "strict-transport-security": {
        "display": "HSTS",
        "score": 20,
        "missing": "HSTS is missing. HTTPS downgrade and SSL stripping risks may increase.",
    },
    "content-security-policy": {
        "display": "CSP",
        "score": 30,
        "missing": "Content-Security-Policy is missing. XSS impact may be higher.",
    },
    "x-frame-options": {
        "display": "X-Frame-Options",
        "score": 10,
        "missing": "X-Frame-Options is missing. Clickjacking protection may be weak.",
    },
    "x-content-type-options": {
        "display": "X-Content-Type-Options",
        "score": 10,
        "missing": "X-Content-Type-Options is missing. MIME sniffing risk may exist.",
    },
    "referrer-policy": {
        "display": "Referrer-Policy",
        "score": 10,
        "missing": "Referrer-Policy is missing. Sensitive URL data may leak through referrers.",
    },
    "permissions-policy": {
        "display": "Permissions-Policy",
        "score": 10,
        "missing": "Permissions-Policy is missing. Browser feature access is less restricted.",
    },
    "cross-origin-opener-policy": {
        "display": "COOP",
        "score": 5,
        "missing": "Cross-Origin-Opener-Policy is missing.",
    },
    "cross-origin-resource-policy": {
        "display": "CORP",
        "score": 5,
        "missing": "Cross-Origin-Resource-Policy is missing.",
    },
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


def analyze_headers(url: str) -> dict:
    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    findings: list[HeaderFinding] = []
    total_score = 0

    try:
        with httpx.Client(
            follow_redirects=True,
            timeout=10.0,
            headers={"User-Agent": "SecBrowser-MVP/0.1"},
        ) as client:
            response = client.get(url)

        headers = {k.lower(): v for k, v in response.headers.items()}

        for header_name, rule in SECURITY_HEADERS.items():
            display = rule["display"]

            if header_name in headers:
                value = headers[header_name]
                score = rule["score"]
                total_score += score

                findings.append(
                    HeaderFinding(
                        name=display,
                        status="OK",
                        message=f"{display} is present: {value}",
                        score=score,
                    )
                )
            else:
                findings.append(
                    HeaderFinding(
                        name=display,
                        status="MISSING",
                        message=rule["missing"],
                        score=0,
                    )
                )

        return {
            "ok": True,
            "url": str(response.url),
            "status_code": response.status_code,
            "score": total_score,
            "grade": grade_from_score(total_score),
            "findings": findings,
            "headers": dict(response.headers),
        }

    except Exception as e:
        return {
            "ok": False,
            "error": str(e),
            "score": 0,
            "grade": "N/A",
            "findings": [],
            "headers": {},
        }