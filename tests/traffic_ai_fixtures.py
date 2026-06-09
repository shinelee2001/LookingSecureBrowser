from dataclasses import dataclass


@dataclass(frozen=True)
class TrafficScenario:
    name: str
    expected_suspicious: bool
    events: list[dict]
    expected_title_keywords: tuple[str, ...] = ()


def build_scenarios() -> list[TrafficScenario]:
    return [
        normal_static_site(),
        normal_first_party_api(),
        sensitive_token_exfiltration(),
        insecure_third_party_request(),
        suspicious_injection_url(),
        request_burst_to_single_domain(),
    ]


def normal_static_site() -> TrafficScenario:
    events = []
    for index in range(32):
        events.append(
            event(
                url=f"https://example.com/assets/app-{index % 8}.js",
                resource_type="ResourceTypeScript",
                first_party="https://example.com",
            )
        )
    return TrafficScenario(
        name="normal_static_site",
        expected_suspicious=False,
        events=events,
    )


def normal_first_party_api() -> TrafficScenario:
    events = []
    for index in range(28):
        events.append(
            event(
                url=f"https://app.example.com/api/items?page={index % 4}&limit=20",
                resource_type="ResourceTypeXhr",
                first_party="https://app.example.com/dashboard",
            )
        )
    return TrafficScenario(
        name="normal_first_party_api",
        expected_suspicious=False,
        events=events,
    )


def sensitive_token_exfiltration() -> TrafficScenario:
    events = normal_static_site().events[:24]
    events.append(
        event(
            url=(
                "https://collector.bad-example.test/collect"
                "?access_token=abc123&session=user-session-1"
            ),
            resource_type="ResourceTypeImage",
            first_party="https://example.com/account",
        )
    )
    return TrafficScenario(
        name="sensitive_token_exfiltration",
        expected_suspicious=True,
        events=events,
        expected_title_keywords=("sensitive",),
    )


def insecure_third_party_request() -> TrafficScenario:
    events = normal_first_party_api().events[:24]
    events.append(
        event(
            url="http://cdn.bad-example.test/tracker.gif?id=123",
            resource_type="ResourceTypeImage",
            first_party="https://app.example.com",
        )
    )
    return TrafficScenario(
        name="insecure_third_party_request",
        expected_suspicious=True,
        events=events,
        expected_title_keywords=("insecure",),
    )


def suspicious_injection_url() -> TrafficScenario:
    events = normal_static_site().events[:24]
    events.append(
        event(
            url=(
                "https://example.com/search"
                "?q=%3Cscript%3Efetch('/admin')%3C/script%3E&mode=debug"
            ),
            resource_type="ResourceTypeXhr",
            first_party="https://example.com",
        )
    )
    return TrafficScenario(
        name="suspicious_injection_url",
        expected_suspicious=True,
        events=events,
        expected_title_keywords=("anomaly", "url"),
    )


def request_burst_to_single_domain() -> TrafficScenario:
    events = []
    for index in range(36):
        events.append(
            event(
                url=f"https://telemetry.bad-example.test/pixel/{index}.gif",
                resource_type="ResourceTypeImage",
                first_party="https://example.com",
            )
        )
    return TrafficScenario(
        name="request_burst_to_single_domain",
        expected_suspicious=True,
        events=events,
        expected_title_keywords=("request rate", "anomaly"),
    )


def event(
    *,
    url: str,
    resource_type: str,
    first_party: str,
    method: str = "GET",
    action: str = "ALLOWED",
    reason: str = "",
) -> dict:
    return {
        "method": method,
        "url": url,
        "resource_type": resource_type,
        "action": action,
        "reason": reason,
        "first_party": first_party,
    }
