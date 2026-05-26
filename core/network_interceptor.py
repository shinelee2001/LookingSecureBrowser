from urllib.parse import parse_qsl

from PySide6.QtCore import QObject, Signal
from PySide6.QtWebEngineCore import QWebEngineUrlRequestInterceptor


TRACKER_HOST_KEYWORDS = (
    "doubleclick.net",
    "googlesyndication.com",
    "google-analytics.com",
    "googletagmanager.com",
    "facebook.net",
    "connect.facebook.com",
    "analytics.",
    "ads.",
    "adservice.",
    "adserver.",
    "tracking.",
    "tracker.",
    "metrics.",
    "telemetry.",
)

TRACKING_QUERY_KEYS = {
    "fbclid",
    "gclid",
    "mc_cid",
    "mc_eid",
    "msclkid",
    "utm_campaign",
    "utm_content",
    "utm_medium",
    "utm_source",
    "utm_term",
}


class NetworkEventBus(QObject):
    request_seen = Signal(str, str, str, str, str)


class NetworkInterceptor(QWebEngineUrlRequestInterceptor):
    def __init__(self, event_bus: NetworkEventBus):
        super().__init__()
        self.event_bus = event_bus
        self.blocking_enabled = True

    def set_blocking_enabled(self, enabled: bool):
        self.blocking_enabled = enabled

    def interceptRequest(self, info):
        method = bytes(info.requestMethod()).decode("utf-8", errors="replace")
        request_url = info.requestUrl()
        first_party_url = info.firstPartyUrl()

        url = request_url.toString()
        resource_type = str(info.resourceType())
        action = "ALLOWED"
        reason = ""

        if self.blocking_enabled:
            should_block, reason = self.should_block_request(
                request_url,
                first_party_url,
                resource_type,
            )

            if should_block:
                info.block(True)
                action = "BLOCKED"

        self.event_bus.request_seen.emit(method, url, resource_type, action, reason)

    def should_block_request(self, request_url, first_party_url, resource_type: str):
        scheme = request_url.scheme().lower()
        host = request_url.host().lower()
        first_party_scheme = first_party_url.scheme().lower()
        first_party_host = first_party_url.host().lower()
        is_main_frame = "MainFrame" in resource_type

        if (
            not is_main_frame
            and scheme == "http"
            and first_party_scheme == "https"
            and host != first_party_host
        ):
            return True, "Mixed HTTP subresource"

        if self._host_matches_tracker(host):
            return True, "Tracker/ad host"

        if not is_main_frame and self._has_tracking_query(request_url.query()):
            return True, "Tracking query parameter"

        return False, ""

    def _host_matches_tracker(self, host: str) -> bool:
        if not host:
            return False

        return any(keyword in host for keyword in TRACKER_HOST_KEYWORDS)

    def _has_tracking_query(self, query: str) -> bool:
        if not query:
            return False

        return any(key.lower() in TRACKING_QUERY_KEYS for key, _ in parse_qsl(query))
