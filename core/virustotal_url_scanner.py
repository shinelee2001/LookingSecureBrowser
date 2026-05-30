import os
import time
from dataclasses import dataclass
from pathlib import Path

import httpx


VIRUSTOTAL_API_BASE = "https://www.virustotal.com/api/v3"
VIRUSTOTAL_FREE_LOOKUPS_PER_MINUTE = 4
VIRUSTOTAL_FREE_LOOKUPS_PER_DAY = 500
VIRUSTOTAL_FREE_LOOKUPS_PER_MONTH = 15500
VIRUSTOTAL_LOOKUPS_PER_URL_SCAN = 2
VIRUSTOTAL_FREE_URLS_PER_RUN = (
    VIRUSTOTAL_FREE_LOOKUPS_PER_MINUTE // VIRUSTOTAL_LOOKUPS_PER_URL_SCAN
)
VIRUSTOTAL_FREE_REQUEST_INTERVAL_SECONDS = 60 / VIRUSTOTAL_FREE_LOOKUPS_PER_MINUTE
PROJECT_ROOT = Path(__file__).resolve().parents[1]
DOTENV_PATH = PROJECT_ROOT / ".env"


@dataclass
class UrlScanResult:
    url: str
    label: str
    summary: str
    malicious: int = 0
    suspicious: int = 0
    harmless: int = 0
    undetected: int = 0


class VirusTotalUrlScanner:
    def __init__(self, api_key: str | None = None, timeout: float = 20.0):
        self.api_key = api_key or get_setting("VIRUSTOTAL_API_KEY")
        self.timeout = timeout
        self.free_lookups_per_minute = VIRUSTOTAL_FREE_LOOKUPS_PER_MINUTE
        self.free_lookups_per_day = VIRUSTOTAL_FREE_LOOKUPS_PER_DAY
        self.free_lookups_per_month = VIRUSTOTAL_FREE_LOOKUPS_PER_MONTH
        self.lookups_per_url_scan = VIRUSTOTAL_LOOKUPS_PER_URL_SCAN
        self.free_url_scan_limit = VIRUSTOTAL_FREE_URLS_PER_RUN
        self.request_interval_seconds = VIRUSTOTAL_FREE_REQUEST_INTERVAL_SECONDS
        self.last_request_at = 0.0

    def is_configured(self) -> bool:
        return bool(self.api_key)

    def scan_urls(
        self,
        urls: list[str],
        max_urls: int | None = VIRUSTOTAL_FREE_URLS_PER_RUN,
    ) -> list[UrlScanResult]:
        if not self.api_key:
            raise RuntimeError("VIRUSTOTAL_API_KEY is not set.")

        unique_urls = list(dict.fromkeys(urls))
        if max_urls is not None:
            unique_urls = unique_urls[:max_urls]

        results = []

        with httpx.Client(
            timeout=self.timeout,
            headers={"x-apikey": self.api_key},
        ) as client:
            for url in unique_urls:
                results.append(self.scan_url(client, url))

        return results

    def scan_url(self, client: httpx.Client, url: str) -> UrlScanResult:
        try:
            self.throttle_request()
            response = client.post(
                f"{VIRUSTOTAL_API_BASE}/urls",
                data={"url": url},
            )
            response.raise_for_status()
            analysis_id = response.json()["data"]["id"]

            analysis = self.fetch_analysis_once(client, analysis_id)
            stats = analysis.get("data", {}).get("attributes", {}).get("stats", {})

            malicious = int(stats.get("malicious", 0))
            suspicious = int(stats.get("suspicious", 0))
            harmless = int(stats.get("harmless", 0))
            undetected = int(stats.get("undetected", 0))

            label = self.label_from_stats(malicious, suspicious)
            summary = (
                f"VirusTotal: {malicious} malicious, {suspicious} suspicious, "
                f"{harmless} harmless, {undetected} undetected"
            )

            return UrlScanResult(
                url=url,
                label=label,
                summary=summary,
                malicious=malicious,
                suspicious=suspicious,
                harmless=harmless,
                undetected=undetected,
            )
        except Exception as exc:
            return UrlScanResult(
                url=url,
                label="UNKNOWN",
                summary=f"VirusTotal scan failed: {exc}",
            )

    def fetch_analysis_once(self, client: httpx.Client, analysis_id: str) -> dict:
        self.throttle_request()
        response = client.get(f"{VIRUSTOTAL_API_BASE}/analyses/{analysis_id}")
        response.raise_for_status()
        return response.json()

    def throttle_request(self):
        elapsed = time.monotonic() - self.last_request_at
        if self.last_request_at and elapsed < self.request_interval_seconds:
            time.sleep(self.request_interval_seconds - elapsed)

        self.last_request_at = time.monotonic()

    def label_from_stats(self, malicious: int, suspicious: int) -> str:
        if malicious > 0:
            return "RISK"
        if suspicious > 0:
            return "WARN"
        return "SAFE"


def get_setting(name: str) -> str:
    env_value = os.getenv(name, "").strip()
    if env_value:
        return env_value

    return read_dotenv_value(name)


def read_dotenv_value(name: str) -> str:
    if not DOTENV_PATH.exists():
        return ""

    for raw_line in DOTENV_PATH.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()

        if not line or line.startswith("#") or "=" not in line:
            continue

        key, value = line.split("=", 1)
        if key.strip() == name:
            return value.strip().strip('"').strip("'")

    return ""
