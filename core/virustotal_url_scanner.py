import os
import time
from dataclasses import dataclass

import httpx


VIRUSTOTAL_API_BASE = "https://www.virustotal.com/api/v3"


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
        self.api_key = api_key or os.getenv("VIRUSTOTAL_API_KEY", "").strip()
        self.timeout = timeout

    def is_configured(self) -> bool:
        return bool(self.api_key)

    def scan_urls(
        self,
        urls: list[str],
        max_urls: int | None = None,
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
            response = client.post(
                f"{VIRUSTOTAL_API_BASE}/urls",
                data={"url": url},
            )
            response.raise_for_status()
            analysis_id = response.json()["data"]["id"]

            analysis = self.wait_for_analysis(client, analysis_id)
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

    def wait_for_analysis(self, client: httpx.Client, analysis_id: str) -> dict:
        last_response = {}

        for _ in range(4):
            response = client.get(f"{VIRUSTOTAL_API_BASE}/analyses/{analysis_id}")
            response.raise_for_status()
            last_response = response.json()

            status = (
                last_response.get("data", {})
                .get("attributes", {})
                .get("status", "")
            )
            if status == "completed":
                return last_response

            time.sleep(2)

        return last_response

    def label_from_stats(self, malicious: int, suspicious: int) -> str:
        if malicious > 0:
            return "RISK"
        if suspicious > 0:
            return "WARN"
        return "SAFE"
