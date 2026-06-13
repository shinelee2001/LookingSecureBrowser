import unittest
import time
from pathlib import Path
from tempfile import TemporaryDirectory

from core.traffic_ai_engine import BrowserTrafficAiEngine
from tests.traffic_ai_fixtures import build_scenarios, event


class TrafficAiEngineTest(unittest.TestCase):
    def test_scenarios_match_expected_session_verdicts(self):
        results = []

        for scenario in build_scenarios():
            report = analyze_scenario(scenario)
            is_suspicious = bool(report.findings)
            results.append((scenario.name, scenario.expected_suspicious, is_suspicious))

        mismatches = [
            result
            for result in results
            if result[1] != result[2]
        ]

        self.assertEqual([], mismatches)

    def test_suspicious_scenarios_include_expected_explanations(self):
        for scenario in build_scenarios():
            if not scenario.expected_suspicious or not scenario.expected_title_keywords:
                continue

            report = analyze_scenario(scenario)
            titles = " | ".join(finding.title.lower() for finding in report.findings)

            self.assertTrue(
                any(keyword in titles for keyword in scenario.expected_title_keywords),
                f"{scenario.name} titles did not include expected keywords: {titles}",
            )

    def test_sklearn_model_path_is_used_when_enough_events_exist(self):
        scenario = build_scenarios()[0]
        report = analyze_scenario(scenario)

        self.assertIn(
            report.model_name,
            {"sklearn-isolation-forest", "heuristic-baseline"},
        )

        if report.model_name.startswith("heuristic-baseline"):
            self.assertIn("sklearn unavailable", report.model_name)

    def test_store_enforces_max_event_count(self):
        with TemporaryDirectory() as tmpdir:
            engine = BrowserTrafficAiEngine(
                db_path=Path(tmpdir) / "traffic.sqlite",
                max_events=3,
            )
            base_ts = time.time()

            for index in range(8):
                traffic_event = event(
                    url=f"https://example.com/assets/{index}.js",
                    resource_type="ResourceTypeScript",
                    first_party="https://example.com",
                )
                traffic_event["ts"] = base_ts + index
                engine.record_event("event-cap", traffic_event)

            rows = engine.store.fetch_session_features("event-cap", limit=20)

        self.assertEqual(3, len(rows))
        self.assertEqual(
            [
                "https://example.com/assets/5.js",
                "https://example.com/assets/6.js",
                "https://example.com/assets/7.js",
            ],
            [f"https://{row['domain']}{row['path']}" for row in rows],
        )

    def test_store_prunes_old_events_when_db_size_limit_is_exceeded(self):
        with TemporaryDirectory() as tmpdir:
            engine = BrowserTrafficAiEngine(
                db_path=Path(tmpdir) / "traffic.sqlite",
                max_events=1000,
                max_db_size_bytes=32 * 1024,
            )
            base_ts = time.time()

            for index in range(50):
                long_path = "x" * 1500
                traffic_event = event(
                    url=f"https://example.com/assets/{index}/{long_path}.js",
                    resource_type="ResourceTypeScript",
                    first_party="https://example.com",
                )
                traffic_event["ts"] = base_ts + index
                engine.record_event("size-cap", traffic_event)

            stored_events = engine.store.count_events()

        self.assertLess(stored_events, 50)


def analyze_scenario(scenario):
    with TemporaryDirectory() as tmpdir:
        engine = BrowserTrafficAiEngine(db_path=Path(tmpdir) / "traffic.sqlite")
        session_id = scenario.name
        base_ts = time.time()

        for index, event in enumerate(scenario.events):
            enriched_event = dict(event)
            enriched_event["ts"] = base_ts + index
            engine.record_event(session_id, enriched_event)

        return engine.analyze_session(session_id)


if __name__ == "__main__":
    unittest.main()
