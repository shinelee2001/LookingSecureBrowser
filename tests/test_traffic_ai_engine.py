import unittest
import time
from pathlib import Path
from tempfile import TemporaryDirectory

from core.traffic_ai_engine import BrowserTrafficAiEngine
from tests.traffic_ai_fixtures import build_scenarios


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
