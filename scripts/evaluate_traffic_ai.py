import sys
import time
from pathlib import Path
from tempfile import TemporaryDirectory

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))

from core.traffic_ai_engine import BrowserTrafficAiEngine
from tests.traffic_ai_fixtures import TrafficScenario, build_scenarios


def main():
    scenarios = build_scenarios()
    results = [evaluate_scenario(scenario) for scenario in scenarios]
    metrics = calculate_metrics(results)

    print("Traffic AI Evaluation")
    print("=====================")
    print(f"Scenarios: {len(results)}")
    print(f"Accuracy:  {metrics['accuracy']:.2f}")
    print(f"Precision: {metrics['precision']:.2f}")
    print(f"Recall:    {metrics['recall']:.2f}")
    print(f"F1:        {metrics['f1']:.2f}")
    print("")
    print("Per-scenario results")

    for result in results:
        verdict = "SUSPICIOUS" if result["predicted"] else "NORMAL"
        expected = "SUSPICIOUS" if result["expected"] else "NORMAL"
        status = "PASS" if result["expected"] == result["predicted"] else "FAIL"
        print(
            f"- {status} {result['name']}: expected={expected}, "
            f"predicted={verdict}, findings={result['finding_count']}, "
            f"model={result['model_name']}"
        )
        if result["top_finding"]:
            print(f"  top={result['top_finding']}")
            print(f"  score={result['top_score']:.1f}")
            print(f"  features={', '.join(result['top_features']) or 'n/a'}")


def evaluate_scenario(scenario: TrafficScenario) -> dict:
    with TemporaryDirectory() as tmpdir:
        engine = BrowserTrafficAiEngine(db_path=Path(tmpdir) / "traffic.sqlite")
        session_id = scenario.name
        base_ts = time.time()

        for index, event in enumerate(scenario.events):
            enriched_event = dict(event)
            enriched_event["ts"] = base_ts + index
            engine.record_event(session_id, enriched_event)

        report = engine.analyze_session(session_id)

    top_finding = report.findings[0] if report.findings else None

    return {
        "name": scenario.name,
        "expected": scenario.expected_suspicious,
        "predicted": bool(report.findings),
        "finding_count": len(report.findings),
        "model_name": report.model_name,
        "top_finding": top_finding.title if top_finding else "",
        "top_score": top_finding.score if top_finding else 0.0,
        "top_features": top_finding.top_features if top_finding else [],
    }


def calculate_metrics(results: list[dict]) -> dict[str, float]:
    true_positive = sum(1 for result in results if result["expected"] and result["predicted"])
    true_negative = sum(1 for result in results if not result["expected"] and not result["predicted"])
    false_positive = sum(1 for result in results if not result["expected"] and result["predicted"])
    false_negative = sum(1 for result in results if result["expected"] and not result["predicted"])

    precision = safe_divide(true_positive, true_positive + false_positive)
    recall = safe_divide(true_positive, true_positive + false_negative)
    accuracy = safe_divide(true_positive + true_negative, len(results))
    f1 = safe_divide(2 * precision * recall, precision + recall)

    return {
        "accuracy": accuracy,
        "precision": precision,
        "recall": recall,
        "f1": f1,
    }


def safe_divide(numerator: float, denominator: float) -> float:
    if denominator == 0:
        return 0.0
    return numerator / denominator


if __name__ == "__main__":
    main()
