# Traffic AI Engine

This document explains the local traffic AI engine used by LookingSecureBrowser.
The goal is to make the implementation easy to review, extend, and test without
needing to read the whole UI code first.

## Purpose

The engine analyzes browser network metadata for suspicious behavior while
remaining lightweight and local-first.

It is designed to:

- Store request metadata in SQLite with retention, event-count, and file-size caps
- Avoid storing raw request bodies, cookies, authorization headers, or tokens
- Extract compact security features from each request
- Combine rule-based security signals with unsupervised anomaly detection
- Explain suspicious traffic in a format that can later be replaced or enhanced
  by a local LLM

The main implementation is in:

- `core/traffic_ai_engine.py`
- UI integration: `ui/main_window.py`
- Test fixtures: `tests/traffic_ai_fixtures.py`
- Regression tests: `tests/test_traffic_ai_engine.py`
- Evaluation script: `scripts/evaluate_traffic_ai.py`

## High-Level Flow

```text
QWebEngine request event
        |
        v
BrowserTrafficAiEngine.record_event()
        |
        v
TrafficFeatureExtractor
        |
        v
TrafficRuleDetector
        |
        v
SQLiteTrafficStore
        |
        v
BrowserTrafficAiEngine.analyze_session()
        |
        v
UnsupervisedTrafficAnalyzer
        |
        v
TrafficExplanationEngine
        |
        v
AI TRAFFIC ANALYSIS panel
```

In the browser UI, every intercepted request is passed into
`BrowserTrafficAiEngine.record_event()`. The user can then click `AI ANALYZE` to
run analysis for the current page session.

## Stored Data

The SQLite database is created at:

```text
data/traffic_ai.sqlite
```

This path is ignored by git.

The storage layer keeps only lightweight metadata and derived features. It stores
the URL hash, scheme, domain, path, resource type, request method, first-party
domain, and feature values.

It does not store:

- Request body
- Response body
- Cookie headers
- Authorization headers
- Raw tokens
- Raw credentials

Retention defaults:

- `DEFAULT_RETENTION_DAYS = 7`
- `DEFAULT_MAX_EVENTS = 5000`
- `DEFAULT_MAX_DB_SIZE_BYTES = 5 * 1024 * 1024`

Cleanup runs during inserts. It removes data older than the retention window and
keeps only the newest events when the event cap is exceeded.

The store also checks SQLite file size after inserts. If the database grows past
the 5 MB default cap, it prunes the oldest events until the file can be compacted
below the target range, then runs `VACUUM` so deleted rows release disk space.
This matters because SQLite does not automatically shrink the database file after
`DELETE` statements.

## Extracted Features

`TrafficFeatureExtractor` derives features from each request.

Current feature set:

- `url_length`
- `domain_entropy`
- `path_entropy`
- `query_param_count`
- `sensitive_query_count`
- `is_third_party`
- `is_http`
- `is_tracker_like`
- `has_suspicious_keyword`
- `domain_requests_per_minute`
- `risk_score`

Entropy features help identify unusual or encoded-looking values. Query features
help identify accidental token leakage. Third-party and HTTP flags help identify
browser security risks.

Sensitive query keys currently include names such as:

```text
access_token, api_key, auth, authorization, email, jwt, password,
refresh_token, secret, session, token
```

Suspicious URL keyword checks currently include:

```text
cmd=, eval(, javascript:, passwd, powershell, select%20,
union%20, <script, %3cscript
```

## Rule-Based Signals

`TrafficRuleDetector` adds security context before the ML layer runs.

Current rule signals:

- Insecure third-party HTTP request
- Sensitive-looking query parameter
- Attack-like URL keyword
- High-entropy or unusually long URL
- High request rate to a third-party or tracker-like domain
- Request already blocked by the browser network interceptor

These signals produce a `risk_score`. The final report uses this score together
with the ML anomaly score.

## Unsupervised ML Detection

`SklearnIsolationForestDetector` is the main ML detector.

It uses:

- `StandardScaler`
- `IsolationForest`
- Dynamic contamination based on sample size

The detector returns a `ModelScore` for each stored request:

```python
ModelScore(
    anomaly_score: float,
    is_model_anomaly: bool,
    top_features: list[str],
)
```

`top_features` is built from the largest absolute scaled feature values, so the
UI can show why the model considered an event unusual.

Example:

```text
url_length z=4.90, query_param_count z=4.90, has_suspicious_keyword z=4.90
```

## Fallback Behavior

If there are not enough events, or if `scikit-learn` cannot be imported, the
engine falls back to `heuristic-baseline`.

The fallback still produces anomaly-style scores using robust simple features,
but it is not the preferred model path.

The normal expected model name when `scikit-learn` is available is:

```text
sklearn-isolation-forest
```

## Reporting Logic

The engine does not report every ML anomaly directly. This is intentional.

During early evaluation, pure IsolationForest scoring produced false positives
for normal repeated browser resources, because they were unusual relative to the
session even though they had no security meaning.

The current report gate is:

- Always report if rule-based `risk_score >= 20`
- Otherwise, report high-confidence ML anomalies only when there is security
  context, such as:
  - Sensitive query parameter
  - Third-party HTTP
  - Suspicious URL keyword
  - Tracker-like third-party domain
  - High domain or path entropy
  - Very long URL

This makes the engine less noisy and more useful for browser security work.

## Explanation Output

`TrafficExplanationEngine` creates a human-readable summary.

The UI shows:

- Model name
- Number of analyzed events
- Finding count
- Severity
- Finding title
- Combined score
- Model score
- Rule score
- Evidence
- Top contributing features

This explanation layer is intentionally simple. It is meant to be replaceable
later with a local LLM provider such as Ollama, llama.cpp, GPT4All, or LM Studio.

## Test Set Design

The test set is synthetic and scenario-based. It is not meant to represent the
entire web. Its job is to lock down important behavior while the engine evolves.

Each scenario is a `TrafficScenario` in `tests/traffic_ai_fixtures.py`:

```python
TrafficScenario(
    name="sensitive_token_exfiltration",
    expected_suspicious=True,
    events=[...],
    expected_title_keywords=("sensitive",),
)
```

Each scenario contains:

- A name
- Expected final verdict
- A list of request events
- Optional expected keywords for the explanation title

Current scenarios:

| Scenario | Expected | Purpose |
| --- | --- | --- |
| `normal_static_site` | Normal | Repeated first-party static resources |
| `normal_first_party_api` | Normal | Repeated first-party API traffic |
| `sensitive_token_exfiltration` | Suspicious | Token/session-like query leakage |
| `insecure_third_party_request` | Suspicious | HTTP request from HTTPS first-party context |
| `suspicious_injection_url` | Suspicious | Script/injection-looking query |
| `request_burst_to_single_domain` | Suspicious | Burst to third-party telemetry-like host |

## Regression Tests

Run:

```powershell
venv\Scripts\python.exe -m unittest tests.test_traffic_ai_engine
```

The tests verify five things:

1. Scenario verdicts match expectations

   If a scenario is expected to be suspicious, the report must contain findings.
   If it is expected to be normal, the report must contain no findings.

2. Suspicious explanations contain expected keywords

   This prevents the engine from detecting the right event for the wrong reason.

3. The model path is valid

   With enough events, the engine should use `sklearn-isolation-forest` when
   available. If it falls back, the fallback reason should mention that sklearn
   was unavailable.

4. The SQLite store enforces the event cap

   When more than `DEFAULT_MAX_EVENTS` are stored, the oldest events are pruned
   and the newest events remain available for session analysis.

5. The SQLite store prunes when the database size cap is exceeded

   When the file grows beyond `DEFAULT_MAX_DB_SIZE_BYTES`, old events are removed
   and the database is compacted to keep local storage bounded.

## Evaluation Script

Run:

```powershell
venv\Scripts\python.exe scripts\evaluate_traffic_ai.py
```

The script runs every scenario in an isolated temporary SQLite database, then
prints:

- Accuracy
- Precision
- Recall
- F1
- Per-scenario verdict
- Top finding
- Score
- Top features

Latest evaluation result:

```text
Scenarios: 6
Accuracy:  1.00
Precision: 1.00
Recall:    1.00
F1:        1.00
```

This is only for the current synthetic set. Real browser traffic will be noisier,
so future evaluation should add captured local traffic samples and more benign
third-party cases.

## Extension Ideas

Good next steps:

- Add anonymized real browsing sessions as fixtures
- Add benign third-party cases to reduce future false positives
- Add malicious redirect-chain scenarios
- Track per-domain baselines across sessions
- Add model calibration over longer retention windows
- Add an LLM provider interface for richer explanations
- Export evaluation reports as JSON for trend tracking
