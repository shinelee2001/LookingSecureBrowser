import hashlib
import math
import sqlite3
import time
from contextlib import closing
from dataclasses import dataclass, field
from pathlib import Path
from statistics import median
from urllib.parse import parse_qsl, urlparse


PROJECT_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_DB_PATH = PROJECT_ROOT / "data" / "traffic_ai.sqlite"
DEFAULT_RETENTION_DAYS = 7
DEFAULT_MAX_EVENTS = 5000

SENSITIVE_QUERY_KEYS = {
    "access_token",
    "apikey",
    "api_key",
    "auth",
    "authorization",
    "email",
    "jwt",
    "key",
    "password",
    "refresh_token",
    "secret",
    "session",
    "token",
}

SUSPICIOUS_URL_KEYWORDS = {
    "cmd=",
    "eval(",
    "javascript:",
    "passwd",
    "powershell",
    "select%20",
    "union%20",
    "<script",
    "%3cscript",
}

TRACKER_HINTS = {
    "adservice",
    "analytics",
    "doubleclick",
    "facebook",
    "googlesyndication",
    "googletagmanager",
    "metrics",
    "telemetry",
    "tracking",
}


@dataclass
class TrafficFeatures:
    url_length: int
    domain_entropy: float
    path_entropy: float
    query_param_count: int
    sensitive_query_count: int
    is_third_party: int
    is_http: int
    is_tracker_like: int
    has_suspicious_keyword: int
    domain_requests_per_minute: float

    def as_vector(self) -> list[float]:
        return [
            float(self.url_length),
            self.domain_entropy,
            self.path_entropy,
            float(self.query_param_count),
            float(self.sensitive_query_count),
            float(self.is_third_party),
            float(self.is_http),
            float(self.is_tracker_like),
            float(self.has_suspicious_keyword),
            self.domain_requests_per_minute,
        ]


@dataclass
class ModelScore:
    anomaly_score: float
    is_model_anomaly: bool
    top_features: list[str] = field(default_factory=list)


@dataclass
class TrafficFinding:
    title: str
    severity: str
    reason: str
    evidence: str
    score: float
    model_score: float = 0.0
    rule_score: float = 0.0
    top_features: list[str] = field(default_factory=list)


@dataclass
class TrafficAnalysisReport:
    analyzed_events: int
    findings: list[TrafficFinding] = field(default_factory=list)
    model_name: str = "heuristic-baseline"
    summary: str = ""


FEATURE_NAMES = [
    "url_length",
    "domain_entropy",
    "path_entropy",
    "query_param_count",
    "sensitive_query_count",
    "is_third_party",
    "is_http",
    "is_tracker_like",
    "has_suspicious_keyword",
    "domain_requests_per_minute",
    "risk_score",
]


class SQLiteTrafficStore:
    def __init__(
        self,
        db_path: Path = DEFAULT_DB_PATH,
        retention_days: int = DEFAULT_RETENTION_DAYS,
        max_events: int = DEFAULT_MAX_EVENTS,
    ):
        self.db_path = db_path
        self.retention_days = retention_days
        self.max_events = max_events
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self.initialize()

    def initialize(self):
        with closing(self.connect()) as connection:
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS network_events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    session_id TEXT NOT NULL,
                    ts REAL NOT NULL,
                    method TEXT NOT NULL,
                    url_hash TEXT NOT NULL,
                    scheme TEXT,
                    domain TEXT,
                    path TEXT,
                    resource_type TEXT,
                    action TEXT,
                    reason TEXT,
                    first_party_domain TEXT,
                    is_third_party INTEGER NOT NULL,
                    query_param_count INTEGER NOT NULL,
                    sensitive_query_count INTEGER NOT NULL,
                    url_length INTEGER NOT NULL,
                    domain_entropy REAL NOT NULL,
                    path_entropy REAL NOT NULL,
                    is_http INTEGER NOT NULL DEFAULT 0,
                    is_tracker_like INTEGER NOT NULL DEFAULT 0,
                    has_suspicious_keyword INTEGER NOT NULL DEFAULT 0,
                    domain_requests_per_minute REAL NOT NULL DEFAULT 0,
                    risk_score REAL NOT NULL
                )
                """
            )
            self.migrate_schema(connection)
            connection.execute(
                """
                CREATE INDEX IF NOT EXISTS idx_network_events_session_ts
                ON network_events(session_id, ts)
                """
            )
            connection.execute(
                """
                CREATE INDEX IF NOT EXISTS idx_network_events_domain_ts
                ON network_events(domain, ts)
                """
            )
            connection.commit()

    def connect(self):
        return sqlite3.connect(self.db_path)

    def migrate_schema(self, connection: sqlite3.Connection):
        existing_columns = {
            row[1]
            for row in connection.execute("PRAGMA table_info(network_events)").fetchall()
        }
        migrations = {
            "is_http": "ALTER TABLE network_events ADD COLUMN is_http INTEGER NOT NULL DEFAULT 0",
            "is_tracker_like": "ALTER TABLE network_events ADD COLUMN is_tracker_like INTEGER NOT NULL DEFAULT 0",
            "has_suspicious_keyword": "ALTER TABLE network_events ADD COLUMN has_suspicious_keyword INTEGER NOT NULL DEFAULT 0",
            "domain_requests_per_minute": "ALTER TABLE network_events ADD COLUMN domain_requests_per_minute REAL NOT NULL DEFAULT 0",
        }

        for column, statement in migrations.items():
            if column not in existing_columns:
                connection.execute(statement)

    def insert_event(
        self,
        *,
        session_id: str,
        event: dict,
        features: TrafficFeatures,
        risk_score: float,
    ) -> int:
        parsed_url = urlparse(event.get("url", ""))
        first_party = urlparse(event.get("first_party", ""))
        url_hash = hashlib.sha256(event.get("url", "").encode("utf-8")).hexdigest()

        with closing(self.connect()) as connection:
            cursor = connection.execute(
                """
                INSERT INTO network_events (
                    session_id, ts, method, url_hash, scheme, domain, path,
                    resource_type, action, reason, first_party_domain,
                    is_third_party, query_param_count, sensitive_query_count,
                    url_length, domain_entropy, path_entropy, is_http,
                    is_tracker_like, has_suspicious_keyword,
                    domain_requests_per_minute, risk_score
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    session_id,
                    float(event.get("ts", time.time())),
                    event.get("method", ""),
                    url_hash,
                    parsed_url.scheme,
                    parsed_url.hostname or "",
                    parsed_url.path or "/",
                    event.get("resource_type", ""),
                    event.get("action", ""),
                    event.get("reason", ""),
                    first_party.hostname or "",
                    features.is_third_party,
                    features.query_param_count,
                    features.sensitive_query_count,
                    features.url_length,
                    features.domain_entropy,
                    features.path_entropy,
                    features.is_http,
                    features.is_tracker_like,
                    features.has_suspicious_keyword,
                    features.domain_requests_per_minute,
                    risk_score,
                ),
            )
            self.cleanup(connection)
            connection.commit()
            return int(cursor.lastrowid)

    def fetch_session_features(self, session_id: str, limit: int = 500) -> list[dict]:
        with closing(self.connect()) as connection:
            connection.row_factory = sqlite3.Row
            rows = connection.execute(
                """
                SELECT *
                FROM network_events
                WHERE session_id = ?
                ORDER BY ts DESC
                LIMIT ?
                """,
                (session_id, limit),
            ).fetchall()

        return [dict(row) for row in reversed(rows)]

    def domain_requests_per_minute(self, domain: str, window_seconds: int = 60) -> float:
        if not domain:
            return 0.0

        since = time.time() - window_seconds
        with closing(self.connect()) as connection:
            count = connection.execute(
                """
                SELECT COUNT(*)
                FROM network_events
                WHERE domain = ? AND ts >= ?
                """,
                (domain, since),
            ).fetchone()[0]

        return float(count)

    def cleanup(self, connection: sqlite3.Connection):
        cutoff = time.time() - (self.retention_days * 24 * 60 * 60)
        connection.execute("DELETE FROM network_events WHERE ts < ?", (cutoff,))
        connection.execute(
            """
            DELETE FROM network_events
            WHERE id NOT IN (
                SELECT id FROM network_events ORDER BY ts DESC LIMIT ?
            )
            """,
            (self.max_events,),
        )


class TrafficFeatureExtractor:
    def __init__(self, store: SQLiteTrafficStore):
        self.store = store

    def extract(self, event: dict) -> TrafficFeatures:
        url = event.get("url", "")
        first_party = event.get("first_party", "")
        parsed_url = urlparse(url)
        parsed_first_party = urlparse(first_party)
        domain = parsed_url.hostname or ""
        first_party_domain = parsed_first_party.hostname or ""
        query_pairs = parse_qsl(parsed_url.query, keep_blank_values=True)
        lowered_url = url.lower()

        sensitive_query_count = sum(
            1 for key, _ in query_pairs if key.lower() in SENSITIVE_QUERY_KEYS
        )
        is_third_party = int(bool(domain and first_party_domain and domain != first_party_domain))
        is_tracker_like = int(any(hint in domain for hint in TRACKER_HINTS))
        has_suspicious_keyword = int(
            any(keyword in lowered_url for keyword in SUSPICIOUS_URL_KEYWORDS)
        )

        return TrafficFeatures(
            url_length=len(url),
            domain_entropy=shannon_entropy(domain),
            path_entropy=shannon_entropy(parsed_url.path or ""),
            query_param_count=len(query_pairs),
            sensitive_query_count=sensitive_query_count,
            is_third_party=is_third_party,
            is_http=int(parsed_url.scheme == "http"),
            is_tracker_like=is_tracker_like,
            has_suspicious_keyword=has_suspicious_keyword,
            domain_requests_per_minute=self.store.domain_requests_per_minute(domain),
        )


class TrafficRuleDetector:
    def evaluate(
        self,
        event: dict,
        features: TrafficFeatures,
    ) -> tuple[float, list[TrafficFinding]]:
        findings: list[TrafficFinding] = []
        score = 0.0
        url = event.get("url", "")

        if features.is_http and features.is_third_party:
            score += 35
            findings.append(
                TrafficFinding(
                    title="Mixed or insecure third-party request",
                    severity="HIGH",
                    reason="An HTTP request was observed outside the first-party origin.",
                    evidence=url,
                    score=35,
                )
            )

        if features.sensitive_query_count:
            score += 30
            findings.append(
                TrafficFinding(
                    title="Sensitive-looking query parameter",
                    severity="HIGH",
                    reason="Token, session, key, or credential-like parameter names appeared in the URL.",
                    evidence=url,
                    score=30,
                )
            )

        if features.has_suspicious_keyword:
            score += 25
            findings.append(
                TrafficFinding(
                    title="Attack-like URL keyword",
                    severity="MEDIUM",
                    reason="The URL contains script, command, or injection-like markers.",
                    evidence=url,
                    score=25,
                )
            )

        if features.url_length > 220 or features.path_entropy > 4.5:
            score += 15
            findings.append(
                TrafficFinding(
                    title="High-entropy or unusually long URL",
                    severity="MEDIUM",
                    reason="Long or high-entropy URLs can indicate encoded payloads, tracking, or exfiltration.",
                    evidence=url,
                    score=15,
                )
            )

        if (
            features.domain_requests_per_minute >= 30
            and (features.is_third_party or features.is_tracker_like)
        ):
            score += 20
            findings.append(
                TrafficFinding(
                    title="High request rate to one domain",
                    severity="MEDIUM",
                    reason="The same domain received a burst of browser requests within one minute.",
                    evidence=url,
                    score=20,
                )
            )

        if event.get("action") == "BLOCKED":
            score += 20

        return min(score, 100.0), findings


class UnsupervisedTrafficAnalyzer:
    def __init__(self):
        self.sklearn_detector = SklearnIsolationForestDetector()

    def analyze(self, rows: list[dict]) -> tuple[str, dict[int, ModelScore]]:
        model_scores = self.sklearn_detector.detect(rows)
        if model_scores is not None:
            return "sklearn-isolation-forest", model_scores

        if self.sklearn_detector.last_error:
            return (
                f"heuristic-baseline (sklearn unavailable: {self.sklearn_detector.last_error})",
                self.robust_scores(rows),
            )

        return "heuristic-baseline", self.robust_scores(rows)

    def robust_scores(self, rows: list[dict]) -> dict[int, ModelScore]:
        if not rows:
            return {}

        url_lengths = [float(row["url_length"]) for row in rows]
        risk_scores = [float(row.get("risk_score", 0)) for row in rows]
        length_center = median(url_lengths)
        risk_center = median(risk_scores)

        scores: dict[int, ModelScore] = {}

        for row in rows:
            score = min(
                100.0,
                abs(float(row["url_length"]) - length_center) * 0.25
                + abs(float(row.get("risk_score", 0)) - risk_center) * 0.8
                + float(row["sensitive_query_count"]) * 20
                + float(row["is_third_party"]) * 5,
            )
            scores[int(row["id"])] = ModelScore(
                anomaly_score=round(score, 2),
                is_model_anomaly=score >= 65,
                top_features=top_deviating_features(row, FEATURE_NAMES[:7]),
            )

        return scores


class SklearnIsolationForestDetector:
    def __init__(
        self,
        min_training_events: int = 12,
        random_state: int = 42,
    ):
        self.min_training_events = min_training_events
        self.random_state = random_state
        self.last_error = ""

    def detect(self, rows: list[dict]) -> dict[int, ModelScore] | None:
        self.last_error = ""

        if len(rows) < self.min_training_events:
            return None

        try:
            from sklearn.ensemble import IsolationForest
            from sklearn.preprocessing import StandardScaler
        except Exception as exc:
            self.last_error = str(exc)
            return None

        vectors = [row_to_vector(row) for row in rows]
        scaler = StandardScaler()
        scaled = scaler.fit_transform(vectors)
        contamination = self.contamination_for_sample_size(len(rows))
        model = IsolationForest(
            n_estimators=160,
            contamination=contamination,
            random_state=self.random_state,
        )
        model.fit(scaled)
        decision_scores = model.decision_function(scaled)
        predictions = model.predict(scaled)

        if not len(decision_scores):
            return {}

        raw_anomaly_scores = [-float(score) for score in decision_scores]
        min_score = min(raw_anomaly_scores)
        max_score = max(raw_anomaly_scores)
        span = max(max_score - min_score, 0.000001)

        scores: dict[int, ModelScore] = {}
        for row, raw_score, prediction, scaled_vector in zip(
            rows,
            raw_anomaly_scores,
            predictions,
            scaled,
        ):
            normalized_score = ((raw_score - min_score) / span) * 100
            is_model_anomaly = int(prediction) == -1
            if is_model_anomaly:
                normalized_score = max(normalized_score, 65.0)

            scores[int(row["id"])] = ModelScore(
                anomaly_score=round(min(normalized_score, 100.0), 2),
                is_model_anomaly=is_model_anomaly,
                top_features=top_scaled_features(scaled_vector),
            )

        return scores

    def contamination_for_sample_size(self, sample_size: int) -> float:
        likely_anomaly_count = max(1, round(sample_size * 0.12))
        return min(0.25, max(0.05, likely_anomaly_count / sample_size))


class TrafficExplanationEngine:
    def explain(self, report: TrafficAnalysisReport) -> str:
        if not report.findings:
            return (
                f"Analyzed {report.analyzed_events} stored request events with "
                f"{report.model_name}. No high-confidence suspicious traffic pattern "
                "was found in the current session."
            )

        high = sum(1 for finding in report.findings if finding.severity == "HIGH")
        medium = sum(1 for finding in report.findings if finding.severity == "MEDIUM")
        top = report.findings[0]

        lines = [
            (
                f"Analyzed {report.analyzed_events} stored request events with "
                f"{report.model_name}. Found {len(report.findings)} notable signal(s): "
                f"{high} high, {medium} medium."
            ),
            "",
            f"Primary concern: {top.title}.",
            top.reason,
            "",
            "Recommended next step: inspect the highlighted request, confirm whether the destination domain is expected, and avoid sending raw cookies, tokens, or credentials in URLs.",
        ]

        return "\n".join(lines)


class BrowserTrafficAiEngine:
    def __init__(
        self,
        db_path: Path = DEFAULT_DB_PATH,
        retention_days: int = DEFAULT_RETENTION_DAYS,
        max_events: int = DEFAULT_MAX_EVENTS,
    ):
        self.store = SQLiteTrafficStore(db_path, retention_days, max_events)
        self.extractor = TrafficFeatureExtractor(self.store)
        self.rules = TrafficRuleDetector()
        self.analyzer = UnsupervisedTrafficAnalyzer()
        self.explainer = TrafficExplanationEngine()

    def record_event(self, session_id: str, event: dict) -> list[TrafficFinding]:
        event = dict(event)
        event.setdefault("ts", time.time())
        features = self.extractor.extract(event)
        risk_score, findings = self.rules.evaluate(event, features)
        self.store.insert_event(
            session_id=session_id,
            event=event,
            features=features,
            risk_score=risk_score,
        )
        return findings

    def analyze_session(self, session_id: str) -> TrafficAnalysisReport:
        rows = self.store.fetch_session_features(session_id)
        model_name, anomaly_scores = self.analyzer.analyze(rows)
        findings = self.find_session_anomalies(rows, anomaly_scores)
        report = TrafficAnalysisReport(
            analyzed_events=len(rows),
            findings=findings,
            model_name=model_name,
        )
        report.summary = self.explainer.explain(report)
        return report

    def find_session_anomalies(
        self,
        rows: list[dict],
        anomaly_scores: dict[int, ModelScore],
    ) -> list[TrafficFinding]:
        findings: list[TrafficFinding] = []

        for row in rows:
            model_score = anomaly_scores.get(int(row["id"]), ModelScore(0.0, False))
            stored_risk = float(row.get("risk_score", 0.0))
            combined = min(100.0, max(model_score.anomaly_score, stored_risk))

            if not self.should_report_anomaly(row, stored_risk, model_score):
                continue

            title = "Unsupervised traffic anomaly"
            reason = "IsolationForest marked this request as unusual compared with other stored requests in this session."
            severity = "HIGH" if combined >= 70 else "MEDIUM"

            if row.get("sensitive_query_count"):
                title = "Possible sensitive data in URL"
                reason = "Credential-like query parameter names were observed."
            elif row.get("is_third_party") and row.get("scheme") == "http":
                title = "Insecure third-party request"
                reason = "A third-party request used plain HTTP."
            elif row.get("domain_entropy", 0) >= 4.0:
                title = "Unusual destination domain"
                reason = "The destination domain has high entropy relative to normal browsing traffic."

            findings.append(
                TrafficFinding(
                    title=title,
                    severity=severity,
                    reason=reason,
                    evidence=f"{row.get('method', '')} {row.get('scheme', '')}://{row.get('domain', '')}{row.get('path', '')}",
                    score=round(combined, 2),
                    model_score=model_score.anomaly_score,
                    rule_score=stored_risk,
                    top_features=model_score.top_features,
                )
            )

        return sorted(findings, key=lambda finding: finding.score, reverse=True)[:10]

    def should_report_anomaly(
        self,
        row: dict,
        stored_risk: float,
        model_score: ModelScore,
    ) -> bool:
        if stored_risk >= 20:
            return True

        if not model_score.is_model_anomaly or model_score.anomaly_score < 85:
            return False

        return any(
            [
                row.get("sensitive_query_count"),
                row.get("is_http") and row.get("is_third_party"),
                row.get("has_suspicious_keyword"),
                row.get("is_tracker_like") and row.get("is_third_party"),
                float(row.get("domain_entropy", 0)) >= 4.2,
                float(row.get("path_entropy", 0)) >= 4.5,
                int(row.get("url_length", 0)) >= 180,
            ]
        )


def shannon_entropy(value: str) -> float:
    if not value:
        return 0.0

    frequencies = {}
    for char in value:
        frequencies[char] = frequencies.get(char, 0) + 1

    total = len(value)
    return -sum((count / total) * math.log2(count / total) for count in frequencies.values())


def row_to_vector(row: dict) -> list[float]:
    return [
        float(row["url_length"]),
        float(row["domain_entropy"]),
        float(row["path_entropy"]),
        float(row["query_param_count"]),
        float(row["sensitive_query_count"]),
        float(row["is_third_party"]),
        float(row["is_http"]),
        float(row["is_tracker_like"]),
        float(row["has_suspicious_keyword"]),
        float(row["domain_requests_per_minute"]),
        float(row["risk_score"]),
    ]


def top_scaled_features(scaled_vector, limit: int = 3) -> list[str]:
    ranked_indexes = sorted(
        range(len(FEATURE_NAMES)),
        key=lambda index: abs(float(scaled_vector[index])),
        reverse=True,
    )
    return [
        f"{FEATURE_NAMES[index]} z={float(scaled_vector[index]):.2f}"
        for index in ranked_indexes[:limit]
    ]


def top_deviating_features(
    row: dict,
    feature_names: list[str],
    limit: int = 3,
) -> list[str]:
    ranked_names = sorted(
        feature_names,
        key=lambda name: abs(float(row.get(name, 0))),
        reverse=True,
    )
    return [f"{name}={row.get(name, 0)}" for name in ranked_names[:limit]]
