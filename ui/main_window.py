import json
import time
from threading import Thread
from urllib.parse import quote_plus
from uuid import uuid4

from PySide6.QtCore import QUrl, Qt, QDateTime, QUrlQuery, Signal
from PySide6.QtWidgets import (
    QMainWindow,
    QWidget,
    QVBoxLayout,
    QHBoxLayout,
    QLineEdit,
    QPushButton,
    QTextEdit,
    QLabel,
    QFrame,
    QDockWidget,
    QSplitter,
    QTableWidget,
    QTableWidgetItem,
    QHeaderView,
    QDialog,
    QDialogButtonBox,
    QAbstractItemView,
)
from PySide6.QtGui import QColor, QBrush
from PySide6.QtWebEngineWidgets import QWebEngineView

from core.header_analyzer import analyze_headers
from core.mitre_attack_mapper import (
    combine_mappings,
    format_mitre_report,
    map_header_findings,
    map_link_scan_results,
    map_network_events,
)
from core.network_interceptor import NetworkEventBus, NetworkInterceptor
from core.traffic_ai_engine import BrowserTrafficAiEngine
from core.virustotal_url_scanner import VirusTotalUrlScanner


GOOGLE_SEARCH_URL = "https://www.google.com/search?q="


def normalize_browser_input(text: str) -> str:
    text = text.strip()

    if not text:
        return "https://google.com"

    if text.startswith(("http://", "https://")):
        return text

    if is_probable_url(text):
        return "https://" + text

    return GOOGLE_SEARCH_URL + quote_plus(text)


def is_probable_url(text: str) -> bool:
    if any(char.isspace() for char in text):
        return False

    host = text.split("/", 1)[0].split("?", 1)[0].split("#", 1)[0]

    if not host:
        return False

    if ":" in host:
        host, port = host.rsplit(":", 1)
        if not port.isdigit():
            return False

    lowered_host = host.lower()
    if lowered_host in {"localhost", "127.0.0.1"}:
        return True

    labels = lowered_host.split(".")
    if len(labels) == 4 and all(label.isdigit() for label in labels):
        return all(0 <= int(label) <= 255 for label in labels)

    if len(labels) < 2 or any(not label for label in labels):
        return False

    tld = labels[-1]
    return len(tld) >= 2 and tld.isalpha()


class MainWindow(QMainWindow):
    link_scan_finished = Signal(list)
    link_scan_failed = Signal(str)
    header_scan_finished = Signal(int, object, bool)

    def __init__(self):
        super().__init__()

        self.setWindowTitle("LookingSecureBrowser - Looking secure... hopefully really secure...")
        self.resize(1400, 850)

        self.browser = QWebEngineView()
        self.url_bar = QLineEdit()

        self.security_output = QTextEdit()
        self.security_output.setReadOnly(True)

        self.score_label = QLabel("Score: N/A")
        self.grade_label = QLabel("Grade: N/A")
        self.blocked_label = QLabel("Blocked: 0")
        self.allowed_label = QLabel("Allowed: 0")
        self.blocked_count = 0
        self.allowed_count = 0
        self.network_events = []
        self.last_header_findings = []
        self.last_link_scan_results = []
        self.link_scanner = VirusTotalUrlScanner()
        self.link_scan_total_urls = 0
        self.link_scan_submitted_urls = 0
        self.ai_engine = BrowserTrafficAiEngine()
        self.traffic_session_id = self.new_traffic_session_id()
        self.header_scan_id = 0

        # Network tab style request table
        self.network_table = QTableWidget()
        self.mitre_output = QTextEdit()
        self.mitre_output.setReadOnly(True)
        self.ai_output = QTextEdit()
        self.ai_output.setReadOnly(True)

        # Browser request interceptor
        self.network_event_bus = NetworkEventBus()
        self.network_interceptor = NetworkInterceptor(self.network_event_bus)

        self._build_ui()
        self._connect_signals()

        # Attach interceptor to the browser profile
        self.browser.page().profile().setUrlRequestInterceptor(
            self.network_interceptor
        )

        self.load_url("https://google.com")

    def _build_ui(self):
        # Main container
        root = QWidget()
        root_layout = QVBoxLayout(root)
        root_layout.setContentsMargins(0, 0, 0, 0)
        root_layout.setSpacing(0)

        # Navigation bar
        nav_bar = QHBoxLayout()
        nav_bar.setContentsMargins(8, 8, 8, 8)
        nav_bar.setSpacing(6)

        self.back_btn = QPushButton("←")
        self.forward_btn = QPushButton("→")
        self.reload_btn = QPushButton("⟳")
        self.scan_btn = QPushButton("SCAN HEADERS")
        self.link_scan_btn = QPushButton("SCAN LINKS")
        self.ai_analyze_btn = QPushButton("AI ANALYZE")
        self.blocking_btn = QPushButton("BLOCKING OFF")
        self.console_btn = QPushButton("CONSOLE")
        self.dock_bottom_btn = QPushButton("BOTTOM PANEL")
        self.dock_right_btn = QPushButton("RIGHT SIDE")

        self.url_bar.setPlaceholderText("Enter URL...")

        nav_bar.addWidget(self.back_btn)
        nav_bar.addWidget(self.forward_btn)
        nav_bar.addWidget(self.reload_btn)
        nav_bar.addWidget(self.url_bar)
        nav_bar.addWidget(self.scan_btn)
        nav_bar.addWidget(self.link_scan_btn)
        nav_bar.addWidget(self.ai_analyze_btn)
        nav_bar.addWidget(self.blocking_btn)
        nav_bar.addWidget(self.console_btn)

        root_layout.addLayout(nav_bar)
        root_layout.addWidget(self.browser)

        self.setCentralWidget(root)

        # Security dock panel
        self._build_security_dock()

    def _build_security_dock(self):
        self.security_dock = QDockWidget("SECURITY CONSOLE", self)
        self.security_dock.setObjectName("SecurityDock")
    
        self.security_dock.setAllowedAreas(
            Qt.BottomDockWidgetArea
            | Qt.RightDockWidgetArea
            | Qt.LeftDockWidgetArea
        )
    
        self.security_dock.setFeatures(
            QDockWidget.DockWidgetMovable
            | QDockWidget.DockWidgetFloatable
            | QDockWidget.DockWidgetClosable
        )
    
        security_frame = QFrame()
        security_frame.setObjectName("SecurityPanel")
    
        security_layout = QVBoxLayout(security_frame)
        security_layout.setContentsMargins(8, 6, 8, 8)
        security_layout.setSpacing(6)

        summary_bar = QFrame()
        summary_bar.setObjectName("SecuritySummaryBar")
        summary_bar.setFixedHeight(62)

        summary_layout = QVBoxLayout(summary_bar)
        summary_layout.setContentsMargins(8, 5, 8, 5)
        summary_layout.setSpacing(4)

        title_row = QHBoxLayout()
        title_row.setContentsMargins(0, 0, 0, 0)
        title_row.setSpacing(8)

        stats_row = QHBoxLayout()
        stats_row.setContentsMargins(0, 0, 0, 0)
        stats_row.setSpacing(12)

        title = QLabel("SECURITY CONSOLE")
        title.setObjectName("PanelTitle")
        position_label = QLabel("DOCK:")
        position_label.setObjectName("ConsolePositionLabel")
        self.dock_bottom_btn.setObjectName("ConsoleToolButton")
        self.dock_right_btn.setObjectName("ConsoleToolButton")
        self.dock_bottom_btn.setCheckable(True)
        self.dock_right_btn.setCheckable(True)
        self.dock_bottom_btn.setChecked(True)
        self.dock_bottom_btn.setToolTip("Dock the security console below the browser.")
        self.dock_right_btn.setToolTip("Dock the security console on the right side.")
    
        self.score_label.setObjectName("ScoreLabel")
        self.grade_label.setObjectName("GradeLabel")
        self.blocked_label.setObjectName("BlockedLabel")
        self.allowed_label.setObjectName("AllowedLabel")
    
        title_row.addWidget(title)
        title_row.addStretch()
        title_row.addWidget(position_label)
        title_row.addWidget(self.dock_bottom_btn)
        title_row.addWidget(self.dock_right_btn)

        stats_row.addWidget(self.allowed_label)
        stats_row.addWidget(self.blocked_label)
        stats_row.addWidget(self.score_label)
        stats_row.addWidget(self.grade_label)
        stats_row.addStretch()

        summary_layout.addLayout(title_row)
        summary_layout.addLayout(stats_row)

        security_layout.addWidget(summary_bar)
    
        # Console body: network first, MITRE mapping second, header scan third.
        self.console_splitter = QSplitter(Qt.Horizontal)
    
        # Header scan summary
        findings_frame = QFrame()
        findings_frame.setObjectName("FindingsPanel")
        findings_layout = QVBoxLayout(findings_frame)
        findings_layout.setContentsMargins(0, 0, 0, 0)
        findings_layout.setSpacing(6)
    
        findings_title = QLabel("HEADER SCAN")
        findings_title.setObjectName("SubPanelTitle")
    
        findings_layout.addWidget(findings_title)
        findings_layout.addWidget(self.security_output)
    
        # Network traffic table
        network_frame = QFrame()
        network_frame.setObjectName("NetworkPanel")
        network_layout = QVBoxLayout(network_frame)
        network_layout.setContentsMargins(0, 0, 0, 0)
        network_layout.setSpacing(6)
    
        network_title = QLabel("NETWORK TRAFFIC")
        network_title.setObjectName("SubPanelTitle")
    
        self.network_table.setColumnCount(6)
        self.network_table.setHorizontalHeaderLabels(
            ["Time", "Action", "Method", "Type", "Reason", "URL"]
        )
    
        header = self.network_table.horizontalHeader()
        header.setStretchLastSection(False)
        for column in range(6):
            header.setSectionResizeMode(column, QHeaderView.Interactive)
        self.network_table.setColumnWidth(0, 118)
        self.network_table.setColumnWidth(1, 92)
        self.network_table.setColumnWidth(2, 82)
        self.network_table.setColumnWidth(3, 290)
        self.network_table.setColumnWidth(4, 220)
        self.network_table.setColumnWidth(5, 900)
    
        self.network_table.verticalHeader().setVisible(False)
        self.network_table.setHorizontalScrollBarPolicy(Qt.ScrollBarAsNeeded)
        self.network_table.setHorizontalScrollMode(QAbstractItemView.ScrollPerPixel)
        self.network_table.setTextElideMode(Qt.ElideNone)
        self.network_table.setWordWrap(False)
        self.network_table.setShowGrid(False)
        self.network_table.setEditTriggers(QTableWidget.NoEditTriggers)
        self.network_table.setSelectionBehavior(QTableWidget.SelectRows)
        self.network_table.setToolTip("Double-click a request to inspect details.")
    
        network_layout.addWidget(network_title)
        network_layout.addWidget(self.network_table)

        mitre_frame = QFrame()
        mitre_frame.setObjectName("MitrePanel")
        mitre_layout = QVBoxLayout(mitre_frame)
        mitre_layout.setContentsMargins(0, 0, 0, 0)
        mitre_layout.setSpacing(6)

        mitre_title = QLabel("MITRE ATT&CK")
        mitre_title.setObjectName("SubPanelTitle")
        self.mitre_output.setPlainText(format_mitre_report([]))

        mitre_layout.addWidget(mitre_title)
        mitre_layout.addWidget(self.mitre_output)

        ai_frame = QFrame()
        ai_frame.setObjectName("AiPanel")
        ai_layout = QVBoxLayout(ai_frame)
        ai_layout.setContentsMargins(0, 0, 0, 0)
        ai_layout.setSpacing(6)

        ai_title = QLabel("AI TRAFFIC ANALYSIS")
        ai_title.setObjectName("SubPanelTitle")
        self.ai_output.setPlainText(
            "No AI traffic analysis yet.\n\n"
            "Network events are stored locally in SQLite. Click AI ANALYZE to run "
            "unsupervised anomaly analysis on the current browsing session."
        )

        ai_layout.addWidget(ai_title)
        ai_layout.addWidget(self.ai_output)
    
        self.console_splitter.addWidget(network_frame)
        self.console_splitter.addWidget(ai_frame)
        self.console_splitter.addWidget(mitre_frame)
        self.console_splitter.addWidget(findings_frame)
    
        # Give network traffic most of the console area.
        self.console_splitter.setStretchFactor(0, 4)
        self.console_splitter.setStretchFactor(1, 2)
        self.console_splitter.setStretchFactor(2, 2)
        self.console_splitter.setStretchFactor(3, 1)
        self.console_splitter.setSizes([700, 320, 300, 240])
    
        security_layout.addWidget(self.console_splitter, 1)
    
        self.security_dock.setWidget(security_frame)
    
        # 기본 위치: 아래쪽 DevTools 스타일
        self.addDockWidget(Qt.BottomDockWidgetArea, self.security_dock)
    
        self.resizeDocks(
            [self.security_dock],
            [360],
            Qt.Vertical,
        )
    
        # 시작 시 숨김
        self.security_dock.hide()

    def _connect_signals(self):
        self.scan_btn.clicked.connect(self.scan_current_url)
        self.link_scan_btn.clicked.connect(self.scan_page_links)
        self.ai_analyze_btn.clicked.connect(self.analyze_current_traffic)
        self.blocking_btn.clicked.connect(self.toggle_request_blocking)
        self.console_btn.clicked.connect(self.toggle_console)

        self.dock_bottom_btn.clicked.connect(self.move_console_bottom)
        self.dock_right_btn.clicked.connect(self.move_console_right)

        self.url_bar.returnPressed.connect(self.go_to_url)

        self.back_btn.clicked.connect(self.browser.back)
        self.forward_btn.clicked.connect(self.browser.forward)
        self.reload_btn.clicked.connect(self.browser.reload)

        self.browser.urlChanged.connect(self.update_url_bar)
        self.browser.loadStarted.connect(self.on_load_started)
        self.browser.loadFinished.connect(self.on_load_finished)

        self.security_dock.visibilityChanged.connect(self.on_console_visibility_changed)
        self.network_event_bus.request_seen.connect(self.add_network_row)
        self.network_table.cellDoubleClicked.connect(self.show_network_detail)
        self.link_scan_finished.connect(self.apply_link_scan_results)
        self.link_scan_failed.connect(self.on_link_scan_failed)
        self.header_scan_finished.connect(self.apply_header_scan_result)

    def normalize_url(self, text: str) -> str:
        return normalize_browser_input(text)

    def load_url(self, url: str):
        normalized = self.normalize_url(url)
        self.browser.setUrl(QUrl(normalized))
        self.url_bar.setText(normalized)

    def go_to_url(self):
        self.load_url(self.url_bar.text())

    def update_url_bar(self, qurl: QUrl):
        self.url_bar.setText(qurl.toString())

    def on_load_finished(self, ok: bool):
        if ok:
            # 페이지 로딩 후 자동 분석은 하되,
            # 콘솔은 자동으로 열지 않음.
            self.scan_current_url(show_console=False)
        else:
            self.security_output.setPlainText("[ERROR] Page failed to load.")

    def on_load_started(self):
        self.reset_header_scan_state()
        self.reset_network_stats()
        self.reset_link_scan_state()

    def toggle_request_blocking(self):
        enabled = not self.network_interceptor.blocking_enabled
        self.network_interceptor.set_blocking_enabled(enabled)
        self.blocking_btn.setText("BLOCKING ON" if enabled else "BLOCKING OFF")

    def reset_link_scan_state(self):
        self.link_scan_btn.setEnabled(True)
        self.link_scan_btn.setText("SCAN LINKS")
        self.last_link_scan_results = []
        self.update_mitre_panel()

    def reset_header_scan_state(self):
        self.header_scan_id += 1
        self.scan_btn.setEnabled(True)
        self.scan_btn.setText("SCAN HEADERS")

    def reset_network_stats(self):
        self.traffic_session_id = self.new_traffic_session_id()
        self.blocked_count = 0
        self.allowed_count = 0
        self.network_events.clear()
        self.network_table.setRowCount(0)
        self.ai_output.setPlainText(
            "Current page session reset.\n\n"
            "Network events are being stored locally for lightweight anomaly analysis."
        )
        self.update_network_stats()
        self.update_mitre_panel()

    def new_traffic_session_id(self) -> str:
        return f"session-{int(time.time())}-{uuid4().hex[:8]}"

    def update_network_stats(self):
        self.blocked_label.setText(f"Blocked: {self.blocked_count}")
        self.allowed_label.setText(f"Allowed: {self.allowed_count}")

    def toggle_console(self):
        if self.security_dock.isVisible():
            self.security_dock.hide()
        else:
            self.security_dock.show()
            self.security_dock.raise_()

    def on_console_visibility_changed(self, visible: bool):
        if visible:
            self.console_btn.setText("HIDE CONSOLE")
        else:
            self.console_btn.setText("CONSOLE")

    def move_console_bottom(self):
        self.security_dock.show()
        self.dock_bottom_btn.setChecked(True)
        self.dock_right_btn.setChecked(False)

        if self.security_dock.isFloating():
            self.security_dock.setFloating(False)

        self.console_splitter.setOrientation(Qt.Horizontal)
        self.console_splitter.setSizes([700, 320, 300, 240])
        self.addDockWidget(Qt.BottomDockWidgetArea, self.security_dock)

        self.resizeDocks(
            [self.security_dock],
            [360],
            Qt.Vertical,
        )

    def move_console_right(self):
        self.security_dock.show()
        self.dock_bottom_btn.setChecked(False)
        self.dock_right_btn.setChecked(True)

        if self.security_dock.isFloating():
            self.security_dock.setFloating(False)

        self.console_splitter.setOrientation(Qt.Vertical)
        self.console_splitter.setSizes([420, 260, 240, 220])
        self.addDockWidget(Qt.RightDockWidgetArea, self.security_dock)

        self.resizeDocks(
            [self.security_dock],
            [520],
            Qt.Horizontal,
        )

    def scan_current_url(self, show_console: bool = True):
        url = self.url_bar.text().strip()

        if show_console:
            self.security_output.setPlainText("[*] Scanning security headers...\n")
            self.scan_btn.setEnabled(False)
            self.scan_btn.setText("SCANNING...")

        self.header_scan_id += 1
        scan_id = self.header_scan_id
        worker = Thread(
            target=self.run_header_scan_worker,
            args=(scan_id, url, show_console),
            daemon=True,
        )
        worker.start()

        if show_console:
            self.security_dock.show()
            self.security_dock.raise_()

    def run_header_scan_worker(self, scan_id: int, url: str, show_console: bool):
        timeout = 2.0 if not show_console else 5.0
        result = analyze_headers(url, timeout=timeout)
        self.header_scan_finished.emit(scan_id, result, show_console)

    def apply_header_scan_result(self, scan_id: int, result: dict, show_console: bool):
        if scan_id != self.header_scan_id:
            return

        if show_console:
            self.scan_btn.setEnabled(True)
            self.scan_btn.setText("SCAN HEADERS")

        self.render_header_scan_result(result, show_console)

    def render_header_scan_result(self, result: dict, show_console: bool):
        if not result["ok"]:
            self.score_label.setText("Score: N/A")
            self.grade_label.setText("Grade: N/A")
            self.last_header_findings = []
            self.update_mitre_panel()
            self.security_output.setPlainText(
                f"[ERROR] Failed to analyze target.\n\n{result['error']}"
            )

            if show_console:
                self.security_dock.show()
                self.security_dock.raise_()

            return

        self.score_label.setText(f"Score: {result['score']} / 100")
        self.grade_label.setText(f"Grade: {result['grade']}")
        self.last_header_findings = result["findings"]
        self.update_mitre_panel()

        lines = []
        lines.append(f"Target: {result['url']}")
        lines.append(f"HTTP Status: {result['status_code']}")
        lines.append(f"Score: {result['score']} / 100")
        lines.append(f"Grade: {result['grade']}")
        lines.append("")
        lines.append("Header Findings")

        for finding in result["findings"]:
            prefix = "[+]" if finding.status == "OK" else "[!]"
            lines.append(
                f"{prefix} {finding.name}: {finding.status} "
                f"[{finding.severity}] ({finding.score}/{finding.max_score})"
            )
            lines.append(f"    {finding.message}")

            if finding.evidence:
                lines.append(f"    Evidence: {finding.evidence}")

            if finding.recommendation:
                lines.append(f"    Fix: {finding.recommendation}")

        self.security_output.setPlainText("\n".join(lines))

        if show_console:
            self.security_dock.show()
            self.security_dock.raise_()

    def scan_page_links(self):
        if not self.link_scanner.is_configured():
            self.show_link_scan_message(
                "VirusTotal API Key Missing",
                "VIRUSTOTAL_API_KEY is not set.\n\n"
                "Add it to your local .env file, then restart the app.",
            )
            return

        self.link_scan_btn.setEnabled(False)
        self.link_scan_btn.setText("COLLECTING...")

        script = """
        (() => {
            const anchors = Array.from(document.links || document.querySelectorAll('a[href]'));
            const isVisible = (element) => {
                const style = window.getComputedStyle(element);
                return (
                    style.display !== 'none' &&
                    style.visibility !== 'hidden' &&
                    style.opacity !== '0' &&
                    element.getClientRects().length > 0
                );
            };

            const links = anchors
                .filter(isVisible)
                .map((anchor) => {
                    const rawHref = anchor.getAttribute('href') || '';
                    const resolvedHref = anchor.href || rawHref;
                    const text = (anchor.innerText || anchor.textContent || '').trim();

                    if (/^https?:\\/\\//i.test(rawHref)) {
                        return { source: 'PAGE LINK', text, url: rawHref };
                    }

                    if (/^https?:\\/\\//i.test(resolvedHref)) {
                        return { source: 'PAGE LINK', text, url: resolvedHref };
                    }

                    return null;
                })
                .filter(Boolean);

            const byUrl = new Map();
            links.forEach((link) => {
                if (!byUrl.has(link.url)) {
                    byUrl.set(link.url, link);
                }
            });

            return JSON.stringify({
                totalAnchors: anchors.length,
                visibleAnchors: anchors.filter(isVisible).length,
                links: Array.from(byUrl.values()),
            });
        })();
        """
        self.browser.page().runJavaScript(script, self.start_link_scan)

    def start_link_scan(self, payload):
        total_anchors = 0
        visible_anchors = 0
        link_entries = []

        try:
            if isinstance(payload, str):
                data = json.loads(payload)
                total_anchors = int(data.get("totalAnchors", 0))
                visible_anchors = int(data.get("visibleAnchors", 0))
                link_entries = data.get("links", [])
            elif isinstance(payload, dict):
                total_anchors = int(payload.get("totalAnchors", 0))
                visible_anchors = int(payload.get("visibleAnchors", 0))
                link_entries = payload.get("links", [])
            elif isinstance(payload, list):
                link_entries = [{"source": "PAGE LINK", "text": "", "url": url} for url in payload]
                total_anchors = len(payload)
                visible_anchors = len(payload)
        except Exception as exc:
            self.link_scan_btn.setEnabled(True)
            self.link_scan_btn.setText("SCAN LINKS")
            self.show_link_scan_message(
                "Link Collection Failed",
                f"Failed to parse page links.\n\n{exc}",
            )
            return

        link_entries = [
            entry
            for entry in link_entries
            if isinstance(entry, dict)
            and isinstance(entry.get("url"), str)
            and entry["url"].startswith(("http://", "https://"))
        ]

        if not link_entries:
            self.link_scan_btn.setEnabled(True)
            self.link_scan_btn.setText("SCAN LINKS")
            self.show_link_scan_message(
                "No Links Found",
                "No http/https links found.\n\n"
                f"Anchors found in current page: {total_anchors}\n"
                f"Visible anchors: {visible_anchors}",
            )
            return

        selected_urls = self.show_link_selection_dialog(link_entries)
        if not selected_urls:
            self.link_scan_btn.setEnabled(True)
            self.link_scan_btn.setText("SCAN LINKS")
            return

        self.link_scan_total_urls = len(link_entries)
        self.link_scan_submitted_urls = len(selected_urls)

        self.link_scan_btn.setText("SCANNING...")

        worker = Thread(
            target=self.run_link_scan_worker,
            args=(selected_urls, self.link_scan_submitted_urls),
            daemon=True,
        )
        worker.start()

    def run_link_scan_worker(self, urls: list[str], max_urls: int):
        try:
            results = self.link_scanner.scan_urls(urls, max_urls=max_urls)
            payload = [result.__dict__ for result in results]
            self.link_scan_finished.emit(payload)
        except Exception as exc:
            self.link_scan_failed.emit(str(exc))

    def apply_link_scan_results(self, results: list[dict]):
        self.link_scan_btn.setEnabled(True)
        self.link_scan_btn.setText("SCAN LINKS")
        self.last_link_scan_results = results
        self.update_mitre_panel()
        self.inject_link_safety_badges(results)
        self.show_link_scan_results_dialog(results)

    def on_link_scan_failed(self, error: str):
        self.link_scan_btn.setEnabled(True)
        self.link_scan_btn.setText("SCAN LINKS")
        self.show_link_scan_message(
            "VirusTotal Link Scan Failed",
            f"VirusTotal link scan failed.\n\n{error}",
        )

    def show_link_selection_dialog(self, link_entries: list[dict]) -> list[str]:
        limit = self.link_scanner.free_url_scan_limit
        dialog = QDialog(self)
        dialog.setWindowTitle("Select Links to Scan")
        dialog.resize(900, 520)
        dialog.selected_urls = []

        layout = QVBoxLayout(dialog)

        title = QLabel("SELECT LINKS FOR VIRUSTOTAL SCAN")
        title.setObjectName("SubPanelTitle")

        hint = QLabel(
            f"Found {len(link_entries)} rendered page links. "
            f"Check up to {limit} links to stay within the free API lookup limit. "
            "Network traffic URLs are listed separately in the Network Traffic table."
        )
        selected_label = QLabel("Selected: 0")
        selected_label.setObjectName("AllowedLabel")
        meta_row = QHBoxLayout()
        meta_row.addWidget(hint)
        meta_row.addStretch()
        meta_row.addWidget(selected_label)

        network_note = QLabel(
            "Source: PAGE LINK means the URL exists as a visible anchor in the rendered page."
        )
        warning = QLabel("")
        warning.setObjectName("BlockedLabel")

        table = QTableWidget()
        table.setColumnCount(4)
        table.setHorizontalHeaderLabels(["Select", "Source", "Text", "URL"])
        table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeToContents)
        table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeToContents)
        table.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeToContents)
        table.horizontalHeader().setSectionResizeMode(3, QHeaderView.Stretch)
        table.verticalHeader().setVisible(False)
        table.setShowGrid(False)
        table.setEditTriggers(QTableWidget.NoEditTriggers)
        table.setSelectionBehavior(QTableWidget.SelectRows)
        table.setSelectionMode(QAbstractItemView.SingleSelection)
        table.setRowCount(len(link_entries))

        for row, entry in enumerate(link_entries):
            checkbox = QTableWidgetItem("")
            checkbox.setFlags(
                Qt.ItemIsUserCheckable | Qt.ItemIsEnabled | Qt.ItemIsSelectable
            )
            checkbox.setCheckState(Qt.Checked if row < limit else Qt.Unchecked)

            source_item = QTableWidgetItem(entry.get("source", "PAGE LINK"))
            text_item = QTableWidgetItem(entry.get("text", ""))
            url_item = QTableWidgetItem(entry.get("url", ""))

            table.setItem(row, 0, checkbox)
            table.setItem(row, 1, source_item)
            table.setItem(row, 2, text_item)
            table.setItem(row, 3, url_item)

        def checked_rows() -> list[int]:
            rows = []
            for row in range(table.rowCount()):
                item = table.item(row, 0)
                if item and item.checkState() == Qt.Checked:
                    rows.append(row)
            return rows

        def update_selected_count():
            count = len(checked_rows())
            selected_label.setText(f"Selected: {count} / {limit}")
            if count > limit:
                warning.setText(f"Select up to {limit} links for this scan.")
            elif count == 0:
                warning.setText("Select at least one link.")
            else:
                warning.setText("")

        table.itemChanged.connect(lambda item: update_selected_count())
        update_selected_count()

        buttons = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)

        def accept_selection():
            selected_rows = checked_rows()

            if not selected_rows:
                warning.setText("Select at least one link.")
                return

            if len(selected_rows) > limit:
                warning.setText(f"Select up to {limit} links for this scan.")
                return

            dialog.selected_urls = [link_entries[row]["url"] for row in selected_rows]
            dialog.accept()

        buttons.accepted.connect(accept_selection)
        buttons.rejected.connect(dialog.reject)

        layout.addWidget(title)
        layout.addLayout(meta_row)
        layout.addWidget(network_note)
        layout.addWidget(table)
        layout.addWidget(warning)
        layout.addWidget(buttons)

        if dialog.exec() != QDialog.Accepted:
            return []

        return dialog.selected_urls

    def show_link_scan_results_dialog(self, results: list[dict]):
        dialog = QDialog(self)
        dialog.setWindowTitle("VirusTotal Link Scan Results")
        dialog.resize(1100, 560)

        layout = QVBoxLayout(dialog)

        title = QLabel("VIRUSTOTAL LINK SCAN RESULTS")
        title.setObjectName("SubPanelTitle")

        counts = {"SAFE": 0, "WARN": 0, "RISK": 0, "UNKNOWN": 0}
        for result in results:
            label = result.get("label", "UNKNOWN")
            counts[label] = counts.get(label, 0) + 1

        summary = QLabel(
            f"Found {self.link_scan_total_urls} links | "
            f"Scanned {len(results)} | "
            f"Skipped {max(self.link_scan_total_urls - len(results), 0)} | "
            f"SAFE {counts['SAFE']} | WARN {counts['WARN']} | "
            f"RISK {counts['RISK']} | UNKNOWN {counts['UNKNOWN']}"
        )

        table = QTableWidget()
        table.setColumnCount(6)
        table.setHorizontalHeaderLabels(
            [
                "Verdict",
                "Malicious",
                "Suspicious",
                "Harmless",
                "Undetected",
                "URL",
            ]
        )
        table.verticalHeader().setVisible(False)
        table.setShowGrid(False)
        table.setEditTriggers(QTableWidget.NoEditTriggers)
        table.setSelectionBehavior(QTableWidget.SelectRows)
        table.setRowCount(len(results))
        table.setWordWrap(False)

        table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeToContents)
        table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeToContents)
        table.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeToContents)
        table.horizontalHeader().setSectionResizeMode(3, QHeaderView.ResizeToContents)
        table.horizontalHeader().setSectionResizeMode(4, QHeaderView.ResizeToContents)
        table.horizontalHeader().setSectionResizeMode(5, QHeaderView.Stretch)
        table.setColumnWidth(0, 90)
        table.setColumnWidth(1, 90)
        table.setColumnWidth(2, 100)
        table.setColumnWidth(3, 90)
        table.setColumnWidth(4, 100)

        for row, result in enumerate(results):
            label = result.get("label", "UNKNOWN")
            values = [
                label,
                str(result.get("malicious", 0)),
                str(result.get("suspicious", 0)),
                str(result.get("harmless", 0)),
                str(result.get("undetected", 0)),
                result.get("url", ""),
            ]

            for column, value in enumerate(values):
                item = QTableWidgetItem(value)
                if column == 0:
                    item.setForeground(QBrush(self.link_result_color(label)))
                if column == 5:
                    item.setToolTip(
                        f"{result.get('url', '')}\n\n{result.get('summary', '')}"
                    )
                table.setItem(row, column, item)

        buttons = QDialogButtonBox(QDialogButtonBox.Close)
        buttons.rejected.connect(dialog.reject)

        layout.addWidget(title)
        layout.addWidget(summary)
        layout.addWidget(table)
        layout.addWidget(buttons)

        dialog.exec()

    def show_link_scan_message(self, title: str, message: str):
        dialog = QDialog(self)
        dialog.setWindowTitle(title)
        dialog.resize(520, 260)

        layout = QVBoxLayout(dialog)
        title_label = QLabel(title.upper())
        title_label.setObjectName("SubPanelTitle")

        body = QTextEdit()
        body.setReadOnly(True)
        body.setPlainText(message)

        buttons = QDialogButtonBox(QDialogButtonBox.Close)
        buttons.rejected.connect(dialog.reject)

        layout.addWidget(title_label)
        layout.addWidget(body)
        layout.addWidget(buttons)

        dialog.exec()

    def link_result_color(self, label: str) -> QColor:
        if label == "RISK":
            return QColor("#ff6666")
        if label == "WARN":
            return QColor("#ffcc00")
        if label == "SAFE":
            return QColor("#00ff88")
        return QColor("#d8ffe8")

    def inject_link_safety_badges(self, results: list[dict]):
        results_json = json.dumps(results)
        script = f"""
        (() => {{
            const results = {results_json};
            const byUrl = new Map(results.map((result) => [result.url, result]));
            const colors = {{
                SAFE: {{ fg: '#001b0e', bg: '#00ff88', border: '#00ff88' }},
                WARN: {{ fg: '#1f1700', bg: '#ffcc00', border: '#ffcc00' }},
                RISK: {{ fg: '#240000', bg: '#ff6666', border: '#ff6666' }},
                UNKNOWN: {{ fg: '#d8ffe8', bg: '#203027', border: '#6f8f7d' }},
            }};

            document
                .querySelectorAll('.shadow-link-risk-badge')
                .forEach((badge) => badge.remove());

            Array.from(document.querySelectorAll('a[href]')).forEach((anchor) => {{
                const rawHref = anchor.getAttribute('href') || '';
                const result = byUrl.get(anchor.href) || byUrl.get(rawHref);
                if (!result) {{
                    return;
                }}

                const palette = colors[result.label] || colors.UNKNOWN;
                const badge = document.createElement('span');
                badge.className = 'shadow-link-risk-badge';
                badge.textContent = result.label;
                badge.title = result.summary;
                badge.style.display = 'inline-block';
                badge.style.marginLeft = '6px';
                badge.style.padding = '1px 5px';
                badge.style.border = `1px solid ${{palette.border}}`;
                badge.style.borderRadius = '3px';
                badge.style.background = palette.bg;
                badge.style.color = palette.fg;
                badge.style.fontSize = '10px';
                badge.style.fontWeight = '700';
                badge.style.lineHeight = '1.4';
                badge.style.verticalAlign = 'middle';
                badge.style.zIndex = '2147483647';

                anchor.insertAdjacentElement('afterend', badge);
            }});
        }})();
        """
        self.browser.page().runJavaScript(script)
            
    def add_network_row(
        self,
        method: str,
        url: str,
        resource_type: str,
        action: str,
        reason: str,
        first_party: str,
    ):
        if action == "BLOCKED":
            self.blocked_count += 1
        else:
            self.allowed_count += 1

        self.update_network_stats()

        row = self.network_table.rowCount()
        self.network_table.insertRow(row)
    
        now = QDateTime.currentDateTime().toString("HH:mm:ss.zzz")
        event = {
            "time": now,
            "ts": time.time(),
            "action": action,
            "method": method,
            "resource_type": resource_type,
            "reason": reason,
            "url": url,
            "first_party": first_party,
        }
        self.network_events.append(event)
        self.ai_engine.record_event(self.traffic_session_id, event)
        self.update_mitre_panel()

        values = [now, action, method, resource_type, reason, url]
        color = QColor("#ff6666") if action == "BLOCKED" else QColor("#00ff88")

        for column, value in enumerate(values):
            item = QTableWidgetItem(value)

            if column == 1:
                item.setForeground(QBrush(color))

            self.network_table.setItem(row, column, item)
    
        self.network_table.scrollToBottom()

    def update_mitre_panel(self):
        mappings = combine_mappings(
            map_header_findings(self.last_header_findings),
            map_network_events(self.network_events),
            map_link_scan_results(self.last_link_scan_results),
        )
        self.mitre_output.setPlainText(format_mitre_report(mappings))

    def analyze_current_traffic(self):
        report = self.ai_engine.analyze_session(self.traffic_session_id)
        lines = [
            report.summary,
            "",
            "Findings",
        ]

        if not report.findings:
            lines.append("  None")
        else:
            for finding in report.findings:
                lines.extend(
                    [
                        f"  [{finding.severity}] {finding.title} ({finding.score:.1f})",
                        f"    Model: {finding.model_score:.1f} | Rules: {finding.rule_score:.1f}",
                        f"    Reason: {finding.reason}",
                        f"    Evidence: {finding.evidence}",
                    ]
                )
                if finding.top_features:
                    lines.append(f"    Top features: {', '.join(finding.top_features)}")

        self.ai_output.setPlainText("\n".join(lines))
        self.security_dock.show()
        self.security_dock.raise_()

    def show_network_detail(self, row: int, column: int):
        if row < 0 or row >= len(self.network_events):
            return

        event = self.network_events[row]
        dialog = QDialog(self)
        dialog.setWindowTitle("Network Request Detail")
        dialog.resize(760, 560)

        layout = QVBoxLayout(dialog)
        title = QLabel("REQUEST DETAIL")
        title.setObjectName("SubPanelTitle")

        detail_output = QTextEdit()
        detail_output.setReadOnly(True)
        detail_output.setPlainText(self.format_network_detail(event))

        buttons = QDialogButtonBox(QDialogButtonBox.Close)
        buttons.rejected.connect(dialog.reject)

        layout.addWidget(title)
        layout.addWidget(detail_output)
        layout.addWidget(buttons)

        dialog.exec()

    def format_network_detail(self, event: dict) -> str:
        request_url = QUrl(event["url"])
        first_party_url = QUrl(event["first_party"])
        query = QUrlQuery(request_url)

        lines = [
            "Summary",
            f"  Time: {event['time']}",
            f"  Action: {event['action']}",
            f"  Reason: {event['reason'] or 'None'}",
            f"  Method: {event['method']}",
            f"  Resource Type: {event['resource_type']}",
            "",
            "Request URL",
            f"  Full URL: {event['url']}",
            f"  Scheme: {request_url.scheme() or 'N/A'}",
            f"  Host: {request_url.host() or 'N/A'}",
            f"  Port: {request_url.port() if request_url.port() != -1 else 'Default'}",
            f"  Path: {request_url.path() or '/'}",
            "",
            "First Party",
            f"  Full URL: {event['first_party'] or 'N/A'}",
            f"  Host: {first_party_url.host() or 'N/A'}",
            "",
            "Query Parameters",
        ]

        query_items = query.queryItems()
        if query_items:
            for key, value in query_items:
                lines.append(f"  {key}: {value}")
        else:
            lines.append("  None")

        lines.extend(
            [
                "",
                "Capture Note",
                "  QWebEngine exposes request metadata here, not raw TCP bytes,",
                "  request bodies, or response bodies.",
            ]
        )

        return "\n".join(lines)
