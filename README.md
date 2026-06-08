# LookingSecureBrowser

Security-focused Python web browser prototype built with PySide6 and Qt WebEngine.

![ShadowBrowser screenshot](docs/browser.png)

## Features

- Basic web browsing with back, forward, reload, and URL navigation
- Security header scan with score and grade
- Network traffic console with per-page request history
- Optional request blocking for tracker-like URLs and mixed HTTP subresources
- Double-click request details in the network table
- VirusTotal-based link safety scan for `http://` and `https://` page links
- MITRE ATT&CK candidate mapping for observed header, network, and risky-link signals
- Local SQLite-backed traffic history for lightweight browser request analysis
- Unsupervised AI traffic analysis with optional `scikit-learn` IsolationForest
- Template explanation engine for suspicious request summaries and next steps

## Run

```powershell
venv\Scripts\python.exe main.py
```

For the optional unsupervised ML model:

```powershell
venv\Scripts\python.exe -m pip install -e .[ai]
```

Without `scikit-learn`, ShadowBrowser falls back to a lightweight local baseline analyzer.

## Local Traffic AI Engine

The `AI ANALYZE` button runs analysis on the current page session. Request metadata is stored locally in `data/traffic_ai.sqlite` with a short retention policy and an event cap. The store keeps hashes, domains, paths, and extracted features instead of raw request bodies, cookies, or authorization headers.

Current engine layers:

- SQLite event store with retention cleanup
- Feature extraction for URL length, entropy, query counts, third-party status, tracker hints, and HTTP usage
- Rule signals for insecure third-party requests, sensitive query names, suspicious URL keywords, and bursts
- `scikit-learn` IsolationForest anomaly detection with StandardScaler normalization, model anomaly scores, and top contributing feature hints
- Explanation output designed to be replaceable later with a local LLM provider such as Ollama or llama.cpp

## VirusTotal API

Link scanning requires a VirusTotal API key.
The free public API is limited and should not be used for business workflows, commercial products, or services.
ShadowBrowser handles it conservatively: one `SCAN LINKS` run submits up to 2 URLs because each URL scan uses about 2 lookups and the free rate is 4 lookups/minute.

Create a local `.env` file:

```env
VIRUSTOTAL_API_KEY=your_api_key_here
```

`.env` is ignored by git. Use `.env.example` as the template.

## Status

Early MVP. More detailed documentation and screenshots will be added later.
