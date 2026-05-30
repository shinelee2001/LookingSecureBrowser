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

## Run

```powershell
venv\Scripts\python.exe main.py
```

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
