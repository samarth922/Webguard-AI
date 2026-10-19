# WebGuard AI

A beginner-friendly, local-first website security checker built with Python and Streamlit. It performs a small set of low-impact checks and generates HTML/JSON reports.

> **Authorization required:** Only scan websites you own or have explicit permission to assess. This starter project does not run exploit payloads or attempt to bypass authentication.

## Features

- Simple browser-based local dashboard
- Limited same-origin page discovery
- Low request rate and bounded response reads
- Checks for common security headers, starting HTTP URL, and possible cookie attributes
- HTML and JSON report downloads
- Basic protection against localhost/private IP targets and cross-origin crawling

## Limitations

This is an educational starter project, **not** a full penetration-testing tool. It does not test SQL injection, XSS exploitability, authentication, access control, or business logic. Missing headers do not automatically mean a site is exploitable. A clean report is not proof of security.

## Requirements

- Python 3.10 or newer
- Internet access for checking a public target
- A computer running Windows, macOS, or Linux

## Install and run

### Windows

1. Install Python from https://www.python.org/downloads/ and enable **Add Python to PATH**.
2. Download or clone this repository.
3. Open a terminal in the project folder.
4. Run:

```bash
py -m venv .venv
.venv\Scripts\activate
python -m pip install -r requirements.txt
streamlit run app.py
```

### macOS / Linux

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
streamlit run app.py
```

The app opens in your browser, usually at `http://localhost:8501`.

## Install on Android using Termux

This is possible but may require troubleshooting because some Python packages and network features vary by device.

1. Install Termux from its official F-Droid or GitHub distribution.
2. In Termux, run:

```bash
pkg update
pkg install python git
git clone https://github.com/YOUR-USERNAME/WebGuard-AI.git
cd WebGuard-AI
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
streamlit run app.py --server.address 127.0.0.1
```

3. Open `http://127.0.0.1:8501` in your phone browser.

Replace `YOUR-USERNAME` with your GitHub username. If installation fails on Android, use a PC or a Linux environment; this project does not promise compatibility with every phone.

## Push to GitHub from a phone browser

You can publish the files without a computer:

1. Sign in at https://github.com/ and create a **new public repository** named `WebGuard-AI`.
2. Open the new repository and choose **Add file → Upload files**.
3. Upload the project files and folders from the extracted ZIP. If mobile upload is difficult, use GitHub's browser editor to add files individually.
4. Enter a commit message such as `Add WebGuard AI starter project` and commit the files.
5. Replace `YOUR-USERNAME` in the clone command above with your actual GitHub username.

For large edits or future development, a Git client or Termux can be more convenient. Never upload API keys, passwords, session cookies, private scan reports, or `.env` files.

## Safety design

- Acknowledgement of authorization is required in the UI.
- The crawler is limited to the starting origin and a small page count.
- Requests have timeouts, a delay, and a bounded response size.
- Local/private IP targets are blocked in this starter version.
- Redirects are not followed automatically.

These are starter safeguards, not a substitute for a hardened security boundary. DNS rebinding, unusual network configurations, proxy behavior, and other edge cases may require additional protections before deployment to untrusted users.

## Development checks

```bash
python -m pytest
```

## Roadmap

- Add unit tests and CI
- Optional OWASP ZAP integration for explicitly scoped targets
- Authentication-aware tests using dedicated test accounts
- More robust DNS/IP validation and redirect handling
- Better severity scoring and deduplication
- Optional AI explanations with user-supplied credentials stored locally

## License

MIT. See `LICENSE`.
