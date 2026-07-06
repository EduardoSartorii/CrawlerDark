# AGENTS.md

## Cursor Cloud specific instructions

### What this is
Crawler News (a.k.a. Vigilant Onion) is a Python 3.12 dark-web crawler. It drives
headless Firefox (via `geckodriver`) through the TOR SOCKS proxy to scrape ransomware
leak `.onion` sites, dedups findings in a local sqlite DB, screenshots + OCRs pages
(`pytesseract`), and pushes results to a MISP instance (`pymisp`).
Entry point: `python main.py -f onion` (also `-f all`). It runs in an infinite `while True` loop.

### Dependencies / how to run
- Python deps live in a virtualenv at `.venv` (gitignored). Run the app as `.venv/bin/python main.py -f onion`.
- Pins matter: `selenium<4` (the code uses the removed `firefox_profile=`/`executable_path=` kwargs and `webdriver.FirefoxProfile`) and `urllib3<2` (selenium 3.141 is incompatible with urllib3 2.x's timeout sentinel and raises `ValueError: Timeout value connect was <object ...>`). See `requirements.txt`.

### TOR must be running first (SOCKS 127.0.0.1:9050)
Start it before running the crawler: `tor` (bootstraps to 100% in ~30s; leave it running).
- Gotcha: if `tor` dies immediately with `symbol lookup error: undefined symbol: evutil_secure_rng_add_bytes`, a polluted `LD_PRELOAD`/`LD_LIBRARY_PATH` shadowed libevent. Start it with a clean env: `env -u LD_PRELOAD -u LD_LIBRARY_PATH tor`.

### Browser / driver (non-obvious)
- Firefox is installed at `/opt/firefox` (symlinked to `/usr/local/bin/firefox`). The apt `firefox` package is snap-only and does not work in this container.
- The bundled `utils/webdriver/geckodriver` is a 32-bit i386 binary and will NOT run on this x86_64 host. A working x86_64 geckodriver is installed at `/usr/local/bin/geckodriver`. To run `main.py` as-is, point `webdriver_path` in `utils/config/config.yml` to `/usr/local/bin/geckodriver` (or replace the bundled binary).

### MISP is required for a full run
`main.py` builds the framework objects at startup, and each one instantiates
`frameworks/mispadd.py`, which immediately connects to a MISP server using the placeholder
credentials `URL-DO-MISP` / `CHAVE-DO-MISP`. Startup therefore fails at the MISP handshake
until you edit `frameworks/mispadd.py` (and the event id) with a real MISP URL + API key, as
described in the README. Everything else (config, sqlite dedup, Selenium+TOR fetch,
BeautifulSoup parse, OCR) works without MISP.

### Tests / lint
No automated test suite or linter is configured. Use `.venv/bin/python -m py_compile main.py frameworks/*.py` as a syntax check.
