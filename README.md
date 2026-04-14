# WebScan

Python CLI tool for **website security and configuration checks**: sensitive paths, TLS, headers, CORS, WAF hints, tech fingerprinting, basic XSS/SSRF-style signals, WordPress probes, Supabase patterns, and more. Optional crawl, JSON/HTML reports, proxies, and rate limiting.

**Use only on systems you own or have explicit permission to test.** Unauthorized scanning may be illegal.

## Requirements

- Python 3.x  
- Dependencies: see [`requirements.txt`](requirements.txt) (`requests`, `beautifulsoup4`, `colorama`, SOCKS extras for `requests`).

## Install

```bash
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
```

On macOS/Linux, activate with `source .venv/bin/activate`.

## Usage

```bash
python webscan.py https://example.com
```

### Common options

| Option | Description |
|--------|-------------|
| `--crawl` | Crawl linked pages |
| `--depth N` | Crawl depth (default `1`) |
| `--threads N` | Concurrent probes (default `10`) |
| `--rate-limit SECS` | Delay between requests |
| `--timeout SECS` | Request timeout (default `10`) |
| `--proxy URL` | HTTP, HTTPS, or SOCKS proxy |
| `--no-ssl-verify` | Skip TLS certificate verification |
| `--user-agent UA` | Custom User-Agent |
| `--min-severity LEVEL` | Filter findings (`CRITICAL` … `INFO`) |
| `--output FILE` | Write JSON report |
| `--output-html FILE` | Write HTML report |
| `--verbose` | More console output |
| `--no-internal-probes` | Disable some internal checks |
| `--no-link-check` | Skip optional internal link HEAD checks |
| `--link-check-max N` | Max links to check (default `15`) |

### Examples

```bash
python webscan.py https://example.com --crawl --depth 2
python webscan.py https://example.com --proxy socks5://127.0.0.1:1080
python webscan.py https://example.com --threads 20 --rate-limit 0.2
python webscan.py https://example.com --output report.json --output-html report.html
python webscan.py https://example.com --min-severity HIGH --no-ssl-verify
```

## What it checks (overview)

Proxy support, concurrent sensitive-file probing, JavaScript/source-map hints, WAF detection, CMS/tech fingerprinting, TLS 1.0/1.1, SRI, CORS (including reflected/null origin), host-header and CRLF injection probes, GraphQL introspection, WordPress-focused checks, error-page disclosure, reflected parameters, SSRF-prone parameter names, email harvesting, Supabase-related patterns, health/debug routes, `.well-known`, redirects, performance signals, and basic frontend sanity (title, `h1`, canonical, etc.).

For the full, authoritative list and behavior, see the module docstring at the top of [`webscan.py`](webscan.py).
