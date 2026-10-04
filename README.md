<div align="center">
  <img src="./banner.svg" alt="http-headers-auditor" width="800">
</div>

# HTTP Security Headers Auditor

A small, dependency-free command-line tool that requests an HTTP(S) URL and reports selected security headers from the final response. It checks header presence, recognizes CSP `frame-ancestors` as a framing control, and reports software versions explicitly exposed by `Server` or `X-Powered-By`.

The audit uses the final response only. HSTS is evaluated only for HTTPS responses; an HTTP response cannot establish HSTS. This tool checks response posture, not whether a policy is sufficiently restrictive or correct for a particular application.

## Requirements

- Python 3.10 or newer
- No third-party packages

## Usage

```text
python main.py [options] target
```

For example:

```bash
python main.py https://example.com
python main.py example.com --output report.json
python main.py --yes --quiet https://example.com
```

The tool asks for authorization before making a request unless `--yes` is supplied. `--output` writes a JSON report and `--quiet` suppresses the banner and summary. The report contains the response status, effective origin, audited headers, and findings. It deliberately excludes cookies and other unexamined response headers.

Requests use Python's default certificate and hostname verification, a 10-second timeout, and at most five redirects. HTTPS-to-HTTP redirects and redirects to unsupported URL schemes are rejected. The request does not forward credentials or custom headers.

## Offline tests

Run the test suite without network access:

```bash
python -m unittest discover -s tests -v
```

## Authorization

Use only on systems you own or have explicit permission to assess. The tool makes a single GET request, plus any permitted redirects; it does not exploit findings or modify the target.
