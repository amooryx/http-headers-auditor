# HTTP Security Headers Auditor

An automated script to scan server responses, verify HTTP security header compliance, and output structured security reports.

## 📋 Features

- **Security Header Auditing**: Checks for critical headers such as `Content-Security-Policy`, `Strict-Transport-Security`, `X-Frame-Options`, `X-Content-Type-Options`, and `Referrer-Policy`.
- **Compliance Scoring**: Calculates a security score based on header presence and configuration strength.
- **Verbose Leak Check**: Detects headers exposing server versions or framework signatures (`Server`, `X-Powered-By`).
- **Structured Export**: Outputs findings in clean JSON, Markdown, or HTML.

## ⚙️ Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/amooryx/http-headers-auditor.git
   cd http-headers-auditor
   ```

2. Install dependencies:
   ```bash
   pip install requests
   ```

## 🚀 Usage

Scan a single target domain:

```bash
python main.py -d target.com
```

Save report to a JSON file:

```bash
python main.py -d target.com -o report.json
```

## 🛡️ Disclaimer

This tool is designed for educational and security compliance auditing purposes only. Ensure you have authorized permission prior to running scans against active environments.
