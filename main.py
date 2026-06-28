#!/usr/bin/env python3
"""
HTTP Security Headers Auditor - by amooryx
Audit, score, and report HTTP security headers for one or many targets.
"""

import sys
import json
import argparse
import csv
import time
from typing import Dict, List, Optional, Tuple
from datetime import datetime
from urllib.parse import urlparse

try:
    import requests
    requests.packages.urllib3.disable_warnings()
except ImportError:
    print("[!] Missing dep: pip install requests")
    sys.exit(1)

BANNER = r"""
  __  __               __         ___               ___ __            
 / / / /__  ____ _____/ /__  ____|__ \   ____ ___  / _// /_____  _____
/ /_/ / _ \/ __ `/ __  / _ \/ ___/_/ /  / __ `__ \/ /_ / __/ _ \/ ___/
/ __ /  __/ /_/ / /_/ /  __/ /  / __/  / / / / / / __// /_/  __/ /    
/_/ /_/\___/\__,_/\__,_/\___/_/  /____/ /_/ /_/ /_/_/   \__/\___/_/    

  HTTP Security Headers Auditor v1.0 | by amooryx
"""

# ─────────────────────────────────────────────
#  Header Definitions
# ─────────────────────────────────────────────

HEADERS_SPEC = {
    "Strict-Transport-Security": {
        "weight": 10,
        "description": "Enforces HTTPS connections",
        "recommended": "max-age=31536000; includeSubDomains; preload",
        "check": lambda v: "max-age" in v.lower() and int(
            [x.split("=")[1] for x in v.split(";") if "max-age" in x.lower()][0].strip()
        ) >= 31536000 if v else False,
        "warn": lambda v: "preload" not in v.lower() if v else True,
    },
    "Content-Security-Policy": {
        "weight": 15,
        "description": "Controls resources the browser is allowed to load",
        "recommended": "default-src 'self'; script-src 'self'; object-src 'none'",
        "check": lambda v: bool(v) and "default-src" in v,
        "warn": lambda v: any(bad in v for bad in ["unsafe-inline", "unsafe-eval", "*"]) if v else True,
    },
    "X-Content-Type-Options": {
        "weight": 5,
        "description": "Prevents MIME type sniffing",
        "recommended": "nosniff",
        "check": lambda v: v and v.strip().lower() == "nosniff",
        "warn": lambda v: False,
    },
    "X-Frame-Options": {
        "weight": 8,
        "description": "Protects against clickjacking",
        "recommended": "DENY",
        "check": lambda v: v and v.strip().upper() in ["DENY", "SAMEORIGIN"],
        "warn": lambda v: v and "ALLOW-FROM" in v.upper(),
    },
    "Referrer-Policy": {
        "weight": 5,
        "description": "Controls referrer information in requests",
        "recommended": "strict-origin-when-cross-origin",
        "check": lambda v: v and v.strip().lower() in [
            "no-referrer", "strict-origin", "strict-origin-when-cross-origin",
            "same-origin", "no-referrer-when-downgrade"
        ],
        "warn": lambda v: v and v.strip().lower() in ["unsafe-url", "origin"] if v else True,
    },
    "Permissions-Policy": {
        "weight": 6,
        "description": "Controls browser features and APIs",
        "recommended": "geolocation=(), microphone=(), camera=()",
        "check": lambda v: bool(v),
        "warn": lambda v: False,
    },
    "X-XSS-Protection": {
        "weight": 3,
        "description": "Legacy XSS filter (deprecated but common)",
        "recommended": "0 (disable legacy filter; rely on CSP instead)",
        "check": lambda v: v is not None,
        "warn": lambda v: v and v.strip() not in ["0", "1; mode=block"],
    },
    "Cache-Control": {
        "weight": 4,
        "description": "Controls caching of sensitive responses",
        "recommended": "no-store, no-cache (for sensitive endpoints)",
        "check": lambda v: bool(v),
        "warn": lambda v: v and "public" in v.lower() if v else False,
    },
    "Cross-Origin-Opener-Policy": {
        "weight": 5,
        "description": "Isolates browsing context from cross-origin documents",
        "recommended": "same-origin",
        "check": lambda v: bool(v),
        "warn": lambda v: False,
    },
    "Cross-Origin-Resource-Policy": {
        "weight": 4,
        "description": "Controls which origins can load the resource",
        "recommended": "same-origin",
        "check": lambda v: bool(v),
        "warn": lambda v: False,
    },
}

BAD_HEADERS = {
    "Server": "Reveals server software and version",
    "X-Powered-By": "Reveals backend technology",
    "X-AspNet-Version": "Reveals ASP.NET version",
    "X-AspNetMvc-Version": "Reveals ASP.NET MVC version",
    "X-Generator": "Reveals CMS or framework",
}

# ─────────────────────────────────────────────
#  Auditor
# ─────────────────────────────────────────────

def fetch_headers(url: str, timeout: int = 10) -> Tuple[Optional[Dict], int, float]:
    if not url.startswith("http"):
        url = "https://" + url
    try:
        start = time.time()
        r = requests.get(url, timeout=timeout, verify=False, allow_redirects=True)
        elapsed = time.time() - start
        return dict(r.headers), r.status_code, elapsed
    except requests.exceptions.ConnectionError:
        print(f"  [!] Could not connect to {url}")
    except requests.exceptions.Timeout:
        print(f"  [!] Timeout connecting to {url}")
    except Exception as e:
        print(f"  [!] Error: {e}")
    return None, 0, 0


def audit_url(url: str, timeout: int = 10) -> Dict:
    if not url.startswith("http"):
        url = "https://" + url

    print(f"\n{'─'*60}")
    print(f"  Target: {url}")
    print(f"{'─'*60}")

    headers, status, elapsed = fetch_headers(url, timeout)
    if headers is None:
        return {"url": url, "error": "unreachable", "score": 0}

    print(f"  HTTP Status : {status}")
    print(f"  Response    : {elapsed:.2f}s")

    # Normalize header keys to title case for lookup
    normalized = {k.title(): v for k, v in headers.items()}

    total_weight = sum(spec["weight"] for spec in HEADERS_SPEC.values())
    earned = 0
    findings = []

    print(f"\n  {'Header':<40} {'Status':<12} {'Note'}")
    print(f"  {'─'*38} {'─'*10} {'─'*30}")

    for hname, spec in HEADERS_SPEC.items():
        value = normalized.get(hname)
        present = value is not None
        valid = spec["check"](value) if present else False
        warned = spec["warn"](value) if present else False

        if valid and not warned:
            status_str = "✓ GOOD"
            earned += spec["weight"]
            note = ""
        elif present and warned:
            status_str = "⚠ WEAK"
            earned += spec["weight"] // 2
            note = "value needs improvement"
        elif present and not valid:
            status_str = "✗ INVALID"
            note = "header present but misconfigured"
        else:
            status_str = "✗ MISSING"
            note = f"recommended: {spec['recommended'][:40]}"

        print(f"  {hname:<40} {status_str:<12} {note}")
        findings.append({
            "header": hname,
            "present": present,
            "valid": valid,
            "warned": warned,
            "value": value,
            "recommended": spec["recommended"],
            "description": spec["description"],
        })

    # Info-leaking headers
    print(f"\n  {'─'*60}")
    print("  Information Disclosure Headers:")
    leaking = []
    for h, reason in BAD_HEADERS.items():
        val = normalized.get(h)
        if val:
            print(f"  [!!!] {h}: {val} → {reason}")
            leaking.append({"header": h, "value": val, "reason": reason})
        else:
            print(f"  [+]  {h}: not present")

    # Score
    score = round((earned / total_weight) * 100)
    grade = score_to_grade(score)

    print(f"\n  {'─'*60}")
    print(f"  Score : {score}/100  |  Grade: {grade}")
    print(f"  {'─'*60}")

    return {
        "url": url,
        "http_status": status,
        "response_time": round(elapsed, 3),
        "score": score,
        "grade": grade,
        "findings": findings,
        "leaking_headers": leaking,
        "timestamp": datetime.utcnow().isoformat(),
    }


def score_to_grade(score: int) -> str:
    if score >= 90: return "A+"
    if score >= 80: return "A"
    if score >= 70: return "B"
    if score >= 60: return "C"
    if score >= 50: return "D"
    return "F"


# ─────────────────────────────────────────────
#  Output Formats
# ─────────────────────────────────────────────

def save_json(results: List[Dict], path: str):
    with open(path, "w") as f:
        json.dump(results, f, indent=2)
    print(f"\n[+] JSON report saved: {path}")


def save_csv(results: List[Dict], path: str):
    rows = []
    for r in results:
        base = {
            "url": r.get("url"),
            "score": r.get("score"),
            "grade": r.get("grade"),
            "http_status": r.get("http_status"),
            "response_time": r.get("response_time"),
        }
        for f in r.get("findings", []):
            row = {**base, "header": f["header"], "present": f["present"],
                   "valid": f["valid"], "value": f.get("value", "")}
            rows.append(row)

    if not rows:
        return

    with open(path, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=rows[0].keys())
        writer.writeheader()
        writer.writerows(rows)
    print(f"[+] CSV report saved: {path}")


def save_markdown(results: List[Dict], path: str):
    lines = ["# HTTP Security Headers Audit Report\n",
             f"Generated: {datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')}\n"]

    for r in results:
        lines.append(f"\n## {r.get('url', 'Unknown')}\n")
        lines.append(f"- **Score:** {r.get('score')}/100 ({r.get('grade')})\n")
        lines.append(f"- **HTTP Status:** {r.get('http_status')}\n")
        lines.append(f"- **Response Time:** {r.get('response_time')}s\n")
        lines.append("\n### Security Headers\n")
        lines.append("| Header | Status | Value |\n|---|---|---|\n")
        for f in r.get("findings", []):
            status = "✓" if f["valid"] and not f["warned"] else ("⚠" if f["warned"] else "✗")
            val = (f.get("value") or "-")[:60]
            lines.append(f"| {f['header']} | {status} | `{val}` |\n")

        if r.get("leaking_headers"):
            lines.append("\n### Information Disclosure\n")
            for lh in r["leaking_headers"]:
                lines.append(f"- **{lh['header']}**: `{lh['value']}` → {lh['reason']}\n")

    with open(path, "w") as f:
        f.writelines(lines)
    print(f"[+] Markdown report saved: {path}")


# ─────────────────────────────────────────────
#  CLI
# ─────────────────────────────────────────────

def main():
    print(BANNER)

    parser = argparse.ArgumentParser(
        description="HTTP Security Headers Auditor — score and report security headers",
        formatter_class=argparse.RawTextHelpFormatter
    )
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("-u", "--url", help="Single target URL")
    group.add_argument("-l", "--list", help="File containing URLs (one per line)")

    parser.add_argument("--json", help="Save JSON report to file")
    parser.add_argument("--csv", help="Save CSV report to file")
    parser.add_argument("--md", help="Save Markdown report to file")
    parser.add_argument("--timeout", type=int, default=10, help="Request timeout in seconds (default: 10)")

    args = parser.parse_args()

    urls = []
    if args.url:
        urls = [args.url]
    elif args.list:
        try:
            with open(args.list) as f:
                urls = [line.strip() for line in f if line.strip()]
        except FileNotFoundError:
            print(f"[!] File not found: {args.list}")
            sys.exit(1)

    results = []
    for url in urls:
        result = audit_url(url, args.timeout)
        results.append(result)

    # Summary table
    if len(results) > 1:
        print(f"\n{'═'*60}")
        print("  SUMMARY")
        print(f"{'═'*60}")
        print(f"  {'URL':<45} {'Score':<8} Grade")
        print(f"  {'─'*43} {'─'*6} {'─'*5}")
        for r in results:
            print(f"  {r['url'][:44]:<45} {r.get('score', 0):<8} {r.get('grade', 'N/A')}")

    if args.json:
        save_json(results, args.json)
    if args.csv:
        save_csv(results, args.csv)
    if args.md:
        save_markdown(results, args.md)

    print("\n[*] Done.")


if __name__ == "__main__":
    main()
