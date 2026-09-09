import urllib.request, urllib.error, ssl, rclib

CHECKS = {
 "strict-transport-security": ("medium","HSTS missing — downgrade not prevented"),
 "content-security-policy": ("medium","No CSP — main XSS defence-in-depth absent"),
 "x-content-type-options": ("low","MIME sniffing not disabled"),
 "x-frame-options": ("low","Clickjacking framing not restricted"),
 "referrer-policy": ("info","Referrer-Policy not set"),
 "permissions-policy": ("info","Permissions-Policy not set"),
}

def run(ctx):
    url = ctx.target if "://" in ctx.target else "https://" + ctx.target
    ctx.info(f"GET {url}")
    ctx.info = ctx.info
    try:
        req = urllib.request.Request(url, headers={"User-Agent":"redcell/hdr"})
        r = urllib.request.urlopen(req, timeout=15, context=ssl.create_default_context())
        headers = {k.lower(): v for k, v in r.headers.items()}
    except urllib.error.HTTPError as e:
        headers = {k.lower(): v for k, v in e.headers.items()}
    except Exception as e:
        ctx.err(f"request failed: {e}"); return 1
    csp = headers.get("content-security-policy","")
    for h,(sev,msg) in CHECKS.items():
        if h in headers: continue
        if h=="x-frame-options" and "frame-ancestors" in csp: continue
        ctx.finding(msg, sev, detail=h)
    srv = headers.get("server","")
    if srv and any(c.isdigit() for c in srv):
        ctx.finding("Server header discloses version", "info", detail=srv)
    ctx.data["headers"] = headers
    return 0

rclib.main("http-headers-auditor", "HTTP security-header posture audit", run)
