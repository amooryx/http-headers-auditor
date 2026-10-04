import re
import ssl
import urllib.error
import urllib.parse
import urllib.request

import rclib


CHECKS = {
    "strict-transport-security": (
        "medium",
        "Strict-Transport-Security is missing or ineffective",
        "Set Strict-Transport-Security with an appropriate max-age on HTTPS responses.",
    ),
    "content-security-policy": (
        "medium",
        "Content-Security-Policy is missing",
        "Define an enforced Content-Security-Policy for the served content.",
    ),
    "x-content-type-options": (
        "low",
        "X-Content-Type-Options is missing or ineffective",
        "Set X-Content-Type-Options: nosniff.",
    ),
    "x-frame-options": (
        "low",
        "Framing protection is missing or ineffective",
        "Set X-Frame-Options or an enforced CSP frame-ancestors directive.",
    ),
    "referrer-policy": (
        "info",
        "Referrer-Policy is missing",
        "Set a Referrer-Policy appropriate for the site's privacy requirements.",
    ),
    "permissions-policy": (
        "info",
        "Permissions-Policy is missing",
        "Set a Permissions-Policy for browser features the site does not need.",
    ),
}

MAX_REDIRECTS = 5
REQUEST_TIMEOUT = 10
REDIRECT_STATUSES = {301, 302, 303, 307, 308}
REPORTED_HEADERS = tuple(CHECKS) + ("server", "x-powered-by")
VERSION_RE = re.compile(r"\b[A-Za-z][\w.-]*/v?\d+(?:\.\d+){0,3}\b")
HSTS_MAX_AGE_RE = re.compile(r"(?:^|;)\s*max-age\s*=\s*(\d+)\s*(?=;|$)", re.IGNORECASE)


def _validated_url(value):
    url = value if "://" in value else "https://" + value
    parsed = urllib.parse.urlsplit(url)
    if parsed.scheme.lower() not in ("http", "https") or not parsed.hostname:
        raise ValueError("target must be an HTTP or HTTPS URL with a hostname")
    if parsed.username is not None or parsed.password is not None:
        raise ValueError("credentials in target URLs are not allowed")
    parsed.port  # Validate malformed/out-of-range ports.
    return urllib.parse.urlunsplit(
        (parsed.scheme.lower(), parsed.netloc, parsed.path or "/", parsed.query, "")
    )


def _origin(url):
    parsed = urllib.parse.urlsplit(url)
    host = parsed.hostname or ""
    if ":" in host:
        host = f"[{host}]"
    port = parsed.port
    default_port = 443 if parsed.scheme == "https" else 80
    return f"{parsed.scheme}://{host}" + (f":{port}" if port and port != default_port else "")


def _target_display(value):
    try:
        return _origin(_validated_url(value))
    except (ValueError, UnicodeError):
        return "provided target"


class SafeRedirectHandler(urllib.request.HTTPRedirectHandler):
    def __init__(self):
        super().__init__()
        self.redirect_count = 0

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        try:
            destination = _validated_url(urllib.parse.urljoin(req.full_url, newurl))
        except ValueError as exc:
            raise urllib.error.URLError(str(exc)) from exc
        source_scheme = urllib.parse.urlsplit(req.full_url).scheme.lower()
        destination_scheme = urllib.parse.urlsplit(destination).scheme
        if source_scheme == "https" and destination_scheme != "https":
            raise urllib.error.URLError("refusing HTTPS-to-HTTP redirect")
        if self.redirect_count >= MAX_REDIRECTS:
            raise urllib.error.URLError("redirect limit exceeded")
        self.redirect_count += 1
        return super().redirect_request(req, fp, code, msg, headers, destination)


def _header_values(headers, name):
    if hasattr(headers, "get_all"):
        return headers.get_all(name, []) or []
    return [
        value for key, value in headers.items()
        if key.lower() == name
    ]


def _has_frame_ancestors(csp_values):
    for policy in csp_values:
        for directive in policy.split(";"):
            parts = directive.strip().split()
            if len(parts) > 1 and parts[0].lower() == "frame-ancestors":
                return True
    return False


def _header_is_effective(name, values):
    if not values or any(not value.strip() for value in values):
        return False
    if name == "strict-transport-security":
        if len(values) != 1:
            return False
        max_ages = HSTS_MAX_AGE_RE.findall(values[0])
        return len(max_ages) == 1 and int(max_ages[0]) > 0
    if name == "x-content-type-options":
        return len(values) == 1 and values[0].strip().lower() == "nosniff"
    if name == "x-frame-options":
        return len(values) == 1 and values[0].strip().lower() in ("deny", "sameorigin")
    return True


def run(ctx):
    try:
        url = _validated_url(ctx.target)
        opener = urllib.request.build_opener(
            SafeRedirectHandler(),
            urllib.request.HTTPSHandler(context=ssl.create_default_context()),
        )
        request = urllib.request.Request(url, headers={"User-Agent": "http-headers-auditor/1.0"})
        try:
            response = opener.open(request, timeout=REQUEST_TIMEOUT)
        except urllib.error.HTTPError as exc:
            if exc.code in REDIRECT_STATUSES:
                raise urllib.error.URLError("redirect could not be safely followed") from exc
            response = exc
        try:
            status = response.getcode()
            final_url = response.geturl()
            headers = response.headers
        finally:
            response.close()
    except (urllib.error.URLError, OSError, ValueError) as exc:
        reason = getattr(exc, "reason", None)
        message = str(reason) if isinstance(reason, (str, TimeoutError)) else str(exc)
        ctx.err(f"request failed: {message}")
        return 1

    effective_origin = _origin(final_url)
    final_scheme = urllib.parse.urlsplit(final_url).scheme
    reported = {
        name: [str(value).strip()[:1024] for value in _header_values(headers, name)
               if str(value).strip()]
        for name in REPORTED_HEADERS
    }
    reported = {name: values for name, values in reported.items() if values}

    ctx.info(f"Audited {effective_origin} (HTTP {status})")
    for name, (severity, title, recommendation) in CHECKS.items():
        if name == "strict-transport-security" and final_scheme != "https":
            continue
        if _header_is_effective(name, reported.get(name, [])):
            continue
        if name == "x-frame-options" and _has_frame_ancestors(
            _header_values(headers, "content-security-policy")
        ):
            continue
        ctx.finding(title, severity, detail=recommendation, header=name)

    if final_scheme != "https":
        ctx.info("HSTS was not evaluated because the final response used HTTP.")

    for name in ("server", "x-powered-by"):
        for value in reported.get(name, []):
            if VERSION_RE.search(value):
                ctx.finding(
                    f"{name.title()} header discloses a software version",
                    "info",
                    detail="Remove or minimize version details in this response header.",
                    header=name,
                    value=value,
                )

    ctx.data.update({
        "status": status,
        "effective_url": effective_origin,
        "headers": reported,
    })
    return 0


if __name__ == "__main__":
    rclib.main(
        "http-headers-auditor",
        "HTTP security-header posture audit",
        run,
        target_display=_target_display,
    )
