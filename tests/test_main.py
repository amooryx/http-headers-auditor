import argparse
import contextlib
import io
import sys
import threading
import unittest
from email.message import Message
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.error import URLError
from urllib.request import Request
from unittest.mock import Mock, patch

import main
import rclib


class TestHandler(BaseHTTPRequestHandler):
    server_version = "cloudflare"
    sys_version = ""

    def do_GET(self):
        if self.path.startswith("/chain/"):
            count = int(self.path.rsplit("/", 1)[1])
            too_many = self.path.startswith("/chain/too-many/")
            limit = main.MAX_REDIRECTS + (1 if too_many else 0)
            if count < limit:
                self.send_response(302)
                prefix = "/chain/too-many/" if too_many else "/chain/"
                self.send_header("Location", f"{prefix}{count + 1}")
                self.end_headers()
                return
        if self.path == "/redirect":
            self.send_response(302)
            self.send_header("Location", "/headers")
            self.end_headers()
            return
        if self.path == "/loop":
            self.send_response(302)
            self.send_header("Location", "/loop")
            self.end_headers()
            return
        self.send_response(200)
        csp = "frame-ancestors" if self.path == "/invalid-csp" else "default-src 'self'"
        self.send_header("Content-Security-Policy", csp)
        if self.path != "/invalid-csp":
            self.send_header("Content-Security-Policy", "frame-ancestors 'none'")
        self.send_header("Referrer-Policy", "strict-origin")
        self.send_header("Server", "cloudflare")
        self.send_header("Set-Cookie", "session=secret-value")
        self.end_headers()

    def log_message(self, format, *args):
        pass


class HeaderAuditTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = ThreadingHTTPServer(("127.0.0.1", 0), TestHandler)
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()
        cls.base_url = f"http://127.0.0.1:{cls.server.server_port}"

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.thread.join()

    def audit(self, target):
        ctx = rclib.Context(argparse.Namespace(), "test", target)
        output = io.StringIO()
        with contextlib.redirect_stdout(output), contextlib.redirect_stderr(output):
            result = main.run(ctx)
        return result, ctx, output.getvalue()

    def test_final_response_headers_and_frame_ancestors(self):
        result, ctx, output = self.audit(self.base_url + "/headers")
        finding_titles = [finding.title for finding in ctx.findings]

        self.assertEqual(result, 0)
        self.assertEqual(ctx.data["status"], 200)
        self.assertNotIn("Framing protection is missing", finding_titles)
        self.assertNotIn("Strict-Transport-Security is missing", finding_titles)
        self.assertIn("X-Content-Type-Options is missing or ineffective", finding_titles)
        self.assertEqual(len(ctx.data["headers"]["content-security-policy"]), 2)
        self.assertNotIn("set-cookie", ctx.data["headers"])
        self.assertNotIn("secret-value", output)
        self.assertNotIn("discloses a software version", " ".join(finding_titles))

    def test_redirect_is_followed_and_reported_as_final_response(self):
        result, ctx, _ = self.audit(self.base_url + "/redirect")

        self.assertEqual(result, 0)
        self.assertEqual(ctx.data["status"], 200)
        self.assertEqual(ctx.data["effective_url"], self.base_url)

    def test_redirect_limit_allows_five_hops_and_rejects_six(self):
        success, _, _ = self.audit(self.base_url + "/chain/0")
        failure, _, output = self.audit(self.base_url + "/chain/too-many/0")

        self.assertEqual(success, 0)
        self.assertEqual(failure, 1)
        self.assertIn("redirect", output)

    def test_redirect_loop_is_bounded_and_reported_as_failure(self):
        result, _, output = self.audit(self.base_url + "/loop")

        self.assertEqual(result, 1)
        self.assertIn("redirect", output)

    def test_https_downgrade_redirect_is_rejected(self):
        handler = main.SafeRedirectHandler()
        request = Request("https://example.test/")

        with self.assertRaises(URLError) as error:
            handler.redirect_request(request, None, 302, "Found", {}, "http://example.test/")

        self.assertIn("HTTPS-to-HTTP", str(error.exception))

    def test_request_has_a_timeout_and_verified_tls_context(self):
        class FakeResponse:
            headers = Message()

            def getcode(self):
                return 200

            def geturl(self):
                return "https://example.test/"

            def close(self):
                pass

        opener = Mock()
        opener.open.return_value = FakeResponse()
        with patch("main.urllib.request.build_opener", return_value=opener) as build_opener:
            result, _, _ = self.audit("https://example.test/")

        self.assertEqual(result, 0)
        request, = opener.open.call_args.args
        self.assertEqual(request.get_method(), "GET")
        self.assertEqual(opener.open.call_args.kwargs["timeout"], main.REQUEST_TIMEOUT)
        https_handler = next(
            handler for handler in build_opener.call_args.args
            if isinstance(handler, main.urllib.request.HTTPSHandler)
        )
        self.assertTrue(https_handler._context.check_hostname)
        self.assertEqual(https_handler._context.verify_mode, main.ssl.CERT_REQUIRED)

    def test_timeout_is_reported_as_a_failed_request(self):
        opener = Mock()
        opener.open.side_effect = TimeoutError("timed out")
        with patch("main.urllib.request.build_opener", return_value=opener):
            result, _, output = self.audit("https://example.test/")

        self.assertEqual(result, 1)
        self.assertIn("request failed: timed out", output)

    def test_ineffective_security_header_values_are_reported(self):
        class FakeResponse:
            headers = Message()

            def getcode(self):
                return 200

            def geturl(self):
                return "https://example.test/"

            def close(self):
                pass

        response = FakeResponse()
        response.headers["Strict-Transport-Security"] = "max-age=0"
        response.headers["X-Content-Type-Options"] = "sniff"
        response.headers["X-Frame-Options"] = "ALLOW-FROM https://example.test"
        opener = Mock()
        opener.open.return_value = response
        with patch("main.urllib.request.build_opener", return_value=opener):
            result, ctx, _ = self.audit("https://example.test/")

        self.assertEqual(result, 0)
        finding_titles = [finding.title for finding in ctx.findings]
        self.assertIn("Strict-Transport-Security is missing or ineffective", finding_titles)
        self.assertIn("X-Content-Type-Options is missing or ineffective", finding_titles)
        self.assertIn("Framing protection is missing or ineffective", finding_titles)

    def test_empty_frame_ancestors_directive_does_not_count_as_protection(self):
        _, ctx, _ = self.audit(self.base_url + "/invalid-csp")

        self.assertIn(
            "Framing protection is missing or ineffective",
            [finding.title for finding in ctx.findings],
        )

    def test_version_detection_requires_a_product_version_signature(self):
        self.assertIsNotNone(main.VERSION_RE.search("Apache/2.4.57"))
        self.assertIsNone(main.VERSION_RE.search("cloudflare"))
        self.assertIsNone(main.VERSION_RE.search("127.0.0.1"))

    def test_target_credentials_are_rejected(self):
        result, _, output = self.audit("https://user@example.test/")

        self.assertEqual(result, 1)
        self.assertIn("credentials in target URLs are not allowed", output)

    def test_cli_target_display_and_json_redact_url_path_and_query(self):
        result_data = {}

        def collect(ctx):
            result_data.update(ctx.to_json())
            return 0

        target = "https://example.test/private-path?token=secret-value"
        output = io.StringIO()
        with patch.object(sys, "argv", ["auditor", target, "--yes"]):
            with contextlib.redirect_stdout(output):
                result = rclib.main(
                    "test",
                    "test",
                    collect,
                    target_display=main._target_display,
                )

        self.assertEqual(result, 0)
        self.assertEqual(result_data["target"], "https://example.test")
        self.assertNotIn("secret-value", output.getvalue())
        self.assertNotIn("private-path", output.getvalue())


if __name__ == "__main__":
    unittest.main()
