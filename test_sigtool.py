from __future__ import annotations

import base64
import contextlib
import hashlib
import hmac
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import io
import json
from pathlib import Path
import threading
import unittest

from sigtool import (
    generate_signature,
    inspect_payload,
    main,
    verify_signature,
)


SAMPLE_PATH = Path(__file__).parent / "sample_payload.json"


class TestWebhookHmacSigTool(unittest.TestCase):
    def test_github_sign_and_verify(self) -> None:
        payload = SAMPLE_PATH.read_bytes()
        secret = "gh_whsec_super_secret_123"

        expected_hex = hmac.new(
            secret.encode("utf-8"), payload, hashlib.sha256
        ).hexdigest()

        gen = generate_signature(payload, secret, provider="github")
        self.assertEqual(gen.provider, "github")
        self.assertEqual(gen.encoding, "hex")
        self.assertEqual(gen.header_name, "X-Hub-Signature-256")
        self.assertEqual(gen.header_value, f"sha256={expected_hex}")

        ok = verify_signature(payload, secret, gen.header_value, provider="github")
        self.assertTrue(ok.valid)
        self.assertTrue(ok.signature_matched)

        # Case-insensitive hex after sha256=
        ok_upper = verify_signature(
            payload, secret, f"sha256={expected_hex.upper()}", provider="github"
        )
        self.assertTrue(ok_upper.valid)

        # Missing prefix fails
        bad_prefix = verify_signature(payload, secret, expected_hex, provider="github")
        self.assertFalse(bad_prefix.valid)
        self.assertFalse(bad_prefix.signature_matched)

        # Tampered payload fails
        tampered = verify_signature(
            payload + b" ", secret, gen.header_value, provider="github"
        )
        self.assertFalse(tampered.valid)
        self.assertFalse(tampered.signature_matched)

    def test_stripe_sign_verify_and_replay_tolerance(self) -> None:
        payload = SAMPLE_PATH.read_bytes()
        secret = "whsec_stripe_testing_key"
        signed_ts = 1763520000

        signed_input = f"{signed_ts}.".encode("utf-8") + payload
        expected_v1 = hmac.new(
            secret.encode("utf-8"), signed_input, hashlib.sha256
        ).hexdigest()

        gen = generate_signature(
            payload, secret, provider="stripe", timestamp=signed_ts
        )
        self.assertEqual(gen.header_name, "Stripe-Signature")
        self.assertEqual(gen.timestamp, signed_ts)
        self.assertEqual(gen.header_value, f"t={signed_ts},v1={expected_v1}")

        # Valid within tolerance (120s <= 300s)
        res_ok = verify_signature(
            payload,
            secret,
            gen.header_value,
            provider="stripe",
            now=signed_ts + 120,
            tolerance_seconds=300,
        )
        self.assertTrue(res_ok.valid)
        self.assertTrue(res_ok.signature_matched)
        self.assertTrue(res_ok.timestamp_valid)
        self.assertEqual(res_ok.timestamp_age_seconds, 120)

        # Key rotation: multiple v1 entries where second matches
        multi_sig = f"t={signed_ts},v1={'0' * 64},v1={expected_v1}"
        res_multi = verify_signature(
            payload,
            secret,
            multi_sig,
            provider="stripe",
            now=signed_ts + 5,
            tolerance_seconds=300,
        )
        self.assertTrue(res_multi.valid)
        self.assertTrue(res_multi.signature_matched)

        # Expired beyond replay window (301s > 300s)
        res_expired = verify_signature(
            payload,
            secret,
            gen.header_value,
            provider="stripe",
            now=signed_ts + 301,
            tolerance_seconds=300,
        )
        self.assertFalse(res_expired.valid)
        self.assertTrue(res_expired.signature_matched)
        self.assertFalse(res_expired.timestamp_valid)

        # Disabled replay tolerance allows old timestamp if crypto matches
        res_ignored = verify_signature(
            payload,
            secret,
            gen.header_value,
            provider="stripe",
            now=signed_ts + 999999,
            tolerance_seconds=None,
        )
        self.assertTrue(res_ignored.valid)
        self.assertTrue(res_ignored.timestamp_valid)

    def test_shopify_and_generic_hex_base64(self) -> None:
        payload = b'{"order_id":98123,"total_price":"149.00","currency":"USD"}'
        secret = "shpss_secret_key_xyz"

        raw_digest = hmac.new(
            secret.encode("utf-8"), payload, hashlib.sha256
        ).digest()
        expected_b64 = base64.b64encode(raw_digest).decode("ascii")
        expected_hex = raw_digest.hex()

        # Shopify
        shop = generate_signature(payload, secret, provider="shopify")
        self.assertEqual(shop.header_name, "X-Shopify-Hmac-Sha256")
        self.assertEqual(shop.header_value, expected_b64)
        self.assertTrue(
            verify_signature(payload, secret, shop.header_value, provider="shopify").valid
        )
        # Base64 must remain case-sensitive
        self.assertFalse(
            verify_signature(
                payload, secret, shop.header_value.swapcase(), provider="shopify"
            ).valid
        )

        # Generic hex & base64 with custom header
        gen_hex = generate_signature(
            payload,
            secret,
            provider="generic",
            encoding="hex",
            header_name="X-Custom-Sig",
        )
        self.assertEqual(gen_hex.header_name, "X-Custom-Sig")
        self.assertEqual(gen_hex.header_value, expected_hex)
        self.assertTrue(
            verify_signature(
                payload, secret, expected_hex, provider="generic-hex"
            ).valid
        )

        gen_b64 = generate_signature(
            payload, secret, provider="generic", encoding="base64"
        )
        self.assertEqual(gen_b64.header_value, expected_b64)
        self.assertTrue(
            verify_signature(
                payload, secret, expected_b64, provider="generic-b64"
            ).valid
        )

        # Conflicting encoding raises ValueError
        with self.assertRaises(ValueError):
            generate_signature(payload, secret, provider="github", encoding="base64")
        with self.assertRaises(ValueError):
            generate_signature(payload, "", provider="github")

    def test_payload_inspector_sample_and_edge_cases(self) -> None:
        sample_bytes = SAMPLE_PATH.read_bytes()
        info = inspect_payload(sample_bytes)
        self.assertTrue(info.is_json)
        self.assertEqual(info.root_type, "object")
        self.assertEqual(info.byte_length, len(sample_bytes))
        self.assertEqual(info.provider_hint, "stripe")
        self.assertEqual(info.event_type, "invoice.payment_succeeded")
        self.assertEqual(info.event_id, "evt_3Q9xLm2eZvKYlo2C1aBcDeFg")
        self.assertEqual(info.timestamp, 1763520000)
        self.assertEqual(info.key_fields.get("data.object.amount_paid"), 4900)
        self.assertEqual(info.key_fields.get("data.object.currency"), "usd")

        # GitHub-style JSON payload
        gh_bytes = json.dumps(
            {
                "action": "opened",
                "repository": {"full_name": "Kreqwaii/demo", "private": False},
                "sender": {"login": "octo-ci"},
            }
        ).encode("utf-8")
        gh_info = inspect_payload(gh_bytes)
        self.assertEqual(gh_info.provider_hint, "github")
        self.assertEqual(gh_info.event_type, "opened")
        self.assertEqual(gh_info.key_fields.get("repository.full_name"), "Kreqwaii/demo")
        self.assertEqual(gh_info.key_fields.get("sender.login"), "octo-ci")

        # Invalid JSON and empty payload
        bad_info = inspect_payload(b"{not-valid-json")
        self.assertFalse(bad_info.is_json)
        self.assertEqual(bad_info.root_type, "invalid")
        self.assertIsNotNone(bad_info.json_error)

        empty_info = inspect_payload(b"   ")
        self.assertFalse(empty_info.is_json)
        self.assertEqual(empty_info.root_type, "empty")

    def test_cli_json_sign_and_verify_exit_codes(self) -> None:
        secret = "cli_test_secret_789"

        # 1) Generate signature via CLI JSON output
        out_sign = io.StringIO()
        with contextlib.redirect_stdout(out_sign):
            rc = main(
                [
                    str(SAMPLE_PATH),
                    "--provider",
                    "stripe",
                    "--secret",
                    secret,
                    "--timestamp",
                    "1763520000",
                    "--format",
                    "json",
                ]
            )
        self.assertEqual(rc, 0)
        doc_sign = json.loads(out_sign.getvalue())
        self.assertTrue(doc_sign["ok"])
        sig_header = doc_sign["signature"]["header_value"]
        self.assertTrue(sig_header.startswith("t=1763520000,v1="))
        self.assertEqual(
            doc_sign["inspection"]["event_type"], "invoice.payment_succeeded"
        )

        # 2) Verify valid signature via CLI -> exit 0
        out_ok = io.StringIO()
        with contextlib.redirect_stdout(out_ok):
            rc_ok = main(
                [
                    "--payload",
                    str(SAMPLE_PATH),
                    "--provider",
                    "stripe",
                    "--secret",
                    secret,
                    "--verify",
                    sig_header,
                    "--now",
                    "1763520050",
                    "--tolerance",
                    "300",
                    "--format",
                    "json",
                ]
            )
        self.assertEqual(rc_ok, 0)
        self.assertTrue(json.loads(out_ok.getvalue())["verification"]["valid"])

        # 3) Verify invalid signature via CLI -> exit 1
        out_fail = io.StringIO()
        with contextlib.redirect_stdout(out_fail):
            rc_fail = main(
                [
                    "--payload",
                    str(SAMPLE_PATH),
                    "--provider",
                    "stripe",
                    "--secret",
                    "wrong_secret",
                    "--verify",
                    sig_header,
                    "--now",
                    "1763520050",
                    "--format",
                    "json",
                ]
            )
        self.assertEqual(rc_fail, 1)
        self.assertFalse(json.loads(out_fail.getvalue())["verification"]["valid"])

    def test_send_signed_webhook_to_ephemeral_http_server(self) -> None:
        secret = "live_http_test_secret"
        captured: list[dict[str, object]] = []

        class WebhookReceiver(BaseHTTPRequestHandler):
            def log_message(self, format: str, *args: object) -> None:
                return

            def do_POST(self) -> None:
                length = int(self.headers.get("Content-Length", "0"))
                body = self.rfile.read(length)
                sig_header = self.headers.get("Stripe-Signature", "")
                ver = verify_signature(
                    body,
                    secret,
                    sig_header,
                    provider="stripe",
                    tolerance_seconds=300,
                )
                captured.append(
                    {
                        "path": self.path,
                        "body": body,
                        "headers": dict(self.headers.items()),
                        "valid": ver.valid,
                    }
                )
                if ver.valid and self.path == "/webhook/ok":
                    resp_body = json.dumps(
                        {"accepted": True, "verified": True}
                    ).encode("utf-8")
                    self.send_response(HTTPStatus.OK)
                    self.send_header("Content-Type", "application/json")
                    self.send_header("Content-Length", str(len(resp_body)))
                    self.end_headers()
                    self.wfile.write(resp_body)
                else:
                    resp_body = b'{"accepted":false,"error":"rejected"}'
                    self.send_response(HTTPStatus.UNAUTHORIZED)
                    self.send_header("Content-Type", "application/json")
                    self.send_header("Content-Length", str(len(resp_body)))
                    self.end_headers()
                    self.wfile.write(resp_body)

        server = ThreadingHTTPServer(("127.0.0.1", 0), WebhookReceiver)
        port = server.server_address[1]
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()

        try:
            # 1) Successful signed POST delivery -> exit 0
            out_ok = io.StringIO()
            with contextlib.redirect_stdout(out_ok):
                rc_ok = main(
                    [
                        str(SAMPLE_PATH),
                        "--provider",
                        "stripe",
                        "--secret",
                        secret,
                        "--send",
                        f"http://127.0.0.1:{port}/webhook/ok",
                        "-H",
                        "X-Test-Trace: trace-001",
                        "--format",
                        "json",
                    ]
                )
            self.assertEqual(rc_ok, 0)
            result_ok = json.loads(out_ok.getvalue())
            self.assertTrue(result_ok["send"]["ok"])
            self.assertEqual(result_ok["send"]["status_code"], 200)
            self.assertEqual(len(captured), 1)
            self.assertTrue(captured[0]["valid"])
            self.assertEqual(captured[0]["body"], SAMPLE_PATH.read_bytes())
            self.assertEqual(
                captured[0]["headers"].get("X-Test-Trace"), "trace-001"
            )

            # 2) Endpoint rejects with HTTP 401 -> exit 1
            out_rej = io.StringIO()
            with contextlib.redirect_stdout(out_rej):
                rc_rej = main(
                    [
                        str(SAMPLE_PATH),
                        "--provider",
                        "stripe",
                        "--secret",
                        secret,
                        "--send",
                        f"http://127.0.0.1:{port}/webhook/reject",
                        "--format",
                        "json",
                    ]
                )
            self.assertEqual(rc_rej, 1)
            result_rej = json.loads(out_rej.getvalue())
            self.assertFalse(result_rej["send"]["ok"])
            self.assertEqual(result_rej["send"]["status_code"], 401)
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=2.0)

    def test_cli_inline_data_and_inspect_only(self) -> None:
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            rc = main(
                [
                    "--data",
                    '{"event":"deploy.finished","id":"dep_42","status":"success"}',
                ]
            )
        self.assertEqual(rc, 0)
        text = out.getvalue()
        self.assertIn("deploy.finished", text)
        self.assertIn("dep_42", text)
        self.assertIn("JSON Valid    : True", text)

    def test_cli_ignore_timestamp_and_send_invalid_url(self) -> None:
        payload = b'{"ping":true}'
        secret = "whsec_old_replay_test"
        gen = generate_signature(payload, secret, provider="stripe", timestamp=1000)

        out_ok = io.StringIO()
        with contextlib.redirect_stdout(out_ok):
            rc_ok = main(
                [
                    "--data",
                    '{"ping":true}',
                    "--provider",
                    "stripe",
                    "--secret",
                    secret,
                    "--verify",
                    gen.header_value,
                    "--now",
                    "1900000000",
                    "--ignore-timestamp",
                    "--format",
                    "json",
                ]
            )
        self.assertEqual(rc_ok, 0)
        ver = json.loads(out_ok.getvalue())["verification"]
        self.assertTrue(ver["valid"])
        self.assertTrue(ver["timestamp_valid"])
        self.assertIsNone(ver["tolerance_seconds"])

        # Invalid URL scheme returns CLI error code 2
        err_buf = io.StringIO()
        with contextlib.redirect_stderr(err_buf):
            rc_bad_url = main(
                [
                    "--data",
                    '{"ping":true}',
                    "--provider",
                    "github",
                    "--secret",
                    secret,
                    "--send",
                    "ftp://127.0.0.1:1234/hook",
                ]
            )
        self.assertEqual(rc_bad_url, 2)
        self.assertIn("http:// or https://", err_buf.getvalue())


if __name__ == "__main__":
    unittest.main()
