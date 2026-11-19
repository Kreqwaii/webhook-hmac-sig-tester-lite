#!/usr/bin/env python3
"""
Webhook HMAC-SHA256 Signature Generator, Verifier & Payload Inspector (Lite CLI)
Zero-dependency Python 3.9+ standard library utility for DevOps and backend engineers.

Supported webhook signature formats:
  - GitHub:      X-Hub-Signature-256: sha256=<hex>
  - Stripe:      Stripe-Signature: t=<unix_ts>,v1=<hex> (with replay tolerance check)
  - Shopify:     X-Shopify-Hmac-Sha256: <base64>
  - Generic:     X-Webhook-Signature-256: <hex> or <base64> (customizable header)

Features:
  - Constant-time signature verification via hmac.compare_digest
  - JSON webhook payload inspection (event type, id, timestamp, key fields, SHA-256)
  - Signed HTTP POST delivery to local or staging endpoints (--send)
  - Clean text and JSON output modes

License: MIT
"""

from __future__ import annotations

import argparse
import base64
from dataclasses import asdict, dataclass
import hashlib
import hmac
import json
from pathlib import Path
import sys
import time
from typing import Any, Optional
import urllib.error
import urllib.parse
import urllib.request

VERSION = "1.0.0"
DEFAULT_STRIPE_TOLERANCE_SECONDS = 300
DEFAULT_TIMEOUT_SECONDS = 10.0

PROVIDERS = (
    "github",
    "stripe",
    "shopify",
    "generic",
    "generic-hex",
    "generic-b64",
)
ENCODINGS = ("hex", "base64")

DEFAULT_HEADERS: dict[str, str] = {
    "github": "X-Hub-Signature-256",
    "stripe": "Stripe-Signature",
    "shopify": "X-Shopify-Hmac-Sha256",
    "generic-hex": "X-Webhook-Signature-256",
    "generic-b64": "X-Webhook-Signature-256",
}


def _configure_stdio_utf8() -> None:
    for stream in (sys.stdout, sys.stderr):
        reconfigure = getattr(stream, "reconfigure", None)
        if callable(reconfigure):
            try:
                reconfigure(encoding="utf-8", errors="replace")
            except OSError:
                pass


def _to_bytes(secret: str | bytes) -> bytes:
    if isinstance(secret, bytes):
        secret_bytes = secret
    elif isinstance(secret, str):
        secret_bytes = secret.encode("utf-8")
    else:
        raise TypeError("secret must be str or bytes")
    if not secret_bytes:
        raise ValueError("Webhook secret must not be empty.")
    return secret_bytes


def _hmac_sha256_digest(secret: str | bytes, signing_input: bytes) -> bytes:
    return hmac.new(_to_bytes(secret), signing_input, hashlib.sha256).digest()


def normalize_provider(
    provider: str, encoding: Optional[str] = None
) -> tuple[str, str]:
    """Return canonical (provider_id, encoding) pair and validate overrides."""
    prov = provider.strip().lower()
    if prov not in PROVIDERS:
        raise ValueError(
            f"Unsupported provider {provider!r}. Choose from: {', '.join(PROVIDERS)}"
        )

    enc = encoding.strip().lower() if encoding is not None else None
    if enc is not None and enc not in ENCODINGS:
        raise ValueError(
            f"Unsupported encoding {encoding!r}. Choose from: {', '.join(ENCODINGS)}"
        )

    if prov == "github":
        if enc == "base64":
            raise ValueError("GitHub webhooks require hex encoding ('sha256=<hex>').")
        return ("github", "hex")
    if prov == "stripe":
        if enc == "base64":
            raise ValueError("Stripe webhooks require hex encoding ('t=...,v1=<hex>').")
        return ("stripe", "hex")
    if prov == "shopify":
        if enc == "hex":
            raise ValueError("Shopify webhooks require base64 encoding.")
        return ("shopify", "base64")
    if prov == "generic-hex":
        if enc == "base64":
            raise ValueError("Provider 'generic-hex' conflicts with '--encoding base64'.")
        return ("generic-hex", "hex")
    if prov == "generic-b64":
        if enc == "hex":
            raise ValueError("Provider 'generic-b64' conflicts with '--encoding hex'.")
        return ("generic-b64", "base64")

    # prov == "generic"
    resolved_enc = enc or "hex"
    return ("generic-b64" if resolved_enc == "base64" else "generic-hex", resolved_enc)


@dataclass(frozen=True)
class GeneratedSignature:
    provider: str
    encoding: str
    header_name: str
    header_value: str
    digest_hex: str
    digest_base64: str
    timestamp: Optional[int]
    signed_payload_bytes: int
    payload_sha256: str


@dataclass(frozen=True)
class VerificationResult:
    valid: bool
    provider: str
    encoding: str
    header_name: str
    provided_signature: str
    expected_signature: str
    signature_matched: bool
    timestamp: Optional[int]
    timestamp_valid: Optional[bool]
    timestamp_age_seconds: Optional[int]
    tolerance_seconds: Optional[int]
    reason: str


@dataclass(frozen=True)
class PayloadInspection:
    byte_length: int
    body_sha256: str
    is_json: bool
    root_type: str
    json_error: Optional[str]
    provider_hint: Optional[str]
    event_type: Optional[str]
    event_id: Optional[str]
    timestamp: Any
    top_level_keys: list[str]
    key_fields: dict[str, Any]


@dataclass(frozen=True)
class SendResult:
    url: str
    status_code: int
    reason: str
    latency_ms: float
    request_headers: dict[str, str]
    response_headers: dict[str, str]
    response_body: str
    ok: bool
    error: Optional[str]


def generate_signature(
    payload: bytes,
    secret: str | bytes,
    provider: str = "github",
    *,
    encoding: Optional[str] = None,
    header_name: Optional[str] = None,
    timestamp: Optional[int] = None,
) -> GeneratedSignature:
    """Generate an HMAC-SHA256 webhook signature for the given raw payload bytes."""
    canonical_provider, resolved_encoding = normalize_provider(provider, encoding)
    resolved_header = (header_name or DEFAULT_HEADERS[canonical_provider]).strip()
    if not resolved_header:
        raise ValueError("Header name must not be empty.")

    ts: Optional[int] = None
    if canonical_provider == "stripe":
        ts = int(time.time()) if timestamp is None else int(timestamp)
        signing_input = f"{ts}.".encode("utf-8") + payload
    else:
        signing_input = payload

    digest_bytes = _hmac_sha256_digest(secret, signing_input)
    digest_hex = digest_bytes.hex()
    digest_b64 = base64.b64encode(digest_bytes).decode("ascii")

    if canonical_provider == "github":
        header_value = f"sha256={digest_hex}"
    elif canonical_provider == "stripe":
        header_value = f"t={ts},v1={digest_hex}"
    elif canonical_provider == "shopify":
        header_value = digest_b64
    elif canonical_provider == "generic-hex":
        header_value = digest_hex
    else:
        header_value = digest_b64

    return GeneratedSignature(
        provider=canonical_provider,
        encoding=resolved_encoding,
        header_name=resolved_header,
        header_value=header_value,
        digest_hex=digest_hex,
        digest_base64=digest_b64,
        timestamp=ts,
        signed_payload_bytes=len(signing_input),
        payload_sha256=hashlib.sha256(payload).hexdigest(),
    )


def parse_stripe_signature_header(
    header_value: str,
) -> tuple[Optional[int], list[str], Optional[str]]:
    """Parse Stripe-Signature header ('t=...,v1=...') into (timestamp, v1_list, error)."""
    if not header_value or not header_value.strip():
        return (None, [], "Empty Stripe-Signature header.")

    parsed_ts: Optional[int] = None
    v1_signatures: list[str] = []

    for part in header_value.split(","):
        item = part.strip()
        if not item:
            continue
        if "=" not in item:
            return (None, [], f"Malformed Stripe-Signature segment: {item!r}")
        key, value = item.split("=", 1)
        key = key.strip()
        value = value.strip()
        if key == "t":
            if parsed_ts is None:
                try:
                    parsed_ts = int(value)
                except ValueError:
                    return (None, [], f"Invalid Stripe timestamp 't={value}'.")
        elif key == "v1":
            if value:
                v1_signatures.append(value)

    if parsed_ts is None:
        return (None, [], "Missing 't=' timestamp in Stripe-Signature header.")
    if not v1_signatures:
        return (parsed_ts, [], "Missing 'v1=' signature in Stripe-Signature header.")
    return (parsed_ts, v1_signatures, None)


def verify_signature(
    payload: bytes,
    secret: str | bytes,
    signature_header_value: str,
    provider: str = "github",
    *,
    encoding: Optional[str] = None,
    header_name: Optional[str] = None,
    now: Optional[int] = None,
    tolerance_seconds: Optional[int] = DEFAULT_STRIPE_TOLERANCE_SECONDS,
) -> VerificationResult:
    """Verify a webhook signature in constant time using hmac.compare_digest."""
    canonical_provider, resolved_encoding = normalize_provider(provider, encoding)
    resolved_header = (header_name or DEFAULT_HEADERS[canonical_provider]).strip()
    provided = signature_header_value.strip()

    if canonical_provider == "stripe":
        if tolerance_seconds is not None and tolerance_seconds < 0:
            raise ValueError("tolerance_seconds must be >= 0 or None.")

        parsed_ts, v1_list, parse_error = parse_stripe_signature_header(provided)
        if parse_error or parsed_ts is None:
            expected_dummy = generate_signature(
                payload,
                secret,
                "stripe",
                header_name=resolved_header,
                timestamp=0 if now is None else int(now),
            )
            return VerificationResult(
                valid=False,
                provider=canonical_provider,
                encoding=resolved_encoding,
                header_name=resolved_header,
                provided_signature=provided,
                expected_signature=expected_dummy.header_value,
                signature_matched=False,
                timestamp=parsed_ts,
                timestamp_valid=False if parsed_ts is not None else None,
                timestamp_age_seconds=None,
                tolerance_seconds=tolerance_seconds,
                reason=parse_error or "Invalid Stripe-Signature header.",
            )

        expected = generate_signature(
            payload,
            secret,
            "stripe",
            header_name=resolved_header,
            timestamp=parsed_ts,
        )

        # Constant-time check across all v1 candidates without short-circuiting.
        matched = False
        for candidate in v1_list:
            if hmac.compare_digest(expected.digest_hex, candidate.lower()):
                matched = True

        current_ts = int(time.time()) if now is None else int(now)
        age_seconds = current_ts - parsed_ts
        if tolerance_seconds is None:
            ts_valid = True
        else:
            ts_valid = abs(age_seconds) <= tolerance_seconds

        valid = matched and ts_valid
        if valid:
            if tolerance_seconds is None:
                reason = "Valid Stripe signature (replay timestamp check disabled)."
            else:
                reason = (
                    f"Valid Stripe signature within replay window "
                    f"(age={age_seconds}s, tolerance=+/-{tolerance_seconds}s)."
                )
        elif not matched:
            reason = "Stripe HMAC-SHA256 signature mismatch."
        else:
            reason = (
                f"Stripe signature matched, but timestamp is outside replay tolerance "
                f"(age={age_seconds}s, tolerance=+/-{tolerance_seconds}s)."
            )

        return VerificationResult(
            valid=valid,
            provider=canonical_provider,
            encoding=resolved_encoding,
            header_name=resolved_header,
            provided_signature=provided,
            expected_signature=expected.header_value,
            signature_matched=matched,
            timestamp=parsed_ts,
            timestamp_valid=ts_valid,
            timestamp_age_seconds=age_seconds,
            tolerance_seconds=tolerance_seconds,
            reason=reason,
        )

    expected = generate_signature(
        payload,
        secret,
        canonical_provider,
        encoding=resolved_encoding,
        header_name=resolved_header,
    )

    if canonical_provider == "github":
        if not provided.startswith("sha256="):
            return VerificationResult(
                valid=False,
                provider=canonical_provider,
                encoding=resolved_encoding,
                header_name=resolved_header,
                provided_signature=provided,
                expected_signature=expected.header_value,
                signature_matched=False,
                timestamp=None,
                timestamp_valid=None,
                timestamp_age_seconds=None,
                tolerance_seconds=None,
                reason="Missing 'sha256=' prefix in GitHub signature header.",
            )
        candidate_hex = provided[len("sha256=") :].strip().lower()
        matched = hmac.compare_digest(expected.digest_hex, candidate_hex)
        reason = (
            "Valid GitHub X-Hub-Signature-256 signature."
            if matched
            else "GitHub X-Hub-Signature-256 signature mismatch."
        )
    elif canonical_provider in ("shopify", "generic-b64"):
        matched = hmac.compare_digest(expected.digest_base64, provided)
        reason = (
            f"Valid {canonical_provider} base64 HMAC-SHA256 signature."
            if matched
            else f"{canonical_provider} base64 HMAC-SHA256 signature mismatch."
        )
    else:
        # generic-hex
        matched = hmac.compare_digest(expected.digest_hex, provided.lower())
        reason = (
            "Valid generic-hex HMAC-SHA256 signature."
            if matched
            else "generic-hex HMAC-SHA256 signature mismatch."
        )

    return VerificationResult(
        valid=matched,
        provider=canonical_provider,
        encoding=resolved_encoding,
        header_name=resolved_header,
        provided_signature=provided,
        expected_signature=expected.header_value,
        signature_matched=matched,
        timestamp=None,
        timestamp_valid=None,
        timestamp_age_seconds=None,
        tolerance_seconds=None,
        reason=reason,
    )


def _is_scalar(value: Any) -> bool:
    return isinstance(value, (str, int, float, bool)) or value is None


def inspect_payload(payload: bytes) -> PayloadInspection:
    """Inspect raw payload bytes and extract webhook JSON metadata if applicable."""
    byte_length = len(payload)
    body_sha256 = hashlib.sha256(payload).hexdigest()

    if not payload.strip():
        return PayloadInspection(
            byte_length=byte_length,
            body_sha256=body_sha256,
            is_json=False,
            root_type="empty",
            json_error="Payload is empty.",
            provider_hint=None,
            event_type=None,
            event_id=None,
            timestamp=None,
            top_level_keys=[],
            key_fields={},
        )

    try:
        text = payload.decode("utf-8")
    except UnicodeDecodeError as exc:
        return PayloadInspection(
            byte_length=byte_length,
            body_sha256=body_sha256,
            is_json=False,
            root_type="binary",
            json_error=f"Invalid UTF-8 bytes: {exc}",
            provider_hint=None,
            event_type=None,
            event_id=None,
            timestamp=None,
            top_level_keys=[],
            key_fields={},
        )

    try:
        parsed = json.loads(text)
    except json.JSONDecodeError as exc:
        return PayloadInspection(
            byte_length=byte_length,
            body_sha256=body_sha256,
            is_json=False,
            root_type="invalid",
            json_error=f"Invalid JSON: {exc.msg} (line {exc.lineno}, col {exc.colno})",
            provider_hint=None,
            event_type=None,
            event_id=None,
            timestamp=None,
            top_level_keys=[],
            key_fields={},
        )

    if isinstance(parsed, list):
        return PayloadInspection(
            byte_length=byte_length,
            body_sha256=body_sha256,
            is_json=True,
            root_type="array",
            json_error=None,
            provider_hint=None,
            event_type=None,
            event_id=None,
            timestamp=None,
            top_level_keys=[],
            key_fields={"array_length": len(parsed)},
        )

    if not isinstance(parsed, dict):
        return PayloadInspection(
            byte_length=byte_length,
            body_sha256=body_sha256,
            is_json=True,
            root_type="primitive",
            json_error=None,
            provider_hint=None,
            event_type=None,
            event_id=None,
            timestamp=None,
            top_level_keys=[],
            key_fields={"value": parsed},
        )

    top_keys = [str(k) for k in parsed.keys()]

    # Provider heuristic
    provider_hint: Optional[str] = None
    data_obj = None
    if isinstance(parsed.get("data"), dict) and isinstance(
        parsed["data"].get("object"), dict
    ):
        data_obj = parsed["data"]["object"]

    if parsed.get("object") == "event" or (
        "type" in parsed and "api_version" in parsed and data_obj is not None
    ):
        provider_hint = "stripe"
    elif "repository" in parsed and (
        "sender" in parsed or "action" in parsed or "ref" in parsed
    ):
        provider_hint = "github"
    elif "admin_graphql_api_id" in parsed or (
        "line_items" in parsed and "currency" in parsed
    ):
        provider_hint = "shopify"

    # Event type extraction
    event_type: Optional[str] = None
    for key in ("type", "event", "event_type", "topic"):
        val = parsed.get(key)
        if isinstance(val, str) and val.strip():
            event_type = val.strip()
            break
    if event_type is None and isinstance(parsed.get("action"), str):
        event_type = parsed["action"].strip() or None
    elif (
        event_type is not None
        and isinstance(parsed.get("action"), str)
        and parsed["action"].strip()
        and "." not in event_type
    ):
        event_type = f"{event_type}.{parsed['action'].strip()}"

    # Event ID extraction
    event_id: Optional[str] = None
    for key in ("id", "event_id", "delivery_id", "hook_id", "request_id", "order_id"):
        val = parsed.get(key)
        if val not in (None, "") and _is_scalar(val):
            event_id = str(val)
            break
    if event_id is None and data_obj is not None and data_obj.get("id") not in (None, ""):
        event_id = str(data_obj["id"])

    # Timestamp extraction
    timestamp: Any = None
    for key in ("created", "created_at", "timestamp", "occurred_at", "updated_at"):
        val = parsed.get(key)
        if val not in (None, "") and _is_scalar(val):
            timestamp = val
            break

    # Key fields summary
    key_fields: dict[str, Any] = {}
    top_interest = (
        "id",
        "object",
        "type",
        "event",
        "event_type",
        "topic",
        "action",
        "api_version",
        "livemode",
        "created",
        "created_at",
        "timestamp",
        "status",
        "currency",
        "total_price",
        "financial_status",
        "ref",
    )
    for k in top_interest:
        if k in parsed and _is_scalar(parsed[k]):
            key_fields[k] = parsed[k]

    if data_obj is not None:
        for k in (
            "id",
            "object",
            "status",
            "amount",
            "amount_paid",
            "amount_due",
            "currency",
            "customer",
            "subscription",
            "billing_reason",
        ):
            if k in data_obj and _is_scalar(data_obj[k]):
                key_fields[f"data.object.{k}"] = data_obj[k]

    repo = parsed.get("repository")
    if isinstance(repo, dict):
        for k in ("full_name", "name", "private", "default_branch"):
            if k in repo and _is_scalar(repo[k]):
                key_fields[f"repository.{k}"] = repo[k]

    sender = parsed.get("sender")
    if isinstance(sender, dict) and _is_scalar(sender.get("login")):
        key_fields["sender.login"] = sender["login"]

    return PayloadInspection(
        byte_length=byte_length,
        body_sha256=body_sha256,
        is_json=True,
        root_type="object",
        json_error=None,
        provider_hint=provider_hint,
        event_type=event_type,
        event_id=event_id,
        timestamp=timestamp,
        top_level_keys=top_keys,
        key_fields=key_fields,
    )


def send_signed_webhook(
    url: str,
    payload: bytes,
    signature: GeneratedSignature,
    *,
    content_type: str = "application/json",
    extra_headers: Optional[dict[str, str]] = None,
    timeout_seconds: float = DEFAULT_TIMEOUT_SECONDS,
) -> SendResult:
    """Send raw payload bytes as an HTTP POST with the generated HMAC signature header."""
    parsed_url = urllib.parse.urlsplit(url)
    if parsed_url.scheme.lower() not in ("http", "https") or not parsed_url.netloc:
        raise ValueError(f"Target URL must be a valid http:// or https:// URL: {url!r}")

    headers: dict[str, str] = {
        "Content-Type": content_type,
        "User-Agent": f"webhook-hmac-sig-tester-lite/{VERSION}",
        signature.header_name: signature.header_value,
    }
    if extra_headers:
        for k, v in extra_headers.items():
            headers[k] = v

    req = urllib.request.Request(url, data=payload, headers=headers, method="POST")

    # Bypass environment proxies for loopback addresses so local testing stays reliable.
    hostname = (parsed_url.hostname or "").lower()
    if hostname in ("127.0.0.1", "localhost", "::1"):
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    else:
        opener = urllib.request.build_opener()

    t0 = time.perf_counter()
    try:
        with opener.open(req, timeout=timeout_seconds) as resp:
            raw_resp = resp.read(65_536)
            latency_ms = round((time.perf_counter() - t0) * 1000.0, 3)
            resp_headers = {k: v for k, v in resp.headers.items()}
            status = int(resp.status)
            return SendResult(
                url=url,
                status_code=status,
                reason=str(getattr(resp, "reason", "OK")),
                latency_ms=latency_ms,
                request_headers=headers,
                response_headers=resp_headers,
                response_body=raw_resp.decode("utf-8", errors="replace"),
                ok=200 <= status < 300,
                error=None,
            )
    except urllib.error.HTTPError as exc:
        latency_ms = round((time.perf_counter() - t0) * 1000.0, 3)
        raw_resp = b""
        try:
            raw_resp = exc.read(65_536)
        except OSError:
            pass
        resp_headers = {k: v for k, v in exc.headers.items()} if exc.headers else {}
        return SendResult(
            url=url,
            status_code=int(exc.code),
            reason=str(exc.reason),
            latency_ms=latency_ms,
            request_headers=headers,
            response_headers=resp_headers,
            response_body=raw_resp.decode("utf-8", errors="replace"),
            ok=False,
            error=f"HTTP {exc.code}: {exc.reason}",
        )
    except (urllib.error.URLError, OSError, TimeoutError) as exc:
        latency_ms = round((time.perf_counter() - t0) * 1000.0, 3)
        reason_obj = getattr(exc, "reason", exc)
        return SendResult(
            url=url,
            status_code=0,
            reason="ConnectionError",
            latency_ms=latency_ms,
            request_headers=headers,
            response_headers={},
            response_body="",
            ok=False,
            error=str(reason_obj),
        )


def _parse_extra_headers(raw_headers: list[str]) -> dict[str, str]:
    parsed: dict[str, str] = {}
    for item in raw_headers:
        if ":" not in item:
            raise ValueError(
                f"Invalid header format {item!r}. Expected 'Header-Name: value'."
            )
        name, value = item.split(":", 1)
        name = name.strip()
        value = value.strip()
        if not name:
            raise ValueError(f"Empty header name in {item!r}.")
        parsed[name] = value
    return parsed


def _load_payload_bytes(
    payload_pos: Optional[str],
    payload_flag: Optional[str],
    data_str: Optional[str],
) -> tuple[bytes, str]:
    if payload_pos is not None and payload_flag is not None:
        raise ValueError("Specify either positional payload path or --payload, not both.")
    source = payload_flag if payload_flag is not None else payload_pos

    if data_str is not None and source is not None:
        raise ValueError("Specify either a payload file or --data, not both.")

    if data_str is not None:
        return (data_str.encode("utf-8"), "<inline --data>")

    if source is not None:
        if source == "-":
            return (sys.stdin.buffer.read(), "<stdin>")
        path = Path(source)
        if not path.is_file():
            raise FileNotFoundError(f"Payload file not found: {path}")
        return (path.read_bytes(), str(path))

    if not sys.stdin.isatty():
        return (sys.stdin.buffer.read(), "<stdin>")

    raise ValueError(
        "No payload provided. Pass a file path, '--payload <file>', '--data <text>', or pipe via stdin."
    )


def _format_text_report(
    *,
    source_label: str,
    inspection: Optional[PayloadInspection],
    signature: Optional[GeneratedSignature],
    verification: Optional[VerificationResult],
    send_result: Optional[SendResult],
) -> str:
    lines: list[str] = []
    lines.append("=== Webhook HMAC-SHA256 Tester & Inspector ===")
    lines.append(f"Source        : {source_label}")

    if inspection is not None:
        lines.append("")
        lines.append("[Payload Inspection]")
        lines.append(f"Byte Length   : {inspection.byte_length} bytes")
        lines.append(f"Body SHA-256  : {inspection.body_sha256}")
        lines.append(f"JSON Valid    : {inspection.is_json} (root={inspection.root_type})")
        if inspection.json_error:
            lines.append(f"JSON Error    : {inspection.json_error}")
        if inspection.provider_hint:
            lines.append(f"Detected Hint : {inspection.provider_hint}")
        if inspection.event_type:
            lines.append(f"Event Type    : {inspection.event_type}")
        if inspection.event_id:
            lines.append(f"Event ID      : {inspection.event_id}")
        if inspection.timestamp is not None:
            lines.append(f"Event Time    : {inspection.timestamp}")
        if inspection.top_level_keys:
            lines.append(f"Top Keys      : {', '.join(inspection.top_level_keys)}")
        if inspection.key_fields:
            lines.append("Key Fields    :")
            for k, v in inspection.key_fields.items():
                lines.append(f"  - {k}: {v}")

    if signature is not None:
        lines.append("")
        lines.append("[Generated Signature]")
        lines.append(f"Provider      : {signature.provider} ({signature.encoding})")
        if signature.timestamp is not None:
            lines.append(f"Timestamp (t) : {signature.timestamp}")
        lines.append(f"Header        : {signature.header_name}: {signature.header_value}")
        lines.append(f"Digest (Hex)  : {signature.digest_hex}")
        lines.append(f"Digest (B64)  : {signature.digest_base64}")

    if verification is not None:
        lines.append("")
        lines.append("[Signature Verification]")
        lines.append(
            f"Status        : {'PASS (VALID)' if verification.valid else 'FAIL (INVALID)'}"
        )
        lines.append(f"Provider      : {verification.provider} ({verification.encoding})")
        lines.append(f"Header        : {verification.header_name}")
        lines.append(f"Crypto Match  : {verification.signature_matched}")
        if verification.timestamp is not None:
            lines.append(
                f"Replay Check  : valid={verification.timestamp_valid} "
                f"(age={verification.timestamp_age_seconds}s, tolerance={verification.tolerance_seconds})"
            )
        lines.append(f"Reason        : {verification.reason}")

    if send_result is not None:
        lines.append("")
        lines.append("[HTTP Delivery]")
        lines.append(f"Target URL    : {send_result.url}")
        lines.append(
            f"Outcome       : {'OK' if send_result.ok else 'FAILED'} "
            f"(HTTP {send_result.status_code} {send_result.reason})"
        )
        lines.append(f"Latency       : {send_result.latency_ms} ms")
        if send_result.error:
            lines.append(f"Error         : {send_result.error}")
        if send_result.response_body:
            preview = send_result.response_body.strip()
            if len(preview) > 500:
                preview = preview[:500] + "... [truncated]"
            lines.append(f"Response Body : {preview}")

    return "\n".join(lines)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="sigtool.py",
        description=(
            "Zero-dependency Python 3.9+ CLI to generate and verify GitHub, Stripe, "
            "Shopify, and Generic HMAC-SHA256 webhook signatures, inspect JSON payloads, "
            "and send signed test POST requests."
        ),
    )
    parser.add_argument(
        "payload_pos",
        nargs="?",
        metavar="PAYLOAD",
        help="Path to webhook payload file (or '-' for stdin).",
    )
    parser.add_argument(
        "-p",
        "--payload",
        dest="payload_flag",
        metavar="FILE",
        help="Path to webhook payload file (or '-' for stdin).",
    )
    parser.add_argument(
        "-d",
        "--data",
        dest="data_str",
        help="Inline UTF-8 payload string instead of reading a file.",
    )
    parser.add_argument(
        "--provider",
        choices=PROVIDERS,
        default="github",
        help="Signature format preset (default: github).",
    )
    parser.add_argument(
        "-s",
        "--secret",
        help="Webhook signing secret key (required for signing, verification, or --send).",
    )
    parser.add_argument(
        "--encoding",
        choices=ENCODINGS,
        default=None,
        help="Digest encoding for 'generic' provider (hex or base64).",
    )
    parser.add_argument(
        "--header",
        default=None,
        help="Override the signature HTTP header name.",
    )
    parser.add_argument(
        "--timestamp",
        type=int,
        default=None,
        help="Explicit Unix epoch timestamp for Stripe signature generation.",
    )
    parser.add_argument(
        "--verify",
        metavar="HEADER_VALUE",
        default=None,
        help="Verify an incoming signature header value in constant time.",
    )
    parser.add_argument(
        "--tolerance",
        type=int,
        default=DEFAULT_STRIPE_TOLERANCE_SECONDS,
        help=f"Stripe replay tolerance window in seconds (default: {DEFAULT_STRIPE_TOLERANCE_SECONDS}).",
    )
    parser.add_argument(
        "--ignore-timestamp",
        action="store_true",
        help="Disable Stripe replay timestamp age validation during verification.",
    )
    parser.add_argument(
        "--now",
        type=int,
        default=None,
        help="Override current Unix timestamp for Stripe replay window evaluation.",
    )
    parser.add_argument(
        "--send",
        metavar="URL",
        default=None,
        help="Send a signed HTTP POST request with the payload to URL.",
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=DEFAULT_TIMEOUT_SECONDS,
        help=f"HTTP timeout in seconds for --send (default: {DEFAULT_TIMEOUT_SECONDS}).",
    )
    parser.add_argument(
        "--content-type",
        default="application/json",
        help="Content-Type header for --send (default: application/json).",
    )
    parser.add_argument(
        "-H",
        "--extra-header",
        action="append",
        default=[],
        metavar="NAME:VALUE",
        help="Additional HTTP header for --send (repeatable).",
    )
    parser.add_argument(
        "-f",
        "--format",
        choices=("text", "json"),
        default="text",
        help="Output format (default: text).",
    )
    parser.add_argument(
        "--no-inspect",
        action="store_true",
        help="Omit payload inspection details from output.",
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"%(prog)s {VERSION}",
    )
    return parser


def main(argv: Optional[list[str]] = None) -> int:
    _configure_stdio_utf8()
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.verify is not None and args.send is not None:
        parser.error("--verify and --send cannot be used together.")

    if (args.verify is not None or args.send is not None) and args.secret is None:
        parser.error("--secret is required when using --verify or --send.")

    try:
        payload_bytes, source_label = _load_payload_bytes(
            args.payload_pos, args.payload_flag, args.data_str
        )
        extra_headers = _parse_extra_headers(args.extra_header)
    except (ValueError, FileNotFoundError) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 2

    inspection = None if args.no_inspect else inspect_payload(payload_bytes)
    signature: Optional[GeneratedSignature] = None
    verification: Optional[VerificationResult] = None
    send_result: Optional[SendResult] = None
    exit_code = 0

    try:
        if args.verify is not None:
            tolerance: Optional[int] = (
                None if args.ignore_timestamp else args.tolerance
            )
            verification = verify_signature(
                payload_bytes,
                args.secret,
                args.verify,
                args.provider,
                encoding=args.encoding,
                header_name=args.header,
                now=args.now,
                tolerance_seconds=tolerance,
            )
            if not verification.valid:
                exit_code = 1
        elif args.secret is not None:
            signature = generate_signature(
                payload_bytes,
                args.secret,
                args.provider,
                encoding=args.encoding,
                header_name=args.header,
                timestamp=args.timestamp,
            )
            if args.send is not None:
                send_result = send_signed_webhook(
                    args.send,
                    payload_bytes,
                    signature,
                    content_type=args.content_type,
                    extra_headers=extra_headers,
                    timeout_seconds=args.timeout,
                )
                if not send_result.ok:
                    exit_code = 1
    except ValueError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 2

    if args.format == "json":
        output_doc: dict[str, Any] = {
            "source": source_label,
            "ok": exit_code == 0,
        }
        if inspection is not None:
            output_doc["inspection"] = asdict(inspection)
        if signature is not None:
            output_doc["signature"] = asdict(signature)
        if verification is not None:
            output_doc["verification"] = asdict(verification)
        if send_result is not None:
            output_doc["send"] = asdict(send_result)
        print(json.dumps(output_doc, indent=2, ensure_ascii=False))
    else:
        print(
            _format_text_report(
                source_label=source_label,
                inspection=inspection,
                signature=signature,
                verification=verification,
                send_result=send_result,
            )
        )

    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())
