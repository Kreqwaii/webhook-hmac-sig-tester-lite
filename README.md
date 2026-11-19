# webhook-hmac-sig-tester-lite

**Webhook HMAC-SHA256 Signature Generator, Verifier & Payload Inspector (Lite CLI)** — 100% Python 3.9+ standard-library CLI utility for DevOps and backend developers.

Утилита на чистом Python 3.9+ (без `pip install` и сторонних зависимостей) для DevOps-инженеров и бэкенд-разработчиков: генерирует и проверяет криптографические подписи вебхуков **GitHub**, **Stripe**, **Shopify** и **Generic HMAC-SHA256** (hex/base64) с постоянным временем сравнения (`hmac.compare_digest`), инспектирует JSON-пейлоад и отправляет подписанный тестовый `POST`-запрос на локальный или тестовый URL (`--send`).

---

## Features / Возможности

- **Zero external dependencies** — 100% Python 3.9+ `stdlib` (`hmac`, `hashlib`, `base64`, `json`, `urllib`, `argparse`, `dataclasses`).
- **GitHub Webhooks (`github`)** — generates and verifies `X-Hub-Signature-256: sha256=<hex>`.
- **Stripe Webhooks (`stripe`)** — generates and verifies `Stripe-Signature: t=<unix_ts>,v1=<hex>` with key-rotation multi-`v1` support and configurable replay tolerance (`--tolerance 300` by default, or `--ignore-timestamp`).
- **Shopify & Generic HMAC-SHA256 (`shopify`, `generic`, `generic-hex`, `generic-b64`)** — supports `X-Shopify-Hmac-Sha256` (base64) as well as generic hex and base64 signatures with optional `--header` override.
- **Constant-time verification** — uses `hmac.compare_digest` to prevent timing side-channel leaks; returns exit code `0` on valid signature and `1` on mismatch/expired timestamp.
- **JSON Payload Inspector** — reports raw byte length, SHA-256 digest, JSON validity, detected provider hint, `event_type`, `event_id`, timestamp, and extracted key fields.
- **Live Test Sender (`--send`)** — dispatches raw payload bytes over HTTP/HTTPS `POST` with exact signature headers and reports HTTP status, round-trip latency (`ms`), and response body preview.
- **Automation-friendly output** — clean human-readable `--format text` (default) or structured `--format json`.

---

## Supported Signature Formats

| Provider Flag | Default Header | Header Value Format | Encoding |
| :--- | :--- | :--- | :--- |
| `github` | `X-Hub-Signature-256` | `sha256=<hex>` | hex |
| `stripe` | `Stripe-Signature` | `t=<ts>,v1=<hex>` | hex (`t + "." + body`) |
| `shopify` | `X-Shopify-Hmac-Sha256` | `<base64>` | base64 |
| `generic` / `generic-hex` | `X-Webhook-Signature-256` | `<hex>` | hex |
| `generic --encoding base64` / `generic-b64` | `X-Webhook-Signature-256` | `<base64>` | base64 |

---

## Quick Start / Быстрый старт

### 1. Inspect a JSON webhook payload (no secret required)

```bash
python sigtool.py sample_payload.json
```

### 2. Generate signatures

```bash
# GitHub (X-Hub-Signature-256)
python sigtool.py sample_payload.json --provider github --secret my_gh_secret

# Stripe (Stripe-Signature with deterministic timestamp)
python sigtool.py sample_payload.json --provider stripe --secret whsec_demo_secret --timestamp 1763520000

# Shopify (X-Shopify-Hmac-Sha256 base64)
python sigtool.py sample_payload.json --provider shopify --secret shpss_demo_secret

# Generic HMAC-SHA256 (base64 with custom header)
python sigtool.py sample_payload.json --provider generic --encoding base64 --header X-App-Sig --secret my_secret
```

### 3. Verify an incoming signature (constant-time)

```bash
# Verify GitHub signature
python sigtool.py sample_payload.json --provider github --secret my_gh_secret --verify "sha256=<hex>"

# Verify Stripe signature within 300s replay tolerance
python sigtool.py sample_payload.json --provider stripe --secret whsec_demo_secret --verify "t=1763520000,v1=..." --tolerance 300
```

### 4. Send a signed POST request to a local/test endpoint (`--send`)

```bash
python sigtool.py sample_payload.json --provider stripe --secret whsec_demo_secret --send http://127.0.0.1:8787/webhook
```

### 5. Run unit tests

```bash
py -B -m unittest -v
```

---

## Example Output

```text
$ python sigtool.py sample_payload.json --provider stripe --secret whsec_demo_secret --timestamp 1763520000
=== Webhook HMAC-SHA256 Tester & Inspector ===
Source        : sample_payload.json

[Payload Inspection]
Byte Length   : 503 bytes
Body SHA-256  : df337a0c70c296e3a4cd5be421ce72e8b9e47f08900b223a1211740045997231
JSON Valid    : True (root=object)
Detected Hint : stripe
Event Type    : invoice.payment_succeeded
Event ID      : evt_3Q9xLm2eZvKYlo2C1aBcDeFg
Event Time    : 1763520000
Top Keys      : id, object, api_version, created, livemode, type, data
Key Fields    :
  - id: evt_3Q9xLm2eZvKYlo2C1aBcDeFg
  - object: event
  - type: invoice.payment_succeeded
  - api_version: 2024-06-20
  - livemode: False
  - created: 1763520000
  - data.object.id: in_1Q9xLl2eZvKYlo2C9xYzAbCd
  - data.object.object: invoice
  - data.object.status: paid
  - data.object.amount_paid: 4900
  - data.object.currency: usd
  - data.object.customer: cus_R4k9xSample01
  - data.object.subscription: sub_1Q9xLk2eZvKYlo2C4mNpQrSt
  - data.object.billing_reason: subscription_cycle

[Generated Signature]
Provider      : stripe (hex)
Timestamp (t) : 1763520000
Header        : Stripe-Signature: t=1763520000,v1=e6606ee361632c8f26c9f956ff325fcaf9e5f0106390154d78753656f42b48e7
Digest (Hex)  : e6606ee361632c8f26c9f956ff325fcaf9e5f0106390154d78753656f42b48e7
Digest (B64)  : 5mBu42FjLI8myflW/zJfyvnl8BBjkBVNeHU2VvQrSOc=
```

---

## Need a Self-Hosted Webhook-to-Telegram Alert Router with Dedup, Rate Limiting & Retry Queue?

This Lite CLI handles manual signature generation, verification, payload inspection, and one-shot test requests. If you need a **turnkey self-hosted Webhook-to-Telegram Alert Router** with incoming HMAC verification, event deduplication, rate limiting, and a persistent retry queue:

- **Pro Full Version on FunPay (Product #26):** https://funpay.com/lots/offer?id=82601431

---

## License

MIT License — see [LICENSE](LICENSE).
