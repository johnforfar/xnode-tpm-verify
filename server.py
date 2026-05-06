#!/usr/bin/env python3
"""
xnode-tpm-verify — TPM2 attestation verifier service (Phase 2).

Runs as a single-process HTTP server. State persisted to JSON files.
AK quote signatures are verified server-side via openssl. Operator
endpoints are bearer-token-gated.

Endpoints:
  GET  /                    health + status page
  GET  /api                 machine-readable endpoint index

  POST /register-app        operator: pin golden values for an app
                            auth: Authorization: Bearer $OPERATOR_TOKEN
  GET  /golden/<app>        anyone: read pinned values
  GET  /badge/<app>         anyone: SVG/HTML status badge for embedding

  POST /verify-quote        prover: submit quote, get verdict + receipt
                            (validates AK signature on quote.msg)
  POST /heartbeat           prover: continuous-attestation refresh
  POST /task-result         prover: submit task output + final receipt

  GET  /receipt/<id>        anyone: read a previously-issued receipt

Phase 2 deltas vs Phase 1:
  + Server-side AK signature verification (RSASSA-PKCS1v1.5-SHA256)
  + Bearer-token auth on /register-app (env: OPERATOR_TOKEN)
  + /heartbeat for continuous attestation (lighter than full /verify)
  + /badge/<app> SVG endpoint for embedding in app frontends
  + Enrollment ledger (EK fingerprint + AK pubkey captured on first quote)
  + Receipts now include the AK fingerprint to support per-node tracking

Phase 2.5 deferred:
  - EIP-712 wallet auth (replaces bearer token; needs client-side signer)
  - Sealed credentials via tpm2_makecredential (needs per-node EK enrollment)
"""

import base64
import hashlib
import hmac
import http.server
import json
import os
import secrets
import socketserver
import struct
import subprocess
import sys
import threading
import time
import tempfile
import uuid
from pathlib import Path
from typing import Any

STATE_DIR = Path(os.environ.get("STATE_DIR", "/var/lib/xnode-tpm-verify"))
APPS_FILE = STATE_DIR / "apps.json"
NODES_FILE = STATE_DIR / "nodes.json"
ATTESTATIONS_FILE = STATE_DIR / "attestations.jsonl"
RECEIPTS_FILE = STATE_DIR / "receipts.jsonl"
SECRET_FILE = STATE_DIR / "verifier.secret"
PORT = int(os.environ.get("PORT", "8080"))
OPERATOR_TOKEN = os.environ.get("OPERATOR_TOKEN", "")

LOCK = threading.Lock()


# ─── persistence ──────────────────────────────────────────────────────────


def get_secret() -> bytes:
    if not SECRET_FILE.exists():
        SECRET_FILE.write_bytes(secrets.token_bytes(32))
        SECRET_FILE.chmod(0o600)
    return SECRET_FILE.read_bytes()


def load_apps() -> dict[str, Any]:
    if APPS_FILE.exists():
        return json.loads(APPS_FILE.read_text())
    return {}


def save_apps(apps: dict[str, Any]) -> None:
    with open(APPS_FILE, "w") as f:
        json.dump(apps, f, indent=2)


def load_nodes() -> dict[str, Any]:
    if NODES_FILE.exists():
        return json.loads(NODES_FILE.read_text())
    return {}


def save_nodes(nodes: dict[str, Any]) -> None:
    with open(NODES_FILE, "w") as f:
        json.dump(nodes, f, indent=2)


def append_jsonl(path: Path, record: dict[str, Any]) -> None:
    with open(path, "a") as f:
        f.write(json.dumps(record) + "\n")


def find_receipt(receipt_id: str) -> dict[str, Any] | None:
    if not RECEIPTS_FILE.exists():
        return None
    with RECEIPTS_FILE.open() as f:
        for line in f:
            r = json.loads(line)
            if r.get("receipt_id") == receipt_id:
                return r
    return None


def latest_receipt_for_app(app_name: str, kind: str | None = None) -> dict[str, Any] | None:
    if not RECEIPTS_FILE.exists():
        return None
    last = None
    with RECEIPTS_FILE.open() as f:
        for line in f:
            r = json.loads(line)
            body = r.get("body", {})
            if body.get("app_name") != app_name:
                continue
            if kind and r.get("kind") != kind:
                continue
            last = r
    return last


# ─── parsing ──────────────────────────────────────────────────────────────


def parse_tpms_attest(quote_msg: bytes) -> dict[str, Any]:
    """Minimal TPMS_ATTEST parser — extracts nonce, AK name, pcrDigest."""
    off = 0
    magic = struct.unpack(">I", quote_msg[off:off+4])[0]; off += 4
    if magic != 0xff544347:
        raise ValueError(f"bad magic 0x{magic:08x}")
    type_ = struct.unpack(">H", quote_msg[off:off+2])[0]; off += 2
    if type_ != 0x8018:
        raise ValueError(f"not a quote (type 0x{type_:04x})")

    qs_size = struct.unpack(">H", quote_msg[off:off+2])[0]; off += 2
    qualified_signer = quote_msg[off:off+qs_size]; off += qs_size

    ed_size = struct.unpack(">H", quote_msg[off:off+2])[0]; off += 2
    extra_data = quote_msg[off:off+ed_size]; off += ed_size

    off += 17                                              # clockInfo
    off += 8                                               # firmwareVersion

    pcr_count = struct.unpack(">I", quote_msg[off:off+4])[0]; off += 4
    selections = []
    for _ in range(pcr_count):
        alg = struct.unpack(">H", quote_msg[off:off+2])[0]; off += 2
        sel_size = quote_msg[off]; off += 1
        sel = quote_msg[off:off+sel_size]; off += sel_size
        pcrs = []
        for byte_i, b in enumerate(sel):
            for bit in range(8):
                if b & (1 << bit):
                    pcrs.append(byte_i * 8 + bit)
        selections.append({"alg_id": f"0x{alg:04x}", "pcrs": pcrs})

    pd_size = struct.unpack(">H", quote_msg[off:off+2])[0]; off += 2
    pcr_digest = quote_msg[off:off+pd_size]

    return {
        "magic": f"0x{magic:08x}",
        "type": f"0x{type_:04x}",
        "qualified_signer_hex": qualified_signer.hex(),
        "extra_data_hex": extra_data.hex(),
        "pcr_selections": selections,
        "pcr_digest_hex": pcr_digest.hex(),
    }


# ─── crypto ───────────────────────────────────────────────────────────────


def verify_ak_signature(ak_pem: str, signature: bytes, message: bytes) -> bool:
    """Verify RSASSA-PKCS1v1.5-SHA256 over `message` using the AK pubkey.

    Shells out to openssl to avoid adding a `cryptography` dependency.
    Returns True if valid, False otherwise.
    """
    try:
        with tempfile.NamedTemporaryFile(suffix=".pem", delete=False) as keyf, \
             tempfile.NamedTemporaryFile(suffix=".sig", delete=False) as sigf, \
             tempfile.NamedTemporaryFile(suffix=".msg", delete=False) as msgf:
            keyf.write(ak_pem.encode())
            keyf.flush()
            sigf.write(signature)
            sigf.flush()
            msgf.write(message)
            msgf.flush()
            r = subprocess.run(
                ["openssl", "dgst", "-sha256", "-verify", keyf.name,
                 "-signature", sigf.name, msgf.name],
                capture_output=True,
                timeout=10,
            )
            return r.returncode == 0 and b"Verified OK" in r.stdout
    except Exception as e:
        sys.stderr.write(f"verify_ak_signature error: {e}\n")
        return False
    finally:
        for p in (keyf.name, sigf.name, msgf.name):
            try:
                os.unlink(p)
            except Exception:
                pass


def ak_fingerprint(ak_pem: str) -> str:
    """SHA-256 fingerprint of the AK pubkey's DER encoding."""
    try:
        r = subprocess.run(
            ["openssl", "pkey", "-pubin", "-outform", "DER"],
            input=ak_pem.encode(),
            capture_output=True,
            timeout=5,
        )
        if r.returncode == 0:
            return hashlib.sha256(r.stdout).hexdigest()
    except Exception:
        pass
    # Fallback: hash the PEM directly
    return hashlib.sha256(ak_pem.encode()).hexdigest()


def sign_receipt(payload: dict[str, Any]) -> str:
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    return hmac.new(get_secret(), canonical, hashlib.sha256).hexdigest()


def make_receipt(kind: str, body: dict[str, Any]) -> dict[str, Any]:
    receipt = {
        "receipt_id": uuid.uuid4().hex,
        "kind": kind,
        "issued_at": int(time.time()),
        "verifier": "xnode-tpm-verify/0.2",
        "body": body,
    }
    receipt["signature"] = sign_receipt(receipt)
    return receipt


# ─── HTTP handler ─────────────────────────────────────────────────────────


class H(http.server.BaseHTTPRequestHandler):

    def log_message(self, fmt: str, *args: Any) -> None:
        sys.stderr.write(f"[{self.log_date_time_string()}] {self.address_string()} {fmt % args}\n")

    def send_json(self, code: int, body: Any) -> None:
        data = json.dumps(body, indent=2).encode()
        self.send_response(code)
        self.send_header("content-type", "application/json")
        self.send_header("content-length", str(len(data)))
        self.send_header("access-control-allow-origin", "*")
        self.end_headers()
        self.wfile.write(data)

    def send_text(self, code: int, body: str, content_type: str = "text/plain") -> None:
        data = body.encode()
        self.send_response(code)
        self.send_header("content-type", content_type)
        self.send_header("content-length", str(len(data)))
        self.send_header("access-control-allow-origin", "*")
        self.end_headers()
        self.wfile.write(data)

    def read_json(self) -> dict[str, Any]:
        n = int(self.headers.get("content-length", 0))
        if n == 0:
            return {}
        return json.loads(self.rfile.read(n))

    def operator_authed(self) -> bool:
        if not OPERATOR_TOKEN:
            return True            # auth disabled when no token configured
        auth = self.headers.get("authorization", "")
        if not auth.startswith("Bearer "):
            return False
        return hmac.compare_digest(auth[7:], OPERATOR_TOKEN)

    # ── routing ──

    def do_GET(self) -> None:
        path = self.path.split("?", 1)[0]

        if path in ("/", "/health"):
            with LOCK:
                apps = load_apps()
                nodes = load_nodes()
            n_attest = sum(1 for _ in ATTESTATIONS_FILE.open()) if ATTESTATIONS_FILE.exists() else 0
            n_receipts = sum(1 for _ in RECEIPTS_FILE.open()) if RECEIPTS_FILE.exists() else 0
            self.send_json(200, {
                "service": "xnode-tpm-verify",
                "version": "0.2",
                "operator_auth_enabled": bool(OPERATOR_TOKEN),
                "registered_apps": list(apps.keys()),
                "enrolled_nodes": len(nodes),
                "attestations_seen": n_attest,
                "receipts_issued": n_receipts,
                "endpoints": "/api",
            })
            return

        if path == "/api":
            self.send_json(200, {
                "endpoints": [
                    {"method": "POST", "path": "/register-app", "auth": "Bearer $OPERATOR_TOKEN", "body_keys": ["app_name", "version", "expected_pcrs", "closure_hash"]},
                    {"method": "GET",  "path": "/golden/<app>"},
                    {"method": "GET",  "path": "/badge/<app>", "format": "image/svg+xml"},
                    {"method": "POST", "path": "/verify-quote", "body_keys": ["app_name", "client_nonce_hex", "quote_msg_b64", "quote_sig_b64", "ak_pub_pem", "live_pcrs"]},
                    {"method": "POST", "path": "/heartbeat", "body_keys": ["app_name", "client_nonce_hex", "quote_msg_b64", "quote_sig_b64", "ak_pub_pem"]},
                    {"method": "POST", "path": "/task-result", "body_keys": ["attestation_receipt_id", "task_input", "task_output"]},
                    {"method": "GET",  "path": "/receipt/<id>"},
                ],
            })
            return

        if path.startswith("/golden/"):
            name = path[len("/golden/"):]
            with LOCK:
                apps = load_apps()
            if name in apps:
                self.send_json(200, apps[name])
            else:
                self.send_json(404, {"error": f"app '{name}' not registered"})
            return

        if path.startswith("/badge/"):
            self.handle_badge(path[len("/badge/"):])
            return

        if path.startswith("/receipt/"):
            rid = path[len("/receipt/"):]
            r = find_receipt(rid)
            if r:
                self.send_json(200, r)
            else:
                self.send_json(404, {"error": "receipt not found"})
            return

        self.send_json(404, {"error": "no such endpoint"})

    def do_POST(self) -> None:
        path = self.path.split("?", 1)[0]
        try:
            body = self.read_json()
        except Exception as e:
            self.send_json(400, {"error": f"bad json: {e}"})
            return

        if path == "/register-app":
            if not self.operator_authed():
                self.send_json(401, {"error": "operator token required"})
                return
            self.handle_register_app(body)
            return
        if path == "/verify-quote":
            self.handle_verify_quote(body)
            return
        if path == "/heartbeat":
            self.handle_heartbeat(body)
            return
        if path == "/task-result":
            self.handle_task_result(body)
            return

        self.send_json(404, {"error": "no such endpoint"})

    # ── handlers ──

    def handle_register_app(self, body: dict[str, Any]) -> None:
        for k in ("app_name", "version", "expected_pcrs", "closure_hash"):
            if k not in body:
                self.send_json(400, {"error": f"missing field: {k}"})
                return
        with LOCK:
            apps = load_apps()
            apps[body["app_name"]] = {
                "app_name": body["app_name"],
                "version": body["version"],
                "expected_pcrs": body["expected_pcrs"],
                "closure_hash": body["closure_hash"],
                "registered_at": int(time.time()),
            }
            save_apps(apps)
        self.send_json(200, {"ok": True, "registered": apps[body["app_name"]]})

    def _parse_and_verify(self, body: dict[str, Any]) -> tuple[dict[str, Any] | None, str, dict[str, Any]]:
        """Shared verify-quote / heartbeat parse + crypto check.
        Returns (attest_parsed, error_msg_or_empty, meta).
        meta includes ak_fpr, mismatches, expected_pcrs, live_pcrs.
        """
        app_name = body.get("app_name")
        with LOCK:
            apps = load_apps()
        if not app_name or app_name not in apps:
            return None, f"unknown app '{app_name}'", {}
        expected = apps[app_name]

        try:
            quote_msg = base64.b64decode(body["quote_msg_b64"])
            quote_sig = base64.b64decode(body["quote_sig_b64"])
            attest = parse_tpms_attest(quote_msg)
        except Exception as e:
            return None, f"bad quote bytes: {e}", {}

        ak_pem = body.get("ak_pub_pem", "")
        if not ak_pem:
            return None, "ak_pub_pem required", {}

        # AK signature verification (Phase 2)
        if not verify_ak_signature(ak_pem, quote_sig, quote_msg):
            return None, "AK signature on quote.msg failed verification", {}

        # Nonce echo check
        client_nonce = body.get("client_nonce_hex", "").lower()
        if not client_nonce:
            return None, "client_nonce_hex required", {}
        if attest["extra_data_hex"].lower() != client_nonce:
            return None, "nonce mismatch — quote is stale or replayed", {}

        # PCR comparison
        live = {str(k): v.lower() for k, v in body.get("live_pcrs", {}).items()}
        expected_pcrs = {str(k): v.lower() for k, v in expected["expected_pcrs"].items()}
        mismatches = []
        for k, exp in expected_pcrs.items():
            if live.get(k) != exp:
                mismatches.append({"pcr": k, "expected": exp, "live": live.get(k, "(missing)")})

        meta = {
            "ak_fpr": ak_fingerprint(ak_pem),
            "ak_pem": ak_pem,
            "mismatches": mismatches,
            "expected_pcrs": expected_pcrs,
            "live_pcrs": live,
            "client_nonce": client_nonce,
            "app_name": app_name,
        }
        return attest, "", meta

    def _enroll_or_update_node(self, ak_fpr: str, ak_pem: str, app_name: str) -> None:
        with LOCK:
            nodes = load_nodes()
            n = nodes.get(ak_fpr, {
                "ak_fingerprint": ak_fpr,
                "ak_pub_pem": ak_pem,
                "first_seen_at": int(time.time()),
                "apps_attested": [],
            })
            if app_name not in n["apps_attested"]:
                n["apps_attested"].append(app_name)
            n["last_seen_at"] = int(time.time())
            nodes[ak_fpr] = n
            save_nodes(nodes)

    def handle_verify_quote(self, body: dict[str, Any]) -> None:
        attest, err, meta = self._parse_and_verify(body)
        if err:
            self.send_json(400, {"error": err})
            return

        verdict = "attested" if not meta["mismatches"] else "drift"
        self._enroll_or_update_node(meta["ak_fpr"], meta["ak_pem"], meta["app_name"])

        record = {
            "kind": "verify-quote",
            "app_name": meta["app_name"],
            "received_at": int(time.time()),
            "verdict": verdict,
            "ak_fpr": meta["ak_fpr"],
            "client_nonce": meta["client_nonce"],
            "live_pcrs": meta["live_pcrs"],
            "expected_pcrs": meta["expected_pcrs"],
            "mismatches": meta["mismatches"],
            "attest_parsed": attest,
        }
        append_jsonl(ATTESTATIONS_FILE, record)

        receipt = make_receipt("attestation", {
            "app_name": meta["app_name"],
            "verdict": verdict,
            "ak_fpr": meta["ak_fpr"],
            "nonce_echoed": meta["client_nonce"],
            "pcr_digest_in_quote": attest["pcr_digest_hex"],
            "ak_signature_verified": True,
            "mismatches": meta["mismatches"],
            "valid_until": int(time.time()) + 600,
        })
        append_jsonl(RECEIPTS_FILE, receipt)
        self.send_json(200, receipt)

    def handle_heartbeat(self, body: dict[str, Any]) -> None:
        attest, err, meta = self._parse_and_verify(body)
        if err:
            self.send_json(400, {"error": err})
            return

        verdict = "attested" if not meta["mismatches"] else "drift"
        self._enroll_or_update_node(meta["ak_fpr"], meta["ak_pem"], meta["app_name"])

        record = {
            "kind": "heartbeat",
            "app_name": meta["app_name"],
            "received_at": int(time.time()),
            "verdict": verdict,
            "ak_fpr": meta["ak_fpr"],
        }
        append_jsonl(ATTESTATIONS_FILE, record)

        receipt = make_receipt("heartbeat", {
            "app_name": meta["app_name"],
            "verdict": verdict,
            "ak_fpr": meta["ak_fpr"],
            "nonce_echoed": meta["client_nonce"],
            "valid_until": int(time.time()) + 300,
        })
        append_jsonl(RECEIPTS_FILE, receipt)
        self.send_json(200, receipt)

    def handle_task_result(self, body: dict[str, Any]) -> None:
        for k in ("attestation_receipt_id", "task_input", "task_output"):
            if k not in body:
                self.send_json(400, {"error": f"missing field: {k}"})
                return
        prior = find_receipt(body["attestation_receipt_id"])
        if not prior or prior["kind"] not in ("attestation", "heartbeat"):
            self.send_json(400, {"error": "no matching prior attestation/heartbeat receipt"})
            return
        if prior["body"]["verdict"] != "attested":
            self.send_json(400, {"error": "prior attestation was not 'attested'"})
            return
        if prior["body"]["valid_until"] < int(time.time()):
            self.send_json(400, {"error": "prior attestation expired"})
            return

        output_hash = hashlib.sha256(body["task_output"].encode()).hexdigest()
        receipt = make_receipt("task-completion", {
            "app_name": prior["body"]["app_name"],
            "ak_fpr": prior["body"].get("ak_fpr"),
            "input_hash": hashlib.sha256(body["task_input"].encode()).hexdigest(),
            "output_hash": output_hash,
            "output_preview": body["task_output"][:256],
            "linked_attestation": body["attestation_receipt_id"],
            "linked_pcr_digest": prior["body"].get("pcr_digest_in_quote"),
        })
        append_jsonl(RECEIPTS_FILE, receipt)
        self.send_json(200, receipt)

    def handle_badge(self, app: str) -> None:
        wants_svg = "image/svg" in self.headers.get("accept", "") or app.endswith(".svg")
        app = app.removesuffix(".svg")

        with LOCK:
            apps = load_apps()
        if app not in apps:
            self.send_text(404, "app not registered", "text/plain")
            return

        latest = latest_receipt_for_app(app)
        if not latest:
            verdict, color, age = "no-data", "#888", "—"
        else:
            verdict = latest["body"].get("verdict", "?")
            age_s = max(0, int(time.time()) - int(latest["issued_at"]))
            age = f"{age_s//60}m" if age_s >= 60 else f"{age_s}s"
            color = {
                "attested": "#0a7d2c",
                "drift": "#c47b00",
                "no-data": "#888",
            }.get(verdict, "#888")

        if wants_svg:
            svg = self._render_svg_badge(app, verdict, age, color)
            self.send_text(200, svg, "image/svg+xml")
        else:
            html = self._render_html_badge(app, verdict, age, color, latest)
            self.send_text(200, html, "text/html")

    @staticmethod
    def _render_svg_badge(app: str, verdict: str, age: str, color: str) -> str:
        label = f"attested · {age}"
        # crude width estimate
        w_label = max(60, 8 * len(app))
        w_value = max(80, 8 * len(label))
        total = w_label + w_value
        return f'''<svg xmlns="http://www.w3.org/2000/svg" width="{total}" height="20">
  <linearGradient id="b" x2="0" y2="100%">
    <stop offset="0" stop-color="#bbb" stop-opacity=".1"/>
    <stop offset="1" stop-opacity=".1"/>
  </linearGradient>
  <rect rx="3" width="{total}" height="20" fill="#555"/>
  <rect rx="3" x="{w_label}" width="{w_value}" height="20" fill="{color}"/>
  <rect rx="3" width="{total}" height="20" fill="url(#b)"/>
  <g fill="#fff" text-anchor="middle" font-family="DejaVu Sans,Verdana,Geneva,sans-serif" font-size="11">
    <text x="{w_label/2}" y="14">{app}</text>
    <text x="{w_label + w_value/2}" y="14">{label}</text>
  </g>
</svg>'''

    @staticmethod
    def _render_html_badge(app: str, verdict: str, age: str, color: str, latest: dict[str, Any] | None) -> str:
        rid = latest["receipt_id"] if latest else ""
        return f'''<!doctype html><meta charset=utf-8>
<title>{app} — attestation status</title>
<style>
body {{ font-family: system-ui, sans-serif; max-width: 720px; margin: 2em auto; padding: 0 1em; color: #222; }}
.badge {{ display: inline-block; padding: 4px 10px; border-radius: 4px; color: #fff; background: {color}; font-weight: 600; }}
.muted {{ color: #666; font-size: 0.9em; }}
code {{ font-size: 0.85em; }}
</style>
<h1>{app}</h1>
<p><span class="badge">{verdict.upper()}</span> &middot; <span class="muted">attested {age} ago</span></p>
<p class="muted">Receipt: <a href="/receipt/{rid}"><code>{rid}</code></a></p>
'''


class ThreadingHTTPServer(socketserver.ThreadingMixIn, http.server.HTTPServer):
    daemon_threads = True


if __name__ == "__main__":
    sys.stderr.write(f"xnode-tpm-verify listening on 0.0.0.0:{PORT}; state in {STATE_DIR}\n")
    sys.stderr.write(f"operator_auth_enabled={bool(OPERATOR_TOKEN)}\n")
    sys.stderr.flush()
    ThreadingHTTPServer(("0.0.0.0", PORT), H).serve_forever()
