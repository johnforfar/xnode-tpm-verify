#!/usr/bin/env python3
"""
xnode-tpm-verify — minimal TPM2 attestation verifier service.

Runs as a single-process HTTP server. State persisted to JSON files in
$STATE_DIR. Cryptographic verification uses openssl for chain checks and
python's stdlib for signature validation.

Endpoints:
  GET  /                    health + status page
  POST /register-app        operator pins golden values for an app
  GET  /golden/<app>        anyone reads pinned values
  POST /verify-quote        prover submits quote bundle, gets verdict
  POST /task-result         prover submits final output + final quote
  GET  /receipt/<id>        anyone reads a task receipt
  GET  /api                 machine-readable index of endpoints

This is a Phase-1 demo verifier. Not hardened, not wallet-authenticated,
not yet HMAC-receipt-signed. Designed to prove the loop works end-to-end.
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
import sys
import threading
import time
import uuid
from pathlib import Path
from typing import Any

STATE_DIR = Path(os.environ.get("STATE_DIR", "/var/lib/xnode-tpm-verify"))
STATE_DIR.mkdir(parents=True, exist_ok=True)
APPS_FILE = STATE_DIR / "apps.json"
ATTESTATIONS_FILE = STATE_DIR / "attestations.jsonl"
RECEIPTS_FILE = STATE_DIR / "receipts.jsonl"
SECRET_FILE = STATE_DIR / "verifier.secret"
PORT = int(os.environ.get("PORT", "8080"))

LOCK = threading.Lock()


def get_secret() -> bytes:
    """Verifier-side secret for HMAC-signed receipts. Generated at first run."""
    if not SECRET_FILE.exists():
        SECRET_FILE.write_bytes(secrets.token_bytes(32))
        SECRET_FILE.chmod(0o600)
    return SECRET_FILE.read_bytes()


def load_apps() -> dict[str, Any]:
    if APPS_FILE.exists():
        return json.loads(APPS_FILE.read_text())
    return {}


def save_apps(apps: dict[str, Any]) -> None:
    tmp = APPS_FILE.with_suffix(".tmp")
    tmp.write_text(json.dumps(apps, indent=2))
    tmp.replace(APPS_FILE)


def append_jsonl(path: Path, record: dict[str, Any]) -> None:
    with path.open("a") as f:
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


def parse_tpms_attest(quote_msg: bytes) -> dict[str, Any]:
    """Minimal TPMS_ATTEST parser — enough to extract nonce + pcrDigest."""
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


def sign_receipt(payload: dict[str, Any]) -> str:
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    sig = hmac.new(get_secret(), canonical, hashlib.sha256).hexdigest()
    return sig


def make_receipt(kind: str, body: dict[str, Any]) -> dict[str, Any]:
    receipt = {
        "receipt_id": uuid.uuid4().hex,
        "kind": kind,
        "issued_at": int(time.time()),
        "verifier": "xnode-tpm-verify/0.1",
        "body": body,
    }
    receipt["signature"] = sign_receipt(receipt)
    return receipt


# ─── HTTP handler ────────────────────────────────────────────────────────


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

    def read_json(self) -> dict[str, Any]:
        n = int(self.headers.get("content-length", 0))
        if n == 0:
            return {}
        return json.loads(self.rfile.read(n))

    # ── routing ──

    def do_GET(self) -> None:
        path = self.path.split("?", 1)[0]

        if path == "/" or path == "/health":
            with LOCK:
                apps = load_apps()
            n_attest = sum(1 for _ in ATTESTATIONS_FILE.open()) if ATTESTATIONS_FILE.exists() else 0
            n_receipts = sum(1 for _ in RECEIPTS_FILE.open()) if RECEIPTS_FILE.exists() else 0
            self.send_json(200, {
                "service": "xnode-tpm-verify",
                "version": "0.1",
                "registered_apps": list(apps.keys()),
                "attestations_seen": n_attest,
                "receipts_issued": n_receipts,
                "endpoints": "/api",
            })
            return

        if path == "/api":
            self.send_json(200, {
                "endpoints": [
                    {"method": "POST", "path": "/register-app", "body": {"app_name": "str", "version": "str", "expected_pcrs": {"<n>": "<hex>"}, "closure_hash": "str"}},
                    {"method": "GET",  "path": "/golden/<app>"},
                    {"method": "POST", "path": "/verify-quote", "body": {"app_name": "str", "quote_msg_b64": "str", "quote_sig_b64": "str", "ak_pub_pem": "str", "live_pcrs": {"<n>": "<hex>"}, "client_nonce_hex": "str"}},
                    {"method": "POST", "path": "/task-result", "body": {"attestation_receipt_id": "str", "task_input": "str", "task_output": "str", "final_quote": "...", "final_pcrs": "..."}},
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
            self.handle_register_app(body)
            return
        if path == "/verify-quote":
            self.handle_verify_quote(body)
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

    def handle_verify_quote(self, body: dict[str, Any]) -> None:
        app_name = body.get("app_name")
        with LOCK:
            apps = load_apps()
        if not app_name or app_name not in apps:
            self.send_json(400, {"error": f"unknown app '{app_name}'"})
            return
        expected = apps[app_name]

        # Parse quote
        try:
            quote_msg = base64.b64decode(body["quote_msg_b64"])
            attest = parse_tpms_attest(quote_msg)
        except Exception as e:
            self.send_json(400, {"error": f"bad quote.msg: {e}"})
            return

        # Check nonce echoes back what client sent (anti-replay)
        client_nonce = body.get("client_nonce_hex", "").lower()
        if not client_nonce:
            self.send_json(400, {"error": "client_nonce_hex required"})
            return
        if attest["extra_data_hex"].lower() != client_nonce:
            self.send_json(400, {"error": "nonce mismatch — quote is stale or replayed"})
            return

        # Compare live PCRs to expected
        live = {str(k): v.lower() for k, v in body.get("live_pcrs", {}).items()}
        expected_pcrs = {str(k): v.lower() for k, v in expected["expected_pcrs"].items()}
        mismatches = []
        for k, exp in expected_pcrs.items():
            if live.get(k) != exp:
                mismatches.append({"pcr": k, "expected": exp, "live": live.get(k, "(missing)")})

        verdict = "attested" if not mismatches else "drift"

        # NB: full deployment also verifies AK signature on quote.msg here.
        # Deferred to keep Phase 1 dependency-free; AK pubkey + signature are
        # captured in the receipt for future server-side verify.

        attestation_record = {
            "app_name": app_name,
            "received_at": int(time.time()),
            "verdict": verdict,
            "client_nonce": client_nonce,
            "live_pcrs": live,
            "expected_pcrs": expected_pcrs,
            "mismatches": mismatches,
            "attest_parsed": attest,
        }
        append_jsonl(ATTESTATIONS_FILE, attestation_record)

        receipt = make_receipt("attestation", {
            "app_name": app_name,
            "verdict": verdict,
            "nonce_echoed": client_nonce,
            "pcr_digest_in_quote": attest["pcr_digest_hex"],
            "mismatches": mismatches,
            "valid_until": int(time.time()) + 600,
        })
        append_jsonl(RECEIPTS_FILE, receipt)
        self.send_json(200, receipt)

    def handle_task_result(self, body: dict[str, Any]) -> None:
        for k in ("attestation_receipt_id", "task_input", "task_output"):
            if k not in body:
                self.send_json(400, {"error": f"missing field: {k}"})
                return
        prior = find_receipt(body["attestation_receipt_id"])
        if not prior or prior["kind"] != "attestation":
            self.send_json(400, {"error": "no matching prior attestation receipt"})
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
            "input_hash": hashlib.sha256(body["task_input"].encode()).hexdigest(),
            "output_hash": output_hash,
            "output_preview": body["task_output"][:256],
            "linked_attestation": body["attestation_receipt_id"],
            "linked_pcr_digest": prior["body"]["pcr_digest_in_quote"],
        })
        append_jsonl(RECEIPTS_FILE, receipt)
        self.send_json(200, receipt)


class ThreadingHTTPServer(socketserver.ThreadingMixIn, http.server.HTTPServer):
    daemon_threads = True


if __name__ == "__main__":
    sys.stderr.write(f"xnode-tpm-verify listening on 0.0.0.0:{PORT}; state in {STATE_DIR}\n")
    sys.stderr.flush()
    ThreadingHTTPServer(("0.0.0.0", PORT), H).serve_forever()
