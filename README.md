# xnode-tpm-verify

A minimal TPM 2.0 attestation **verifier** service. Companion to
[`xnode-tpm-attest`](https://github.com/johnforfar/xnode-tpm-attest)
(the prover side).

This is the service a node sends its quote bundles to. It validates the
attestation key's signature on the quote, compares live PCR values
against operator-pinned expected values, returns a verdict, and issues
short-lived signed receipts.

## Status — v0.2 (Phase 2 shipped)

Now in production-ready state for non-confidential workloads:

- ✅ Server-side AK signature verification (RSASSA-PKCS1v1.5-SHA256 via openssl)
- ✅ Bearer-token auth on operator endpoints (env: `OPERATOR_TOKEN`)
- ✅ `/heartbeat` for continuous attestation (lighter than full `/verify-quote`)
- ✅ `/badge/<app>` returning HTML or SVG for embedding in any frontend
- ✅ Node enrollment ledger captures `(ak_fingerprint, ak_pub_pem, apps_attested)`
- ✅ Receipts include `ak_signature_verified: true` + `ak_fpr` for chain-of-custody

Phase 2.5 deferred (documented in caller's engineering handoff):
- EIP-712 wallet auth (replaces bearer; clean integration via xnode-auth)
- TPM-sealed credentials (`tpm2_makecredential` server-side)
- ed25519 receipt signing (third-party verifiable, replaces HMAC)
- Full Intel On-Die CA chain validation (intermediate not publicly downloadable)

## Endpoints

| Method | Path | Caller | Auth | Purpose |
|---|---|---|---|---|
| GET | `/` | anyone | — | health + summary stats |
| GET | `/api` | anyone | — | machine-readable endpoint index |
| POST | `/register-app` | operator | `Bearer $OPERATOR_TOKEN` | pin golden values for an app version |
| GET | `/golden/<app>` | anyone | — | read pinned values |
| GET | `/badge/<app>[.svg]` | anyone | — | HTML or SVG status badge for embedding |
| POST | `/verify-quote` | node (prover) | AK signature on quote | submit quote, get verdict + attestation receipt |
| POST | `/heartbeat` | node (prover) | AK signature on quote | continuous attestation (lighter, shorter TTL) |
| POST | `/task-result` | node (prover) | links to prior receipt_id | submit task output, get task-completion receipt |
| GET | `/receipt/<id>` | anyone | — | read a previously-issued receipt |

## Deploying

As an xnode-app via `om`:

```sh
om app deploy --flake github:johnforfar/xnode-tpm-verify xnode-tpm-verify --wait true
om app expose xnode-tpm-verify --port 8080 --domain attest.<your-xnode-domain>
```

Set the operator token (optional but recommended in production) via a
secrets file the systemd unit auto-loads:

```sh
echo 'OPERATOR_TOKEN=...random_64_hex...' \
  > /run/secrets/xnode-tpm-verify.env
```

After that, anyone can query `https://attest.<your-xnode-domain>/`.

## Demo flow (verified end-to-end)

```
1. operator: POST /register-app    pin app + closure hash
2. prover:   GET  /golden/<app>    fetch what verifier expects
3. prover:   tpm2 pcrextend 16:sha256=<binary_hash>
             tpm2 pcrextend 16:sha256=<model_hash>
4. prover:   tpm2 quote             with verifier-supplied nonce
5. prover:   POST /verify-quote     with quote + AK pubkey + live PCRs
6. verifier: parse, openssl-verify AK sig, compare PCRs
             → attestation receipt
7. prover:   run real task (Qwen3 inference, image gen, etc.)
8. prover:   POST /task-result      input + output hashes + prior receipt
9. verifier: validate prior is fresh + attested
             → task-completion receipt linking input → output → attestation
```

## Embedding the badge in your app frontend

Three patterns — all load from the verifier directly so the source
can't lie about its own attestation status:

```html
<!-- iframe (simplest) -->
<iframe src="https://attest.<your-xnode-domain>/badge/<app>"
        width="100%" height="60" frameborder="0"></iframe>

<!-- inline SVG with click-through to the receipt -->
<a href="https://attest.<your-xnode-domain>/receipt/<latest-id>">
  <img src="https://attest.<your-xnode-domain>/badge/<app>.svg">
</a>

<!-- JS polling for live updates -->
<div id="attest-status">…</div>
<script>
  async function refresh() {
    const r = await fetch('https://attest.<your-xnode-domain>/badge/<app>');
    document.getElementById('attest-status').innerHTML = await r.text();
  }
  refresh(); setInterval(refresh, 60_000);
</script>
```

## Storage layout

```
$STATE_DIR/
├── apps.json           registered apps + golden values
├── nodes.json          enrolled node ledger (ak_fingerprint → metadata)
├── attestations.jsonl  audit log of all submitted quotes
├── receipts.jsonl      audit log of all issued receipts
└── verifier.secret     HMAC key (auto-generated, mode 0600)
```

State is JSON-file backed for simplicity; production rollout would swap
in SQLite or PostgreSQL with the same schema.

## Engineering handoff

For full architecture, threat model, integration recipes, and Phase 3
roadmap, see the consuming project's engineering doc (private
documentation; pointer available on request).

## License

MIT.
