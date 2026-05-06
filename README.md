# xnode-tpm-verify

A minimal TPM 2.0 attestation **verifier** service. Companion to
[`xnode-tpm-attest`](https://github.com/johnforfar/xnode-tpm-attest)
(the prover side).

This is the service a node sends its quote bundles to. It compares
live PCR values against operator-pinned expected values, returns a
verdict, and issues short-lived signed receipts.

## Status — Phase 1 (demo)

This is the smallest possible implementation that proves the
end-to-end attestation loop works. Stateless except for a JSON-file
ledger; HMAC-signed receipts (not yet wallet-signed); no TLS at the
service level (terminate at xnode-manager's reverse proxy).

Production hardening (wallet-signed receipts, full AK signature
verification server-side, multi-verifier federation) is out of scope
for Phase 1 and explicitly deferred.

## Endpoints

| Method | Path | Caller | Purpose |
|---|---|---|---|
| GET | `/` | anyone | health + summary stats |
| GET | `/api` | anyone | machine-readable endpoint index |
| POST | `/register-app` | operator | pin golden values for an app version |
| GET | `/golden/<app>` | anyone | read pinned values |
| POST | `/verify-quote` | node (prover) | submit quote, get verdict + receipt |
| POST | `/task-result` | node (prover) | submit task output + final receipt |
| GET | `/receipt/<id>` | anyone | read a previously-issued receipt |

## Deploying

As an xnode-app via `om`:

```sh
om app deploy --flake github:johnforfar/xnode-tpm-verify xnode-tpm-verify --wait true
om app expose xnode-tpm-verify --port 8080 --domain attest.<your-xnode-domain>
```

After that, anyone can query `https://attest.<your-xnode-domain>/`.

## Demo flow

1. Operator: `POST /register-app` with the expected closure hash + PCR
   values for an app (e.g. `hello-attested`)
2. Node: `GET /golden/<app>` to fetch what the verifier expects
3. Node: extends PCR 16 with `sha256(closure)`, runs `tpm2_quote` over a
   verifier-supplied nonce
4. Node: `POST /verify-quote` with the bundle
5. Verifier: parses the quote, checks nonce echoes back, compares PCRs,
   returns receipt with verdict
6. Node runs the task (whatever the app does), POSTs `/task-result`
7. Verifier issues a task-completion receipt linking input → output → attestation

## Storage layout

```
$STATE_DIR/
├── apps.json           registered apps + golden values
├── attestations.jsonl  audit log of all submitted quotes
├── receipts.jsonl      audit log of all issued receipts
└── verifier.secret     HMAC key (auto-generated, mode 0600)
```

## License

MIT.
