# Log shipping and receiver (v1)

Every guard can ship its audit entries to a receiver the operator does not
control, so the local hash chain becomes **third-party evidence**.

- **Sender** lives in the MIT SDK: `safety_protocol.shipping`.
- **Receiver** lives in the BSL platform layer:
  `safety_protocol.platform.receiver`.

## 1. Event format

One JSON object per guard decision. The canonical form for hashing is sorted
keys, no whitespace, UTF-8 (`safety_protocol.shipping.canonical_json`).

```json
{
  "v": 1,
  "event_id": "uuid4",
  "agent_id": "agent-001",
  "seq": 42,
  "ts": "2026-10-14T18:03:11Z",
  "action_type": "api_call",
  "target": "https://api.example.com/v1/search",
  "method": "POST",
  "cost": 2.5,
  "params_digest": "sha256-hex of canonical params",
  "param_keys": ["query"],
  "policy_decision": "allowed",
  "decision": "allowed",
  "rule_id": "rule-0",
  "reason": null,
  "mode": "enforce",
  "config_hash": "sha256-hex of active config",
  "prev_hash": "64 zeros for seq 1, otherwise previous event's hash",
  "hash": "sha256-hex of this event with the hash field removed"
}
```

- `decision` is what actually happened: `allowed | denied | needs_approval |
  approved | rejected | killswitch`.
- `policy_decision` is what the policy said. In `enforce` mode the two are
  always equal. In `shadow` mode `decision` is `allowed` and `policy_decision`
  shows what *would* have been blocked.
- `seq` is monotonic per agent with no gaps, starting at 1.
- `config_hash` proves which limits were in force at that moment.
- **Privacy default:** raw params are never shipped — only `params_digest` and
  `param_keys`. Set `log_params` to `"none"` (default), `"redacted"` (values
  for keys matching `key|token|secret|password|auth` are masked `***`), or
  `"full"`.

## 2. Guard-side config

```json
"shipping": {
  "receiver_url": "https://logs.example.com",
  "api_key": "per-agent key",
  "batch_size": 50,
  "flush_interval_s": 5,
  "heartbeat_interval_s": 60,
  "log_params": "none",
  "outbox_dir": ".safety_outbox/agent-001"
},
"mode": "enforce"
```

Shipping is asynchronous — the action never waits on the receiver. Events are
written to a durable local outbox (JSONL + state file) first, then sent in
batches. The outbox survives restarts and retries with backoff. The heartbeat
is a background push, separate from `/health`.

`mode: "shadow"` logs `policy_decision` but returns `allowed` for everything
the policy would have denied. The kill switch and a revoked binding still
block in shadow mode.

Wire it up:

```python
from safety_protocol import build_protocol_from_config, shipper_from_config

cfg = json.load(open("guard_config.json"))
protocol, _ = build_protocol_from_config(cfg)
shipper = shipper_from_config(cfg)
protocol.add_decision_sink(shipper.emit)   # every decision is now shipped
shipper.start()                            # background flush + heartbeat
```

The `GuardService` (platform) does this automatically when the config has a
`shipping` block. `GET /receipts` returns the latest stored receipt and
shipping status; `GET /health` includes a `shipping` section.

For a one-shot check: `safety-guard check ... --ship` emits and flushes once,
returning the receipt inline.

## 3. Receiver endpoints

Auth: `Authorization: Bearer <agent api key>` on ingest. Admin endpoints use a
separate admin key.

| Method | Path | Purpose |
| --- | --- | --- |
| POST | `/v1/events` | Ingest batch (max 100 events) |
| POST | `/v1/heartbeat` | `{agent_id, ts, head_seq, head_hash, mode, config_hash, guard_version}` |
| GET | `/v1/agents/{id}/events` | Query: `from`, `to`, `decision`, `limit` |
| GET | `/v1/agents/{id}/verify` | Re-verify the stored chain |
| GET | `/v1/agents/{id}/report?month=YYYY-MM` | JSON summary |
| POST | `/v1/admin/clients` | Create a client |
| POST | `/v1/admin/agents` | Create an agent; returns its API key once, stores only the hash |

Ingest verifies each event's own hash, that `prev_hash` matches the stored head
and `seq` is `head + 1`. It is idempotent (an identical resend is accepted
silently). A same-`seq`-different-`hash` event is rejected as a **fork**. On a
gap or mismatch it returns `409` with `{expected_seq, expected_prev_hash}` so
the sender can resend from there.

On success it returns a signed receipt:

```json
{
  "agent_id": "agent-001",
  "head_seq": 42,
  "head_hash": "…",
  "received_at": "2026-10-14T18:03:12Z",
  "sig": "Ed25519 signature over the four fields above",
  "sig_alg": "ed25519"
}
```

The receipt is the evidence: a specific chain head existed at a specific time,
recorded by the receiver, not the partner. Guards store receipts locally
(`Outbox.latest_receipt`) and the report includes the latest one.

`/verify` returns `{ok, head_seq, head_hash, first_break}`, where `first_break`
is the first `seq` where recomputation fails, or `null`.

`sig_alg` is `ed25519` when the `cryptography` dependency is installed, else
`hmac-sha256` with a receiver-held secret (still a verifiable MAC).

## 4. Storage

SQLite on the VPS. Tables: `clients`, `agents` (API-key hash), `events`,
`receipts`, `heartbeats`, `meta` (receipt signing key). Append-only: no UPDATE
or DELETE is issued against `events` or `receipts` anywhere in the code. Back
the database file up nightly, off the VPS.

## 5. Run the receiver

```bash
pip install "cryptography>=42"          # for Ed25519 receipts (optional)
export RECEIVER_ADMIN_KEY=change-me
python -m safety_protocol.platform.receiver --db receiver.db --port 8787
```

Create a client and an agent (the key is shown once):

```bash
curl -s -XPOST localhost:8787/v1/admin/clients \
  -H "Authorization: Bearer $RECEIVER_ADMIN_KEY" \
  -d '{"client_id":"acme","name":"Acme"}'

curl -s -XPOST localhost:8787/v1/admin/agents \
  -H "Authorization: Bearer $RECEIVER_ADMIN_KEY" \
  -d '{"agent_id":"agent-001","client_id":"acme"}'
```
