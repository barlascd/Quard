# Quard

A small zero-trust decision gateway: a Rust HTTP service receives a security
event, asks a Python/ONNX model for a risk score, applies a policy
(`ALLOW` / `DENY` / `ISOLATE`) and writes every decision to a hash-chained
audit log.

> **Status: experimental / educational.** The model is trained on *synthetic*
> data and the identity check is a static allow-list. It has not been
> security-audited. Do not use it as-is to protect production systems.

## Layout

| Path | What it is |
|------|------------|
| `src/`, `tests/` | Rust gateway (axum), policy, isolation state machine, audit log, crypto helpers |
| `ai/` | PyTorch training, ONNX export, int8 quantization, FastAPI inference service |
| `cpp/` | Eigen-based math engine, tests and a Google Benchmark target |
| `verification/` | Z3 policy proofs, TLA+ state-machine model, Lean and Verus examples |

## Quick start

```bash
# 1. Build the model (writes models/*.onnx and models/scaler.json)
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
python -m ai.train
python -m ai.export_model
python -m ai.quantize

# 2. Start the AI service (port 8000)
uvicorn ai.server:app --port 8000

# 3. Start the gateway (port 3000), in another terminal
export QS_API_TOKEN="$(openssl rand -hex 32)"
export QS_AUTHORIZED_USERS="alice,bob"
cargo run --release

# 4. Query it
curl -X POST localhost:3000/v1/security/check \
  -H "Authorization: Bearer $QS_API_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"user_id":"alice","resource":"/db","action":"read","features":[10,0,0.2,5]}'
```

`features` = `[request_rate, failed_logins, cpu_fraction (0..1), process_count]`.

| Variable | Default | Meaning |
|----------|---------|---------|
| `QS_API_TOKEN` | *(required, >= 32 chars)* | Bearer token for the API |
| `QS_AUTHORIZED_USERS` | empty (nobody allowed) | Comma-separated allow-list |
| `QS_BIND` | `127.0.0.1:3000` | Gateway address |
| `QS_AI_URL` | `http://127.0.0.1:8000/predict` | AI service endpoint |
| `QS_AUDIT_PATH` | `logs/audit.jsonl` | Audit log file |
| `QUARD_MODELS_DIR` | `./models` | Where the Python side finds model files |

Decisions: risk `< 0.70` -> `ALLOW` (200); `0.70 .. 0.95` -> `DENY` (403);
`>= 0.95` -> `ISOLATE` (403). Invalid scores are always denied.

## Tests

```bash
cargo test                              # Rust
python -m pytest                        # Python (model tests skip if no model is built)
python verification/z3/policy.py        # Z3 proofs
cmake -S . -B build && cmake --build build && ctest --test-dir build   # C++
cd verification/tla && java -cp tla2tools.jar tlc2.TLC -config system.cfg system.tla
```

Lean (`lean verification/lean/Theorem.lean`) and Verus
(`verus --crate-type=lib verification/verus/score.rs`) need their own toolchains.

## Known limitations

* Identity is a static user-id allow-list; there is no separate authorization layer yet.
* `src/isolation.rs` (state machine) is tested and modelled in TLA+ but not yet wired into the API.
* The audit log is tamper-*evident* (verify with `audit::verify_chain`), not tamper-proof:
  someone with write access can rewrite the whole file.
* The AI service is unauthenticated; run it on localhost or a private network only.

## License

Licensed under the [Apache License, Version 2.0](LICENSE).
Copyright 2026 [YOUR NAME].

### Third-party software

Quard links against, but does not modify or redistribute the source of, the
following. All are under permissive licenses compatible with Apache-2.0.

* **Rust crates** (178 incl. transitive): MIT, Apache-2.0, BSD-3-Clause, ISC,
  Unicode-3.0, CDLA-Permissive-2.0 (e.g. tokio, axum, serde, ed25519-dalek, rustls).
* **Python**: PyTorch, NumPy, pandas, scikit-learn, uvicorn (BSD-3-Clause);
  ONNX (Apache-2.0); ONNX Runtime, FastAPI, z3-solver (MIT).
* **C++**: Eigen (MPL-2.0, file-level copyleft; fine as long as you don't modify
  Eigen's own files, or you publish those modifications), Google Benchmark (Apache-2.0).
