# Quard

A small zero-trust decision gateway: a Rust HTTP service receives a security
event, asks a Python/ONNX model for a risk score, applies a policy
(`ALLOW` / `DENY` / `ISOLATE`) and writes every decision to a hash-chained
audit log. Since v0.1.1 it also ships post-quantum cryptography (ML-KEM-768,
ML-DSA-65) and can sign its audit log with a quantum-resistant signature.

> **Status: experimental / educational.** The model is trained on *synthetic*
> data and the identity check is a static allow-list. It has not been
> security-audited. Do not use it as-is to protect production systems.

## Layout

| Path | What it is |
|------|------------|
| `src/`, `tests/` | Rust gateway (axum), policy, isolation state machine, audit log, crypto helpers |
| `ai/` | PyTorch training, ONNX export, int8 quantization, FastAPI inference service |
| `src/pqc/` | Post-quantum crypto: ML-KEM-768, ML-DSA-65, HKDF, AES-256-GCM, SHA3-256, sealed envelopes |
| `cpp/` | Eigen-based math engine, liboqs ML-KEM test, Google Benchmark target |
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
| `QS_PQC_KEY_PATH` | *(unset = signing off)* | Path of the ML-DSA-65 audit signing key. Created (mode 0600) with a `.pub` file if missing |
| `QUARD_MODELS_DIR` | `./models` | Where the Python side finds model files |

Decisions: risk `< 0.70` -> `ALLOW` (200); `0.70 .. 0.95` -> `DENY` (403);
`>= 0.95` -> `ISOLATE` (403). Invalid scores are always denied.

## Post-quantum features

| Feature | Algorithm | Where |
|---------|-----------|-------|
| Key encapsulation | ML-KEM-768 (FIPS 203) | `pqc::kem` |
| Signatures | ML-DSA-65 (FIPS 204) | `pqc::signature` |
| Key derivation | HKDF-SHA256 | `pqc::key_derivation` |
| Authenticated encryption | AES-256-GCM | `pqc::encryption` |
| Hashing | SHA3-256 | `pqc::integrity` |
| Seal/open to a public key | ML-KEM + HKDF + AES-GCM | `pqc::envelope` |
| Tamper-proof audit log | ML-DSA-65 over every record hash | `audit`, `QS_PQC_KEY_PATH` |

Signed audit log:

```bash
export QS_PQC_KEY_PATH=keys/audit_key.hex     # created on first start
cargo run --release
# later, anywhere (needs only the PUBLIC key):
cargo run --release -- verify-audit logs/audit.jsonl keys/audit_key.hex.pub
```

Keep `audit_key.hex` secret and out of git (it is in `.gitignore`); publish or
archive `audit_key.hex.pub` so others can verify. Each signed record adds about
6.9 KB (a 3309-byte signature in hex).

Existing hash-only logs keep working; `verify-audit` without a key file checks
the hash chain only, with a key file it also requires every record to be signed.

## Tests

```bash
cargo test                              # Rust
python -m pytest                        # Python (model tests skip if no model is built)
python verification/z3/policy.py        # Z3 proofs
python verification/z3/pqc_policy.py    # Z3 proofs, signature-aware policy
cmake -S . -B build && cmake --build build && ctest --test-dir build   # C++
# ML-KEM C++ test additionally needs liboqs:  -DQUARD_BUILD_PQC_TESTS=ON -DCMAKE_PREFIX_PATH=<liboqs>
cd verification/tla && java -cp tla2tools.jar tlc2.TLC -config system.cfg system.tla
```

Lean (`lean verification/lean/Theorem.lean`) and Verus
(`verus --crate-type=lib verification/verus/score.rs`) need their own toolchains.

## Known limitations

* Identity is a static user-id allow-list; there is no separate authorization layer yet.
* `src/isolation.rs` (state machine) is tested and modelled in TLA+ but not yet wired into the API.
* Without `QS_PQC_KEY_PATH` the audit log is only tamper-*evident*: someone with write
  access can rewrite the whole file. With signing on, forging records requires the signing key.
* `policy::evaluate_signed` (requests must carry a valid PQ signature) is implemented, tested and
  modelled in Z3, but the HTTP API does not accept signed requests yet.
* ML-KEM/ML-DSA come from the RustCrypto `ml-kem` and `ml-dsa` crates, which are not independently
  audited or FIPS 140-validated. Review before relying on them for anything critical.
* The AI service is unauthenticated; run it on localhost or a private network only.

## License

Licensed under the [MIT License](LICENSE).
Copyright (c) 2026 [YOUR NAME].

### Third-party software

Quard links against, but does not modify or redistribute the source of, the
following. All are under permissive licenses compatible with the MIT license.

* **Rust crates** (212 incl. transitive): MIT, Apache-2.0, BSD-2/3-Clause, ISC, Zlib,
  Unicode-3.0, CDLA-Permissive-2.0 (e.g. tokio, axum, ml-kem, ml-dsa, aes-gcm, ed25519-dalek).
  A few are dual-licensed with an extra copyleft option (e.g. LGPL); the MIT/Apache option applies.
* **Python**: PyTorch, NumPy, pandas, scikit-learn, uvicorn (BSD-3-Clause);
  ONNX (Apache-2.0); ONNX Runtime, FastAPI, z3-solver (MIT).
* **C++**: liboqs (MIT, with some Apache-2.0/CC0 components; test-only); Eigen (MPL-2.0, file-level copyleft; fine as long as you don't modify
  Eigen's own files, or you publish those modifications), Google Benchmark (Apache-2.0).
  <img width="1536" height="1024" alt="image" src="https://github.com/user-attachments/assets/2e8ede27-4bf7-4ba8-9f19-cd8db0f6a7d4" />

