# AIGIS Core – Transaction Verifier in Rust

[![Rust](https://img.shields.io/badge/rust-1.85%2B-blue)](https://www.rust-lang.org/)
[![License](https://img.shields.io/badge/license-MIT%2FApache--2.0-blue)](LICENSE)

**AIGIS Core** is a demonstration project that combines **post‑quantum cryptography**, **formal verification**, and a **tamper‑evident audit log** in a single Rust codebase.

It is **not** a production system – it is a portfolio piece that shows how I build reliable, idiomatic Rust.

---

## What’s inside

| Feature | Technology | What it does |
|---------|------------|---------------|
| Post‑quantum key exchange | Kyber‑1024 (KEM) | Encapsulate / decapsulate shared secrets |
| Post‑quantum signatures | Dilithium‑5 | Identity and authentication |
| Formal verification | Z3 theorem prover | Check transaction amounts against rules |
| Immutable audit log | BLAKE3 + chaining | Tamper‑evident event history |
| Async HTTP server | Axum / Tokio | REST API for transactions |

All secrets are zeroised on drop (`zeroize` crate). No panics, proper error handling, and test coverage.

---

## Quick start

```bash
git clone https://github.com/yourusername/aigis-core
cd aigis-core
cargo run --bin server

The server will start on http://0.0.0.0:3000.
Example request
bash

curl -X POST http://localhost:3000/api/tx \
  -H "Content-Type: application/json" \
  -d '{"amount": 500000, "ciphertext_hex": "..."}'

    The ciphertext_hex field expects a valid Kyber‑1024 ciphertext (hex encoded).
    For testing, you can generate one using the encapsulate method from QuantumIdentity.

Project structure
text

src/
├── audit_log.rs            # blockchain‑style audit trail
├── post_quantum_identity.rs # Kyber + Dilithium, zeroised secrets
├── z3_verifier.rs          # global Z3 solver for amount checks
└── axum_server.rs          # async HTTP server entrypoint
examples/
└── audit_demo.rs           # standalone audit log example

Running tests
bash

cargo test

All modules have unit tests that verify correctness (integrity checks, encap/decap roundtrip, Z3 constraints).
Why this project matters

This code shows that I understand:

    Low‑level systems programming – ownership, lifetimes, concurrency, async

    Cryptographic primitives – post‑quantum KEM and signatures, secure memory

    Formal methods – using Z3 as a library from Rust

    Defensive design – tamper‑evident logs, error handling, no panics

    Production tooling – HTTP, testing, zeroisation

It reflects the way I write code for real environments: correct, readable, and maintainable.
Technologies
Technology	Purpose
Rust 2021 edition	Core language
Axum + Tokio	Async web framework
pqcrypto-kyber / pqcrypto-dilithium	Post‑quantum algorithms
z3 (Rust bindings)	Theorem prover
blake3	Fast, secure hashing
zeroize	Automatic secret zeroisation
hex, serde, chrono	Utilities
License

This project is dual‑licensed under the MIT license or the Apache License 2.0, at your option.
Author

Anton Vylderov – GitHub – LinkedIn

I am currently open for Rust / Backend roles in Germany (remote or on‑site). Visa support required.
