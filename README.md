# eVoting Cryptographic Library (Rust)

This repository implements a verifiable end-to-end voting protocol
based on ElGamal encryption and Sigma protocols.

## ⚠ Security Disclaimer

This codebase is meant for **research, evaluation, and prototyping**, not for production use.

## High-level overview

TODO

## Roles

The code is structured around four explicit roles:

**Client (Voter).**  
The client runs on the voter device and is responsible for all voter-side cryptography. It generates a voter key pair, receives a voting credential from the Registration Teller, constructs ballots with zero-knowledge proofs, and submits them to the bulletin board. The client can locally verify the correctness of the PIN associated with its credential. No plaintext vote information is ever revealed by the client.

**Registration Teller (RT).**  
The Registration Teller is trusted for eligibility but not for vote privacy. It issues PIN-bound voting credentials and produces credential control proofs that allow invalid or unauthorized ballots to be filtered later in the pipeline. The RT never learns voter choices and never decrypts votes.

**Bulletin Board (BB).**  
The Bulletin Board acts as an append-only public log and hosts the public verification pipeline. It stores ballots together with deterministic receipts, verifies ballot proofs, performs vote and credential shuffles with zero-knowledge proofs, filters invalid ballots, enforces revoting semantics, and homomorphically aggregates encrypted votes. All BB computations are publicly verifiable and can be re-run independently by any observer, auditor, or authority.

**Tabulation Teller (TT).**  
The Tabulation Teller is trusted exclusively for decryption. It produces verifiable decryptions for credential validity checks, credential fingerprint matching, and final tally decryption. The TT outputs are publicly verifiable and can be checked by anyone.

## Performance measurements

The repository includes an ignored integration test that executes the full end-to-end protocol and reports wall-clock timings and serialized sizes of public artifacts. Measurements are aggregated per protocol step and per role (Client, BB, RT, TT).

The test can be run in optimized mode with:
```
cargo test --release --test bench_pipeline -- --ignored --nocapture
```

The results show that the Bulletin Board dominates runtime. This is expected, as the BB performs the most expensive public cryptographic operations, including proof verification and shuffles. The Tabulation Teller incurs a moderate and bounded cost due to verifiable decryptions, while the Registration Teller and client-side costs are comparatively small.

Importantly, this does not imply that voting is slow for users. Most BB work happens after voting has ended, is fully publicly verifiable, can be parallelized, and can be re-run offline by auditors. The reported measurements primarily reflect **audit and verification cost**, not online voting latency.

## Limitations

- centralized deployment (single RT, single TT)
- no networking layer
- no persistence beyond in-memory bulletin board
- no threshold cryptography yet
