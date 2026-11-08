# Contributing

This repository is the PQ-ID v4 publication package: code and experimental evidence for *Auditing and
Redesigning a Zero-Knowledge Digital Identity System: Issuance-Bound Credentials with Post-Quantum-Signed
Statements*. Its main purpose is to make the paper's claims inspectable and reproducible, not to be a
production library.

## How to engage

- **Reproducing results** — start with [`README.md`](README.md) and [`REPRODUCE.md`](REPRODUCE.md).
  `make docker` builds the pinned Linux environment and runs the full validation; `make validate` runs
  the default checks on an installed toolchain (Node 24.18.0, Circom 2.2.3, Anvil 1.5.1, Python 3.11+, Bash).
- **Questions and problems** — open an issue with the command you ran, the output, and your host
  (CPU, OS, Node, Python and Docker versions).
- **Pull requests** — open an issue first if the change touches the protocol, the circuits, keys or
  recorded results. If you think you found a soundness bug, please open an issue so it can be discussed
  and recorded.
- **Response time** — I aim to reply to every new issue within 24 hours
  (India Standard Time). If I'm slower than that, I'll say so on the issue
  rather than leave it silent.

## Ground rules

1. Files listed in `MANIFEST.sha256.tsv` are hash-checked by `artifact/rebuild.sh` and by CI. Editing a
   listed file (including `README.md`) makes the publication-integrity step fail until the manifest is
   updated, so please open an issue first and let the maintainer re-seal the package.
2. Keep the `[M]` / `[S]` / `[A]` / `[F]` labels (measured, simulated, assumption, future work) on any
   quantitative claim.
3. Never commit runtime key material.

## Code of conduct

Be respectful and constructive. This is a student project; good-faith questions
and careful, well-documented contributions are appreciated.
