# @pqid/baseline

Centralized classical baseline for Table VI — OAuth2-style bearer tokens +
ECDSA P-256 + a PostgreSQL-backed PII store, all **measured** `[M]` (the paper's
baseline column was reference/analytical `[A]`).

## What it measures (N=1000, 5 warmup)

- **ECDSA P-256:** keygen / sign / verify (raw 64-byte ieee-p1363 signatures) + sizes.
- **OAuth2 tokens:** opaque 32-byte bearer token size; JWT ES256 issue/verify + size.
- **PostgreSQL:** per-user PII INSERT latency; token-introspection JOIN SELECT latency;
  row storage size.

## Run

```bash
npx tsx packages/baseline/bench_baseline.ts   # -> results/baseline.json
```

Host discovery: `PQID_PG_HOST` overrides; otherwise `127.0.0.1`, then the WSL2 eth0 IP
(NAT-mode fallback). Server version is embedded in the output. Requires the `pqid` role and
`pqid_baseline` database (see `REPRODUCE.md`).
