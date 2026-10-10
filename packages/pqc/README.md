# @pqid/pqc

liboqs 0.15.0 bridge for ML-DSA-44 (Dilithium-II) and ML-KEM-512 (Kyber-512),
plus the Table IV benchmark and a raw Kyber session-key demo.

The native crypto lives in WSL2/Linux; Node calls it through one-shot JSON
subprocesses (`pqc_cli.py`). All **timing** numbers come from `bench_pqc.py`,
which loops inside a single Python process — never from the per-call bridge.

## API (`@pqid/pqc`)

| Function | Description |
|---|---|
| `dilithiumKeygen()` | ML-DSA-44 keypair `{publicKey, secretKey}` (liboqs) |
| `dilithiumSign(sk, msg)` / `dilithiumVerify(pk, msg, sig)` | ML-DSA-44 sign/verify |
| `kyberKeygen()` / `kyberEncap(pk)` / `kyberDecap(sk, ct)` | ML-KEM-512 KEM |
| `dilithiumKeygenDpy()` / `dilithiumSignDpy(sk, msg)` | dilithium-py 1.4.0 path (E2E issuance only; never timed) |
| `ML_DSA_44_SIZES`, `ML_KEM_512_SIZES` | FIPS 203/204 reference sizes |

## Inputs / outputs

- **bench:** `OQS_INSTALL_PATH=<liboqs install> python bench_pqc.py --n 1000 --warmup 5`
  → JSON (mean/median/σ/min/max/p95 in ms + sizes), consumed by `harness/bench_pqc.ts`.
- **Kyber demo:** `runKyberSessionDemo()` → `{sharedSecretsAgree, channelRoundTripOk, tamperDetected, sizes}`.

## Example

```ts
import { dilithiumKeygen, dilithiumSign, dilithiumVerify } from "@pqid/pqc";
const { publicKey, secretKey } = dilithiumKeygen();
const msg = Buffer.from("credID placeholder", "utf8");
const sig = dilithiumSign(secretKey, msg);
console.log(dilithiumVerify(publicKey, msg, sig)); // true
```

PQ-TLS is out of scope `[F]`; only the raw encap/decap session-key demo is included.
