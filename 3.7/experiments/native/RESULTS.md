# Version 3.7 native presentation and simulated RPC-delay results

The complete native presentation was measured, but only after identifying and
isolating an integration defect. Unchanged rapidsnark output omits `curve`; the
wallet's strict proof schema rejected it in both retained smoke attempts. The
experimental adapter adds `curve=bn128` without changing coordinates or public
signals. **Every native timing below is an experimental adapter variant, not the
shipped native integration.** Interpreter/subprocess startup and adapter file work
are included in its proving stage.

Campaign: `runs/2026-10-07T21-52-33-841Z-run/`, conducted 8 October 2026,
03:22-03:40 IST (7 October 21:52-22:10 UTC). One Core Ultra 7 355 laptop, WSL2,
Node 24.21.0/OpenSSL 3.5.8, Anvil 1.5.1, existing pinned development key. Complete
source, binary and key hashes are in `environment.json`.

Five warm-up blocks preceded 30 randomized measured blocks of eight conditions:
two provers crossed with 0/20/50 ms added per HTTP POST, plus a no-delay
uninstrumented control for each prover. All 240 measured presentations and 40
warmups passed. No block was retried or excluded and no AC-power check failed.
Sources and pins remained unchanged; no temporary witness file remained.

| Prover | Artificial delay per POST | Median complete presentation (ms) | IQR (ms) | Median 95% CI (ms) | S8 median (ms) |
|---|---:|---:|---:|---|---:|
| snarkJS | 0 ms | 1192.17 | 28.48 | 1181.75-1203.11 | 885.33 |
| snarkJS | 20 ms | 1677.13 | 25.23 | 1667.20-1684.13 | 888.17 |
| snarkJS | 50 ms | 2370.22 | 48.71 | 2352.77-2394.03 | 879.70 |
| Native adapter | 0 ms | 585.23 | 11.91 | 580.26-587.71 | 277.05 |
| Native adapter | 20 ms | 1061.34 | 23.55 | 1055.79-1075.33 | 276.77 |
| Native adapter | 50 ms | 1755.06 | 19.38 | 1753.28-1763.79 | 276.40 |

Each cell has n=30. These are **monotonic execution times**, with the clock caveat
below. The native no-delay complete presentation includes all S1-S11 work; it is
not a sum of unrelated phase medians. The paired snarkJS/native median ratio is
2.037 (95% CI 2.018-2.062) at zero added delay, 1.580 at 20 ms and 1.351 at 50 ms.
Each presentation made 23 HTTP POSTs. Native delay-minus-baseline differences were
476.11 ms (470.07-489.75) and 1169.83 ms (1166.58-1178.96), showing how sequential
registry work erodes the benefit from faster proving in this simulated condition.
No-delay chain calls alone had a median about 283.6 ms with either prover.

The instrumented/control total-time ratio was 0.996 (0.979-1.022) for snarkJS and
1.004 (0.994-1.011) for the native adapter. This does not establish zero overhead;
it bounds the observed difference under this protocol. Setup, issuance, publication
and party construction were outside S1-S11 and took 3074 ms for this one setup.
The source blob was already available; no wide-area download/synchronization was
timed. Setup records are auxiliary n=1 observations, not stable latency estimates.

## Clock audit and limits

The settle recorded 617847 ms wall time versus 600369.374 ms monotonic time, a
17.478 s difference. Quiet checks flagged measured blocks 3 and 8 for about 1.03 s
clock divergence. Nine other measured blocks exceeded 1 s wall-minus-monotonic
block time; a tenth was 970 ms. The largest gap was 1279.744 ms, below the
prespecified 2000 ms block-exclusion threshold, so the primary results retain all
30 blocks. The cause is unestablished. Per-iteration wall-clock time was not
recorded, so these results cannot validate user wall-clock waiting times or locate
the divergence within a particular condition.

The prespecified quiet sensitivity retains n=28: no-delay medians are 1194.36 ms
for snarkJS and 585.23 ms for the adapter. A separately labelled **post-hoc**
diagnostic removes any block with a quiet failure or an absolute block clock gap
above 500 ms, leaving n=18: 1194.36 ms (1179.29-1203.30) and 583.30 ms
(577.92-590.32). This diagnostic does not replace the primary result or repair
missing per-iteration wall-clock observations. Exact flags and all six conditions
are in `audit.json`.

The clock fields were added to the derived summary after inspecting the run;
`analyze.py` retains the prespecified statistical definitions and primary samples.
`audit.py` supplies the separate post-hoc diagnostic. Raw observations, the protocol
and environment records are unchanged.

All confidence intervals quantify variation within one session. Both parties share
one process and one host. Fresh party HTTP agents are used with warm application
state. Delays are deterministic response waits through a loopback proxy, with no
jitter, loss, bandwidth bottleneck or TLS. The node is local Anvil, not distributed
consensus; Windows load is not visible to the WSL quiet checker. Remote RPC,
another device, cold first-use, and ceremony-key evidence remain unmeasured. The
original C5 cold-snarkJS failure remains unchanged.

Reproduce the derived outputs after all timing markers are released:

```
python -B 3.7/experiments/native/analyze.py 3.7/experiments/native/runs/2026-10-07T21-52-33-841Z-run
python -B 3.7/experiments/native/audit.py 3.7/experiments/native/runs/2026-10-07T21-52-33-841Z-run
```
