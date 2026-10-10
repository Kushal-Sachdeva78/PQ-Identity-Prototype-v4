# Version 3.7 exploratory native presentation experiment

Development key; one laptop; WSL2; loopback Anvil through an experimental proxy. Native rows use an experimental metadata adapter, not shipped integration; the unadapted native smoke failed the wallet schema check. Both parties share one process. Warm process state and fresh party HTTP agents. Positive delays are deterministic simulated RPC latency, not remote measurements. Times use the monotonic clock; observed clock divergence prevents treating them as validated wall-clock user waits. Original C5 unchanged.

| Prover | Added delay per POST | n | Full presentation median [ms] | IQR [ms] | Median 95% CI [ms] | S8 median [ms] | POSTs |
|---|---:|---:|---:|---:|---|---:|---:|
| snarkjs | 0 ms | 30 | 1192.17 | 28.48 | 1181.75 to 1203.11 | 885.33 | [23] |
| snarkjs | 20 ms | 30 | 1677.13 | 25.23 | 1667.20 to 1684.13 | 888.17 | [23] |
| snarkjs | 50 ms | 30 | 2370.22 | 48.71 | 2352.77 to 2394.03 | 879.70 | [23] |
| rapidsnark | 0 ms | 30 | 585.23 | 11.91 | 580.26 to 587.71 | 277.05 | [23] |
| rapidsnark | 20 ms | 30 | 1061.34 | 23.55 | 1055.79 to 1075.33 | 276.77 | [23] |
| rapidsnark | 50 ms | 30 | 1755.06 | 19.38 | 1753.28 to 1763.79 | 276.40 | [23] |

Accepted measured presentations: 240; excluded block attempts: 0.

## Paired comparisons

| Comparison | Estimate | 95% CI |
|---|---:|---|
| snarkjs_over_rapidsnark_0ms | 2.037 | 2.018 to 2.062 |
| snarkjs_over_rapidsnark_20ms | 1.580 | 1.559 to 1.592 |
| snarkjs_over_rapidsnark_50ms | 1.351 | 1.337 to 1.364 |
| snarkjs_20ms_minus_0ms | 484.960 | 472.440 to 499.172 |
| snarkjs_50ms_minus_0ms | 1178.048 | 1155.862 to 1201.636 |
| snarkjs_instrumented_over_control_0ms | 0.996 | 0.979 to 1.022 |
| rapidsnark_20ms_minus_0ms | 476.112 | 470.065 to 489.748 |
| rapidsnark_50ms_minus_0ms | 1169.827 | 1166.578 to 1178.957 |
| rapidsnark_instrumented_over_control_0ms | 1.004 | 0.994 to 1.011 |

Quiet-check flagged measured blocks: [3, 8]. Sensitivity results are retained in summary.json; the guard cannot observe Windows load.

Clock audit: settle wall time exceeded monotonic time by 17.478 s. 9 measured blocks exceeded 1 s wall-minus-monotonic difference; 10 exceeded 0.5 s. Maximum block gap was 1279.744 ms, below the prespecified 2,000 ms exclusion threshold. Primary results retain these blocks; per-iteration wall times are unavailable and the cause is unestablished. Separate audit.json records a clearly post-hoc diagnostic excluding clock-affected blocks.

Confidence intervals describe within-session variation. Setup/synchronization is outside the timed window and retained in setup.json. This is neither cold/first-use latency nor WAN, second-device, distributed-consensus or ceremony-key evidence.
