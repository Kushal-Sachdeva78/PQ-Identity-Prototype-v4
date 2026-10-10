# Phase D benchmark summary ([M] Phase D benchmark summary)

- Generated 2026-09-29T12:44:10+00:00 by scripts/bench/analyze.py from results/v4/bench_wsl/*/runs.jsonl.
- Quantiles: type 7. CIs: percentile bootstrap 95%, B = 10000, seed 20260927, ratio of medians.
- v4 rows use the dev key. Times in ms.

## Campaigns

| campaign | mode | used | discarded (battery) | errors | used, not quiet | complete |
|---|---|---|---|---|---|---|
| cold_rs_wsl | cold | 90 | 0 | 0 | 0 | True |
| warm_wsl | warm | 180 | 0 | 0 | 0 | True |

## Conditions

| condition | key | phase | n | median | Q1 | Q3 | IQR |
|---|---|---|---|---|---|---|---|
| cold/v2/rapidsnark | committed v2 key | witness | 30 | 53.89 | 52.20 | 55.33 | 3.13 |
| cold/v2/rapidsnark | committed v2 key | prove | 30 | 140.16 | 133.87 | 149.25 | 15.38 |
| cold/v2/rapidsnark | committed v2 key | verify | 30 | 25.60 | 21.63 | 28.99 | 7.36 |
| cold/v2/rapidsnark | committed v2 key | wp | 30 | 194.72 | 187.12 | 206.82 | 19.70 |
| cold/v3/rapidsnark | committed v3 key | witness | 30 | 77.62 | 74.98 | 81.44 | 6.46 |
| cold/v3/rapidsnark | committed v3 key | prove | 30 | 159.25 | 155.35 | 167.25 | 11.90 |
| cold/v3/rapidsnark | committed v3 key | verify | 30 | 26.50 | 23.01 | 28.58 | 5.57 |
| cold/v3/rapidsnark | committed v3 key | wp | 30 | 239.08 | 229.33 | 248.68 | 19.35 |
| cold/v4/rapidsnark | dev key | witness | 30 | 98.04 | 92.27 | 103.31 | 11.04 |
| cold/v4/rapidsnark | dev key | prove | 30 | 159.20 | 154.94 | 167.04 | 12.10 |
| cold/v4/rapidsnark | dev key | verify | 30 | 25.70 | 22.54 | 30.41 | 7.87 |
| cold/v4/rapidsnark | dev key | wp | 30 | 258.33 | 249.65 | 266.40 | 16.75 |
| warm/v2/rapidsnark | committed v2 key | witness | 30 | 46.02 | 43.98 | 49.13 | 5.15 |
| warm/v2/rapidsnark | committed v2 key | prove | 30 | 132.92 | 130.49 | 135.89 | 5.40 |
| warm/v2/rapidsnark | committed v2 key | verify | 30 | 8.88 | 8.42 | 9.28 | 0.86 |
| warm/v2/rapidsnark | committed v2 key | wp | 30 | 181.69 | 174.84 | 184.80 | 9.96 |
| warm/v2/snarkjs | committed v2 key | witness | 30 | 46.52 | 44.24 | 48.55 | 4.31 |
| warm/v2/snarkjs | committed v2 key | prove | 30 | 652.91 | 635.23 | 671.35 | 36.12 |
| warm/v2/snarkjs | committed v2 key | verify | 30 | 10.22 | 9.84 | 11.13 | 1.29 |
| warm/v2/snarkjs | committed v2 key | wp | 30 | 699.81 | 680.40 | 718.25 | 37.85 |
| warm/v3/rapidsnark | committed v3 key | witness | 30 | 65.76 | 63.39 | 67.81 | 4.42 |
| warm/v3/rapidsnark | committed v3 key | prove | 30 | 150.72 | 147.00 | 155.75 | 8.75 |
| warm/v3/rapidsnark | committed v3 key | verify | 30 | 9.91 | 9.14 | 10.28 | 1.14 |
| warm/v3/rapidsnark | committed v3 key | wp | 30 | 216.28 | 209.96 | 223.25 | 13.29 |
| warm/v3/snarkjs | committed v3 key | witness | 30 | 67.80 | 65.26 | 69.00 | 3.74 |
| warm/v3/snarkjs | committed v3 key | prove | 30 | 812.88 | 805.16 | 834.77 | 29.61 |
| warm/v3/snarkjs | committed v3 key | verify | 30 | 10.52 | 10.05 | 11.31 | 1.26 |
| warm/v3/snarkjs | committed v3 key | wp | 30 | 883.67 | 872.46 | 902.45 | 29.99 |
| warm/v4/rapidsnark | dev key | witness | 30 | 80.92 | 76.21 | 85.14 | 8.93 |
| warm/v4/rapidsnark | dev key | prove | 30 | 148.51 | 143.90 | 156.69 | 12.78 |
| warm/v4/rapidsnark | dev key | verify | 30 | 12.28 | 11.92 | 13.22 | 1.30 |
| warm/v4/rapidsnark | dev key | wp | 30 | 232.03 | 223.93 | 239.60 | 15.67 |
| warm/v4/snarkjs | dev key | witness | 30 | 82.41 | 79.68 | 84.92 | 5.24 |
| warm/v4/snarkjs | dev key | prove | 30 | 808.55 | 788.89 | 824.67 | 35.79 |
| warm/v4/snarkjs | dev key | verify | 30 | 10.53 | 10.11 | 11.27 | 1.16 |
| warm/v4/snarkjs | dev key | wp | 30 | 893.20 | 868.77 | 907.50 | 38.73 |

## Ratios

| ratio | phase | numerator | denominator | ratio of medians | 95% CI | n (num, den) | same campaign |
|---|---|---|---|---|---|---|---|
| prover speedup snarkjs/rapidsnark | prove | cold/v2/snarkjs | cold/v2/rapidsnark | no data: cold/v2/snarkjs | | | |
| prover speedup snarkjs/rapidsnark | wp | cold/v2/snarkjs | cold/v2/rapidsnark | no data: cold/v2/snarkjs | | | |
| prover speedup snarkjs/rapidsnark | prove | cold/v3/snarkjs | cold/v3/rapidsnark | no data: cold/v3/snarkjs | | | |
| prover speedup snarkjs/rapidsnark | wp | cold/v3/snarkjs | cold/v3/rapidsnark | no data: cold/v3/snarkjs | | | |
| prover speedup snarkjs/rapidsnark | prove | cold/v4/snarkjs | cold/v4/rapidsnark | no data: cold/v4/snarkjs | | | |
| prover speedup snarkjs/rapidsnark | wp | cold/v4/snarkjs | cold/v4/rapidsnark | no data: cold/v4/snarkjs | | | |
| prover speedup snarkjs/rapidsnark | prove | warm/v2/snarkjs | warm/v2/rapidsnark | 4.912 | 4.812 to 5.003 | 30, 30 | True |
| prover speedup snarkjs/rapidsnark | wp | warm/v2/snarkjs | warm/v2/rapidsnark | 3.852 | 3.774 to 4.012 | 30, 30 | True |
| prover speedup snarkjs/rapidsnark | prove | warm/v3/snarkjs | warm/v3/rapidsnark | 5.393 | 5.284 to 5.554 | 30, 30 | True |
| prover speedup snarkjs/rapidsnark | wp | warm/v3/snarkjs | warm/v3/rapidsnark | 4.086 | 3.989 to 4.189 | 30, 30 | True |
| prover speedup snarkjs/rapidsnark | prove | warm/v4/snarkjs | warm/v4/rapidsnark | 5.445 | 5.244 to 5.568 | 30, 30 | True |
| prover speedup snarkjs/rapidsnark | wp | warm/v4/snarkjs | warm/v4/rapidsnark | 3.850 | 3.734 to 3.939 | 30, 30 | True |
| v4/v2 | witness | cold/v4/snarkjs | cold/v2/snarkjs | no data: cold/v4/snarkjs, cold/v2/snarkjs | | | |
| v4/v2 | prove | cold/v4/snarkjs | cold/v2/snarkjs | no data: cold/v4/snarkjs, cold/v2/snarkjs | | | |
| v4/v2 | verify | cold/v4/snarkjs | cold/v2/snarkjs | no data: cold/v4/snarkjs, cold/v2/snarkjs | | | |
| v4/v2 | wp | cold/v4/snarkjs | cold/v2/snarkjs | no data: cold/v4/snarkjs, cold/v2/snarkjs | | | |
| v4/v3 | witness | cold/v4/snarkjs | cold/v3/snarkjs | no data: cold/v4/snarkjs, cold/v3/snarkjs | | | |
| v4/v3 | prove | cold/v4/snarkjs | cold/v3/snarkjs | no data: cold/v4/snarkjs, cold/v3/snarkjs | | | |
| v4/v3 | verify | cold/v4/snarkjs | cold/v3/snarkjs | no data: cold/v4/snarkjs, cold/v3/snarkjs | | | |
| v4/v3 | wp | cold/v4/snarkjs | cold/v3/snarkjs | no data: cold/v4/snarkjs, cold/v3/snarkjs | | | |
| v4/v2 | witness | cold/v4/rapidsnark | cold/v2/rapidsnark | 1.819 | 1.747 to 1.896 | 30, 30 | True |
| v4/v2 | prove | cold/v4/rapidsnark | cold/v2/rapidsnark | 1.136 | 1.060 to 1.187 | 30, 30 | True |
| v4/v2 | verify | cold/v4/rapidsnark | cold/v2/rapidsnark | 1.004 | 0.887 to 1.205 | 30, 30 | True |
| v4/v2 | wp | cold/v4/rapidsnark | cold/v2/rapidsnark | 1.327 | 1.251 to 1.374 | 30, 30 | True |
| v4/v3 | witness | cold/v4/rapidsnark | cold/v3/rapidsnark | 1.263 | 1.190 to 1.317 | 30, 30 | True |
| v4/v3 | prove | cold/v4/rapidsnark | cold/v3/rapidsnark | 1.000 | 0.954 to 1.031 | 30, 30 | True |
| v4/v3 | verify | cold/v4/rapidsnark | cold/v3/rapidsnark | 0.970 | 0.893 to 1.158 | 30, 30 | True |
| v4/v3 | wp | cold/v4/rapidsnark | cold/v3/rapidsnark | 1.081 | 1.046 to 1.118 | 30, 30 | True |
| v4/v2 | witness | warm/v4/snarkjs | warm/v2/snarkjs | 1.771 | 1.725 to 1.850 | 30, 30 | True |
| v4/v2 | prove | warm/v4/snarkjs | warm/v2/snarkjs | 1.238 | 1.207 to 1.261 | 30, 30 | True |
| v4/v2 | verify | warm/v4/snarkjs | warm/v2/snarkjs | 1.030 | 0.958 to 1.076 | 30, 30 | True |
| v4/v2 | wp | warm/v4/snarkjs | warm/v2/snarkjs | 1.276 | 1.241 to 1.299 | 30, 30 | True |
| v4/v3 | witness | warm/v4/snarkjs | warm/v3/snarkjs | 1.216 | 1.189 to 1.248 | 30, 30 | True |
| v4/v3 | prove | warm/v4/snarkjs | warm/v3/snarkjs | 0.995 | 0.970 to 1.005 | 30, 30 | True |
| v4/v3 | verify | warm/v4/snarkjs | warm/v3/snarkjs | 1.001 | 0.956 to 1.046 | 30, 30 | True |
| v4/v3 | wp | warm/v4/snarkjs | warm/v3/snarkjs | 1.011 | 0.984 to 1.022 | 30, 30 | True |
| v4/v2 | witness | warm/v4/rapidsnark | warm/v2/rapidsnark | 1.758 | 1.641 to 1.831 | 30, 30 | True |
| v4/v2 | prove | warm/v4/rapidsnark | warm/v2/rapidsnark | 1.117 | 1.091 to 1.155 | 30, 30 | True |
| v4/v2 | verify | warm/v4/rapidsnark | warm/v2/rapidsnark | 1.382 | 1.337 to 1.473 | 30, 30 | True |
| v4/v2 | wp | warm/v4/rapidsnark | warm/v2/rapidsnark | 1.277 | 1.242 to 1.329 | 30, 30 | True |
| v4/v3 | witness | warm/v4/rapidsnark | warm/v3/rapidsnark | 1.231 | 1.172 to 1.292 | 30, 30 | True |
| v4/v3 | prove | warm/v4/rapidsnark | warm/v3/rapidsnark | 0.985 | 0.959 to 1.024 | 30, 30 | True |
| v4/v3 | verify | warm/v4/rapidsnark | warm/v3/rapidsnark | 1.239 | 1.207 to 1.333 | 30, 30 | True |
| v4/v3 | wp | warm/v4/rapidsnark | warm/v3/rapidsnark | 1.073 | 1.038 to 1.103 | 30, 30 | True |
| cold/warm | witness | cold/v2/snarkjs | warm/v2/snarkjs | no data: cold/v2/snarkjs | | | |
| cold/warm | prove | cold/v2/snarkjs | warm/v2/snarkjs | no data: cold/v2/snarkjs | | | |
| cold/warm | verify | cold/v2/snarkjs | warm/v2/snarkjs | no data: cold/v2/snarkjs | | | |
| cold/warm | wp | cold/v2/snarkjs | warm/v2/snarkjs | no data: cold/v2/snarkjs | | | |
| cold/warm | witness | cold/v2/rapidsnark | warm/v2/rapidsnark | 1.171 | 1.106 to 1.206 | 30, 30 | False |
| cold/warm | prove | cold/v2/rapidsnark | warm/v2/rapidsnark | 1.054 | 1.018 to 1.117 | 30, 30 | False |
| cold/warm | verify | cold/v2/rapidsnark | warm/v2/rapidsnark | 2.882 | 2.581 to 3.238 | 30, 30 | False |
| cold/warm | wp | cold/v2/rapidsnark | warm/v2/rapidsnark | 1.072 | 1.037 to 1.147 | 30, 30 | False |
| cold/warm | witness | cold/v3/snarkjs | warm/v3/snarkjs | no data: cold/v3/snarkjs | | | |
| cold/warm | prove | cold/v3/snarkjs | warm/v3/snarkjs | no data: cold/v3/snarkjs | | | |
| cold/warm | verify | cold/v3/snarkjs | warm/v3/snarkjs | no data: cold/v3/snarkjs | | | |
| cold/warm | wp | cold/v3/snarkjs | warm/v3/snarkjs | no data: cold/v3/snarkjs | | | |
| cold/warm | witness | cold/v3/rapidsnark | warm/v3/rapidsnark | 1.180 | 1.133 to 1.257 | 30, 30 | False |
| cold/warm | prove | cold/v3/rapidsnark | warm/v3/rapidsnark | 1.057 | 1.030 to 1.102 | 30, 30 | False |
| cold/warm | verify | cold/v3/rapidsnark | warm/v3/rapidsnark | 2.674 | 2.424 to 2.902 | 30, 30 | False |
| cold/warm | wp | cold/v3/rapidsnark | warm/v3/rapidsnark | 1.105 | 1.064 to 1.137 | 30, 30 | False |
| cold/warm | witness | cold/v4/snarkjs | warm/v4/snarkjs | no data: cold/v4/snarkjs | | | |
| cold/warm | prove | cold/v4/snarkjs | warm/v4/snarkjs | no data: cold/v4/snarkjs | | | |
| cold/warm | verify | cold/v4/snarkjs | warm/v4/snarkjs | no data: cold/v4/snarkjs | | | |
| cold/warm | wp | cold/v4/snarkjs | warm/v4/snarkjs | no data: cold/v4/snarkjs | | | |
| cold/warm | witness | cold/v4/rapidsnark | warm/v4/rapidsnark | 1.212 | 1.153 to 1.277 | 30, 30 | False |
| cold/warm | prove | cold/v4/rapidsnark | warm/v4/rapidsnark | 1.072 | 1.030 to 1.106 | 30, 30 | False |
| cold/warm | verify | cold/v4/rapidsnark | warm/v4/rapidsnark | 2.093 | 1.935 to 2.425 | 30, 30 | False |
| cold/warm | wp | cold/v4/rapidsnark | warm/v4/rapidsnark | 1.113 | 1.078 to 1.147 | 30, 30 | False |
