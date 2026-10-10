# Phase D benchmark summary ([M] Phase D benchmark summary)

- Generated 2026-09-28T08:31:44+00:00 by scripts/bench/analyze.py from results/v4/bench/*/runs.jsonl.
- Quantiles: type 7. CIs: percentile bootstrap 95%, B = 10000, seed 20260927, ratio of medians.
- v4 rows use the dev key. Times in ms.

## Campaigns

| campaign | mode | used | discarded (battery) | errors | used, not quiet | complete |
|---|---|---|---|---|---|---|
| cold_v2v3 | cold | 60 | 0 | 0 | 0 | True |
| cold_v4 | cold | 30 | 0 | 0 | 0 | True |
| warm | warm | 90 | 0 | 0 | 0 | True |

## Blocked conditions

- cold/v2/rapidsnark: blocked: rapidsnark unavailable (D-002)
- cold/v3/rapidsnark: blocked: rapidsnark unavailable (D-002)
- cold/v4/rapidsnark: blocked: rapidsnark unavailable (D-002)
- warm/v2/rapidsnark: blocked: rapidsnark unavailable (D-002)
- warm/v3/rapidsnark: blocked: rapidsnark unavailable (D-002)
- warm/v4/rapidsnark: blocked: rapidsnark unavailable (D-002)

## Conditions

| condition | key | phase | n | median | Q1 | Q3 | IQR |
|---|---|---|---|---|---|---|---|
| cold/v2/snarkjs | committed v2 key | witness | 30 | 58.95 | 57.47 | 61.30 | 3.83 |
| cold/v2/snarkjs | committed v2 key | prove | 30 | 964.17 | 934.41 | 986.73 | 52.31 |
| cold/v2/snarkjs | committed v2 key | verify | 30 | 12.29 | 11.02 | 14.12 | 3.09 |
| cold/v2/snarkjs | committed v2 key | wp | 30 | 1030.10 | 992.21 | 1046.64 | 54.43 |
| cold/v3/snarkjs | committed v3 key | witness | 30 | 79.97 | 78.85 | 82.95 | 4.11 |
| cold/v3/snarkjs | committed v3 key | prove | 30 | 1127.10 | 1090.19 | 1142.63 | 52.44 |
| cold/v3/snarkjs | committed v3 key | verify | 30 | 12.32 | 11.15 | 13.98 | 2.82 |
| cold/v3/snarkjs | committed v3 key | wp | 30 | 1207.77 | 1166.68 | 1224.64 | 57.96 |
| cold/v4/snarkjs | dev key | witness | 30 | 93.02 | 90.07 | 96.51 | 6.44 |
| cold/v4/snarkjs | dev key | prove | 30 | 1090.07 | 1068.30 | 1111.90 | 43.60 |
| cold/v4/snarkjs | dev key | verify | 30 | 10.62 | 9.80 | 11.90 | 2.10 |
| cold/v4/snarkjs | dev key | wp | 30 | 1182.26 | 1159.14 | 1207.51 | 48.38 |
| warm/v2/snarkjs | committed v2 key | witness | 30 | 55.25 | 52.86 | 58.35 | 5.49 |
| warm/v2/snarkjs | committed v2 key | prove | 30 | 690.75 | 680.56 | 699.01 | 18.44 |
| warm/v2/snarkjs | committed v2 key | verify | 30 | 11.24 | 10.21 | 12.77 | 2.56 |
| warm/v2/snarkjs | committed v2 key | wp | 30 | 747.14 | 736.31 | 754.00 | 17.69 |
| warm/v3/snarkjs | committed v3 key | witness | 30 | 76.34 | 72.31 | 80.02 | 7.71 |
| warm/v3/snarkjs | committed v3 key | prove | 30 | 842.37 | 833.26 | 849.50 | 16.24 |
| warm/v3/snarkjs | committed v3 key | verify | 30 | 11.32 | 10.24 | 12.50 | 2.25 |
| warm/v3/snarkjs | committed v3 key | wp | 30 | 918.91 | 907.76 | 927.57 | 19.82 |
| warm/v4/snarkjs | dev key | witness | 30 | 92.62 | 90.01 | 98.37 | 8.36 |
| warm/v4/snarkjs | dev key | prove | 30 | 829.94 | 822.27 | 840.18 | 17.91 |
| warm/v4/snarkjs | dev key | verify | 30 | 11.69 | 10.33 | 12.47 | 2.13 |
| warm/v4/snarkjs | dev key | wp | 30 | 924.66 | 915.35 | 937.26 | 21.90 |

## Ratios

| ratio | phase | numerator | denominator | ratio of medians | 95% CI | n (num, den) | same campaign |
|---|---|---|---|---|---|---|---|
| prover speedup snarkjs/rapidsnark | prove | cold/v2/snarkjs | cold/v2/rapidsnark | blocked: rapidsnark unavailable (D-002) | | | |
| prover speedup snarkjs/rapidsnark | wp | cold/v2/snarkjs | cold/v2/rapidsnark | blocked: rapidsnark unavailable (D-002) | | | |
| prover speedup snarkjs/rapidsnark | prove | cold/v3/snarkjs | cold/v3/rapidsnark | blocked: rapidsnark unavailable (D-002) | | | |
| prover speedup snarkjs/rapidsnark | wp | cold/v3/snarkjs | cold/v3/rapidsnark | blocked: rapidsnark unavailable (D-002) | | | |
| prover speedup snarkjs/rapidsnark | prove | cold/v4/snarkjs | cold/v4/rapidsnark | blocked: rapidsnark unavailable (D-002) | | | |
| prover speedup snarkjs/rapidsnark | wp | cold/v4/snarkjs | cold/v4/rapidsnark | blocked: rapidsnark unavailable (D-002) | | | |
| prover speedup snarkjs/rapidsnark | prove | warm/v2/snarkjs | warm/v2/rapidsnark | blocked: rapidsnark unavailable (D-002) | | | |
| prover speedup snarkjs/rapidsnark | wp | warm/v2/snarkjs | warm/v2/rapidsnark | blocked: rapidsnark unavailable (D-002) | | | |
| prover speedup snarkjs/rapidsnark | prove | warm/v3/snarkjs | warm/v3/rapidsnark | blocked: rapidsnark unavailable (D-002) | | | |
| prover speedup snarkjs/rapidsnark | wp | warm/v3/snarkjs | warm/v3/rapidsnark | blocked: rapidsnark unavailable (D-002) | | | |
| prover speedup snarkjs/rapidsnark | prove | warm/v4/snarkjs | warm/v4/rapidsnark | blocked: rapidsnark unavailable (D-002) | | | |
| prover speedup snarkjs/rapidsnark | wp | warm/v4/snarkjs | warm/v4/rapidsnark | blocked: rapidsnark unavailable (D-002) | | | |
| v4/v2 | witness | cold/v4/snarkjs | cold/v2/snarkjs | 1.578 | 1.526 to 1.627 | 30, 30 | False |
| v4/v2 | prove | cold/v4/snarkjs | cold/v2/snarkjs | 1.131 | 1.095 to 1.156 | 30, 30 | False |
| v4/v2 | verify | cold/v4/snarkjs | cold/v2/snarkjs | 0.864 | 0.758 to 0.937 | 30, 30 | False |
| v4/v2 | wp | cold/v4/snarkjs | cold/v2/snarkjs | 1.148 | 1.120 to 1.180 | 30, 30 | False |
| v4/v3 | witness | cold/v4/snarkjs | cold/v3/snarkjs | 1.163 | 1.128 to 1.194 | 30, 30 | False |
| v4/v3 | prove | cold/v4/snarkjs | cold/v3/snarkjs | 0.967 | 0.947 to 0.989 | 30, 30 | False |
| v4/v3 | verify | cold/v4/snarkjs | cold/v3/snarkjs | 0.862 | 0.779 to 0.948 | 30, 30 | False |
| v4/v3 | wp | cold/v4/snarkjs | cold/v3/snarkjs | 0.979 | 0.959 to 0.999 | 30, 30 | False |
| v4/v2 | witness | cold/v4/rapidsnark | cold/v2/rapidsnark | blocked: rapidsnark unavailable (D-002) | | | |
| v4/v2 | prove | cold/v4/rapidsnark | cold/v2/rapidsnark | blocked: rapidsnark unavailable (D-002) | | | |
| v4/v2 | verify | cold/v4/rapidsnark | cold/v2/rapidsnark | blocked: rapidsnark unavailable (D-002) | | | |
| v4/v2 | wp | cold/v4/rapidsnark | cold/v2/rapidsnark | blocked: rapidsnark unavailable (D-002) | | | |
| v4/v3 | witness | cold/v4/rapidsnark | cold/v3/rapidsnark | blocked: rapidsnark unavailable (D-002) | | | |
| v4/v3 | prove | cold/v4/rapidsnark | cold/v3/rapidsnark | blocked: rapidsnark unavailable (D-002) | | | |
| v4/v3 | verify | cold/v4/rapidsnark | cold/v3/rapidsnark | blocked: rapidsnark unavailable (D-002) | | | |
| v4/v3 | wp | cold/v4/rapidsnark | cold/v3/rapidsnark | blocked: rapidsnark unavailable (D-002) | | | |
| v4/v2 | witness | warm/v4/snarkjs | warm/v2/snarkjs | 1.676 | 1.607 to 1.760 | 30, 30 | True |
| v4/v2 | prove | warm/v4/snarkjs | warm/v2/snarkjs | 1.202 | 1.190 to 1.214 | 30, 30 | True |
| v4/v2 | verify | warm/v4/snarkjs | warm/v2/snarkjs | 1.041 | 0.938 to 1.131 | 30, 30 | True |
| v4/v2 | wp | warm/v4/snarkjs | warm/v2/snarkjs | 1.238 | 1.227 to 1.253 | 30, 30 | True |
| v4/v3 | witness | warm/v4/snarkjs | warm/v3/snarkjs | 1.213 | 1.158 to 1.296 | 30, 30 | True |
| v4/v3 | prove | warm/v4/snarkjs | warm/v3/snarkjs | 0.985 | 0.975 to 0.995 | 30, 30 | True |
| v4/v3 | verify | warm/v4/snarkjs | warm/v3/snarkjs | 1.033 | 0.930 to 1.109 | 30, 30 | True |
| v4/v3 | wp | warm/v4/snarkjs | warm/v3/snarkjs | 1.006 | 0.996 to 1.017 | 30, 30 | True |
| v4/v2 | witness | warm/v4/rapidsnark | warm/v2/rapidsnark | blocked: rapidsnark unavailable (D-002) | | | |
| v4/v2 | prove | warm/v4/rapidsnark | warm/v2/rapidsnark | blocked: rapidsnark unavailable (D-002) | | | |
| v4/v2 | verify | warm/v4/rapidsnark | warm/v2/rapidsnark | blocked: rapidsnark unavailable (D-002) | | | |
| v4/v2 | wp | warm/v4/rapidsnark | warm/v2/rapidsnark | blocked: rapidsnark unavailable (D-002) | | | |
| v4/v3 | witness | warm/v4/rapidsnark | warm/v3/rapidsnark | blocked: rapidsnark unavailable (D-002) | | | |
| v4/v3 | prove | warm/v4/rapidsnark | warm/v3/rapidsnark | blocked: rapidsnark unavailable (D-002) | | | |
| v4/v3 | verify | warm/v4/rapidsnark | warm/v3/rapidsnark | blocked: rapidsnark unavailable (D-002) | | | |
| v4/v3 | wp | warm/v4/rapidsnark | warm/v3/rapidsnark | blocked: rapidsnark unavailable (D-002) | | | |
| cold/warm | witness | cold/v2/snarkjs | warm/v2/snarkjs | 1.067 | 1.035 to 1.105 | 30, 30 | False |
| cold/warm | prove | cold/v2/snarkjs | warm/v2/snarkjs | 1.396 | 1.370 to 1.430 | 30, 30 | False |
| cold/warm | verify | cold/v2/snarkjs | warm/v2/snarkjs | 1.094 | 1.014 to 1.263 | 30, 30 | False |
| cold/warm | wp | cold/v2/snarkjs | warm/v2/snarkjs | 1.379 | 1.346 to 1.405 | 30, 30 | False |
| cold/warm | witness | cold/v2/rapidsnark | warm/v2/rapidsnark | blocked: rapidsnark unavailable (D-002) | | | |
| cold/warm | prove | cold/v2/rapidsnark | warm/v2/rapidsnark | blocked: rapidsnark unavailable (D-002) | | | |
| cold/warm | verify | cold/v2/rapidsnark | warm/v2/rapidsnark | blocked: rapidsnark unavailable (D-002) | | | |
| cold/warm | wp | cold/v2/rapidsnark | warm/v2/rapidsnark | blocked: rapidsnark unavailable (D-002) | | | |
| cold/warm | witness | cold/v3/snarkjs | warm/v3/snarkjs | 1.048 | 1.015 to 1.105 | 30, 30 | False |
| cold/warm | prove | cold/v3/snarkjs | warm/v3/snarkjs | 1.338 | 1.312 to 1.357 | 30, 30 | False |
| cold/warm | verify | cold/v3/snarkjs | warm/v3/snarkjs | 1.089 | 0.985 to 1.202 | 30, 30 | False |
| cold/warm | wp | cold/v3/snarkjs | warm/v3/snarkjs | 1.314 | 1.290 to 1.332 | 30, 30 | False |
| cold/warm | witness | cold/v3/rapidsnark | warm/v3/rapidsnark | blocked: rapidsnark unavailable (D-002) | | | |
| cold/warm | prove | cold/v3/rapidsnark | warm/v3/rapidsnark | blocked: rapidsnark unavailable (D-002) | | | |
| cold/warm | verify | cold/v3/rapidsnark | warm/v3/rapidsnark | blocked: rapidsnark unavailable (D-002) | | | |
| cold/warm | wp | cold/v3/rapidsnark | warm/v3/rapidsnark | blocked: rapidsnark unavailable (D-002) | | | |
| cold/warm | witness | cold/v4/snarkjs | warm/v4/snarkjs | 1.004 | 0.959 to 1.046 | 30, 30 | False |
| cold/warm | prove | cold/v4/snarkjs | warm/v4/snarkjs | 1.313 | 1.291 to 1.334 | 30, 30 | False |
| cold/warm | verify | cold/v4/snarkjs | warm/v4/snarkjs | 0.908 | 0.852 to 1.007 | 30, 30 | False |
| cold/warm | wp | cold/v4/snarkjs | warm/v4/snarkjs | 1.279 | 1.255 to 1.301 | 30, 30 | False |
| cold/warm | witness | cold/v4/rapidsnark | warm/v4/rapidsnark | blocked: rapidsnark unavailable (D-002) | | | |
| cold/warm | prove | cold/v4/rapidsnark | warm/v4/rapidsnark | blocked: rapidsnark unavailable (D-002) | | | |
| cold/warm | verify | cold/v4/rapidsnark | warm/v4/rapidsnark | blocked: rapidsnark unavailable (D-002) | | | |
| cold/warm | wp | cold/v4/rapidsnark | warm/v4/rapidsnark | blocked: rapidsnark unavailable (D-002) | | | |
