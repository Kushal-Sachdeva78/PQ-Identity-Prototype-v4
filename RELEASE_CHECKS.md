# Publication package validation

Prepared 10 October 2026 for the accompanying IRIS paper. Validation ran on
Windows with Node 24.18.0, Circom 2.2.3, Anvil 1.5.1 and Python 3.13.14. Native
executables were supplied through environment paths and are not bundled.

| Check | Result |
| --- | --- |
| Git staging and checkout byte preservation | All publication files included; zero byte conversions |
| Locked dependency installation | Passed, including the exact Git dependency over HTTPS |
| Root and three supplementary TypeScript configurations | Passed |
| Selected v4 and portable v2/v3 test suites | 551 passed; 5 optional tests skipped |
| Python analysis tests | 48 passed |
| Native metadata adapter tests | 6 passed |
| Committed setup/circuit pins | 15 verified |
| Fresh v4 circuit compilation | R1CS and WASM match the recorded pins |
| Existing v4 development key audit | Transcript, verification key and Solidity verifier match |
| Fresh v4 security suite | 130 stored and rebuilt verdicts; zero differences |
| Preserved privacy evidence audit | 78 calls checked; 52 historical source/artifact digests accounted for |
| Numeric and boolean evidence preservation | 753 JSON/JSONL records checked; zero changes |

The selected TypeScript results combine the initial successful files with the
rerun of four corrected packaging checks. The skip count comprises four optional
ML-DSA interoperability checks without a repository-local Python environment and
one check requiring a completed ceremony rehearsal output. Individual checks of
Git metadata validate the explicit absence of history in an unpacked source
folder; their committed-checkout assertions remain active when Git HEAD exists.

The Linux Docker rebuild, macOS simulator workflow and WSL native timing campaign
were not executed during packaging. Recorded benchmark timing conditions and
results remain historical evidence. New validation outputs are kept separately
from the distributed measurement records.

`MANIFEST.sha256.tsv` records this package's exact bytes.
`PUBLICATION_PROVENANCE.json` records original and distributed hashes without
rewriting the original hash fields inside experiment records. Git attributes
preserve distributed bytes across platforms and enforce LF for shell/Python
scripts.
