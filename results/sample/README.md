# results/sample

A committed snapshot of one full measurement run, so the repository ships with a
concrete example of every `results/*.json` shape without depending on a clean run.

`results/*.json` at the repo root is gitignored (environment-specific); this `sample/`
directory is the exception that **is** committed. Regenerate the live files with `make bench`
and the sample with `make tables` followed by copying the current outputs here.

Files: `pqc.json`, `pqc_avx2.json`, `zk.json`, `gas.json`, `baseline.json`,
`negative.json`, `malicious_probe.json`, `e2e.json`.
