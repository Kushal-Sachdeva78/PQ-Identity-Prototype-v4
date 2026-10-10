# Benchmark and evidence policy

Run one timed campaign at a time on an idle machine with the recorded power and
affinity settings. While a RUNNING marker is held, avoid compilation, tests,
analysis, other benchmark jobs and chain nodes outside that campaign. Drivers
refuse conflicting RUNNING or BUSY markers and release their own markers on exit.
Confirm that the owning process has stopped before clearing a stale marker.

The inherited Windows harness reads power state and aggregate CPU activity without
enumerating processes or pinning a CPU. Linux campaigns can inspect `/proc` and
record affinity. Record the measurement platform and these differences with the
results rather than treating the platforms as interchangeable.

Evidence labels are `[M]` measured, `[S]` simulated or derived, `[A]` assumed and
`[F]` future work. Measurements using the committed v4 development proving key
retain the `dev` label. A development-key result is not evidence of a completed
multi-party setup ceremony.

Keep failed attempts, raw observations, seeds, configuration and recorded historical
hashes. New measurements use new output directories. See [REPRODUCE.md](../REPRODUCE.md)
for the distinction between historical experiment hashes and the publication manifest.
