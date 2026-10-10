/**
 * Loopback ports of DECISIONS D-034 and the fixed chain ports of committed code.
 *
 * A series binds only its own D-034 port. The other lists exist so that the quiet check
 * (quiesce.ts) can probe for a chain node that another run left listening; probing is a TCP
 * connect and close on 127.0.0.1 and never binds a port.
 */

/** D-034 "Ports" (one owner each). */
export const PORTS = Object.freeze({
  /** Chain-read campaign, Anvil inside WSL2. */
  chainReadAnvilWsl: 8770,
  /** Chain-read campaign, Anvil on the Windows host. */
  chainReadAnvilWindows: 8771,
  /** Verifier load test (robustness row). */
  loadTest: 8780,
  /** Fuzzing (robustness row). */
  fuzzing: 8781,
  /** End-to-end presentation series. */
  endToEnd: 8790,
  /** Besu QBFT, 4 validators (scripts/besu/setup_qbft.sh); one network at a time. */
  besuQbft: Object.freeze([18545, 18546, 18547, 18548] as const),
} as const);

/** Every D-034 port, ascending. */
export function d034Ports(): number[] {
  const out: number[] = [PORTS.chainReadAnvilWsl, PORTS.chainReadAnvilWindows, PORTS.loadTest, PORTS.fuzzing, PORTS.endToEnd, ...PORTS.besuQbft];
  return [...new Set(out)].sort((a, b) => a - b);
}

/**
 * Fixed Anvil ports of committed code (probe targets only; never bound by a new series).
 * 8545 ethers/Anvil default; 8561 tests/v4/ledger_v4; 8570 World default; 8580 demo/v4_demo;
 * 8581 security suite; 8591 tests/v4/published; 8597 harness/v4/gas; 8750-8753 harness/v4/scale
 * (E4); 18549, 18645, 18655, 18711, 18731 v2/v3 harnesses and tests (18545 and 18548 are also
 * used there and are in the Besu range). The mutation campaign counts up from 8600 and is not
 * listed.
 */
export const LEGACY_CHAIN_PORTS: readonly number[] = Object.freeze([
  8545, 8561, 8570, 8580, 8581, 8591, 8597, 8750, 8751, 8752, 8753, 18549, 18645, 18655, 18711, 18731,
]);

/**
 * Ceremony follow-up ports (DECISIONS D-041; harness/v4/ceremony/followup_lib.ts CEREMONY_PORTS):
 * the suite on 8800 and the mutation campaign one port per defence from 8801 (59 defences, up to
 * 8859). Kept apart from the D-034 list; probe targets for the quiet check only.
 */
export const CEREMONY_FOLLOWUP_PORTS: readonly number[] = Object.freeze(Array.from({ length: 60 }, (_, i) => 8800 + i));

/** Default probe list of the quiet check: D-034 ports, the legacy fixed ports and the ceremony follow-up ports. */
export const CHAIN_PROBE_PORTS: readonly number[] = Object.freeze(
  [...new Set([...d034Ports(), ...LEGACY_CHAIN_PORTS, ...CEREMONY_FOLLOWUP_PORTS])].sort((a, b) => a - b)
);
