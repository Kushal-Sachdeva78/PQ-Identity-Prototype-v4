import { CLIENT_VARIANTS, defineClientVariant, type ClientVariantSpec } from "../lib/rpc_trace.ts";

/**
 * Client variants and read plans of the chain-read series (docs/v4/CHAINREAD.md, DECISIONS
 * D-034). Only `asShipped` is the shipped client (packages/v4/src/ledger.ts makeProvider,
 * sequential reads). Every other entry is a measured client construction labelled
 * "variant, not shipped". "Static network" is the ethers v6 option staticNetwork (D-034).
 */

/** ethers client settings (built with harness/v4/lib/rpc_trace.ts createClientProvider). */
export const CLIENTS = Object.freeze({
  asShipped: CLIENT_VARIANTS.asShipped,
  noBatchStall: CLIENT_VARIANTS.noBatchStall,
  staticNetwork: CLIENT_VARIANTS.staticNetwork,
  staticNoStall: defineClientVariant(
    "staticNoStall",
    { staticNetwork: true, batchStallTime: 0 },
    "staticNetwork and batchStallTime 0: no eth_chainId per call; requests leave on the next timer turn, and requests queued in the same turn share one JSON-RPC batch POST"
  ),
  unbatched: defineClientVariant(
    "unbatched",
    { batchMaxCount: 1 },
    "batchMaxCount 1 (ethers then uses stall 0): one HTTP POST per JSON-RPC request; the per-call eth_chainId goes in its own POST"
  ),
  unbatchedStatic: defineClientVariant(
    "unbatchedStatic",
    { staticNetwork: true, batchMaxCount: 1 },
    "staticNetwork and batchMaxCount 1: one HTTP POST per request, no eth_chainId; concurrent requests travel as concurrent POSTs on separate keep-alive sockets"
  ),
});
export type ClientName = keyof typeof CLIENTS;

export function clientSpec(name: ClientName): ClientVariantSpec {
  return CLIENTS[name];
}

export type Label = "as shipped" | "variant, not shipped";

/** S4 (verifier) and S5 (wallet read phase) variants A to I. */
export interface PresentationVariant {
  id: "A" | "B" | "C" | "D" | "E" | "F" | "G" | "H" | "I";
  name: string;
  client: ClientName;
  plan: "sequential" | "concurrent";
  multicall: boolean;
  cached: boolean;
  label: Label;
  description: string;
}

export const PRESENTATION_VARIANTS: readonly PresentationVariant[] = Object.freeze([
  { id: "A", name: "asShipped", client: "asShipped", plan: "sequential", multicall: false, cached: false, label: "as shipped", description: "LedgerV4.connect as shipped, the role's own sequential reads" },
  { id: "B", name: "noBatchStall", client: "noBatchStall", plan: "sequential", multicall: false, cached: false, label: "variant, not shipped", description: "batchStallTime 0, sequential reads (the ethers option of E4's noBatchStall; E4 changed it on the shipped provider through _getOption, this client is a new provider with its own agent that has the global agent's options)" },
  { id: "C", name: "staticNetwork", client: "staticNetwork", plan: "sequential", multicall: false, cached: false, label: "variant, not shipped", description: "ethers staticNetwork (no eth_chainId per call), sequential reads" },
  { id: "D", name: "staticNoStall", client: "staticNoStall", plan: "sequential", multicall: false, cached: false, label: "variant, not shipped", description: "staticNetwork and batchStallTime 0, sequential reads" },
  { id: "E", name: "concurrentShipped", client: "asShipped", plan: "concurrent", multicall: false, cached: false, label: "variant, not shipped", description: "concurrent read plan on the shipped client (ethers batches what arrives within its 10 ms stall)" },
  { id: "F", name: "parallel", client: "unbatchedStatic", plan: "concurrent", multicall: false, cached: false, label: "variant, not shipped", description: "concurrent read plan, staticNetwork, batchMaxCount 1: one POST per request on concurrent keep-alive sockets" },
  { id: "G", name: "batched", client: "staticNoStall", plan: "concurrent", multicall: false, cached: false, label: "variant, not shipped", description: "concurrent read plan, staticNetwork, stall 0: requests of one turn share one JSON-RPC batch POST" },
  { id: "H", name: "multicall", client: "staticNoStall", plan: "concurrent", multicall: true, cached: false, label: "variant, not shipped", description: "as G, plus the registry eth_calls of one turn aggregated into one eth_call of ChainReadBatch (eth_getLogs still batched)" },
  { id: "I", name: "cachedReads", client: "asShipped", plan: "sequential", multicall: false, cached: true, label: "variant, not shipped", description: "every read served from an in-memory cache after its first call: lower bound without chain reads (as E4)" },
] satisfies PresentationVariant[]);

export function presentationVariant(id: string): PresentationVariant {
  const v = PRESENTATION_VARIANTS.find((x) => x.id === id || x.name === id);
  if (!v) throw new Error(`unknown variant ${id}; known: ${PRESENTATION_VARIANTS.map((x) => `${x.id} ${x.name}`).join(", ")}`);
  return v;
}

/** S3 per-read cells: each of the six reads, alone, on each of these clients. */
export const READ_CLIENTS: readonly ClientName[] = Object.freeze(["asShipped", "noBatchStall", "staticNetwork", "staticNoStall", "unbatched", "unbatchedStatic"] as ClientName[]);

/** S3 read-set cells: the six reads issued together (or one after another) on one client. */
export interface ReadSetVariant {
  name: string;
  client: ClientName;
  concurrent: boolean;
  multicall: boolean;
  label: Label;
  description: string;
}

export const READSET_VARIANTS: readonly ReadSetVariant[] = Object.freeze([
  { name: "sequentialShipped", client: "asShipped", concurrent: false, multicall: false, label: "as shipped", description: "the six reads awaited one after another on the shipped client" },
  { name: "concurrentShipped", client: "asShipped", concurrent: true, multicall: false, label: "variant, not shipped", description: "the six reads started together on the shipped client" },
  { name: "parallel", client: "unbatchedStatic", concurrent: true, multicall: false, label: "variant, not shipped", description: "the six reads started together, one POST per request" },
  { name: "batched", client: "staticNoStall", concurrent: true, multicall: false, label: "variant, not shipped", description: "the six reads started together, JSON-RPC batch per turn" },
  { name: "multicall", client: "staticNoStall", concurrent: true, multicall: true, label: "variant, not shipped", description: "the six reads started together, eth_calls aggregated in ChainReadBatch" },
] satisfies ReadSetVariant[]);
