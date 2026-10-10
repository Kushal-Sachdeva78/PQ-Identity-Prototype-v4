import type { Rng } from "./rng.ts";
import { P_BIG, Q_BIG, refUtcDateOf, daysFromCivil, civilFromDays } from "./oracles.ts";

/**
 * Generators of VALID protocol objects with random field values (synthetic: no real keys, no
 * signatures that verify unless a target signs them itself). The fuzz targets start from these
 * and mutate them, so most cases sit near the boundary between valid and invalid input.
 */

const BASE58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

export function didPq(rng: Rng): string {
  const n = rng.weighted<number>([
    [6, 44],
    [2, rng.int(1, 64)],
    [1, 1],
    [1, 64],
  ]);
  let s = "did:pq:";
  for (let i = 0; i < n; i++) s += BASE58[rng.int(0, 57)];
  return s;
}

export function lowerHex(rng: Rng, chars: number): string {
  return rng.bytes(Math.ceil(chars / 2)).toString("hex").slice(0, chars);
}

export function address(rng: Rng): string {
  return "0x" + lowerHex(rng, 40);
}

export function fieldElement(rng: Rng): bigint {
  return rng.weighted<bigint>([
    [8, rng.bigBelow(P_BIG)],
    [1, 0n],
    [1, P_BIG - 1n],
    [1, BigInt(rng.int(0, 1000))],
  ]);
}

export function fieldDec(rng: Rng): string {
  return fieldElement(rng).toString();
}

export function baseFieldDec(rng: Rng): string {
  return rng.weighted<bigint>([
    [8, rng.bigBelow(Q_BIG)],
    [1, 0n],
    [1, 1n],
    [1, Q_BIG - 1n],
  ]).toString();
}

export function chainId(rng: Rng): number {
  return rng.pick([1, 31337, 11155111, 8453, rng.int(1, 2 ** 31), 2 ** 53 - 1]);
}

/** Unix seconds between 1970 and 2100 with a bias towards day boundaries. */
export function unixTime(rng: Rng): number {
  const day = rng.int(0, daysFromCivil(2099, 12, 31));
  const off = rng.weighted<number>([
    [4, rng.int(0, 86399)],
    [1, 0],
    [1, 86399],
    [1, rng.int(0, 600)],
    [1, 86400 - rng.int(1, 600)],
  ]);
  return day * 86400 + off;
}

/** A valid YYYYMMDD date in [1900-01-01, 9999-12-31] with leap-day and month-end bias. */
export function ymd(rng: Rng): number {
  const kind = rng.weighted<string>([
    [5, "any"],
    [1, "feb29"],
    [1, "monthEnd"],
    [1, "yearEdge"],
  ]);
  if (kind === "feb29") {
    const y = rng.pick([1904, 1996, 2000, 2004, 2024, 2028, 2400, 9996]);
    return y * 10000 + 229;
  }
  if (kind === "monthEnd") {
    const y = rng.int(1900, 2100);
    const m = rng.int(1, 12);
    const end = civilFromDays(daysFromCivil(m === 12 ? y + 1 : y, m === 12 ? 1 : m + 1, 1) - 1);
    return end.y * 10000 + end.m * 100 + end.d;
  }
  if (kind === "yearEdge") return rng.pick([19000101, 99991231, 19991231, 20000101, 20991231]);
  const z = rng.int(daysFromCivil(1900, 1, 1), daysFromCivil(9999, 12, 31));
  const c = civilFromDays(z);
  return c.y * 10000 + c.m * 100 + c.d;
}

function windowFor(rng: Rng, cap: number): { notBefore: number; notAfter: number } {
  const notBefore = unixTime(rng);
  const len = rng.weighted<number>([
    [4, cap],
    [2, rng.int(1, cap)],
    [1, 1],
  ]);
  return { notBefore, notAfter: notBefore + len };
}

export const STATEMENT_KINDS = ["pop", "acc", "epoch", "kem"] as const;
export type StatementKind = (typeof STATEMENT_KINDS)[number];

/** A valid statement of the given kind (or a random kind). */
export function statement(rng: Rng, kind?: StatementKind): Record<string, unknown> {
  const k = kind ?? rng.pick(STATEMENT_KINDS);
  switch (k) {
    case "pop": {
      const originLen = rng.weighted<number>([
        [3, 0],
        [3, rng.int(1, 40)],
        [1, 256],
      ]);
      let origin = "";
      for (let i = 0; i < originLen; i++) origin += String.fromCharCode(rng.int(0x21, 0x7e));
      if (originLen > 0 && rng.bool(0.5)) origin = ("https://" + rng.bytes(6).toString("hex") + ".example").slice(0, originLen);
      return { type: "pqid:did-pop:v2", did: didPq(rng), controller: address(rng), chainId: chainId(rng), registry: address(rng), nonce: lowerHex(rng, 64), origin };
    }
    case "acc": {
      const w = windowFor(rng, 30 * 86400);
      return {
        type: "pqid:accreditation:v2",
        issuerDid: didPq(rng),
        controller: address(rng),
        pkSha3: lowerHex(rng, 64),
        chainId: chainId(rng),
        registry: address(rng),
        serial: rng.pick([0, 1, 2, rng.int(0, 1 << 20), 2 ** 53 - 1]),
        status: rng.pick(["accredited", "revoked"]),
        ...w,
      };
    }
    case "epoch": {
      const w = windowFor(rng, 86400);
      return {
        type: "pqid:issuer-epoch:v4",
        issuer: didPq(rng),
        controller: address(rng),
        chainId: chainId(rng),
        registry: address(rng),
        epoch: rng.pick([0, 1, 2, rng.int(0, 1e6)]),
        root: fieldDec(rng),
        revRoot: fieldDec(rng),
        ...w,
        fromDate: refUtcDateOf(w.notBefore),
        toDate: refUtcDateOf(w.notAfter),
      };
    }
    default: {
      const w = windowFor(rng, 400 * 86400);
      return { type: "pqid:verifier-kem:v1", verifier: didPq(rng), controller: address(rng), chainId: chainId(rng), registry: address(rng), kemAlg: "ML-KEM-768", kemPkSha3: lowerHex(rng, 64), ...w };
    }
  }
}

/** A valid ProofRequestV4 (random fields). */
export function request(rng: Rng): Record<string, unknown> {
  const typeIdLen = rng.weighted<number>([
    [4, 27],
    [2, rng.int(1, 64)],
    [1, 256],
  ]);
  const typeId = typeIdLen === 27 ? "pqid:type:age-credential:v1" : "t".repeat(typeIdLen);
  return {
    type: "pqid:request:v4",
    sessionId: lowerHex(rng, 64),
    verifierDid: didPq(rng),
    verifierController: address(rng),
    chainId: chainId(rng),
    policy: {
      predicate: rng.pick(["age_gte", "age_lt"]),
      threshold: rng.pick([13, 14, 15, 16, 18, 21, 65, 0, 255, rng.int(0, 255)]),
      typeId,
      today: ymd(rng),
    },
    issuedAt: unixTime(rng),
  };
}

/** A valid SessionReplyV4 (random ct and box bytes; box short unless asked). */
export function reply(rng: Rng, boxBytes?: number): Record<string, unknown> {
  const n = boxBytes ?? rng.weighted<number>([
    [6, rng.int(16, 4096)],
    [1, 16],
    [1, rng.int(17, 200_000)],
  ]);
  return { type: "pqid:reply:v4", sessionId: lowerHex(rng, 64), ct: lowerHex(rng, 2176), box: rng.bytes(n).toString("hex") };
}

/** A presentation that passes the verifier's shape check (random values, nothing verifies). */
export function presentation(rng: Rng): Record<string, unknown> {
  const w = windowFor(rng, 86400);
  const issuer = didPq(rng);
  const controller = address(rng);
  return {
    proof: {
      pi_a: [baseFieldDec(rng), baseFieldDec(rng), "1"],
      pi_b: [
        [baseFieldDec(rng), baseFieldDec(rng)],
        [baseFieldDec(rng), baseFieldDec(rng)],
        ["1", "0"],
      ],
      pi_c: [baseFieldDec(rng), baseFieldDec(rng), "1"],
      protocol: "groth16",
      curve: "bn128",
    },
    publicSignals: Array.from({ length: 8 }, () => fieldDec(rng)),
    issuerDid: issuer,
    issuerController: controller,
    epochStatement: {
      issuer,
      controller,
      chainId: chainId(rng),
      registry: address(rng),
      epoch: rng.int(0, 1000),
      root: fieldDec(rng),
      revRoot: fieldDec(rng),
      ...w,
      fromDate: refUtcDateOf(w.notBefore),
      toDate: refUtcDateOf(w.notAfter),
      signature: lowerHex(rng, 4840),
    },
  };
}

/** Random JSON-like value tree (iterative; depth up to `maxDepth`, size bounded). */
export function jsonTree(rng: Rng, maxDepth: number, maxNodes = 200): unknown {
  let nodes = 0;
  const leaf = (): unknown => rng.pick([null, true, false, 0, 1, -1, 1.5, "", "x", "0123", rng.int(0, 1e6)]);
  const build = (depth: number): unknown => {
    nodes++;
    if (depth >= maxDepth || nodes > maxNodes || rng.bool(0.3)) return leaf();
    const n = rng.small(4, 0.6);
    if (rng.bool()) {
      const a: unknown[] = [];
      for (let i = 0; i < n; i++) a.push(build(depth + 1));
      return a;
    }
    const o: Record<string, unknown> = {};
    for (let i = 0; i < n; i++) o["k" + i] = build(depth + 1);
    return o;
  };
  return build(0);
}

/** A chain of `depth` nested arrays or objects, built iteratively (no recursion). */
export function deepChain(depth: number, kind: "array" | "object"): unknown {
  let v: unknown = 0;
  for (let i = 0; i < depth; i++) v = kind === "array" ? [v] : { a: v };
  return v;
}
