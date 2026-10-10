import type { Poseidon } from "circomlibjs";
import { getPoseidon, poseidonBig } from "@pqid/common/encoding";
import type { IssuancePath } from "@pqid/issuer";
import { ISSUANCE_DEPTH } from "./constants.ts";
import { IndexedMerkleTree } from "./imt.ts";
import { revKeyFromCredId } from "./encoding.ts";
import type { IssuerV4, EpochStatementV4, IssuanceServiceReply } from "./issuer.ts";
import type { IssuerDataSource } from "./wallet.ts";

/**
 * Published-tree mode (E3). For each anchored epoch the issuer publishes ONE blob that every
 * wallet downloads: the signed epoch statement, every issuance-tree leaf up to the anchored
 * size, and the anchored revocation tree. A wallet rebuilds its own issuance path and
 * non-membership witness locally, so the issuer's online services never learn which
 * credential is about to be presented (or when). The honest wallet's checks are unchanged:
 * the rebuilt roots must equal the anchored statement (wallet check anchorMatches).
 *
 * Blob layout (big-endian):
 *   "PQIDPUB1" | u8 issuance depth | 3 x 0 | u32 size n | u32 statement length L |
 *   L bytes canonical JSON statement (with signature) | n x 32 B issuance leaves |
 *   u32 IMT length M | M bytes IndexedMerkleTree.serialize()
 * Size = 20 + L + 32 n + 4 + (48 + 32 r) bytes for n credentials and r revocations.
 */
export const PUB_MAGIC = "PQIDPUB1";

function writeBig32(out: Uint8Array, off: number, v: bigint): void {
  for (let i = 31; i >= 0; i--) {
    out[off + i] = Number(v & 0xffn);
    v >>= 8n;
  }
}
function readBig32(b: Uint8Array, off: number): bigint {
  let v = 0n;
  for (let i = 0; i < 32; i++) v = (v << 8n) | BigInt(b[off + i] as number);
  return v;
}

/** The issuer's published blob for its currently anchored epoch. */
export function publishedEpochBlob(issuer: IssuerV4): Uint8Array {
  const a = issuer.anchored;
  if (!a) throw new Error("no anchored epoch to publish");
  const st = new TextEncoder().encode(JSON.stringify(a.statement));
  const imt = a.rev.serialize();
  const n = a.size;
  const out = new Uint8Array(20 + st.length + 32 * n + 4 + imt.length);
  const dv = new DataView(out.buffer);
  for (let i = 0; i < 8; i++) out[i] = PUB_MAGIC.charCodeAt(i);
  out[8] = issuer.tree.depth;
  dv.setUint32(12, n, false);
  dv.setUint32(16, st.length, false);
  out.set(st, 20);
  let off = 20 + st.length;
  for (let i = 0; i < n; i++, off += 32) writeBig32(out, off, issuer.tree.leaf(i));
  dv.setUint32(off, imt.length, false);
  out.set(imt, off + 4);
  return out;
}

/** Issuance tree rebuilt bottom-up from published leaves (only non-empty nodes stored). */
export class IssuanceSnapshot {
  private constructor(
    readonly depth: number,
    private readonly levels: bigint[][],
    private readonly zeros: bigint[]
  ) {}

  static async build(leaves: bigint[], depth = ISSUANCE_DEPTH, poseidon?: Poseidon): Promise<IssuanceSnapshot> {
    const p = poseidon ?? (await getPoseidon());
    const zeros: bigint[] = [0n];
    for (let l = 0; l < depth; l++) zeros.push(poseidonBig(p, [zeros[l] as bigint, zeros[l] as bigint]));
    const levels: bigint[][] = [leaves.slice()];
    for (let l = 0; l < depth; l++) {
      const cur = levels[l] as bigint[];
      const next: bigint[] = new Array(Math.ceil(cur.length / 2));
      for (let i = 0; i < next.length; i++) {
        const left = cur[2 * i] as bigint;
        const right = 2 * i + 1 < cur.length ? (cur[2 * i + 1] as bigint) : (zeros[l] as bigint);
        next[i] = poseidonBig(p, [left, right]);
      }
      levels.push(next.length ? next : [zeros[l + 1] as bigint]);
    }
    return new IssuanceSnapshot(depth, levels, zeros);
  }

  root(): bigint {
    const top = this.levels[this.depth] as bigint[];
    return top[0] ?? (this.zeros[this.depth] as bigint);
  }

  path(index: number): IssuancePath {
    if (!Number.isInteger(index) || index < 0 || index >= (this.levels[0] as bigint[]).length) throw new Error(`no published leaf ${index}`);
    const pathElements: string[] = [];
    let i = index;
    for (let l = 0; l < this.depth; l++) {
      const sib = i % 2 === 0 ? i + 1 : i - 1;
      pathElements.push(((this.levels[l] as bigint[])[sib] ?? (this.zeros[l] as bigint)).toString());
      i = Math.floor(i / 2);
    }
    return { leafIndex: index.toString(), pathElements, root: this.root().toString() };
  }
}

export interface ParsedPublication {
  statement: EpochStatementV4;
  issuance: IssuanceSnapshot;
  rev: IndexedMerkleTree;
  bytes: number;
}

/** Parse a downloaded blob and rebuild both trees (throws if they do not match the statement). */
export async function parsePublication(blob: Uint8Array): Promise<ParsedPublication> {
  for (let i = 0; i < 8; i++) if (blob[i] !== PUB_MAGIC.charCodeAt(i)) throw new Error("not a published-tree blob");
  const dv = new DataView(blob.buffer, blob.byteOffset, blob.byteLength);
  const depth = blob[8] as number;
  const n = dv.getUint32(12, false);
  const L = dv.getUint32(16, false);
  const statement = JSON.parse(new TextDecoder().decode(blob.subarray(20, 20 + L))) as EpochStatementV4;
  let off = 20 + L;
  const leaves: bigint[] = new Array(n);
  for (let i = 0; i < n; i++, off += 32) leaves[i] = readBig32(blob, off);
  const M = dv.getUint32(off, false);
  const rev = await IndexedMerkleTree.deserialize(blob.subarray(off + 4, off + 4 + M));
  const issuance = await IssuanceSnapshot.build(leaves, depth);
  if (issuance.root().toString() !== statement.root) throw new Error("published leaves do not rebuild the statement's root");
  if (rev.root().toString() !== statement.revRoot) throw new Error("published revocation tree does not match the statement's revRoot");
  return { statement, issuance, rev, bytes: blob.length };
}

/**
 * Wallet data source backed by a published blob. The wallet knows its own leaf index
 * (returned at issuance); nothing is requested from the issuer.
 */
export function publishedSource(pub: ParsedPublication, leafIndexByCredId: ReadonlyMap<string, number>): IssuerDataSource {
  return {
    issuance(credIdHex: string): IssuanceServiceReply {
      const idx = leafIndexByCredId.get(credIdHex);
      if (idx === undefined) throw new Error("wallet does not know this credential's leaf index");
      return { path: pub.issuance.path(idx), statement: pub.statement };
    },
    revocation(credIdHex: string) {
      return pub.rev.nonMembershipWitness(revKeyFromCredId(Buffer.from(credIdHex, "hex")));
    },
  };
}

/** Exact published size in bytes for n credentials, r revocations, statement length L. */
export function publishedBytes(n: number, r: number, statementBytes: number): number {
  return 20 + statementBytes + 32 * n + 4 + 48 + 32 * r;
}
