// Minimal typed surface of circomlibjs 0.1.7 as used by this prototype.
declare module "circomlibjs" {
  export interface FieldLike {
    toObject(e: Uint8Array): bigint;
    e(v: bigint | number | string): Uint8Array;
    toString(e: Uint8Array, radix?: number): string;
    isZero(e: Uint8Array): boolean;
    p: bigint;
  }

  export interface Poseidon {
    (inputs: Array<bigint | number | string | Uint8Array>): Uint8Array;
    F: FieldLike;
  }
  export function buildPoseidon(): Promise<Poseidon>;

  export interface SmtFindResult {
    found: boolean;
    siblings: Uint8Array[];
    foundValue?: Uint8Array;
    notFoundKey?: Uint8Array;
    notFoundValue?: Uint8Array;
    isOld0: boolean;
  }

  export interface SMT {
    F: FieldLike;
    root: Uint8Array;
    insert(key: bigint | Uint8Array, value: bigint | Uint8Array): Promise<unknown>;
    delete(key: bigint | Uint8Array): Promise<unknown>;
    find(key: bigint | Uint8Array): Promise<SmtFindResult>;
  }
  export function newMemEmptyTrie(): Promise<SMT>;
}
