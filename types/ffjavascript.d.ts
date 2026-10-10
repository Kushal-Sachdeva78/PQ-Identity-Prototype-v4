// Minimal typed surface of ffjavascript (a snarkjs dependency) as used by
// harness/v3/trapdoor.ts to reproduce the public-beacon trapdoor (finding 9.3).
declare module "ffjavascript" {
  export type FieldElement = Uint8Array;
  export type Point = Uint8Array;

  export class ChaCha {
    constructor(seed: number[]);
  }

  export interface Field {
    e(v: string | bigint | number): FieldElement;
    inv(a: FieldElement): FieldElement;
    fromRng(rng: ChaCha): FieldElement;
  }

  export interface Group<C> {
    g: Point;
    fromObject(o: C): Point;
    toObject(p: Point): C;
    toAffine(p: Point): Point;
    add(a: Point, b: Point): Point;
    neg(a: Point): Point;
    eq(a: Point, b: Point): boolean;
    timesFr(p: Point, s: FieldElement): Point;
  }

  export interface Curve {
    Fr: Field;
    G1: Group<bigint[]>;
    G2: Group<bigint[][]>;
    terminate(): Promise<void>;
  }

  export function getCurveFromName(name: string): Promise<Curve>;
}
