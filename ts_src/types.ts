import * as tools from 'uint8array-tools';
import * as v from 'valibot';

const ZERO32 = new Uint8Array(32);
const EC_P = tools.fromHex(
  'fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f',
);

export const NBufferSchemaFactory = (size: number) =>
  v.pipe(v.instance(Uint8Array), v.length(size));

/**
 * Checks if two arrays of Buffers are equal.
 * @param a - The first array of Buffers.
 * @param b - The second array of Buffers.
 * @returns True if the arrays are equal, false otherwise.
 */
export function stacksEqual(a: Uint8Array[], b: Uint8Array[]): boolean {
  if (a.length !== b.length) return false;

  return a.every((x, i) => {
    return tools.compare(x, b[i]) === 0;
  });
}

/**
 * Checks if the given value is a valid elliptic curve point.
 * @param p - The value to check.
 * @returns True if the value is a valid elliptic curve point, false otherwise.
 */
export function isPoint(p: Uint8Array | number | undefined | null): boolean {
  if (!(p instanceof Uint8Array)) return false;
  if (p.length < 33) return false;

  const t = p[0];
  const x = p.slice(1, 33);
  if (tools.compare(ZERO32, x) === 0) return false;
  if (tools.compare(x, EC_P) >= 0) return false;
  if ((t === 0x02 || t === 0x03) && p.length === 33) {
    return true;
  }

  const y = p.slice(33);
  if (tools.compare(ZERO32, y) === 0) return false;
  if (tools.compare(y, EC_P) >= 0) return false;
  if (t === 0x04 && p.length === 65) return true;
  return false;
}

export interface XOnlyPointAddTweakResult {
  parity: 1 | 0;
  xOnlyPubkey: Uint8Array;
}

export interface Tapleaf {
  output: Uint8Array;
  version?: number;
}

export const TAPLEAF_VERSION_MASK = 0xfe;
export function isTapleaf(o: any): o is Tapleaf {
  if (!o || !('output' in o)) return false;
  if (!(o.output instanceof Uint8Array)) return false;
  if (o.version !== undefined)
    return (o.version & TAPLEAF_VERSION_MASK) === o.version;
  return true;
}

/**
 * Binary tree repsenting script path spends for a Taproot input.
 * Each node is either a single Tapleaf, or a pair of Tapleaf | Taptree.
 * The tree has no balancing requirements.
 */
export type Taptree = [Taptree | Tapleaf, Taptree | Tapleaf] | Tapleaf;

export function isTaptree(scriptTree: any): scriptTree is Taptree {
  if (!Array.isArray(scriptTree)) return isTapleaf(scriptTree);
  if (scriptTree.length !== 2) return false;
  return scriptTree.every((t: any) => isTaptree(t));
}

export interface TinySecp256k1Interface {
  isXOnlyPoint(p: Uint8Array): boolean;
  xOnlyPointAddTweak(
    p: Uint8Array,
    tweak: Uint8Array,
  ): XOnlyPointAddTweakResult | null;
}

export const Buffer256bitSchema = NBufferSchemaFactory(32);
export const Hash160bitSchema = NBufferSchemaFactory(20);
export const Hash256bitSchema = NBufferSchemaFactory(32);
export const BufferSchema = v.instance(Uint8Array);
export const HexSchema = v.pipe(v.string(), v.regex(/^([0-9a-f]{2})+$/i));
export const UInt8Schema = v.pipe(
  v.number(),
  v.integer(),
  v.minValue(0),
  v.maxValue(0xff),
);
export const UInt32Schema = v.pipe(
  v.number(),
  v.integer(),
  v.minValue(0),
  v.maxValue(0xffffffff),
);
export const UInt53Schema = v.pipe(
  v.number(),
  v.integer(),
  v.minValue(0),
  v.maxValue(0x1fffffffffffff),
);
export const SatoshiSchema = v.pipe(
  v.bigint(),
  v.minValue(0n),
  v.maxValue(0x7fff_ffff_ffff_ffffn),
);

export const NullablePartial = (a: Record<string, any>) =>
  v.object(
    Object.entries(a).reduce(
      (acc, next) => ({ ...acc, [next[0]]: v.nullish(next[1]) }),
      {},
    ),
  );
