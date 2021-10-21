const createHash = require('create-hash');

const AlgorithmLength: {
  ripemd160: 20;
  sha1: 20;
  sha256: 32;
  hash160: 20;
  hash256: 32;
} = {
  ripemd160: 20,
  sha1: 20,
  sha256: 32,
  hash160: 20,
  hash256: 32,
};

type AlgorithmName = keyof typeof AlgorithmLength;

export type Digest<T extends AlgorithmName = AlgorithmName> = Buffer & {
  length: typeof AlgorithmLength[T];
  preimage: Buffer;
  algorithm: T;
};

export type NonDigest = Buffer &
  Partial<Record<'algorithm' | 'preimage', never>>;

function asDigest<T extends AlgorithmName>(
  buffer: Buffer,
  preimage: Buffer,
  algorithm: T,
): Digest<T> {
  const out = Object.assign(buffer, {
    preimage,
    algorithm,
  });
  const expectedLength = AlgorithmLength[algorithm];
  if (out.length !== expectedLength) throw new Error('bad digest length');
  return out as typeof out & { length: typeof expectedLength };
}

export function ripemd160(buffer: Buffer): Digest<'ripemd160'> {
  let out: Buffer;
  try {
    out = createHash('rmd160')
      .update(buffer)
      .digest();
  } catch (err) {
    out = createHash('ripemd160')
      .update(buffer)
      .digest();
  }
  return asDigest(out, buffer, 'ripemd160');
}

export function sha1(buffer: Buffer): Digest<'sha1'> {
  const out = createHash('sha1')
    .update(buffer)
    .digest();
  return asDigest(out, buffer, 'sha1');
}

export function sha256(buffer: Buffer): Digest<'sha256'> {
  const out = createHash('sha256')
    .update(buffer)
    .digest();
  return asDigest(out, buffer, 'sha256');
}

export function hash160(buffer: Buffer): Digest<'hash160'> {
  const out = ripemd160(sha256(buffer));
  return asDigest(out, buffer, 'hash160');
}

export function hash256(buffer: Buffer): Digest<'hash256'> {
  const out = sha256(sha256(buffer));
  return asDigest(out, buffer, 'hash256');
}
