/**
 * Script tools, including decompile, compile, toASM, fromASM, toStack, isCanonicalPubKey, isCanonicalScriptSignature
 * @packageDocumentation
 */
import * as bip66 from './bip66.js';
import { OPS, REVERSE_OPS } from './ops.js';
import { Stack } from './payments/index.js';
import * as pushdata from './push_data.js';
import * as scriptNumber from './script_number.js';
import * as scriptSignature from './script_signature.js';
import * as types from './types.js';
import * as tools from 'uint8array-tools';
import * as v from 'valibot';

const OP_INT_BASE = OPS.OP_RESERVED; // OP_1 - 1
export { OPS };

const StackSchema = v.array(v.union([v.instance(Uint8Array), v.number()]));

function isOPInt(value: number): boolean {
  return (
    v.is(v.number(), value) &&
    (value === OPS.OP_0 ||
      (value >= OPS.OP_1 && value <= OPS.OP_16) ||
      value === OPS.OP_1NEGATE)
  );
}

function isPushOnlyChunk(value: number | Uint8Array): boolean {
  return v.is(types.BufferSchema, value) || isOPInt(value as number);
}

export function isPushOnly(value: Stack): boolean {
  return v.is(
    v.pipe(v.any(), v.everyItem(isPushOnlyChunk as (x: any) => boolean)),
    value,
  );
}

export function countNonPushOnlyOPs(value: Stack): number {
  return value.length - value.filter(isPushOnlyChunk).length;
}

function asMinimalOP(buffer: Uint8Array): number | void {
  if (buffer.length === 0) return OPS.OP_0;
  if (buffer.length !== 1) return;
  if (buffer[0] >= 1 && buffer[0] <= 16) return OP_INT_BASE + buffer[0];
  if (buffer[0] === 0x81) return OPS.OP_1NEGATE;
}

function chunksIsBuffer(buf: Uint8Array | Stack): buf is Uint8Array {
  return buf instanceof Uint8Array;
}

function chunksIsArray(buf: Uint8Array | Stack): buf is Stack {
  return v.is(StackSchema, buf);
}

function singleChunkIsBuffer(buf: number | Uint8Array): buf is Uint8Array {
  return buf instanceof Uint8Array;
}

/**
 * Compiles an array of chunks into a Buffer.
 *
 * @param chunks - The array of chunks to compile.
 * @returns The compiled Buffer.
 * @throws Error if the compilation fails.
 */
export function compile(chunks: Uint8Array | Stack): Uint8Array {
  // TODO: remove me
  if (chunksIsBuffer(chunks)) return chunks;

  v.parse(StackSchema, chunks);

  const bufferSize = chunks.reduce((accum: number, chunk) => {
    // data chunk
    if (singleChunkIsBuffer(chunk)) {
      // adhere to BIP62.3, minimal push policy
      if (chunk.length === 1 && asMinimalOP(chunk) !== undefined) {
        return accum + 1;
      }

      return accum + pushdata.encodingLength(chunk.length) + chunk.length;
    }

    // opcode
    return accum + 1;
  }, 0.0);

  const buffer = new Uint8Array(bufferSize);
  let offset = 0;

  chunks.forEach(chunk => {
    // data chunk
    if (singleChunkIsBuffer(chunk)) {
      // adhere to BIP62.3, minimal push policy
      const opcode = asMinimalOP(chunk);
      if (opcode !== undefined) {
        tools.writeUInt8(buffer, offset, opcode);
        offset += 1;
        return;
      }

      offset += pushdata.encode(buffer, chunk.length, offset);
      buffer.set(chunk, offset);
      offset += chunk.length;

      // opcode
    } else {
      tools.writeUInt8(buffer, offset, chunk);
      offset += 1;
    }
  });

  if (offset !== buffer.length) throw new Error('Could not decode chunks');
  return buffer;
}

export function decompile(
  buffer: Uint8Array | Array<number | Uint8Array>,
): Array<number | Uint8Array> | null {
  // TODO: remove me
  if (chunksIsArray(buffer)) return buffer;

  v.parse(types.BufferSchema, buffer);

  const chunks: Array<number | Uint8Array> = [];
  let i = 0;

  while (i < buffer.length) {
    const opcode = buffer[i];

    // data chunk
    if (opcode > OPS.OP_0 && opcode <= OPS.OP_PUSHDATA4) {
      const d = pushdata.decode(buffer, i);

      // did reading a pushDataInt fail?
      if (d === null) return null;
      i += d.size;

      // attempt to read too much data?
      if (i + d.number > buffer.length) return null;

      const data = buffer.slice(i, i + d.number);
      i += d.number;

      // decompile minimally
      const op = asMinimalOP(data);
      if (op !== undefined) {
        chunks.push(op);
      } else {
        chunks.push(data);
      }

      // opcode
    } else {
      chunks.push(opcode);

      i += 1;
    }
  }

  return chunks;
}

/**
 * Converts the given chunks into an ASM (Assembly) string representation.
 * If the chunks parameter is a Buffer, it will be decompiled into a Stack before conversion.
 * @param chunks - The chunks to convert into ASM.
 * @returns The ASM string representation of the chunks.
 */
export function toASM(chunks: Uint8Array | Array<number | Uint8Array>): string {
  if (chunksIsBuffer(chunks)) {
    chunks = decompile(chunks) as Stack;
  }
  if (!chunks) {
    throw new Error('Could not convert invalid chunks to ASM');
  }
  return (chunks as Stack)
    .map(chunk => {
      // data?
      if (singleChunkIsBuffer(chunk)) {
        const op = asMinimalOP(chunk);
        if (op === undefined) return tools.toHex(chunk);
        chunk = op as number;
      }

      // opcode!
      return REVERSE_OPS[chunk];
    })
    .join(' ');
}

/**
 * Converts an ASM string to a Buffer.
 * @param asm The ASM string to convert.
 * @returns The converted Buffer.
 */
export function fromASM(asm: string): Uint8Array {
  v.parse(v.string(), asm);

  return compile(
    asm.split(' ').map(chunkStr => {
      // opcode?
      if (OPS[chunkStr] !== undefined) return OPS[chunkStr];
      v.parse(types.HexSchema, chunkStr);

      // data!
      return tools.fromHex(chunkStr);
    }),
  );
}

/**
 * Converts the given chunks into a stack of buffers.
 *
 * @param chunks - The chunks to convert.
 * @returns The stack of buffers.
 */
export function toStack(
  chunks: Uint8Array | Array<number | Uint8Array>,
): Uint8Array[] {
  chunks = decompile(chunks) as Stack;
  v.parse(v.custom(isPushOnly as (x: any) => boolean), chunks);

  return chunks.map(op => {
    if (singleChunkIsBuffer(op)) return op;
    if (op === OPS.OP_0) return new Uint8Array(0);

    return scriptNumber.encode(op - OP_INT_BASE);
  });
}

export function isCanonicalPubKey(buffer: Uint8Array): boolean {
  return types.isPoint(buffer);
}

export function isDefinedHashType(hashType: number): boolean {
  const hashTypeMod = hashType & ~0xc0;

  return hashTypeMod > 0x00 && hashTypeMod < 0x04;
}

export function isCanonicalScriptSignature(buffer: Uint8Array): boolean {
  if (!(buffer instanceof Uint8Array)) return false;
  if (!isDefinedHashType(buffer[buffer.length - 1])) return false;

  return bip66.check(buffer.slice(0, -1));
}

export const number = scriptNumber;
export const signature = scriptSignature;
