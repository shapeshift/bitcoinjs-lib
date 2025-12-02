import {
  BufferReader,
  BufferWriter,
  reverseBuffer,
  varuint,
} from './bufferutils.js';
import * as bcrypto from './crypto.js';
import { sha256 } from '@noble/hashes/sha256';
import * as bscript from './script.js';
import { OPS as opcodes } from './script.js';
import * as types from './types.js';
import * as tools from 'uint8array-tools';
import * as v from 'valibot';
import * as zip243 from './zip243.js';
import * as zip244 from './zip244.js';

export function varSliceSize(someScript: Uint8Array): number {
  const length = someScript.length;

  return varuint.encodingLength(length) + length;
}

function vectorSize(someVector: Uint8Array[]): number {
  const length = someVector.length;

  return (
    varuint.encodingLength(length) +
    someVector.reduce((sum, witness) => {
      return sum + varSliceSize(witness);
    }, 0)
  );
}

const EMPTY_BUFFER: Uint8Array = new Uint8Array(0);
const EMPTY_WITNESS: Uint8Array[] = [];
export const ZERO = tools.fromHex(
  '0000000000000000000000000000000000000000000000000000000000000000',
);
const ONE = tools.fromHex(
  '0000000000000000000000000000000000000000000000000000000000000001',
);
const VALUE_UINT64_MAX = tools.fromHex('ffffffffffffffff');
const BLANK_OUTPUT = {
  script: EMPTY_BUFFER,
  valueBuffer: VALUE_UINT64_MAX,
};

function isOutput(out: Output): boolean {
  return out.value !== undefined;
}

export interface Output {
  script: Uint8Array;
  value: bigint;
}

export interface Input {
  hash: Uint8Array;
  index: number;
  script: Uint8Array;
  sequence: number;
  witness: Uint8Array[];
}

/**
 * Represents a Bitcoin transaction.
 */
export class Transaction {
  static readonly DEFAULT_SEQUENCE = 0xffffffff;
  static readonly SIGHASH_DEFAULT = 0x00;
  static readonly SIGHASH_ALL = 0x01;
  static readonly SIGHASH_NONE = 0x02;
  static readonly SIGHASH_SINGLE = 0x03;
  static readonly SIGHASH_ANYONECANPAY = 0x80;
  static readonly SIGHASH_BITCOINCASHBIP143 = 0x40;
  static readonly SIGHASH_OUTPUT_MASK = 0x03;
  static readonly SIGHASH_INPUT_MASK = 0x80;
  static readonly ADVANCED_TRANSACTION_MARKER = 0x00;
  static readonly ADVANCED_TRANSACTION_FLAG = 0x01;

  static fromBuffer(buffer: Uint8Array, _NO_STRICT?: boolean): Transaction {
    const bufferReader = new BufferReader(buffer);

    const tx = new Transaction();

    const header = bufferReader.readUInt32();

    // Zcash uses the high bit as an "overwintered" flag for versions 3, 4, and 5
    const version = header & 0x7fffffff;
    tx.overwintered =
      [3, 4, 5].includes(version) && (header & 0x80000000) !== 0;

    // For Zcash overwintered txs, version excludes the flag bit
    // For Bitcoin txs, preserve the full 32-bit value
    tx.version = tx.overwintered ? version : header;

    let hasWitnesses = false;
    if (tx.overwintered) {
      tx.versionGroupId = bufferReader.readUInt32();
      if (tx.version === 5) {
        tx.consensusBranchId = bufferReader.readUInt32();
        tx.locktime = bufferReader.readUInt32();
        tx.expiryHeight = bufferReader.readUInt32();
      }
    } else {
      const marker = bufferReader.readUInt8();
      const flag = bufferReader.readUInt8();

      if (
        marker === Transaction.ADVANCED_TRANSACTION_MARKER &&
        flag === Transaction.ADVANCED_TRANSACTION_FLAG
      ) {
        hasWitnesses = true;
      } else {
        bufferReader.offset -= 2;
      }
    }

    const vinLen = bufferReader.readVarInt();
    for (let i = 0; i < vinLen; ++i) {
      tx.ins.push({
        hash: bufferReader.readSlice(32),
        index: bufferReader.readUInt32(),
        script: bufferReader.readVarSlice(),
        sequence: bufferReader.readUInt32(),
        witness: EMPTY_WITNESS,
      });
    }

    const voutLen = bufferReader.readVarInt();
    for (let i = 0; i < voutLen; ++i) {
      tx.outs.push({
        value: bufferReader.readInt64(),
        script: bufferReader.readVarSlice(),
      });
    }

    if (hasWitnesses) {
      for (let i = 0; i < vinLen; ++i) {
        tx.ins[i].witness = bufferReader.readVector();
      }

      // was this pointless?
      if (!tx.hasWitnesses())
        throw new Error('Transaction has superfluous witness data');
    }

    if (tx.overwintered) {
      switch (tx.version) {
        case 3: {
          tx.locktime = bufferReader.readUInt32();
          tx.expiryHeight = bufferReader.readUInt32();
          const nJoinSplit = bufferReader.readVarInt();
          if (nJoinSplit > 0) {
            // vJoinSplit
            // joinSplitPubKey
            // joinSplitSig
            throw new Error('Shielded transactions not supported');
          }
          break;
        }
        case 4: {
          tx.locktime = bufferReader.readUInt32();
          tx.expiryHeight = bufferReader.readUInt32();
          tx.valueBalance = bufferReader.readInt64();
          const nShieldedSpend = bufferReader.readVarInt();
          if (nShieldedSpend > 0) {
            // vShieldedSpend
            throw new Error('Shielded transactions not supported');
          }
          const nShieldedOutput = bufferReader.readVarInt();
          if (nShieldedOutput > 0) {
            // vShieldedOutput
            // bindingSig
            throw new Error('Shielded transactions not supported');
          }
          const nJoinSplit = bufferReader.readVarInt();
          if (nJoinSplit > 0) {
            // vJoinSplit
            // joinSplitPubKey
            // joinSplitSig
            throw new Error('Shielded transactions not supported');
          }
          break;
        }
        case 5: {
          const nSpendsSapling = bufferReader.readVarInt();
          if (nSpendsSapling > 0) {
            // vSpendsSapling
            throw new Error('Shielded transactions not supported');
          }
          const nOutputsSapling = bufferReader.readVarInt();
          if (nOutputsSapling > 0) {
            // vOutputsSapling
            // valueBalanceSapling
            // anchorSapling
            // vSpendProofsSapling
            // vSpendAuthSigsSapling
            // vOutputProofsSapling
            // bindingSigSapling
            throw new Error('Shielded transactions not supported');
          }
          const nActionsOrchard = bufferReader.readVarInt();
          if (nActionsOrchard > 0) {
            // vActionsOrchard
            // flagsOrchard
            // valueBalanceOrchard
            // anchorOrchard
            // sizeProofsOrchard
            // proofsOrchard
            // vSpendAuthSigsOrchard
            // bindingSigOrchard
            throw new Error('Shielded transactions not supported');
          }
          break;
        }
      }
    } else {
      tx.locktime = bufferReader.readUInt32();
    }

    if (_NO_STRICT) return tx;
    if (bufferReader.offset !== buffer.length)
      throw new Error('Transaction has unexpected data');

    return tx;
  }

  static fromHex(hex: string): Transaction {
    return Transaction.fromBuffer(tools.fromHex(hex), false);
  }

  static isCoinbaseHash(buffer: Uint8Array): boolean {
    v.parse(types.Hash256bitSchema, buffer);
    for (let i = 0; i < 32; ++i) {
      if (buffer[i] !== 0) return false;
    }
    return true;
  }

  version: number = 1;
  locktime: number = 0;
  ins: Input[] = [];
  outs: Output[] = [];

  // Zcash
  overwintered: boolean = false;
  versionGroupId?: number;
  consensusBranchId?: number;
  expiryHeight?: number;
  valueBalance?: bigint;

  isCoinbase(): boolean {
    return (
      this.ins.length === 1 && Transaction.isCoinbaseHash(this.ins[0].hash)
    );
  }

  addInput(
    hash: Uint8Array,
    index: number,
    sequence?: number,
    scriptSig?: Uint8Array,
  ): number {
    v.parse(
      v.tuple([
        types.Hash256bitSchema,
        types.UInt32Schema,
        v.nullable(v.optional(types.UInt32Schema)),
        v.nullable(v.optional(types.BufferSchema)),
      ]),
      [hash, index, sequence, scriptSig],
    );

    if (sequence === undefined || sequence === null) {
      sequence = Transaction.DEFAULT_SEQUENCE;
    }

    // Add the input and return the input's index
    return (
      this.ins.push({
        hash,
        index,
        script: scriptSig || EMPTY_BUFFER,
        sequence: sequence as number,
        witness: EMPTY_WITNESS,
      }) - 1
    );
  }

  addOutput(scriptPubKey: Uint8Array, value: bigint): number {
    v.parse(v.tuple([types.BufferSchema, types.SatoshiSchema]), [
      scriptPubKey,
      value,
    ]);

    // Add the output and return the output's index
    return (
      this.outs.push({
        script: scriptPubKey,
        value,
      }) - 1
    );
  }

  hasWitnesses(): boolean {
    return this.ins.some(x => {
      return x.witness.length !== 0;
    });
  }

  stripWitnesses(): void {
    this.ins.forEach(input => {
      input.witness = EMPTY_WITNESS; // Set witness data to an empty array
    });
  }

  weight(): number {
    const base = this.byteLength(false);
    const total = this.byteLength(true);
    return base * 3 + total;
  }

  virtualSize(): number {
    return Math.ceil(this.weight() / 4);
  }

  byteLength(_ALLOW_WITNESS: boolean = true): number {
    const hasWitnesses = _ALLOW_WITNESS && this.hasWitnesses();

    return (
      (hasWitnesses ? 10 : 8) +
      (this.overwintered ? (this.version !== 5 ? 8 : 12) : 0) +
      varuint.encodingLength(this.ins.length) +
      varuint.encodingLength(this.outs.length) +
      this.ins.reduce((sum, input) => {
        return sum + 40 + varSliceSize(input.script);
      }, 0) +
      this.outs.reduce((sum, output) => {
        return sum + 8 + varSliceSize(output.script);
      }, 0) +
      (hasWitnesses
        ? this.ins.reduce((sum, input) => {
            return sum + vectorSize(input.witness);
          }, 0)
        : 0) +
      (this.overwintered && this.version === 3 ? 1 : 0) +
      (this.overwintered && this.version === 4 ? 11 : 0) +
      (this.overwintered && this.version === 5 ? 3 : 0)
    );
  }

  clone(): Transaction {
    const newTx = new Transaction();

    newTx.version = this.version;
    newTx.overwintered = this.overwintered;
    newTx.versionGroupId = this.versionGroupId;
    newTx.consensusBranchId = this.consensusBranchId;
    newTx.locktime = this.locktime;
    newTx.expiryHeight = this.expiryHeight;

    newTx.ins = this.ins.map(txIn => {
      return {
        hash: txIn.hash,
        index: txIn.index,
        script: txIn.script,
        sequence: txIn.sequence,
        witness: txIn.witness,
      };
    });

    newTx.outs = this.outs.map(txOut => {
      return {
        script: txOut.script,
        value: txOut.value,
      };
    });

    newTx.valueBalance = this.valueBalance;

    return newTx;
  }

  /**
   * Hash transaction for signing a specific input.
   *
   * Bitcoin uses a different hash for each signed transaction input.
   * This method copies the transaction, makes the necessary changes based on the
   * hashType, and then hashes the result.
   * This hash can then be used to sign the provided transaction input.
   */
  hashForSignature(
    inIndex: number,
    prevOutScript: Uint8Array,
    hashType: number,
  ): Uint8Array {
    v.parse(v.tuple([types.UInt32Schema, types.BufferSchema, v.number()]), [
      inIndex,
      prevOutScript,
      hashType,
    ]);

    // https://github.com/bitcoin/bitcoin/blob/master/src/test/sighash_tests.cpp#L29
    if (inIndex >= this.ins.length) return ONE;

    // ignore OP_CODESEPARATOR
    const ourScript = bscript.compile(
      bscript.decompile(prevOutScript)!.filter(x => {
        return x !== opcodes.OP_CODESEPARATOR;
      }),
    );

    const txTmp = this.clone();

    // SIGHASH_NONE: ignore all outputs? (wildcard payee)
    if ((hashType & 0x1f) === Transaction.SIGHASH_NONE) {
      txTmp.outs = [];

      // ignore sequence numbers (except at inIndex)
      txTmp.ins.forEach((input, i) => {
        if (i === inIndex) return;

        input.sequence = 0;
      });

      // SIGHASH_SINGLE: ignore all outputs, except at the same index?
    } else if ((hashType & 0x1f) === Transaction.SIGHASH_SINGLE) {
      // https://github.com/bitcoin/bitcoin/blob/master/src/test/sighash_tests.cpp#L60
      if (inIndex >= this.outs.length) return ONE;

      // truncate outputs after
      txTmp.outs.length = inIndex + 1;

      // "blank" outputs before
      for (let i = 0; i < inIndex; i++) {
        (txTmp.outs as any)[i] = BLANK_OUTPUT;
      }

      // ignore sequence numbers (except at inIndex)
      txTmp.ins.forEach((input, y) => {
        if (y === inIndex) return;

        input.sequence = 0;
      });
    }

    // SIGHASH_ANYONECANPAY: ignore inputs entirely?
    if (hashType & Transaction.SIGHASH_ANYONECANPAY) {
      txTmp.ins = [txTmp.ins[inIndex]];
      txTmp.ins[0].script = ourScript;

      // SIGHASH_ALL: only ignore input scripts
    } else {
      // "blank" others input scripts
      txTmp.ins.forEach(input => {
        input.script = EMPTY_BUFFER;
      });
      txTmp.ins[inIndex].script = ourScript;
    }

    // serialize and hash
    const buffer = new Uint8Array(txTmp.byteLength(false) + 4);
    tools.writeInt32(buffer, buffer.length - 4, hashType, 'LE');
    txTmp.__toBuffer(buffer, 0, false);

    return bcrypto.hash256(buffer);
  }

  hashForWitnessV1(
    inIndex: number,
    prevOutScripts: Uint8Array[],
    values: bigint[],
    hashType: number,
    leafHash?: Uint8Array,
    annex?: Uint8Array,
  ): Uint8Array {
    // https://github.com/bitcoin/bips/blob/master/bip-0341.mediawiki#common-signature-message
    v.parse(
      v.tuple([
        types.UInt32Schema,
        v.array(types.BufferSchema),
        v.array(types.SatoshiSchema),
        types.UInt32Schema,
      ]),
      [inIndex, prevOutScripts, values, hashType],
    );

    if (
      values.length !== this.ins.length ||
      prevOutScripts.length !== this.ins.length
    ) {
      throw new Error('Must supply prevout script and value for all inputs');
    }

    const outputType =
      hashType === Transaction.SIGHASH_DEFAULT
        ? Transaction.SIGHASH_ALL
        : hashType & Transaction.SIGHASH_OUTPUT_MASK;

    const inputType = hashType & Transaction.SIGHASH_INPUT_MASK;

    const isAnyoneCanPay = inputType === Transaction.SIGHASH_ANYONECANPAY;
    const isNone = outputType === Transaction.SIGHASH_NONE;
    const isSingle = outputType === Transaction.SIGHASH_SINGLE;

    let hashPrevouts = EMPTY_BUFFER;
    let hashAmounts = EMPTY_BUFFER;
    let hashScriptPubKeys = EMPTY_BUFFER;
    let hashSequences = EMPTY_BUFFER;
    let hashOutputs = EMPTY_BUFFER;

    if (!isAnyoneCanPay) {
      let bufferWriter = BufferWriter.withCapacity(36 * this.ins.length);
      this.ins.forEach(txIn => {
        bufferWriter.writeSlice(txIn.hash);
        bufferWriter.writeUInt32(txIn.index);
      });
      hashPrevouts = sha256(bufferWriter.end());

      bufferWriter = BufferWriter.withCapacity(8 * this.ins.length);
      values.forEach(value => bufferWriter.writeInt64(value));
      hashAmounts = sha256(bufferWriter.end());

      bufferWriter = BufferWriter.withCapacity(
        prevOutScripts.map(varSliceSize).reduce((a, b) => a + b),
      );
      prevOutScripts.forEach(prevOutScript =>
        bufferWriter.writeVarSlice(prevOutScript),
      );
      hashScriptPubKeys = sha256(bufferWriter.end());

      bufferWriter = BufferWriter.withCapacity(4 * this.ins.length);
      this.ins.forEach(txIn => bufferWriter.writeUInt32(txIn.sequence));
      hashSequences = sha256(bufferWriter.end());
    }

    if (!(isNone || isSingle)) {
      if (!this.outs.length)
        throw new Error('Add outputs to the transaction before signing.');
      const txOutsSize = this.outs
        .map(output => 8 + varSliceSize(output.script))
        .reduce((a, b) => a + b);
      const bufferWriter = BufferWriter.withCapacity(txOutsSize);

      this.outs.forEach(out => {
        bufferWriter.writeInt64(out.value);
        bufferWriter.writeVarSlice(out.script);
      });

      hashOutputs = sha256(bufferWriter.end());
    } else if (isSingle && inIndex < this.outs.length) {
      const output = this.outs[inIndex];

      const bufferWriter = BufferWriter.withCapacity(
        8 + varSliceSize(output.script),
      );
      bufferWriter.writeInt64(output.value);
      bufferWriter.writeVarSlice(output.script);
      hashOutputs = sha256(bufferWriter.end());
    }

    const spendType = (leafHash ? 2 : 0) + (annex ? 1 : 0);

    // Length calculation from:
    // https://github.com/bitcoin/bips/blob/master/bip-0341.mediawiki#cite_note-14
    // With extension from:
    // https://github.com/bitcoin/bips/blob/master/bip-0342.mediawiki#signature-validation
    const sigMsgSize =
      174 -
      (isAnyoneCanPay ? 49 : 0) -
      (isNone ? 32 : 0) +
      (annex ? 32 : 0) +
      (leafHash ? 37 : 0);
    const sigMsgWriter = BufferWriter.withCapacity(sigMsgSize);

    sigMsgWriter.writeUInt8(hashType);
    // Transaction
    sigMsgWriter.writeUInt32(this.version);
    sigMsgWriter.writeUInt32(this.locktime);
    sigMsgWriter.writeSlice(hashPrevouts);
    sigMsgWriter.writeSlice(hashAmounts);
    sigMsgWriter.writeSlice(hashScriptPubKeys);
    sigMsgWriter.writeSlice(hashSequences);
    if (!(isNone || isSingle)) {
      sigMsgWriter.writeSlice(hashOutputs);
    }
    // Input
    sigMsgWriter.writeUInt8(spendType);
    if (isAnyoneCanPay) {
      const input = this.ins[inIndex];
      sigMsgWriter.writeSlice(input.hash);
      sigMsgWriter.writeUInt32(input.index);
      sigMsgWriter.writeInt64(values[inIndex]);
      sigMsgWriter.writeVarSlice(prevOutScripts[inIndex]);
      sigMsgWriter.writeUInt32(input.sequence);
    } else {
      sigMsgWriter.writeUInt32(inIndex);
    }
    if (annex) {
      const bufferWriter = BufferWriter.withCapacity(varSliceSize(annex));
      bufferWriter.writeVarSlice(annex);
      sigMsgWriter.writeSlice(sha256(bufferWriter.end()));
    }
    // Output
    if (isSingle) {
      sigMsgWriter.writeSlice(hashOutputs);
    }
    // BIP342 extension
    if (leafHash) {
      sigMsgWriter.writeSlice(leafHash);
      sigMsgWriter.writeUInt8(0);
      sigMsgWriter.writeUInt32(0xffffffff);
    }

    // Extra zero byte because:
    // https://github.com/bitcoin/bips/blob/master/bip-0341.mediawiki#cite_note-19
    return bcrypto.taggedHash(
      'TapSighash',
      tools.concat([Uint8Array.from([0x00]), sigMsgWriter.end()]),
    );
  }

  hashForWitnessV0(
    inIndex: number,
    prevOutScript: Uint8Array,
    value: bigint,
    hashType: number,
  ): Uint8Array {
    v.parse(
      v.tuple([
        types.UInt32Schema,
        types.BufferSchema,
        types.SatoshiSchema,
        types.UInt32Schema,
      ]),
      [inIndex, prevOutScript, value, hashType],
    );

    let tbuffer: Uint8Array = Uint8Array.from([]);
    let bufferWriter: BufferWriter;

    let hashOutputs = ZERO;
    let hashPrevouts = ZERO;
    let hashSequence = ZERO;

    if (!(hashType & Transaction.SIGHASH_ANYONECANPAY)) {
      tbuffer = new Uint8Array(36 * this.ins.length);
      bufferWriter = new BufferWriter(tbuffer, 0);

      this.ins.forEach(txIn => {
        bufferWriter.writeSlice(txIn.hash);
        bufferWriter.writeUInt32(txIn.index);
      });

      hashPrevouts = bcrypto.hash256(tbuffer);
    }

    if (
      !(hashType & Transaction.SIGHASH_ANYONECANPAY) &&
      (hashType & 0x1f) !== Transaction.SIGHASH_SINGLE &&
      (hashType & 0x1f) !== Transaction.SIGHASH_NONE
    ) {
      tbuffer = new Uint8Array(4 * this.ins.length);
      bufferWriter = new BufferWriter(tbuffer, 0);

      this.ins.forEach(txIn => {
        bufferWriter.writeUInt32(txIn.sequence);
      });

      hashSequence = bcrypto.hash256(tbuffer);
    }

    if (
      (hashType & 0x1f) !== Transaction.SIGHASH_SINGLE &&
      (hashType & 0x1f) !== Transaction.SIGHASH_NONE
    ) {
      const txOutsSize = this.outs.reduce((sum, output) => {
        return sum + 8 + varSliceSize(output.script);
      }, 0);

      tbuffer = new Uint8Array(txOutsSize);
      bufferWriter = new BufferWriter(tbuffer, 0);

      this.outs.forEach(out => {
        bufferWriter.writeInt64(out.value);
        bufferWriter.writeVarSlice(out.script);
      });

      hashOutputs = bcrypto.hash256(tbuffer);
    } else if (
      (hashType & 0x1f) === Transaction.SIGHASH_SINGLE &&
      inIndex < this.outs.length
    ) {
      const output = this.outs[inIndex];

      tbuffer = new Uint8Array(8 + varSliceSize(output.script));
      bufferWriter = new BufferWriter(tbuffer, 0);
      bufferWriter.writeInt64(output.value);
      bufferWriter.writeVarSlice(output.script);

      hashOutputs = bcrypto.hash256(tbuffer);
    }

    tbuffer = new Uint8Array(156 + varSliceSize(prevOutScript));
    bufferWriter = new BufferWriter(tbuffer, 0);

    const input = this.ins[inIndex];
    bufferWriter.writeUInt32(this.version);
    bufferWriter.writeSlice(hashPrevouts);
    bufferWriter.writeSlice(hashSequence);
    bufferWriter.writeSlice(input.hash);
    bufferWriter.writeUInt32(input.index);
    bufferWriter.writeVarSlice(prevOutScript);
    bufferWriter.writeInt64(value);
    bufferWriter.writeUInt32(input.sequence);
    bufferWriter.writeSlice(hashOutputs);
    bufferWriter.writeUInt32(this.locktime);
    bufferWriter.writeUInt32(hashType);
    return bcrypto.hash256(tbuffer);
  }

  hashForZIP243(
    inIndex: number,
    prevOutScript: Uint8Array,
    value: bigint,
    hashType: number,
  ): Uint8Array {
    v.parse(
      v.tuple([
        types.UInt32Schema,
        types.BufferSchema,
        types.SatoshiSchema,
        types.UInt32Schema,
      ]),
      [inIndex, prevOutScript, value, hashType],
    );

    return zip243.getSignatureDigest(
      this,
      inIndex,
      prevOutScript,
      value,
      hashType,
    );
  }

  hashForZIP244(
    inIndex: number,
    prevOuts: Output[],
    hashType: number,
  ): Uint8Array {
    v.parse(
      v.tuple([
        types.UInt32Schema,
        v.array(types.OutputSchema),
        types.UInt32Schema,
      ]),
      [inIndex, prevOuts, hashType],
    );

    if (this.ins.length !== prevOuts.length) {
      throw new Error('prevOuts must match inputs');
    }

    return zip244.getSignatureDigest(this, inIndex, prevOuts, hashType);
  }

  getHash(forWitness?: boolean): Uint8Array {
    // wtxid for coinbase is always 32 bytes of 0x00
    if (forWitness && this.isCoinbase()) return new Uint8Array(32);

    if (this.version === 5 && this.overwintered) {
      return zip244.getTxIdDigest(this);
    }

    return bcrypto.hash256(this.__toBuffer(undefined, undefined, forWitness));
  }

  getId(): string {
    // transaction hash's are displayed in reverse order
    return tools.toHex(reverseBuffer(this.getHash(false)));
  }

  toBuffer(buffer?: Uint8Array, initialOffset?: number): Uint8Array {
    return this.__toBuffer(buffer, initialOffset, true);
  }

  toHex(): string {
    return tools.toHex(this.toBuffer(undefined, undefined));
  }

  setInputScript(index: number, scriptSig: Uint8Array): void {
    v.parse(v.tuple([v.number(), types.BufferSchema]), [index, scriptSig]);

    this.ins[index].script = scriptSig;
  }

  setWitness(index: number, witness: Uint8Array[]): void {
    v.parse(v.tuple([v.number(), v.array(types.BufferSchema)]), [
      index,
      witness,
    ]);

    this.ins[index].witness = witness;
  }

  private __toBuffer(
    buffer?: Uint8Array,
    initialOffset?: number,
    _ALLOW_WITNESS: boolean = false,
  ): Uint8Array {
    if (!buffer)
      buffer = new Uint8Array(this.byteLength(_ALLOW_WITNESS)) as Uint8Array;

    const bufferWriter = new BufferWriter(buffer, initialOffset || 0);

    bufferWriter.writeUInt32(
      this.overwintered ? (this.version | 0x80000000) >>> 0 : this.version,
    );

    if (this.overwintered) {
      if (this.versionGroupId !== undefined) {
        bufferWriter.writeUInt32(this.versionGroupId);
      }
      if (this.version === 5) {
        if (this.consensusBranchId !== undefined) {
          bufferWriter.writeUInt32(this.consensusBranchId);
        }
        bufferWriter.writeUInt32(this.locktime);
        bufferWriter.writeUInt32(this.expiryHeight ?? 0);
      }
    }

    const hasWitnesses = _ALLOW_WITNESS && this.hasWitnesses();

    if (hasWitnesses) {
      bufferWriter.writeUInt8(Transaction.ADVANCED_TRANSACTION_MARKER);
      bufferWriter.writeUInt8(Transaction.ADVANCED_TRANSACTION_FLAG);
    }

    bufferWriter.writeVarInt(this.ins.length);

    this.ins.forEach(txIn => {
      bufferWriter.writeSlice(txIn.hash);
      bufferWriter.writeUInt32(txIn.index);
      bufferWriter.writeVarSlice(txIn.script);
      bufferWriter.writeUInt32(txIn.sequence);
    });

    bufferWriter.writeVarInt(this.outs.length);
    this.outs.forEach(txOut => {
      if (isOutput(txOut)) {
        bufferWriter.writeInt64(txOut.value);
      } else {
        bufferWriter.writeSlice((txOut as any).valueBuffer);
      }

      bufferWriter.writeVarSlice(txOut.script);
    });

    if (hasWitnesses) {
      this.ins.forEach(input => {
        bufferWriter.writeVector(input.witness);
      });
    }

    if (this.overwintered) {
      switch (this.version) {
        case 3: {
          bufferWriter.writeUInt32(this.locktime);
          bufferWriter.writeUInt32(this.expiryHeight ?? 0);
          bufferWriter.writeVarInt(0); // nJoinSplit
          // vJoinSplit
          // joinSplitPubKey
          // joinSplitSig
          break;
        }
        case 4: {
          bufferWriter.writeUInt32(this.locktime);
          bufferWriter.writeUInt32(this.expiryHeight ?? 0);
          bufferWriter.writeInt64(this.valueBalance ?? 0); // valueBalance
          bufferWriter.writeVarInt(0); // nShieldedSpend
          // vShieldedSpend
          bufferWriter.writeVarInt(0); // nShieldedOutput
          // vShieldedOutput
          // bindingSig
          bufferWriter.writeVarInt(0); // nJoinSplit
          // vJoinSplit
          // joinSplitPubKey
          // joinSplitSig
          break;
        }
        case 5: {
          bufferWriter.writeVarInt(0); // nSpendsSapling
          // vSpendsSapling
          bufferWriter.writeVarInt(0); // nOutputsSapling
          // vOutputsSapling
          // valueBalanceSapling
          // anchorSapling
          // vSpendProofsSapling
          // vSpendAuthSigsSapling
          // vOutputProofsSapling
          // bindingSigSapling
          bufferWriter.writeVarInt(0); // nActionsOrchard
          // vActionsOrchard
          // flagsOrchard
          // valueBalanceOrchard
          // anchorOrchard
          // sizeProofsOrchard
          // proofsOrchard
          // vSpendAuthSigsOrchard
          // bindingSigOrchard
          break;
        }
      }
    } else {
      bufferWriter.writeUInt32(this.locktime);
    }

    // avoid slicing unless necessary
    if (initialOffset !== undefined)
      return buffer.slice(initialOffset, bufferWriter.offset);
    return buffer;
  }
}
