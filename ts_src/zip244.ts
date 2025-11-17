import { BufferWriter } from './bufferutils.js';
import * as tools from 'uint8array-tools';
import * as bcrypto from './crypto.js';
import { Output, Transaction, varSliceSize } from './transaction.js';

// https://zips.z.cash/zip-0244#t-1-header-digest
function getHeaderDigest(tx: Transaction): Uint8Array {
  const buffer = new Uint8Array(20);
  const writer = new BufferWriter(buffer, 0);

  writer.writeUInt32((tx.version | 0x80000000) >>> 0);
  writer.writeUInt32(tx.versionGroupId!);
  writer.writeUInt32(tx.consensusBranchId!);
  writer.writeUInt32(tx.locktime);
  writer.writeUInt32(tx.expiryHeight ?? 0);

  return bcrypto.blake256(buffer, 'ZTxIdHeadersHash');
}

// https://zips.z.cash/zip-0244#t-2a-prevouts-digest
function getPrevoutsDigest(tx: Transaction): Uint8Array {
  if (tx.ins.length === 0) {
    return bcrypto.blake256(new Uint8Array(0), 'ZTxIdPrevoutHash');
  }

  const buffer = new Uint8Array(36 * tx.ins.length);
  const writer = new BufferWriter(buffer, 0);

  tx.ins.forEach(txIn => {
    writer.writeSlice(txIn.hash);
    writer.writeUInt32(txIn.index);
  });

  return bcrypto.blake256(buffer, 'ZTxIdPrevoutHash');
}

// https://zips.z.cash/zip-0244#t-2b-sequence-digest
function getSequenceDigest(tx: Transaction): Uint8Array {
  if (tx.ins.length === 0) {
    return bcrypto.blake256(new Uint8Array(0), 'ZTxIdSequencHash');
  }

  const buffer = new Uint8Array(4 * tx.ins.length);
  const writer = new BufferWriter(buffer, 0);

  tx.ins.forEach(txIn => {
    writer.writeUInt32(txIn.sequence);
  });

  return bcrypto.blake256(buffer, 'ZTxIdSequencHash');
}

// https://zips.z.cash/zip-0244#t-2c-outputs-digest
function getOutputsDigest(tx: Transaction): Uint8Array {
  if (tx.outs.length === 0) {
    return bcrypto.blake256(new Uint8Array(0), 'ZTxIdOutputsHash');
  }

  const outputsSize = tx.outs.reduce((sum, output) => {
    return sum + 8 + varSliceSize(output.script);
  }, 0);

  const buffer = new Uint8Array(outputsSize);
  const writer = new BufferWriter(buffer, 0);

  tx.outs.forEach(out => {
    writer.writeInt64(out.value);
    writer.writeVarSlice(out.script);
  });

  return bcrypto.blake256(buffer, 'ZTxIdOutputsHash');
}

// https://zips.z.cash/zip-0244#t-3-sapling-digest
function getSaplingDigest(): Uint8Array {
  return bcrypto.blake256(new Uint8Array(0), 'ZTxIdSaplingHash');
}

// https://zips.z.cash/zip-0244#t-4-orchard-digest
function getOrchardDigest(): Uint8Array {
  return bcrypto.blake256(new Uint8Array(0), 'ZTxIdOrchardHash');
}

function getTxDigest(buffer: Uint8Array, tx: Transaction): Uint8Array {
  const personalization = new Uint8Array(16);
  personalization.set(tools.fromUtf8('ZcashTxHash_'), 0);

  const branchIdBytes = new Uint8Array(4);
  tools.writeUInt32(branchIdBytes, 0, tx.consensusBranchId!, 'LE');
  personalization.set(branchIdBytes, 12);

  return bcrypto.blake256(buffer, personalization);
}

// https://zips.z.cash/zip-0244#txid-digest
export function getTxIdDigest(tx: Transaction): Uint8Array {
  // https://zips.z.cash/zip-0244#t-2-transparent-digest
  const transparentDigest = (() => {
    if (tx.ins.length === 0 && tx.outs.length === 0) {
      return bcrypto.blake256(new Uint8Array(0), 'ZTxIdTranspaHash');
    }

    const buffer = tools.concat([
      getPrevoutsDigest(tx),
      getSequenceDigest(tx),
      getOutputsDigest(tx),
    ]);

    return bcrypto.blake256(buffer, 'ZTxIdTranspaHash');
  })();

  const buffer = tools.concat([
    getHeaderDigest(tx),
    transparentDigest,
    getSaplingDigest(),
    getOrchardDigest(),
  ]);

  return getTxDigest(buffer, tx);
}

// https://zips.z.cash/zip-0244#signature-digest
export function getSignatureDigest(
  tx: Transaction,
  inputIndex: number,
  prevOuts: Output[],
  hashType: number,
): Uint8Array {
  // https://zips.z.cash/zip-0244#s-2-transparent-sig-digest
  const transparentSigDigest = (() => {
    // https://zips.z.cash/zip-0244#s-2c-amounts-sig-digest
    const amountsSigDigest = (() => {
      const amounts = prevOuts.map(o => o.value);

      if (amounts.length === 0) {
        return bcrypto.blake256(new Uint8Array(0), 'ZTxTrAmountsHash');
      }

      const buffer = new Uint8Array(8 * amounts.length);
      const writer = new BufferWriter(buffer, 0);

      amounts.forEach(amount => writer.writeInt64(amount));

      return bcrypto.blake256(buffer, 'ZTxTrAmountsHash');
    })();

    const scriptPubKeysSigDigest = (() => {
      const prevOutScripts = prevOuts.map(o => o.script);

      if (prevOutScripts.length === 0) {
        return bcrypto.blake256(new Uint8Array(0), 'ZTxTrScriptsHash');
      }

      const scriptsSize = prevOutScripts.reduce((sum, script) => {
        return sum + varSliceSize(script);
      }, 0);

      const buffer = new Uint8Array(scriptsSize);
      const writer = new BufferWriter(buffer, 0);

      prevOutScripts.forEach(script => writer.writeVarSlice(script));

      return bcrypto.blake256(buffer, 'ZTxTrScriptsHash');
    })();

    const txInSigDigest = (() => {
      const input = tx.ins[inputIndex];
      const prevOut = prevOuts[inputIndex];
      const bufferSize = 32 + 4 + 8 + varSliceSize(prevOut.script) + 4;
      const buffer = new Uint8Array(bufferSize);
      const writer = new BufferWriter(buffer, 0);

      writer.writeSlice(input.hash);
      writer.writeUInt32(input.index);
      writer.writeInt64(prevOut.value);
      writer.writeVarSlice(prevOut.script);
      writer.writeUInt32(input.sequence);

      return bcrypto.blake256(buffer, 'Zcash___TxInHash');
    })();

    const buffer = tools.concat([
      Uint8Array.from([hashType]),
      getPrevoutsDigest(tx),
      amountsSigDigest,
      scriptPubKeysSigDigest,
      getSequenceDigest(tx),
      getOutputsDigest(tx),
      txInSigDigest,
    ]);

    return bcrypto.blake256(buffer, 'ZTxIdTranspaHash');
  })();

  const buffer = tools.concat([
    getHeaderDigest(tx),
    transparentSigDigest,
    getSaplingDigest(),
    getOrchardDigest(),
  ]);

  return getTxDigest(buffer, tx);
}
