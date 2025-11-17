'use strict';
var __createBinding =
  (this && this.__createBinding) ||
  (Object.create
    ? function (o, m, k, k2) {
        if (k2 === undefined) k2 = k;
        var desc = Object.getOwnPropertyDescriptor(m, k);
        if (
          !desc ||
          ('get' in desc ? !m.__esModule : desc.writable || desc.configurable)
        ) {
          desc = {
            enumerable: true,
            get: function () {
              return m[k];
            },
          };
        }
        Object.defineProperty(o, k2, desc);
      }
    : function (o, m, k, k2) {
        if (k2 === undefined) k2 = k;
        o[k2] = m[k];
      });
var __setModuleDefault =
  (this && this.__setModuleDefault) ||
  (Object.create
    ? function (o, v) {
        Object.defineProperty(o, 'default', { enumerable: true, value: v });
      }
    : function (o, v) {
        o['default'] = v;
      });
var __importStar =
  (this && this.__importStar) ||
  function (mod) {
    if (mod && mod.__esModule) return mod;
    var result = {};
    if (mod != null)
      for (var k in mod)
        if (k !== 'default' && Object.prototype.hasOwnProperty.call(mod, k))
          __createBinding(result, mod, k);
    __setModuleDefault(result, mod);
    return result;
  };
Object.defineProperty(exports, '__esModule', { value: true });
exports.getTxIdDigest = getTxIdDigest;
exports.getSignatureDigest = getSignatureDigest;
const bufferutils_js_1 = require('./bufferutils.cjs');
const tools = __importStar(require('uint8array-tools'));
const bcrypto = __importStar(require('./crypto.cjs'));
const transaction_js_1 = require('./transaction.cjs');
// https://zips.z.cash/zip-0244#t-1-header-digest
function getHeaderDigest(tx) {
  const buffer = new Uint8Array(20);
  const writer = new bufferutils_js_1.BufferWriter(buffer, 0);
  writer.writeUInt32((tx.version | 0x80000000) >>> 0);
  writer.writeUInt32(tx.versionGroupId);
  writer.writeUInt32(tx.consensusBranchId);
  writer.writeUInt32(tx.locktime);
  writer.writeUInt32(tx.expiryHeight ?? 0);
  return bcrypto.blake256(buffer, 'ZTxIdHeadersHash');
}
// https://zips.z.cash/zip-0244#t-2a-prevouts-digest
function getPrevoutsDigest(tx) {
  if (tx.ins.length === 0) {
    return bcrypto.blake256(new Uint8Array(0), 'ZTxIdPrevoutHash');
  }
  const buffer = new Uint8Array(36 * tx.ins.length);
  const writer = new bufferutils_js_1.BufferWriter(buffer, 0);
  tx.ins.forEach(txIn => {
    writer.writeSlice(txIn.hash);
    writer.writeUInt32(txIn.index);
  });
  return bcrypto.blake256(buffer, 'ZTxIdPrevoutHash');
}
// https://zips.z.cash/zip-0244#t-2b-sequence-digest
function getSequenceDigest(tx) {
  if (tx.ins.length === 0) {
    return bcrypto.blake256(new Uint8Array(0), 'ZTxIdSequencHash');
  }
  const buffer = new Uint8Array(4 * tx.ins.length);
  const writer = new bufferutils_js_1.BufferWriter(buffer, 0);
  tx.ins.forEach(txIn => {
    writer.writeUInt32(txIn.sequence);
  });
  return bcrypto.blake256(buffer, 'ZTxIdSequencHash');
}
// https://zips.z.cash/zip-0244#t-2c-outputs-digest
function getOutputsDigest(tx) {
  if (tx.outs.length === 0) {
    return bcrypto.blake256(new Uint8Array(0), 'ZTxIdOutputsHash');
  }
  const outputsSize = tx.outs.reduce((sum, output) => {
    return sum + 8 + (0, transaction_js_1.varSliceSize)(output.script);
  }, 0);
  const buffer = new Uint8Array(outputsSize);
  const writer = new bufferutils_js_1.BufferWriter(buffer, 0);
  tx.outs.forEach(out => {
    writer.writeInt64(out.value);
    writer.writeVarSlice(out.script);
  });
  return bcrypto.blake256(buffer, 'ZTxIdOutputsHash');
}
// https://zips.z.cash/zip-0244#t-3-sapling-digest
function getSaplingDigest() {
  return bcrypto.blake256(new Uint8Array(0), 'ZTxIdSaplingHash');
}
// https://zips.z.cash/zip-0244#t-4-orchard-digest
function getOrchardDigest() {
  return bcrypto.blake256(new Uint8Array(0), 'ZTxIdOrchardHash');
}
function getTxDigest(buffer, tx) {
  const personalization = new Uint8Array(16);
  personalization.set(tools.fromUtf8('ZcashTxHash_'), 0);
  const branchIdBytes = new Uint8Array(4);
  tools.writeUInt32(branchIdBytes, 0, tx.consensusBranchId, 'LE');
  personalization.set(branchIdBytes, 12);
  return bcrypto.blake256(buffer, personalization);
}
// https://zips.z.cash/zip-0244#txid-digest
function getTxIdDigest(tx) {
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
function getSignatureDigest(tx, inputIndex, prevOuts, hashType) {
  // https://zips.z.cash/zip-0244#s-2-transparent-sig-digest
  const transparentSigDigest = (() => {
    // https://zips.z.cash/zip-0244#s-2c-amounts-sig-digest
    const amountsSigDigest = (() => {
      const amounts = prevOuts.map(o => o.value);
      if (amounts.length === 0) {
        return bcrypto.blake256(new Uint8Array(0), 'ZTxTrAmountsHash');
      }
      const buffer = new Uint8Array(8 * amounts.length);
      const writer = new bufferutils_js_1.BufferWriter(buffer, 0);
      amounts.forEach(amount => writer.writeInt64(amount));
      return bcrypto.blake256(buffer, 'ZTxTrAmountsHash');
    })();
    const scriptPubKeysSigDigest = (() => {
      const prevOutScripts = prevOuts.map(o => o.script);
      if (prevOutScripts.length === 0) {
        return bcrypto.blake256(new Uint8Array(0), 'ZTxTrScriptsHash');
      }
      const scriptsSize = prevOutScripts.reduce((sum, script) => {
        return sum + (0, transaction_js_1.varSliceSize)(script);
      }, 0);
      const buffer = new Uint8Array(scriptsSize);
      const writer = new bufferutils_js_1.BufferWriter(buffer, 0);
      prevOutScripts.forEach(script => writer.writeVarSlice(script));
      return bcrypto.blake256(buffer, 'ZTxTrScriptsHash');
    })();
    const txInSigDigest = (() => {
      const input = tx.ins[inputIndex];
      const prevOut = prevOuts[inputIndex];
      const bufferSize =
        32 + 4 + 8 + (0, transaction_js_1.varSliceSize)(prevOut.script) + 4;
      const buffer = new Uint8Array(bufferSize);
      const writer = new bufferutils_js_1.BufferWriter(buffer, 0);
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
