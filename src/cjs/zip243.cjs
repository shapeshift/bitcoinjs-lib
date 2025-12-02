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
exports.getSignatureDigest = getSignatureDigest;
const bufferutils_js_1 = require('./bufferutils.cjs');
const tools = __importStar(require('uint8array-tools'));
const bcrypto = __importStar(require('./crypto.cjs'));
const transaction_js_1 = require('./transaction.cjs');
function getPrevoutsHash(tx) {
  if (tx.ins.length === 0) return transaction_js_1.ZERO;
  const buffer = new Uint8Array(36 * tx.ins.length);
  const writer = new bufferutils_js_1.BufferWriter(buffer, 0);
  tx.ins.forEach(txIn => {
    writer.writeSlice(txIn.hash);
    writer.writeUInt32(txIn.index);
  });
  return bcrypto.blake256(buffer, 'ZcashPrevoutHash');
}
function getSequenceHash(tx) {
  if (tx.ins.length === 0) return transaction_js_1.ZERO;
  const buffer = new Uint8Array(4 * tx.ins.length);
  const writer = new bufferutils_js_1.BufferWriter(buffer, 0);
  tx.ins.forEach(txIn => {
    writer.writeUInt32(txIn.sequence);
  });
  return bcrypto.blake256(buffer, 'ZcashSequencHash');
}
function getOutputsHash(tx) {
  if (tx.outs.length === 0) return transaction_js_1.ZERO;
  const outputsSize = tx.outs.reduce((sum, output) => {
    return sum + 8 + (0, transaction_js_1.varSliceSize)(output.script);
  }, 0);
  const buffer = new Uint8Array(outputsSize);
  const writer = new bufferutils_js_1.BufferWriter(buffer, 0);
  tx.outs.forEach(out => {
    writer.writeInt64(out.value);
    writer.writeVarSlice(out.script);
  });
  return bcrypto.blake256(buffer, 'ZcashOutputsHash');
}
function getTxDigest(buffer, tx) {
  const personalization = new Uint8Array(16);
  personalization.set(tools.fromUtf8('ZcashSigHash'), 0);
  const branchIdBytes = new Uint8Array(4);
  tools.writeUInt32(branchIdBytes, 0, tx.consensusBranchId, 'LE');
  personalization.set(branchIdBytes, 12);
  return bcrypto.blake256(buffer, personalization);
}
// https://zips.z.cash/zip-0243
function getSignatureDigest(tx, inputIndex, scriptCode, value, hashType) {
  const size =
    (tx.version === 4 ? 268 : 196) +
    (0, transaction_js_1.varSliceSize)(scriptCode);
  const buffer = new Uint8Array(size);
  const writer = new bufferutils_js_1.BufferWriter(buffer, 0);
  writer.writeUInt32((tx.version | 0x80000000) >>> 0);
  writer.writeUInt32(tx.versionGroupId);
  writer.writeSlice(getPrevoutsHash(tx));
  writer.writeSlice(getSequenceHash(tx));
  writer.writeSlice(getOutputsHash(tx));
  writer.writeSlice(transaction_js_1.ZERO); // hashJoinSplits
  if (tx.version === 4) {
    writer.writeSlice(transaction_js_1.ZERO); // hashShieldedSpends
    writer.writeSlice(transaction_js_1.ZERO); // hashShieldedOutputs
  }
  writer.writeUInt32(tx.locktime);
  writer.writeUInt32(tx.expiryHeight ?? 0);
  if (tx.version === 4) {
    writer.writeInt64(tx.valueBalance ?? 0n);
  }
  writer.writeUInt32(hashType);
  const input = tx.ins[inputIndex];
  writer.writeSlice(input.hash);
  writer.writeUInt32(input.index);
  writer.writeVarSlice(scriptCode);
  writer.writeInt64(value);
  writer.writeUInt32(input.sequence);
  return getTxDigest(buffer, tx);
}
