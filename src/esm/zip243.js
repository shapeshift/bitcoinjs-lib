import { BufferWriter } from './bufferutils.js';
import * as tools from 'uint8array-tools';
import * as bcrypto from './crypto.js';
import { varSliceSize, ZERO } from './transaction.js';
function getPrevoutsHash(tx) {
  if (tx.ins.length === 0) return ZERO;
  const buffer = new Uint8Array(36 * tx.ins.length);
  const writer = new BufferWriter(buffer, 0);
  tx.ins.forEach(txIn => {
    writer.writeSlice(txIn.hash);
    writer.writeUInt32(txIn.index);
  });
  return bcrypto.blake256(buffer, 'ZcashPrevoutHash');
}
function getSequenceHash(tx) {
  if (tx.ins.length === 0) return ZERO;
  const buffer = new Uint8Array(4 * tx.ins.length);
  const writer = new BufferWriter(buffer, 0);
  tx.ins.forEach(txIn => {
    writer.writeUInt32(txIn.sequence);
  });
  return bcrypto.blake256(buffer, 'ZcashSequencHash');
}
function getOutputsHash(tx) {
  if (tx.outs.length === 0) return ZERO;
  const outputsSize = tx.outs.reduce((sum, output) => {
    return sum + 8 + varSliceSize(output.script);
  }, 0);
  const buffer = new Uint8Array(outputsSize);
  const writer = new BufferWriter(buffer, 0);
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
export function getSignatureDigest(
  tx,
  inputIndex,
  scriptCode,
  value,
  hashType,
) {
  const size = (tx.version === 4 ? 268 : 196) + varSliceSize(scriptCode);
  const buffer = new Uint8Array(size);
  const writer = new BufferWriter(buffer, 0);
  writer.writeUInt32((tx.version | 0x80000000) >>> 0);
  writer.writeUInt32(tx.versionGroupId);
  writer.writeSlice(getPrevoutsHash(tx));
  writer.writeSlice(getSequenceHash(tx));
  writer.writeSlice(getOutputsHash(tx));
  writer.writeSlice(ZERO); // hashJoinSplits
  if (tx.version === 4) {
    writer.writeSlice(ZERO); // hashShieldedSpends
    writer.writeSlice(ZERO); // hashShieldedOutputs
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
