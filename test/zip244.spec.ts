import * as assert from 'assert';
import { describe, it } from 'mocha';
import { Transaction } from '@shapeshiftoss/bitcoinjs-lib';
import * as tools from 'uint8array-tools';
import * as zip244 from '@shapeshiftoss/bitcoinjs-lib/src/zip244';
import { reverseBuffer } from '@shapeshiftoss/bitcoinjs-lib/src/bufferutils';

type TestVector = [
  string, // tx
  string, // txid
  string, // auth_digest
  number[], // amounts
  string[], // script_pubkeys
  number, // transparent_input
  string, // sighash_shielded
  string, // sighash_all
  string, // sighash_none
  string, // sighash_single
  string, // sighash_all_anyone
  string, // sighash_none_anyone
  string, // sighash_single_anyone
];

const vector: TestVector = [
  '050000800a27a726b4d0d6c27a8f739a2d6f2c0201e152a8049e294c4d6e66b164939daffa2ef6ee6921481cdd86b3cc4318d9614fc820905d0453516aaca3f2498802b2007b1d3065050005510063ac0081a4cbca2f92020004ac6a006a000000',
  '8ae49307cf803e89a96084c4cfe6281c8d8f3f96f370ed55a74d559e93e6f9c6',
  '9c3b0fc7b163b5206aa611fc35e0fc36f213df58491f2e9f527d663ee37de986',
  [1532201745105867],
  ['ac6565656352'],
  0,
  '10d85e37f3b88cc05792d89f24e81be8d756e3fc666fa528b9ff4b7a9e099f42',
  '52babf0e5f92564bc5d4c3947968e2b617832ef4df1b9a0940ff88ca027e2018',
  '0610072b310fbc95dc9107554a00b13945aba02767794165cafbd870e11d2c0d',
  '2e7f801199712dc9c7b9054168b5a81fe2581705f1a4d85f230ebb7056b2cc66',
  '5962a0fe753a25ec11ebf4ae43dd9e3c0fdf895480b25edc6b6771d8814d6029',
  '5ddc0bbafcd2ff6a2f675e15e9607bbb5a1b2ec35eced5e0a19a37fae5b54b40',
  'a971cfd0dcc65978618fe78c199affa5fc89e23796cd6e6e1d48532829246b84',
];

describe('ZIP244', () => {
  describe('getTxIdDigest', () => {
    it(`should compute correct txid`, () => {
      const [txHex, expectedTxId] = vector;

      const tx = Transaction.fromHex(txHex);
      const txIdDigest = zip244.getTxIdDigest(tx);
      const actualTxId = tools.toHex(reverseBuffer(txIdDigest));

      assert.strictEqual(actualTxId, expectedTxId, `Transaction ID mismatch`);
    });
  });

  describe('getSignatureDigest', () => {
    const [
      txHex,
      ,
      ,
      amounts,
      scriptPubkeys,
      transparentInput,
      ,
      sighashAll,
      ,
      ,
      ,
      ,
      ,
    ] = vector;

    const tx = Transaction.fromHex(txHex);

    const prevOuts = amounts.map((amount, i) => ({
      value: BigInt(amount),
      script: tools.fromHex(scriptPubkeys[i]),
    }));

    it('should compute correct SIGHASH_ALL', () => {
      const sigHash = zip244.getSignatureDigest(
        tx,
        transparentInput,
        prevOuts,
        Transaction.SIGHASH_ALL,
      );

      const actualHash = tools.toHex(reverseBuffer(sigHash));

      assert.strictEqual(actualHash, sighashAll, 'SIGHASH_ALL mismatch');
    });
  });
});
