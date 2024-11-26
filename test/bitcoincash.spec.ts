import * as assert from 'assert';
import {
  payments,
  networks,
  Transaction,
  Psbt,
} from '@shapeshiftoss/bitcoinjs-lib';
import { ECPairFactory } from 'ecpair';
import * as ecc from 'tiny-secp256k1';

const ECPair = ECPairFactory(ecc);

describe('Psbt for Bitcoin Cash', function () {
  const network = networks['testnet'];
  it('Bitcoin Cash test case 3', function () {
    const value = BigInt(50 * 1e8);
    const txid =
      '40c8a218923f23df3692530fa8e475251c50c7d630dccbdfbd92ba8092f4aa13';
    const vout = 0;

    const wif = 'cTNwkxh7nVByhc3i7BH6eaBFQ4yVs6WvXBGBoA9xdKiorwcYVACc';
    const keyPair = ECPair.fromWIF(wif, network);

    const pk = keyPair.publicKey;
    const spk = payments.p2pk({ pubkey: pk }).output!;

    // Psbt
    const psbt = new Psbt({ network, forkCoin: 'bch' });
    const hexPsbt = psbt
      .addInput({
        hash: txid,
        index: vout,
        sequence: Transaction.DEFAULT_SEQUENCE,
        witnessUtxo: {
          script: spk,
          value,
        },
      })
      .addOutput({
        address: 'mzDktdwPcWwqg8aZkPotx6aYi4mKvDD7ay',
        value,
      })
      .signInput(0, keyPair)
      .finalizeAllInputs()
      .extractTransaction()
      .toHex();

    const result =
      '020000000113aaf49280ba92bddfcbdc30d6c7501c2575e4a80f539236df233f9218a2' +
      'c8400000000049483045022100c5874e39da4dd427d35e24792bf31dcd63c25684deec' +
      '66b426271b4043e21c3002201bfdc0621ad4237e8db05aa6cad69f3d5ab4ae32ebb204' +
      '8f65b12165da6cc69341ffffffff0100f2052a010000001976a914cd29cc97826c3728' +
      '1ac61301e4d5ed374770585688ac00000000';
    assert.equal(result, hexPsbt);
  });
});
