import * as assert from 'assert';
import * as ecc from 'tiny-secp256k1';
import ECPairFactory from 'ecpair';
import { describe, it } from 'mocha';
import { payments, Psbt, Transaction } from '@shapeshiftoss/bitcoinjs-lib';

const ECPair = ECPairFactory(ecc);

const network = {
  messagePrefix: '\x18Zcash Signed Message:\n',
  bech32: '',
  bip32: { public: 0x0488b21e, private: 0x0488ade4 },
  pubKeyHash: 0x1cb8,
  scriptHash: 0x1cbd,
  wif: 0x80,
};

const keyPair = ECPair.fromPrivateKey(Buffer.alloc(32, 7));
const script = payments.p2pkh({ pubkey: keyPair.publicKey, network }).output!;

const newZcashPsbt = (): Psbt => {
  const psbt = new Psbt({ network, forkCoin: 'zec' });
  psbt.setVersion(5);
  psbt.setVersionGroupId(0x26a7270a);
  psbt.setConsensusBranchId(0x77190ad9);
  return psbt;
};

const buildParent = (): Transaction => {
  const tx = new Transaction();
  tx.overwintered = true;
  tx.version = 5;
  tx.versionGroupId = 0x26a7270a;
  tx.consensusBranchId = 0x77190ad9;
  tx.locktime = 0;
  tx.expiryHeight = 0;
  tx.addInput(Buffer.alloc(32, 1), 0);
  tx.addOutput(script, 150000n);
  tx.addOutput(script, 40000n);
  return tx;
};

const signSpend = (
  parent: Transaction,
  utxo: 'nonWitnessUtxo' | 'witnessUtxo',
): string => {
  const psbt = newZcashPsbt();
  parent.outs.forEach((out, index) =>
    psbt.addInput({
      hash: parent.getId(),
      index,
      ...(utxo === 'nonWitnessUtxo'
        ? { nonWitnessUtxo: parent.toBuffer() }
        : { witnessUtxo: { script: out.script, value: out.value } }),
    }),
  );
  psbt.addOutput({ script, value: 180000n });
  psbt.signAllInputs(keyPair);
  psbt.finalizeAllInputs();
  return psbt.extractTransaction(true).toHex();
};

describe('Zcash v5 Psbt', () => {
  it('signs non-segwit inputs from witnessUtxo identically to nonWitnessUtxo', () => {
    const parent = buildParent();
    assert.strictEqual(
      signSpend(parent, 'witnessUtxo'),
      signSpend(parent, 'nonWitnessUtxo'),
    );
  });
});
