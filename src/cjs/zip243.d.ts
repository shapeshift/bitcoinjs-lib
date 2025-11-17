import { Transaction } from './transaction.js';
export declare function getSignatureDigest(tx: Transaction, inputIndex: number, scriptCode: Uint8Array, value: bigint, hashType: number): Uint8Array;
