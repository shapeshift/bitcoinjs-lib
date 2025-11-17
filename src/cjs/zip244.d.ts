import { Output, Transaction } from './transaction.js';
export declare function getTxIdDigest(tx: Transaction): Uint8Array;
export declare function getSignatureDigest(tx: Transaction, inputIndex: number, prevOuts: Output[], hashType: number): Uint8Array;
