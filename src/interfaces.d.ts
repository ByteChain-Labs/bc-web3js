import { PubKey } from "./utils.ts";

export interface Tx {
    amount: number;
    sender: PubKey;
    recipient: PubKey;
    fee: number;
    tx_id: string;
    timestamp: number;
    nonce: number;
    signature: string;
}

export interface BlockHeader {
    nonce: number;
    block_height: number;
    timestamp: number;
    merkleroot: string;
    prev_block_hash: string;
    block_hash: string;
    difficulty: number;
}

export interface BlockInterface {
    block_header: BlockHeader;
    transactions: Tx[];
}