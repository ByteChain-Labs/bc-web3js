import base58 from "bs58";
import elliptic_pkg from 'elliptic';
import { hash_tobuf, hash_tostr, type PubKey } from "./utils.js";
import type { Tx } from "./interfaces.js";


const  { ec: EC } = elliptic_pkg;
const ec = new EC('secp256k1');


class Transaction implements Tx {
    amount: number;
    sender: PubKey;
    recipient: PubKey;
    fee: number;
    timestamp: number;
    tx_id: string;
    nonce: number;
    signature: string;

    constructor(
        amount: number,
        sender: PubKey,
        recipient: PubKey,
        fee: number,
        timestamp: number,
        nonce: number,
        signature: string,
    ) {
        this.amount = amount;
        this.sender = sender;
        this.recipient = recipient;
        this.fee = fee;
        this.tx_id = this.compute_tx_id();
        this.timestamp = timestamp;
        this.nonce = nonce;
        this.signature = signature;
    }

    private get_signing_data(): string {
        return `${this.amount}${this.sender}${this.recipient}${this.fee}${this.nonce}${this.timestamp}`;
    }

    private compute_tx_id(): string {
        const data = this.get_signing_data();
        const id = hash_tostr(data);
        
        return id;
    }

    sign_tx(priv_key: string): Transaction {
        try {
            const data_str = this.get_signing_data();
            
            const hashed_tx = hash_tobuf(data_str);
            const key_pair = ec.keyFromPrivate(priv_key, 'hex');
            const sig = key_pair.sign(hashed_tx, 'hex');
            const r = sig.r.toArrayLike(Buffer, 'be', 32);
            const s = sig.s.toArrayLike(Buffer, 'be', 32);
            const compact_sig = Buffer.concat([r, s]);
            const sign = base58.encode(compact_sig);

            this.signature = sign;

            return this;
        } catch (err) {
            throw new Error('Transaction signing failed');
        }
    }
}


export default Transaction;