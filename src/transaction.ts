import { secp256k1 } from "@noble/curves/secp256k1.js";
import { bytesToHex, hexToBytes } from "@noble/curves/utils.js";
import { hash_tobuf, hash_tostr, type PrivKey, type PubKey } from "./utils.js";
import type { Tx } from "./interfaces.js";


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

    sign_tx(priv_key: PrivKey): Transaction {
        try {
            const data_str = this.get_signing_data();
            
            const hashed_tx = hash_tobuf(data_str);
            const sign = secp256k1.sign(hashed_tx, hexToBytes(priv_key));

            this.signature = bytesToHex(sign);

            return this;
        } catch (err) {
            throw new Error('Transaction signing failed');
        }
    }
}


export default Transaction;