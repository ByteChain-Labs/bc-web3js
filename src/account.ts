import { secp256k1 } from '@noble/curves/secp256k1.js';
import { bytesToHex, hexToBytes } from '@noble/curves/utils.js';
import Transaction from './transaction.js';
import type { PubKey, PrivKey } from './utils.js';




class Account {
    private priv_key: PrivKey;
    public  pub_key: PubKey;

    constructor(priv_key?: PrivKey) {
        this.priv_key = Account.new(priv_key).priv_key;
        this.pub_key = Account.create_pub_key(this.priv_key);
    }

    static is_valid_priv_key(priv_key: PrivKey): boolean {
        return typeof priv_key === 'string' && /^[0-9a-fA-F]{64}$/.test(priv_key);
    }

    static new(privKey?: PrivKey): { priv_key: PrivKey, pub_key: PubKey } {
        let priv_key = "";

        if (privKey) {
            if (!Account.is_valid_priv_key(privKey)) {
                throw new Error("Invalid private key: must be a 64-character hex string");
            }
            priv_key = privKey;
        }
        else {
            priv_key = bytesToHex(secp256k1.keygen().secretKey);
        }

        const pub_key = Account.create_pub_key(priv_key);
        return { priv_key, pub_key };
    }

    // Generates the public key from a private key
    static create_pub_key(priv_key: PrivKey): PubKey {
        return bytesToHex(secp256k1.getPublicKey(hexToBytes(priv_key), true));
    }

    sign_tx(tx: Transaction): Transaction {
        return tx.sign_tx(this.priv_key);
    }
}


export default Account;
