import { Buffer } from 'buffer';
import elliptic_pkg from 'elliptic';
import Transaction from './transaction.js';
import type { PubKey, PrivKey } from './utils.js';

const { ec: EC } = elliptic_pkg;
const ec = new EC('secp256k1');


class Account {
    private priv_key: Buffer;
    public  pub_key: PubKey;

    constructor(priv_key?: PrivKey) {
        this.priv_key = Buffer.from(Account.new(priv_key).priv_key, 'hex');
        this.pub_key = Account.create_pub_key(this.priv_key.toString('hex'));
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
            priv_key = ec.genKeyPair().getPrivate('hex');
        }

        const pub_key = Account.create_pub_key(priv_key);
        return { priv_key, pub_key };
    }

    // Generates the public key from a private key
    static create_pub_key(priv_key: PrivKey): PubKey {
        const key_pair = ec.keyFromPrivate(priv_key);
        const pub_key = key_pair.getPublic(true, 'hex');
        return pub_key;
    }

    sign_tx(tx: Transaction): Transaction {
        return tx.sign_tx(this.priv_key.toString('hex'));
    }
}


export default Account;
