import Account from "./account.js";
import Provider from "./provider.js";
import Transaction from "./transaction.js";
import type { PubKey, PrivKey } from "./utils.js";

class Wallet {
    public account;
    
    constructor(priv_key: PrivKey,) {
        this.account = new Account(priv_key)
    }

    async send_byte(provider: Provider, amount: number, recipient: PubKey): Promise<string> {
        try {
            const nonce = await provider.check_nonce(this.account.pub_key);
            const fee = await provider.check_fee();
            const tx = new Transaction(amount, this.account.pub_key, recipient, fee, Date.now(), nonce + 1, "");
            const signed_tx = this.account.sign_tx(tx);
        
            return provider.send_tx(signed_tx);
        } catch (err) {
            throw new Error('Unable to send');
        }
    }
}


export default Wallet;