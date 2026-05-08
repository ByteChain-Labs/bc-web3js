import type { PubKey, PrivKey } from "./utils.js";
import type { BlockHeader, BlockInterface } from "./interfaces.js";
import Account from "./account.js";
import Provider from "./provider.js";
import Wallet from "./wallet.js";


export default class BCWeb3 {
    provider: Provider;
    wallet!: Wallet;

    constructor(node_url: string) {
        this.provider = new Provider(node_url);
    }

    createAccount() {
        let new_account = Account.new();
        this.wallet = new Wallet(new_account.priv_key);
    }

    importAccount(privKey: PrivKey) {
        let imported_account = Account.new(privKey);
        this.wallet = new Wallet(imported_account.priv_key);
    }

    async getBalance(): Promise<number> {
        return await this.provider.check_balance(this.wallet.account.pub_key);
    }

    async getNonce(): Promise<number> {
        return await this.provider.check_nonce(this.wallet.account.pub_key);
    }

    async getLatestBlock(): Promise<BlockInterface>  {
        return await this.provider.get_latest_block();
    }

    async getBlock(block_id: number): Promise<BlockInterface>  {
        return await this.provider.get_block(block_id);
    }

    async getBlocksInRange(start_num: number, end_num: number): Promise<BlockInterface[]> {
        const blocks = await this.provider.get_blocks_in_range(start_num, end_num);
        return [...blocks];
    }

    async getChain(): Promise<BlockInterface[]>  {
        const chain = await this.provider.get_chain();
        return [...chain];
    }

    async transfer(amount: number, recipient: PubKey): Promise<string> {
        const transferResult = await this.wallet.send_byte(this.provider, amount, recipient);
        return transferResult;
    }
}

export type {
    PubKey,
    PrivKey,
    BlockHeader
}

export {
    Account
};