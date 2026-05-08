# bc-web3js
A TypeScript SDK for interacting with the ByteChain Testnet Alpha. Simplifies client-side account management, secure transaction signing, and reliable node communication.


## Installation
To install the bc-web3js SDK in your project, use npm or yarn:


```bash

npm install bc-web3js

```

or

```bash

yarn add bc-web3js

```

## Getting Started
Before using the bc-web3js SDK, you'll need an instance of your core ByteChain Blockchain implementation. This SDK is designed to interact with that instance, which typically represents a running ByteChain node (local or remote).


## 1. Basic Setup & Querying Balance
This example demonstrates how to initialize the bc-web3js SDK and perform basic queries like checking an account's balance and validating an address.



```typescript
import BCWeb3 from 'bc-web3js';

// 1. Get a url of the blockchain node/peer you wish to use
const nodeUrl = "http://your-node-url-and-port";

// 2. Initialize BCWeb3 with your blockchain instance
const bcWeb3 = new BCWeb3(myByteChainInstance);

// 3. Query an account balance
const exampleAddress = 'BC1A2B3C4D5E6F7G8H9I0J1K2L3M4N5O6P7Q8R9S0T1U2V3W4X5Y6Z7';

const balance = bcWeb3.getBalance(exampleAddress);

console.log(`Balance of ${exampleAddress}: ${balance} byte`);

```

## 2. Account Creation & Transaction Signing
This section covers how to create new ByteChain accounts, load existing ones using private keys, and sign transactions.


```typescript
import BCWeb3 from 'bc-web3js';

const nodeUrl = "http://your-node-url-and-port";

const bcWeb3 = new BCWeb3(nodeUrl);

// 1. Create a new account (generates a new private key internally)
bcWeb3.createAccount();

console.log('--- New Account Created ---');

console.log('Address:', bcWeb3.wallet.account.pub_key);


// 2. Load an existing account using its private key
//    Replace 'YOUR_EXISTING_PRIVATE_KEY_HEX_HERE' with an actual private key
//    associated with an account that has funds on your testnet.

const existingPrivateKey = 'YOUR_EXISTING_PRIVATE_KEY_HEX_HERE';

bcWeb3.loadAccount(existingPrivateKey);

const senderAddress = bcWeb3.wallet.account.pub_key;

console.log('\n--- Loaded Account ---');

console.log('Sender Address:', senderAddress);

console.log('Sender Balance:', bcWeb3.getBalance(senderAddress));


// 3. Create and sign a transaction
const amount = 10; // Amount of Byte to send

const recipientAddress = 'BC_ANOTHER_ADDRESS_HERE'; // Replace with a recipient ByteChain address

bcWeb3.transfer(amount, recipientAddress)
    .then(res => {
        // Use response here(Response is just a string)
        console.log(res);
    })
    .catch(err => {
        // Use error here
        console.log(err);
    })

```


## 3. Blockchain Data Querying

Retrieve information about blocks and transactions from the blockchain instance.

```typescript
import BCWeb3 from 'bc-web3js';

const nodeUrl = "http://your-node-url-and-port";

const bcWeb3 = new BCWeb3(nodeUrl);

// 1. Get a block by its height (e.g., block 0 - the genesis block)
const genesisBlock = bcWeb3.getBlock(0);

console.log('Block Hash:', genesisBlock.block_header.block_hash);

// 2. Get transactions currently in the mempool (transaction pool)
const txPool = bcWeb3.getTxPool();

console.log(`\n--- Transaction Pool (${txPool.length} transactions) ---`);

txPool.forEach(tx => {
    console.log(`- ID: ${tx.id}, From: ${tx.sender}, To: ${tx.recipient}, Amount: ${tx.amount}`);
});

// 3. Get the last block in the chain
const lastBlock = bcWeb3.getLatestBlock();

console.log('Block Hash:', lastBlock.block_header.block_hash);

// 4. Get a range of blocks(e.g., blocks 0-20)
const first20Blocks = bcWeb3.getBlocksInRange(0, 20);

first20Blocks.forEach(block => {
    console.log(`- Nonce: ${block.block_header.nonce}, Hash: ${block.block_header.block_hash}, Timestamp: ${block.block_header.timestamp}, Prev Hash: ${block.block_header.prev_block_hash}`);
});

// 5. Get the whole chain(e.g. blocks 0-the last block)
const chain = bcWeb3.getChain();

chain.forEach(block => {
    console.log(`- Height: ${block.block_header.block_height}, Hash: ${block.block_header.block_hash}, Transactions: ${block.transactions.length}`);
});
```