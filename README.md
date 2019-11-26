# Signed Proof-of-Work

### Prerequisites

First of all, purpose of this idea - kill the pool mining, at least in the form we knew it.

So, how does pool mining works exactly? Pooled mining is a mining approach where multiple miners contribute to the generation of a block, and then split the block reward according the contributed processing power. Pooled mining effectively reduces the granularity of the block generation reward, spreading it out more smoothly over time [1].

This seemingly harmless concept centralize control over hash power around small group of peoples and goes against Satoshis idea of `one-CPU-one-vote` [2].

### Idea

Main idea behing SPoW algo is sign header data with private key of miner and check if address in [coinbase](https://learnmeabitcoin.com/glossary/coinbase-transaction) transaction correspond for this key. Since each private key is unique and allow spend coins from derived address, this vould render pool mining impossible, or at least requiring trust between participating parties since it requires sharing private key (imagine that any pool miner would be able steal coins from pool address :D !).

### Implementation

Original Bitcoin Proof-of-Work implementation is based on hashing serialized block header which consists of:

- Block version
- Hash of previous block
- Merkle root of all transactions inside this block
- Block timestamp
- Block bits
- Nonce

And building header hash looks something like this:

```
sha256d(version + prev_block + merkle_root + timestamp + bits + nonce)
```

As you can see this rather simple schema allows outsorce hashing to miners just by giving pool address.

In SPoW miner public key and signature is part of header hash, so this create something like seal making it impossible to sign hash after PoW is completed.

So hash for SPoW header will be derived like this:

```
sha256d(version + prev_block + merkle_root + timestamp + bits + nonce + miner_pubkey + signature(ripemd160(<all data above>)))
```

This repository contains [spow.py](spow.py) implementation, so you can check how it's working on your own. Keep in mind that this algo is hasing/dsa algo agnostic so you can play around with it. Ripemd160 hashing is used to slightly decrease signature size and make data more consistent.

### Open questions

This idea still has bunch of open questions:

- How it will handle multi signature address
- How to implement it in anonymous coins (like Cryptonote/Zk-Snarks based and etc)
- How dsa algo will affect the performance

**Disclaimer**: I'm pretty sure that somebody before me already came up with similar idea in some form or another, but I've got it during the shower and decided to implement it in this simple proof of concept (because why the hell no :D ?).

If you have questions/proposals/critique - feel free to create issue for this repository.

If you would like to use this algo, please check the [license](LICENSE.md) :)

Coins using similar idea:

- [Spreadcoin](https://www.spreadcoin.info/)

### References

[1] https://en.bitcoin.it/wiki/Pooled_mining  
[2] https://bitcoin.org/bitcoin.pdf
