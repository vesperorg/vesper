# How to read this document

This is the long version. It starts from "what is money" and ends at the law, and it does not skip the parts people usually wave their hands at. Every chapter stands alone, so you can read it in order or jump to what you need. Where a concept has a name in the industry, the name is given so you can look it up and recognise it in conversation. Where something is contested or uncertain, it says so.

Three things to keep in mind throughout. First, a cryptocurrency is three separate inventions stacked on each other: a way to prove ownership without a bank (keys and signatures), a way for strangers to agree on one history without a referee (consensus), and a set of money rules nobody can quietly change (the protocol). Second, almost every disaster in this industry came from people forgetting which layer they were trusting. Third, nothing here is investment or legal advice; it is an explanation of how the machinery works.

# 1. The problem money solves, and the problem digital money adds

Money is a shared memory of who is owed what. A coin in your pocket is a memory token: whoever holds it is owed one coin's worth of goods. A bank balance is the same memory, kept in the bank's ledger instead of your pocket. Everything that makes money work comes down to one question: whose ledger do we trust, and why.

For physical cash the ledger is the object itself. You cannot spend a coin twice because handing it over removes it from your hand. For digital money this breaks. A digital coin is a file, and files copy perfectly. If I email you a coin, I still have the coin. This is the double-spending problem, and before 2009 the only known solution was a trusted middleman: a bank, a card network, PayPal. The middleman keeps the one true ledger and refuses the second spend. Every digital payment system before Bitcoin was some version of this, and every one inherited the middleman's weaknesses: it can be hacked, it can be ordered to freeze you, it can fail, it can charge what it likes, and it knows everything you do.

Bitcoin's claim, in the 2008 paper by the pseudonymous Satoshi Nakamoto, was that strangers who do not trust each other can keep one shared ledger with no middleman, and that nobody can spend twice or rewrite the past without doing more computational work than everyone else combined. Everything else in this document is either part of that machine or something built on top of it.

# 2. The building blocks

## 2.1 Hash functions

A hash function takes any data, a word or a terabyte, and produces a fixed-size fingerprint, for SHA-256 a 256-bit number usually shown as 64 hexadecimal characters. Three properties make it useful. It is deterministic: the same input always gives the same fingerprint. It is one-way: from the fingerprint you cannot recover the input or find any other input that produces it. And it is sensitive: change one bit of the input and the fingerprint changes completely and unpredictably.

Hashes are the glue of every blockchain. A transaction's ID is the hash of its contents, so you cannot alter a transaction without changing its ID. A block's ID is the hash of its header, and each header contains the previous block's hash, so changing any old block changes its hash, which changes the next block's header, which changes its hash, and so on to the tip. That cascade is what "chain" means, and it is why rewriting history is detectable instantly.

## 2.2 Public-key cryptography

A keypair is two numbers linked by mathematics that runs one way. The private key is a random 256-bit number you keep secret. The public key is computed from it on an elliptic curve (Bitcoin and Ethereum use a curve called secp256k1; Monero and Vesper use Ed25519), and computing it is fast while reversing it is believed to take longer than the universe has existed. An address is a shortened, checksummed form of the public key, safe to publish.

A digital signature is what the private key is for. Given a message and the private key, you produce a signature; anyone with the public key can verify that the signature was produced by the holder of the matching private key and that the message has not been altered since. The private key never leaves your computer. In a cryptocurrency, a transaction is a message that says "move these coins to that address," and the signature proves the owner authorised it. Whoever holds the private key holds the coins: there is no account recovery, no customer service, no password reset. This is the single most important fact for anyone who owns cryptocurrency.

## 2.3 Merkle trees

A block can hold thousands of transactions. To commit to all of them with one hash, their IDs are paired and hashed, the results paired and hashed, and so on up to one number, the Merkle root, which goes in the block header. Two benefits: the header stays small, and anyone can prove that a given transaction is in a block by showing only the handful of hashes on the path from it to the root. Light wallets on phones use exactly that proof instead of downloading whole blocks.

# 3. Transactions

## 3.1 Two ways to keep the ledger

The UTXO model, used by Bitcoin, Monero and Vesper, keeps no balances at all. It keeps a set of unspent transaction outputs, each a lump of coins locked to a key. A payment consumes some of those lumps as inputs and creates new lumps as outputs; the difference, if any, is the fee to the miner. Your "balance" is the sum of the lumps your keys can unlock. Paying 3 from a lump of 10 produces two outputs: 3 to the recipient and 7 back to you as change, which is a brand-new lump. The model is awkward for programmers and excellent for privacy and parallelism.

The account model, used by Ethereum and most smart-contract chains, keeps a balance per address, like a bank, plus a counter (the nonce) that prevents the same signed transaction being replayed. It is natural for programs that need to read balances, and it makes every balance public forever.

## 3.2 Anatomy of a payment

A transaction states what it spends (inputs), what it creates (outputs, each with an amount and a locking condition), a fee, and the signatures that authorise it. It gets an ID by hashing. A wallet builds it, signs it, and hands it to a node. The node checks the rules: the inputs exist and are unspent, the signatures are valid, the amounts balance, the fee meets the minimum. If it passes, the node puts it in its mempool, the waiting room of valid but unconfirmed transactions, and relays it to its peers. Within seconds the whole network has it. It is "confirmed" when a miner includes it in a block, and "settled" after enough further blocks that reversing it would cost more than it is worth, which on Bitcoin is conventionally six blocks, about an hour.

## 3.3 Fees

Block space is limited, so transactions bid for it with fees. In quiet times the minimum fee gets you in; in busy times a fee auction develops, and Bitcoin fees have ranged from pennies to over fifty dollars per transaction during peaks. Ethereum formalised this with a base fee that rises and falls with demand and is burned, plus a tip to the block producer. Fees are also the long-term pay for the people securing the chain once new-coin rewards run out, which is a live debate covered in chapter 9.

# 4. Blocks and the chain

A block is a batch of transactions plus a header. The header holds the previous block's hash, the Merkle root of its transactions, a timestamp, the difficulty target, and a nonce, a number the miner varies while searching for a valid proof of work. The first transaction in every block is the coinbase, which creates the block reward out of nothing and pays it to the miner; it is the only way new coins enter existence on a mined chain.

Because each header commits to the previous one, the blocks form a chain back to block 0, the genesis block, which is fixed in the software. A node that downloads the chain re-verifies every block and every transaction from genesis before trusting the tip. There is no "the server says so." Every full node independently concludes the same state from the same rules, which is why the rules themselves are the real authority.

Timestamps are only loosely enforced (a block must be later than the median of recent blocks and not too far in the future), because there is no shared clock; they are good enough to drive difficulty adjustment and nothing more.

# 5. Consensus: agreeing on one history

## 5.1 Proof of work

The question is who gets to add the next block. Proof of work answers: whoever first finds a block header whose hash is below a target number. Because hashes are unpredictable, the only way to find one is to try nonces at random, billions of times, and the chance of winning is proportional to how many tries per second you can make. The target is adjusted every so often (Bitcoin every 2,016 blocks, roughly two weeks) so that the network as a whole finds a block at the intended rate, ten minutes for Bitcoin, no matter how much hardware joins. More miners means harder puzzles, not faster blocks.

Why this works: adding a block costs real electricity, and rewriting history means redoing that work for every block after the one you change, faster than the honest network extends the real chain. Nodes follow the chain with the most accumulated work. An attacker needs more hashing power than everyone else combined, the "51% attack," and even then can only reorder recent history and double-spend their own coins; they cannot create coins or spend yours, because every block is still checked against the rules. For Bitcoin that attack would cost billions of dollars in hardware and electricity. For a small new chain using the same hash function it can cost a few thousand dollars of rented hashrate, which is why small chains get attacked and why the choice of hash function matters (chapter 13).

Mining hardware evolved from CPUs (2009) to GPUs (2010) to purpose-built chips, ASICs (2013 onward), which compute SHA-256 millions of times faster per watt than anything general-purpose. Coins that want ordinary people to keep mining choose memory-hard functions that ASICs cannot run efficiently: Monero's RandomX, and Argon2id, which Vesper currently uses. Mining also brought pools: miners combine their power, find blocks jointly, and split rewards in proportion, so a small miner gets a steady trickle instead of a lottery.

Proof of work's costs are its security: energy use that critics find indefensible and defenders call the price of a ledger nobody controls. Both are describing the same property.

## 5.2 Proof of stake

Proof of stake replaces hashing with locked-up coins. Validators deposit coins as a bond; the protocol picks who proposes each block in proportion to the bond; validators who sign conflicting blocks or go offline lose part of the bond (slashing). Ethereum switched to it in 2022, cutting its energy use by about 99.9%. Finality is explicit: after enough validators attest, a block is final and cannot be reverted without destroying a third of all staked coins.

The trade-offs are real and debated. Stake concentrates: those with the most coins earn the most new coins. Initial distribution matters enormously because there is no outside resource (electricity) that newcomers can bring to compete. Liquid-staking services and exchanges end up controlling large shares of validators. And the security argument is circular in a way proof of work's is not: the chain is secured by the value of its own coin.

## 5.3 Other mechanisms

Delegated proof of stake (coin holders elect a small set of block producers; fast, centralised). Proof of authority (named, permissioned validators; used for private and test networks). Byzantine fault tolerant protocols (Tendermint, used by Cosmos chains, where a fixed validator set votes in rounds). Proof of history and its relatives (Solana's ordering trick, combined with stake). Each is a different answer to the same question with a different point on the line between fast and trustless.

## 5.4 Forks

A fork is two valid chains sharing a history. Accidental forks happen constantly when two miners find blocks seconds apart; the next block resolves it, and the losing block becomes an orphan, its miner unpaid. Deliberate forks are rule changes. A soft fork tightens the rules so old nodes still accept new blocks (Bitcoin's SegWit, 2017). A hard fork loosens or changes them so old nodes reject new blocks, which means everyone must upgrade or the chain splits permanently into two coins. Bitcoin Cash (2017) and Ethereum Classic (2016) are both chains that continued the old rules after a contested hard fork; holders of the original coin found themselves holding both.

# 6. Nodes and the network

A full node stores the whole chain, validates everything, and relays blocks and transactions to peers; it is the unit of sovereignty, because it trusts nobody. A mining node is a full node that also builds blocks. A light client stores only headers and asks full nodes for Merkle proofs; phones run these. Peers find each other through hard-coded seed nodes, DNS seeds, and the addresses peers share with each other, then gossip: every new transaction or block is passed to all neighbours, and the whole network has it within seconds.

The protocol is the rules every node enforces; the client is the software. Bitcoin has one dominant client, Ethereum deliberately has several so a bug in one cannot halt the chain. Upgrades require coordination: Bitcoin uses miner signalling and long lead times; Monero schedules a hard fork every six months or so and expects everyone to upgrade; Ethereum sets named upgrade blocks. Governance, who decides, is social, not technical: developers propose, node operators choose what to run, miners or validators choose what to build on, and a change nobody runs does not exist.

# 7. Wallets and keys

A wallet does not hold coins; the chain holds coins. A wallet holds keys and knows which outputs those keys unlock. Modern wallets derive all their keys from one 12- or 24-word seed phrase (the BIP39 standard), so the phrase is the whole wallet: anyone who has it has everything, and anyone who loses it loses everything.

Hot wallets live on an internet-connected device: convenient, exposed. Cold wallets keep the key offline: a hardware wallet signs transactions inside a small device that never reveals the key to the computer. Custodial wallets, which include every exchange account, mean someone else holds the key and you hold a promise; "not your keys, not your coins" is the industry's oldest and most expensively learned lesson, taught again by Mt. Gox (2014) and FTX (2022). Multisignature wallets require several keys to spend, for organisations and for people who want no single point of failure.

Practical rules that hold on every chain: write the seed phrase on paper or metal and store it where fire and strangers cannot reach it; never type it into a website; test a restore before trusting a backup; use a hardware wallet for anything you cannot afford to lose; and assume any message asking for your seed is a theft attempt, because it always is.

# 8. The blockchain as a database, and what it is bad at

A blockchain is an append-only log that thousands of strangers keep identical copies of and that nobody administers. That makes it extraordinary at exactly one thing: being a record nobody can alter or censor. It makes it poor at everything a normal database is good at. It is slow (Bitcoin handles about seven transactions per second, Ethereum about fifteen on its base layer, Visa thousands), expensive (every node stores every byte forever), and public (unless privacy is built in at the protocol level, which chapter 11 covers). Most "blockchain for X" projects of the last decade failed because X did not need the one thing a blockchain offers.

Scaling, therefore, is the industry's central engineering problem. Bigger blocks (Bitcoin Cash's answer) trade decentralisation for throughput. Payment channels (Bitcoin's Lightning Network) move most payments off-chain and settle on-chain occasionally. Rollups (Ethereum's layer-2 chains such as Arbitrum, Optimism and Base) execute transactions elsewhere and post compressed proofs or data to the base chain. Sharding splits the chain itself. Each approach relocates the trust somewhere, and the fine print is always about where.

# 9. Monetary policy: how coins come to exist

## 9.1 Issuance

Every chain decides at genesis how new coins appear. Bitcoin issues 50 per block, halving every 210,000 blocks (about four years), to a hard cap of 21 million around the year 2140. Monero issued on a smooth curve that decreased every block and then, in 2022, settled into a tail emission of 0.6 XMR per block forever, so inflation trends toward zero but miners are always paid. Ethereum issues to validators and burns part of every fee, so its supply can shrink in busy periods. Dogecoin issues a flat 10,000 per block with no cap. The design question behind all of them is the same: when the new-coin reward runs out, do fees alone pay enough to keep the chain secure? Bitcoin is the experiment; nobody knows yet.

## 9.2 Distribution

How the first coins reach people determines the project's legitimacy for years. A fair launch (Bitcoin, Monero, Litecoin, Dogecoin) means the public mines from block 1 and the creators have no head start. A premine (Ripple, many 2017 coins) means the creators allocated coins to themselves before launch. An initial coin offering sells tokens to the public to fund development, which worked for Ethereum in 2014 and became the vehicle for thousands of frauds in 2017, which is why it is now treated as a securities sale in most jurisdictions. A founders' reward or development fund (Zcash, Beam, Firo, Vesper) takes a fixed, public slice of each block for a set period. Airdrops hand tokens to existing users of something else. An instamine is a fair launch in name where insiders secretly mined before the announcement, which is what destroyed Bytecoin and gave birth to Monero as its honest fork.

## 9.3 Supply mechanics people ask about

Halving is a scheduled cut in issuance, a cliff. Tail emission is a floor on issuance, a guarantee. Burning destroys coins by sending them to an address nobody can spend from, and it is only meaningful when the destruction is verifiable and when the coins burned were actually in circulation. "Splitting" does not exist as it does for stocks; a chain can redenominate its units, which changes nothing real, and a chain can fork, which creates two assets from one history. Supply caps are cosmetic to total value and matter mostly for how readable everyday amounts are: a coin capped at 21 million and a coin capped at 100 billion can be worth the same in total with wildly different prices per unit.

## 9.4 Where price comes from

There is no central price. Price is the last agreed trade on whatever venue the trade happened on, and it moves when buyers outnumber sellers at the current level or the reverse. Thin markets move violently; deep ones slowly. The only durable source of demand is use: people who need the coin for something, from payments to collateral to privacy. Everything else is speculation, which can move a price enormously and cannot hold it there. Market capitalisation, price times circulating supply, is widely quoted and widely misread; fully diluted valuation counts coins not yet issued, and the gap between the two is often where the danger is.

# 10. Smart contracts, tokens and the second generation

Ethereum (2015) generalised the blockchain from a ledger of coins to a ledger of programs. A smart contract is code stored on the chain that runs when a transaction calls it, with its results written to the chain and agreed by every node. Users pay "gas," a fee proportional to the computation, in the chain's native coin. Because the code is public and the execution is unstoppable, the contract is the agreement; there is no appeal.

Tokens are the most common contracts. An ERC-20 token is a contract that keeps a table of balances and lets holders transfer them; every "coin" on Ethereum that is not ETH itself is one of these, including stablecoins (USDC, USDT), which are tokens backed by dollars held by a company, and the thousands of project tokens that live and die each year. NFTs are tokens where each unit is unique. Deploying a token costs a few dollars on a layer-2 chain and about twenty lines of standard code, which is why "making a coin" on Ethereum is trivial and why the hard part is everything else.

Decentralised finance (DeFi) is contracts that replace financial intermediaries. Automated market makers like Uniswap let anyone trade tokens against a pool of liquidity priced by a formula, with no order book and no company. Lending protocols let you borrow against collateral the contract holds. Bridges move value between chains by locking coins on one and minting a representation on the other, and because they concentrate value in one contract they have been the most-hacked thing in crypto, with losses above a billion dollars. Oracles feed outside data (prices, weather, results) into contracts and are a classic weak point. Layer-2 rollups now host most activity, because base-layer Ethereum is slow and expensive.

The lessons of this generation: code is law until it is a bug, at which point humans decide anyway (the 2016 DAO hack and the fork that reversed it); composability is power and contagion at once (one protocol's failure cascades into others); and the token itself is rarely the product.

# 11. Privacy: what public chains leak and how privacy coins fix it

## 11.1 The leak

A transparent chain publishes every transaction forever: sender address, receiver address, amount, time. Addresses are pseudonyms, not anonymity. One link between an address and a person, from an exchange's identity records, a public donation page, a merchant, or a careless post, exposes that person's entire history in both directions. Chain-analysis firms sell precisely this reconstruction to exchanges and governments. Reusing an address makes it worse; even without reuse, change outputs, timing and amounts link transactions together. Bitcoin is, in practice, the most surveilled money ever created.

## 11.2 Mixing and partial fixes

CoinJoin combines many people's payments into one transaction so an observer cannot tell which input paid which output; it helps, is statistically attackable, and depends on coordination. Mixers and tumblers take coins in and pay different coins out, and their operators have been prosecuted. These are patches on a transparent design. The coins that solved the problem changed the design.

## 11.3 Stealth addresses

The receiver's published address is two public keys. A payer derives a fresh one-time key from them plus a random secret, pays to that key, and publishes just enough for the receiver to recognise it. Nobody can connect the one-time key to the address or to any other payment the receiver got. The receiver scans the chain with a private view key; a view key can find and (with confidential amounts) read a wallet's incoming payments and cannot spend them, which is what makes audits possible without exposing anyone else.

## 11.4 Confidential amounts

Amounts are replaced by cryptographic commitments, numbers that hide a value but can be added together. A node checks that a transaction's input commitments equal its output commitments plus the fee without learning any amount. Because arithmetic on hidden numbers could be abused to create coins out of a negative output, each output carries a range proof showing its hidden value is within a legal range. Bulletproofs made these proofs small enough (under a kilobyte) to be practical; Monero adopted them in 2018.

## 11.5 Hiding the sender

Monero's answer is ring signatures: a payment's input is signed as one member of a ring of candidate outputs (the real one plus decoys, currently 16), and a key image, a one-way marker of the real output, is published so the same output cannot be spent twice without ever revealing which ring member was real. The weakness is the crowd size: statistics about which ring member is likely real have been used in attacks, which is why Monero is moving to full-chain membership proofs, where the anonymity set is every output ever created.

Zcash's answer is zero-knowledge proofs: a transaction proves it is valid, that the coins exist, are owned by the signer, and balance, without revealing any of the inputs, outputs or amounts, and the anonymity set is the entire shielded pool. The original scheme needed a trusted setup ceremony; newer ones do not. Zcash's historical weakness was policy, not math: shielded transactions were optional, most users chose transparent ones, and the pool stayed small.

## 11.6 The network layer

A perfect ledger still leaks at the door: the first node to relay a transaction is usually the sender's, and its IP address is visible. Dandelion++ (used by Monero) forwards a new transaction along a random path for a few hops before broadcasting it. Routing over Tor or I2P hides the address entirely. Any privacy coin without a network-layer story is private on paper only.

## 11.7 What privacy does not do

It does not hide you from an exchange you gave your identity to, at either end of your trail. It does not hide amounts of mining rewards, which must be public to verify issuance. It does not stop the person you paid from knowing they were paid. And no privacy coin is fully private against a quantum computer, which could recover private keys from public ones and retroactively link one-time keys to addresses; the hidden amounts in commitments would survive, the rest would not. These limits are why serious privacy projects publish exactly what their chain still reveals.

# 12. Exchanges, markets and getting in or out

Centralised exchanges (Coinbase, Binance, Kraken) are companies that hold your coins and run an order book; they are where most people buy their first coin and where identity checks happen. They can be hacked, mismanaged or ordered to freeze accounts; FTX's 2022 collapse took billions of customer funds. Decentralised exchanges (Uniswap, Aerodrome) are contracts on a chain; they can only trade tokens native to that chain, so a coin with its own blockchain cannot be listed on them at all, only wrapped versions of it can, which reintroduces a custodian. Atomic swaps are protocols that let two people trade across chains directly with no custodian, and they are how privacy coins trade without wrapping.

Getting listed is a business process: a legal entity, a working chain, an audit, liquidity, months of due diligence, and often fees. Privacy coins face an extra barrier: anti-money-laundering rules in many countries, and the "travel rule" that requires exchanges to know both ends of a transfer, have led major exchanges to delist Monero and Zcash in several jurisdictions. Market makers are firms exchanges often require to keep buy and sell orders on the book; legitimate projects hire them openly. Wash trading, buying your own coin to fake volume, and price support, buying from a reserve to hold a number, are manipulation, are watched for, and have ended projects.

Terms you will meet: order book (bids and asks), spread (the gap between them), slippage (the price moving against you as your order fills), liquidity (how much can trade without moving the price), volume (how much did trade), market cap, fully diluted valuation, on-ramp and off-ramp (converting between bank money and coins).

# 13. Security and attacks

On the chain: the 51% attack (reorder recent history; feasible against small proof-of-work chains using a big chain's hash function), selfish mining, Sybil attacks (flooding the network with fake nodes), eclipse attacks (surrounding a victim's node with your own), timestamp manipulation, and difficulty manipulation, where a large miner jumps on a small chain when it is easy and leaves it stuck when it is hard. Defences: a hash function big miners cannot rent (memory-hard functions), a difficulty algorithm that reacts within minutes, many independent nodes, and for proof of stake, slashing and finality.

In contracts: re-entrancy, oracle manipulation, flash-loan attacks, and plain bugs; bridges concentrate value and have lost the most. Defences: audits, bounties, formal verification, time locks on upgrades.

Against people: phishing, fake wallets, seed-phrase theft, SIM swaps that defeat text-message two-factor codes, dusting attacks that send tiny amounts to trace wallets, rug pulls where creators drain a project, and exit scams. Defences: hardware wallets, hardware two-factor keys, never typing a seed anywhere, and the oldest rule, that anything promising returns is selling you something.

On the horizon: quantum computers large enough to break elliptic-curve cryptography do not exist yet; when they do, every chain will need to migrate to post-quantum signatures, and coins at addresses whose public key is already visible will be at risk first.

# 14. Law and regulation

This chapter is a map, not advice, and it is written from a United States vantage point.

Whether a coin is a security turns on the Howey test: is it an investment of money in a common enterprise with an expectation of profit from the efforts of others? A token sold by a team that promises to build something and make it valuable usually is; Bitcoin, mined into existence with no issuer, is treated as a commodity; most things are argued over. Securities must be registered or sold under an exemption (Regulation D for accredited investors, Regulation Crowdfunding for the public up to a few million dollars, Regulation A+ for more). Selling coins to fund a project without one of these is how many 2017 projects ended up in settlements.

Handling other people's money as a business, exchanging it, transmitting it, can make you a money services business under federal rules and a money transmitter under state rules, each with licensing and anti-money-laundering duties. Exchanges carry know-your-customer obligations, and the travel rule requires sharing sender and receiver information for transfers between regulated firms. Privacy coins are legal to hold and use in the United States and most countries; some countries have banned them from exchanges, and some exchanges have delisted them pre-emptively.

Taxes: in the United States cryptocurrency is property; selling, trading or spending it is a taxable event, mining rewards are income at their value when received, and records are your problem, which is one argument for view keys. Rules have shifted repeatedly through 2024 to 2026 and differ by country; a lawyer and an accountant who work in this field are not optional for anything beyond a hobby.

Finally, marketing. The sentences that create legal exposure are the ones about price and profit. Describing what a coin does, how it works, and what it still cannot do creates none.

# 15. History and the lessons it keeps teaching

2008 to 2010: the Bitcoin paper and the first blocks; Satoshi mines about a million coins on ordinary hardware because almost nobody else is mining, then leaves. 2011 to 2013: the first alternative coins, Litecoin and Namecoin; Silk Road makes Bitcoin's traceability a law-enforcement tool. 2014: Mt. Gox, then the largest exchange, loses 850,000 bitcoin; Monero is forked from Bytecoin after its hidden premine is exposed. 2015: Ethereum launches after a public sale. 2016: the DAO hack and the fork that reversed it, splitting Ethereum Classic off. 2017: the initial-coin-offering boom raises billions, most of it for nothing, and ends in enforcement; Bitcoin Cash forks over block size. 2018: Bulletproofs, Zcash's Sapling upgrade. 2020: "DeFi summer," automated market makers and lending protocols; the halving. 2021: NFTs, layer-2 rollups, and a peak. 2022: Terra's stablecoin collapses, taking forty billion dollars; FTX collapses, taking customer funds; Ethereum moves to proof of stake. 2023 to 2024: spot Bitcoin ETFs approved in the United States; exchanges delist privacy coins in several regions; Monero plans full-chain membership proofs. 2025 to 2026: stablecoin legislation, market-structure rules under negotiation, and a maturing layer-2 ecosystem.

The lessons that repeat: the projects that lasted had working code before marketing, no secret allocations, honest statements of their limits, and years of patience; the projects that collapsed had a story about the price, a reserve someone controlled, and a reason not to look too closely. The technology has never been the bottleneck. Trust has.

# 16. Mining economics in numbers

Mining is a lottery where tickets cost electricity. Your expected share of blocks over any period is your hashrate divided by the network's. If the network makes 100 blocks a day and you have 2% of its hashrate, you expect 2 blocks a day on average, with large swings; with 0.01% you expect one block every 100 days, which is why pools exist. A pool collects everyone's attempts, finds blocks collectively, and pays each member in proportion to their contributed work, either per share submitted (PPS, steady but the pool takes risk and a fee) or per share over the last N found blocks (PPLNS, variance shared with the pool). Pool operators have real power: they choose which transactions go in blocks, and if a few pools hold most hashrate the chain is centralised in practice even if the protocol is not.

Profitability is a simple formula: coins earned per day times price, minus electricity (watts times hours times your rate), minus hardware amortised over its useful life, which for ASICs is often under two years because the next generation makes them unprofitable. The difficulty adjustment guarantees that as more hardware joins, each unit earns less; the long-run equilibrium is that mining costs roughly what it pays, and the margin goes to whoever has the cheapest power. For a new chain the first weeks are the exception: low difficulty, few competitors, maximum reward per block, which is why early miners end up with disproportionate holdings and why that period must be public.

Small proof-of-work chains face a specific hazard called hash-and-run. A large miner points hardware at the chain when its difficulty is low, grabs blocks quickly, and leaves when the difficulty rises; the chain is then stuck at a difficulty its honest miners cannot sustain, and blocks slow to a crawl until the adjustment catches up. Chains have died this way. The defences are a difficulty algorithm that reacts every block rather than every two weeks, and a hash function the large miner's hardware cannot run.

# 17. Running a node and a miner, practically

A full node needs disk (Bitcoin's chain is over 600 GB; Monero's over 200 GB; a new chain starts near zero), bandwidth (it uploads blocks to peers constantly), an open port so other nodes can reach it, and uptime. It gives you three things: your own verified copy of the truth, so no exchange or website can lie to you about a balance or a payment; privacy, because your wallet asks your node and not a stranger's; and a vote, because the rules that exist are the rules nodes run. Most users never run one and trust somebody else's, which is fine until it is not.

A miner is a node plus hashing. On a CPU-mined chain you need cores and memory; on an ASIC chain you need the chip and cheap power; on a proof-of-stake chain you need the bond and near-perfect uptime, because downtime is penalised. Solo mining makes sense when few people compete or the block reward is small enough that variance does not matter; pools make sense otherwise.

Operational security for a node that holds a wallet: keep the wallet on a separate machine from anything exposed to the internet, keep the node's management interface bound to localhost, update promptly when the project ships a fix, and watch the project's announcement channel, because a chain upgrade you miss can leave your node on a dead fork.

# 18. Layer 2 in depth

Payment channels, Bitcoin's Lightning Network, lock coins in a two-party contract on the chain and then exchange signed balance updates off-chain as fast as the two parties can message; only opening and closing touch the chain. Payments route across many channels using hashed time-locked contracts so that no intermediary can steal. The costs: both parties must stay online or delegate watching, liquidity must be in the right channels, and large payments often fail to route.

Rollups, Ethereum's answer, execute transactions on a separate chain and post either compressed transaction data (so anyone can rebuild the state) or validity proofs to the base chain. Optimistic rollups (Arbitrum, Optimism, Base) assume batches are valid and allow a challenge window, typically seven days, during which anyone can prove fraud; withdrawals to the base chain wait that long. ZK rollups post a cryptographic proof that each batch is valid, so withdrawals are fast but proving is computationally heavy. Both rely on a sequencer that orders transactions, usually a single company today, which is a centralisation and censorship point the designs promise to fix. The data-availability question, where is the data that lets anyone reconstruct the state, is the live engineering frontier.

Sidechains are independent chains with their own security that connect through a bridge; they inherit nothing from the base chain and are only as safe as the bridge. State channels generalise payment channels to arbitrary contract state. Each of these answers "where does the trust go" differently, and reading a layer-2's documentation for that one question tells you most of what you need.

# 19. Stablecoins and tokenised real-world assets

A stablecoin is a token that aims to hold one dollar. Three ways to try. Fiat-backed (USDC, USDT): a company holds dollars and treasuries and issues tokens one-for-one; the trust is in the company's reserves and its willingness to redeem, and the company can freeze tokens. Crypto-collateralised (DAI): users lock more than a dollar of volatile crypto to mint a dollar of stablecoin, with automatic liquidations when collateral falls; the trust is in the contract and the collateral's liquidity. Algorithmic: the peg is held by incentives and a sister token with no hard backing; Terra's UST, the largest, collapsed in May 2022 and took about forty billion dollars with it, and the category is now largely treated as a cautionary tale.

Stablecoins are the most used thing in crypto by transaction value, the plumbing of exchanges and DeFi, and the first part of the industry to get dedicated law: the United States passed stablecoin legislation in 2025 requiring full reserves and licensing for issuers. Central-bank digital currencies are the state's version, and they are the opposite of a privacy coin: a ledger the issuer can read and control completely. Tokenised treasuries and funds, where a regulated issuer puts a traditional asset on a chain, are growing fast and are, again, custodial: the token is a claim on an institution.

# 20. Governance, DAOs and how chains change

No protocol runs itself forever. Bitcoin changes through Bitcoin Improvement Proposals, long public argument, and activation only when an overwhelming share of miners and node operators signal readiness; it has changed very little, by design. Ethereum changes through EIPs, scheduled named upgrades, and a core developer process that is more active and more centralised in practice. Monero schedules a network upgrade every six months or so and expects everyone to follow, which lets it ship privacy improvements quickly. Funding is governance too: Monero's Community Crowdfunding System lets anyone propose work and the community fund it; Zcash funds a company and a foundation from a block-reward slice; Bitcoin has no fund and relies on sponsors.

Decentralised autonomous organisations are governance by token vote: holders vote on proposals and a contract executes the result. In practice token voting is plutocracy, turnout is low, and the largest holders decide; many DAOs are a multisig with a forum attached. A multisig, a wallet needing several named key-holders to sign, is the honest minimum for any treasury, and the names should be public. The questions to ask of any project: who can change the rules, who holds the money, who can be removed, and what happens if they disappear.

# 21. How to evaluate a project

A checklist that catches most of what goes wrong.

1. Is the code public, with a visible commit history, and can a competent person read it? If the code is closed or "coming soon," there is no project yet.
2. Who got coins before the public could, and how many? A premine or an undisclosed allocation is the first and strongest warning.
3. What does the coin actually do that money could not? If the only answer is "it will go up," it is a speculation vehicle.
4. Has anyone independent attacked it: an audit with a named firm, a bounty, academic papers? Unaudited cryptography is unproven cryptography.
5. Who controls upgrades, the treasury, and the keys, and is that written down?
6. Where is the liquidity, how much, and who provided it? A coin that trades on one tiny venue has no price, only a quote.
7. What does the project say about its own weaknesses? Honest projects publish them; dishonest ones have none.
8. What is the tone of the marketing? Countdowns, guaranteed returns, celebrity endorsements and referral bonuses are the vocabulary of schemes.
9. Does the team disclose its own holdings and mining?
10. Would it survive its founders leaving?

Red flags, any one of which should end the conversation: "guaranteed," "risk-free," urgency, requests for your seed phrase, pressure to recruit others, and a treasury nobody can audit.

# 22. The scam catalogue

Knowing the shapes protects you better than any software. The rug pull: creators of a token or liquidity pool drain it and vanish. The honeypot token: a contract that lets you buy but not sell. Pump and dump: coordinated buying and promotion, then selling into the crowd. Pig butchering: a long-con relationship, often starting on dating or messaging apps, ending with a fake trading platform that shows gains and never pays out; this is now the largest category by losses. Approval phishing: a website asks your wallet to "approve" a token, and the approval lets a contract drain it later. Address poisoning: an attacker sends tiny amounts from an address that looks like one you use, hoping you copy it from history. Seed-phrase sites: any page that asks you to "verify" or "sync" your wallet by typing the phrase. Fake support: a helpful stranger in a chat who needs remote access or your phrase. Ponzi yield: a platform paying returns from new deposits; BitConnect promised 1% a day and was exactly this. Celebrity and meme tokens launched to extract money in hours. Wash-traded markets that show volume nobody traded. Bridge exploits that drain locked funds. And the oldest one, the exchange that was never solvent.

Defences, in order of value: never type a seed anywhere; use a hardware wallet for anything that matters; revoke token approvals you no longer need; verify addresses character by character or by QR, never from history; assume unsolicited help is theft; and treat any promised return as the price of admission to a fraud.

# 23. Open problems and ideas worth having

The trilemma: decentralisation, security and scale, pick two, has not been solved, only traded around. Maximal extractable value, where block producers reorder or insert transactions to profit from users, is a live tax on every smart-contract chain and an unsolved fairness problem. Fee markets are still crude: blocks are either empty or auctions. Quantum migration is a known future cost nobody has scheduled. Interoperability without custodial bridges, through atomic swaps and light-client proofs, works in narrow cases and is not general. Usability remains dreadful: seed phrases, irreversible mistakes, and the absence of recovery keep ordinary people out; account abstraction and social recovery are the current attempts. Energy, for proof of work, is a cost that is also the security, and the argument will not end.

For privacy specifically, the open problems are the ones Vesper is built around: an anonymity set equal to the whole chain at a cost that does not slow the network; privacy that can be selectively proven to a chosen party, so compliance and privacy stop being enemies; network-level privacy that does not depend on optional tooling; and the social problem of exchanges that delist what they cannot see into. The idea worth stealing from Monero is transparency about weakness: a project that publishes what its chain still leaks, and pays people to find more, is trusted in a way no marketing can buy.

# 24. A learning path, with the sources I would use

Run a transparent learning chain and watch its explorer while reading chapter 4; change a byte in its chain file and watch validation refuse it. Run Vesper's demo and the two-person test and read the whitepaper's threat model. Read the Bitcoin whitepaper, nine pages, after you have run a chain, because then every sentence lands. For depth: Mastering Bitcoin by Andreas Antonopoulos for the mechanics, Zero to Monero for ring signatures and confidential transactions explained patiently, the Ethereum documentation for contracts, and the Zcash protocol specification if you want to see how zero-knowledge proofs are actually pinned down. Watch mempool.space to see a live fee market and real blocks arriving. Then come back to this document; it will read differently.

# 25. Glossary

| Term | Meaning |
|---|---|
| Address | A shortened, checksummed public key you can safely publish to receive coins. |
| ASIC | A chip built to compute one hash function very fast; dominates Bitcoin mining. |
| Atomic swap | A cross-chain trade between two people with no custodian; either both sides happen or neither. |
| Block | A batch of transactions plus a header that links to the previous block. |
| Bridge | A mechanism that locks coins on one chain and issues a representation on another; frequently hacked. |
| Coinbase transaction | The first transaction in a block, creating the block reward. |
| Cold wallet | Keys kept offline, such as on a hardware wallet. |
| Commitment | A number that hides a value but allows arithmetic and later proof; used for confidential amounts. |
| Consensus | The rules and process by which nodes agree on one chain. |
| Custodial | Someone else holds your keys; you hold a promise. |
| DEX | Decentralised exchange: a contract that trades tokens native to its chain. |
| Difficulty | How hard the proof-of-work puzzle currently is; adjusted to keep block times steady. |
| Double spend | Spending the same coins twice; the problem blockchains exist to prevent. |
| Fair launch | A launch where nobody mines or receives coins before the public can. |
| Fork | Two chains sharing a history; accidental (resolved in a block) or a rule change (soft or hard). |
| Gas | The fee for computation on a smart-contract chain. |
| Genesis block | Block 0, fixed in the software. |
| Halving | A scheduled cut of the block reward by half. |
| Hash | A fixed-size fingerprint of data; one-way and tamper-evident. |
| Key image | A one-way marker of a spent output that prevents double spending without revealing the output. |
| Light client | A wallet that verifies headers and Merkle proofs instead of the whole chain. |
| Mempool | A node's waiting room of valid, unconfirmed transactions. |
| Merkle root | One hash committing to all transactions in a block. |
| Mining pool | Miners combining power and splitting rewards. |
| Node | A computer running the chain software; a full node validates everything. |
| Nonce | A number varied by miners to find a valid block, or a counter preventing replay in account chains. |
| Premine | Coins created for insiders before the public launch. |
| Private key | The secret number that spends your coins; losing it loses them, leaking it gives them away. |
| Proof of stake | Consensus by bonded coins instead of work. |
| Proof of work | Consensus by computational effort. |
| Range proof | A proof that a hidden amount is within a legal range. |
| Ring signature | A signature by one unknown member of a group of possible signers. |
| Rollup | A layer-2 chain that executes off the base chain and posts proofs or data to it. |
| Seed phrase | The 12 or 24 words from which a wallet derives all its keys. |
| Stealth address | A scheme where every payment lands at a fresh one-time key only the receiver can recognise. |
| Tail emission | A small fixed block reward that continues forever. |
| Token | A coin that lives inside a contract on someone else's chain. |
| UTXO | Unspent transaction output: a lump of coins locked to a key. |
| View key | A key that can see a wallet's incoming payments and cannot spend them. |
| Wallet | Software that holds keys and tracks the outputs they unlock. |
| Zero-knowledge proof | A proof that a statement is true that reveals nothing else. |
