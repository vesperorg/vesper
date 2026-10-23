# What this document is

This is the complete picture of Vesper as it stands on 18 October 2026, the day the code went public: what it is, how every part works, what exists on your computer, what the two Claude sessions have built and will build, what you need to do, what you could do, what you should not do, and a realistic timeline with no promised dates. It is written to be re-read as the project moves; where a number or a decision is still open, it says so.

> The one-line thesis: Vesper is money that is private by default and provable on demand. Nobody can read your payments, and you can prove your own history to anyone you choose, without exposing anyone else.

# 1. Where we are today

## 1.1 What exists

- A working private cryptocurrency, in Python with libsodium doing the curve arithmetic, in `~/projects/vesper` and public on GitHub under the Vesper organisation. It has a node with an explorer, a command-line wallet, a peer network, a multi-core miner, a one-click test drive, and a 44-check self-test that passes (node v0.9.0).
- Testnet-1, decided 18 October 2026: a public test network with test coins (tVESP, addresses start `tvsp2`, no value ever), ring size 48 (raised from 32 on 19 October, three times Monero's), a genesis block tied to the newest Bitcoin block at launch, and a seed node on a rented server (kit in `deploy/`).
- Four privacy layers built and tested: hidden receivers (stealth addresses, as many per wallet as you like, and view keys), hidden amounts (commitments and one range proof per payment), hidden senders (rings of 48 with decoys drawn from measured spending, and key images), and network privacy (a payment travels node to node before any node broadcasts it, with the remaining leak measured by `leaktest.py` rather than claimed away).
- Payment proofs, wallet recovery codes, Tor through one flag, per-address limits and a peer table built for strangers.
- A protocol-enforced development fund (10% of each block reward for 4,204,800 blocks) that any observer can audit.
- Memory-hard mining (Argon2id) chosen so Bitcoin mining chips cannot attack the chain on day one.
- Six published pages: the main Vesper page, the launch plan, the whitepaper with threat model, the hands-on test drive, Join Vesper and Breaking Vesper. They are served from the repository (GitHub Pages); local copies are in `vesper\site`, served by `site.bat`.
- Two Claude sessions working in parallel: one owns the code, one owns everything public-facing. They message each other and keep the pages matched to the code.

## 1.2 What does not exist yet

- Proof that the node survives strangers. Its limits, bans, timeouts and peer table have met simulations and one PC, not the open internet; the public testnet is that test. Nothing between nodes is encrypted (Tor is the answer today).
- Stage two of phase 3: hiding the sender among every output on the chain rather than 16. Research, no design chosen.
- The seed node itself: a rented Ubuntu server running `deploy/setup-seed.sh`, whose address goes into `config.json` and onto the Join page. Testnet-1 is open from that moment.
- An independent audit. A hardened production node. Desktop and mobile wallets. A legal entity.
- Any coins. Every chain that has run so far is a test chain. Mainnet genesis has not happened and has no date.

## 1.3 The honest line, which every page holds

Receivers hidden, amounts hidden, sender hidden among 48 (three times Monero's ring, still not everyone), and the first broadcast of a payment comes from a relay rather than the sender's node, with an attacker who runs a tenth of the nodes still guessing right about a tenth of the time: as private as Monero's design, not more. Not "untraceable," not audited, not production software. Those words are earned later, in that order.

# 2. How Vesper works, layer by layer

## 2.1 The engine underneath

Vesper runs on the same engine as the transparent learning chain built first: blocks linked by hashes, proof of work, a difficulty that adjusts, a halving reward schedule, a most-work fork rule, a mempool, a peer network, and a chain file on disk that a node re-validates from genesis every time it starts. What changed is the ledger inside the blocks.

## 2.2 The ledger: outputs, not accounts

The learning chain kept balances: address X has 50 coins, readable by anyone. Vesper keeps no balances. Its state is the set of all outputs ever created plus the set of spent markers ever seen. An output is a one-time key, a sealed commitment to an amount, an encrypted note only the right view key can open, and a range proof. Nothing is ever deleted. A node knows an output exists and whether a given marker has appeared; it never knows which marker belongs to which output, who owns anything, or what anything is worth. Nothing on the chain ever contains an address.

## 2.3 Phase 1: hidden receivers

Your wallet has two private numbers, a view scalar a and a spend scalar b, and hands out as many addresses as you like. Address number i is two public keys: D_i = b times G + m_i times G, where m_i comes from a and i (m_0 = 0, so your first address has the same shape as every other), and C_i = a times D_i. The addresses share no key; nobody, not even several payers comparing notes, can tell two of them belong to one wallet. When Alice pays you she draws a random anchor, derives a secret r from it and your address, publishes R = r times D_i with the output and seals the anchor inside it, and sends the coins to a one-time key P = H(r times C_i) times G + D_i. To everyone else P is a random key. You recognise it because a times R = r times C_i, so P minus H(a times R) times G is one of your D_i: one multiplication per output however many addresses you have, and a one-byte view tag lets the wallet skip almost every output that is not yours after a single hash. Your wallet also re-derives R from the sealed anchor and refuses an output built from one of your addresses that lands on another (the "Janus" trick, which Monero's subaddresses still allow). To spend you need x = H(a times R) + b + m_i, which needs the private spend key too. Two payments to you land at two unrelated keys; your change is just another one-time output to yourself. Give each person who pays you their own address (`python coin.py wallet new-address --label NAME`). A view key, a plus B, finds and reads your incoming payments on every address and can never spend. Give it to an accountant, a court, an exchange, nobody else. Addresses are 98 characters and start `vesp2`; a wallet is rebuilt anywhere from its 55-character recovery code.

## 2.4 Phase 2: hidden amounts

Each amount v is replaced by a commitment C = v times H + k times G, with a blinding scalar k recoverable by the receiver. Commitments add, so a node checks that inputs equal outputs plus fee without seeing a number, via a Schnorr signature over the leftover blinding. One Bulletproofs range proof per payment covers all its outputs (736 bytes for the usual two, instead of 672 each) and proves no hidden value is negative, so nobody can create coins with a negative output; all the proofs in a block are checked as one equation. Every payment has at least two outputs, shuffled, with a zero-value change output added when needed, and lists its inputs in key-image order, so the shape of a payment reveals nothing. Mining rewards are the one public amount, because issuance must be checkable.

## 2.5 Phase 3, stage one: hidden senders

A payment's input no longer names the output it spends. It lists a ring of exactly 48 existing outputs in sorted order and carries one CLSAG-style ring signature proving the signer owns one of them. A key image, a one-way marker derived from the real output's private key, is published; nodes keep the set of key images, so a second spend of the same output produces the same marker and is refused, with nobody learning which output it was. A pseudo-output commitment keeps the amount arithmetic working inside the ring. Decoys are drawn as ages from the spending pattern Monero's wallets use (fitted to real spends) and placed in the line of outputs with the chain's recent pace; an attacker who knows the rule names the real coin 2.1% of the time at the ring of 48, where 2.1% is fair (3.0% at 32, 6.2% at 16), assuming Vesper's users spend like Monero's. The known weakness, stated everywhere: a crowd of 48 is three times Monero's crowd and still not everyone. You chose 48 on 19 October 2026 (64 ms per payment and 9.5 kB, against 45 ms and 5.1 kB at 16 and 54 ms and 7.3 kB at 32); 64 was measured too (82 ms, 11.7 kB, 1.8%) and judged not worth the extra cost until stage two's shape is known. The ring size is hashed into the genesis block. A coin, reward or payment, can be spent or used as a decoy only once it is 10 blocks old (Monero waits 20), so a fresh chain needs 48 such coins, about 58 blocks or fifteen to thirty minutes, before its first payment. Wallets fetch a ring's 48 members together, their own coin among them, so an honest node cannot tell which is real; a dishonest node could feed chosen decoys, which is why real privacy means running your own node.

## 2.6 Phase 3, stage two: hiding among everyone

The research target: replace the ring with a zero-knowledge proof that "I own some unspent output in the set of all outputs," so the anonymity set is the whole chain and decoy statistics cease to exist. Candidate designs are curve-tree membership proofs (Monero's direction; no trusted setup; heavy to implement) or a Merkle tree of outputs with a SNARK (Groth16 needs a per-circuit setup, PLONK-family needs a universal one; either changes the output format). No proof system is chosen, no size or date is promised. It is desirable before genesis but not a gate.

## 2.7 Phase 4: network privacy

Built and measured. A wallet's payment travels along a stem, one node to one other node, before any node broadcasts it (Dandelion++, Monero's design since 2020): 10-minute epochs, two relays per node, own payments always stemmed and only to peers the node chose itself, timers of 30 s plus a random wait for relays and 60 s plus for the sender, every hand-off answered at once and alike, duplicates dropped silently, circles ended by timer. `python leaktest.py` runs the node's own routing code in a 200-node simulation: an attacker with 5, 10, 20 or 30% of the nodes names the sender's node 7, 11, 23 or 32% of the time, against 15, 25, 39 or 51% with plain broadcast. That is what Dandelion++ promises and no better. A trace-back leak in the first build (a "loop" answer that revealed which nodes held a payment) was found and closed the same day, before any network ran it. Nothing between nodes is encrypted; `python node.py --proxy socks5h://127.0.0.1:9050` sends every connection through Tor, name lookups included, and a hidden node stops announcing its address. The node also has per-address rate limits, a one-hour ban for rule-breakers, at most 64 connections and 8 per address, a 20-second timeout, caps on request bodies (8 MB), peer answers (16 MB) and blocks (4,000,000 bytes, a consensus rule), and a peer table that treats gossip as candidates to check. All of it tested in simulation and on one PC; the public testnet is the test against strangers.

## 2.8 View keys and attestation

Wallets read only new blocks and keep an encrypted notebook beside the wallet file (re-reading the newest 20 blocks each time in case of a reorganisation); a re-check when nothing is new takes about 15 ms. A view key sees incoming payments and their amounts. For one payment there is the payment proof: `proof pay TXID` (payer) or `proof receive TXID` (receiver, from the view key) writes a small file proving that one output paid one address an amount and nothing else, and `proof check FILE` verifies it against your own node. A view-key file exported by the wallet also carries the key images of the outputs it held at export time, so the holder can see when those are spent; outputs that arrive later show as "spent status unknown" until a fresh export. There is deliberately no on-chain flag for "this payment is auditable," because any optional marker would make unmarked payments a smaller crowd. Attestations are handed over off-chain, privately. This is the compliance story Monero lacks and the argument for exchanges later.

## 2.9 The development fund

For the first 4,204,800 blocks, four years at a 30-second block, each block reward splits 90% to the miner at a private one-time key and 10% to the fund at a one-time key whose derivation secret is published in the block. Anyone can recompute that key from the published secret and the fund's address, verify the amount, and total the fund's income across the chain. Fees go to miners in full. The fund is a glass box in both directions: its outputs are never ring members, and it spends by naming them openly, so its spending is public too; only what it pays out to is sealed. From block 4,204,801 the share is zero forever. The fund address goes into the config before genesis with `python coin.py devfund init`; in your config it is still off.

## 2.10 Mining and consensus

Proof of work is Argon2id over the block header, 32 MiB of memory and one pass per attempt, about 90 tries per second per laptop core. Bitcoin's chips compute SHA-256 roughly a hundred million times faster than a laptop and cannot run Argon2id at all, which is what stops a small chain being overrun by rented hashrate. It is hostile to those chips, not to graphics cards, which keep an edge; it is an interim choice, with RandomX the likely production algorithm. Difficulty adjusts every block (the step form of ASERT, 10-minute half-life, never more than double or a quarter per block): in simulation honest miners keep 90 to 99% of fair pay against hit-and-run mining, and recovery from losing 99% of miners takes 106 minutes instead of 279. If 90% of miners vanish at once, blocks are slow for about 40 minutes, then normal. A block's ID is a plain hash of its header; the proof of work is a separate value checked with one Argon2id evaluation, about 11 ms. The miner runs on worker processes, half your cores by default (300 to 420 tries a second on eight), and every find is re-checked. A block holds at most 200 payments and 4,000,000 bytes. Every consensus setting, reward, halving, ring size, proof of work, fund address, is hashed into the genesis block, so a node with different rules rejects the chain at block 0.

# 3. What the chain shows and hides

| An observer wants to learn | Today (phases 1 to 4) | After stage two |
|---|---|---|
| Who received a payment | hidden | hidden |
| The amount | hidden | hidden |
| Which output was spent | one of 48 | hidden among all |
| Who sent it | one of 48 | hidden among all |
| Which computer first broadcast it | a relay's, not the sender's; an attacker with x% of nodes guesses right about x% of the time; Tor hides each node's address | the same |
| Fee, counts, transaction size, which block | public | public |
| Mining reward amounts, fund income and spending | public by design | public by design |

Adversaries the design considers: a passive observer with the whole chain; a network observer running many peers; the counterparty you paid (knows they were paid, the amount, the one-time key; nothing else); a malicious miner (can delay or censor, cannot create coins, alter amounts, or redirect the fund); anyone holding your view key (sees all your incoming payments forever, cannot spend). Out of scope: timing correlation with your own behaviour, anything you reveal yourself, a compromised device, and quantum computers, which would not break the hiding of amounts but would break soundness and link past one-time keys to addresses.

# 4. The numbers

| Operation | Cost on your PC | Note |
|---|---|---|
| Build a payment | about half a second at a ring of 48 while the PC also mines (204 ms at 16, idle) | sender, once; includes the range proof and ring signature |
| Node accepts a payment | 64 ms at the ring of 48 (45 at 16, 54 at 32) | every node, once |
| Validate a block of 20 payments, fresh node | 33 ms per payment (15.1 at 16, 23 at 32) | range proofs batched, ring signatures not |
| Ring signature | 26 ms to sign, 26 ms to verify at a ring of 48 (18 and 17 at 32; 9 and 10 at 16) | per input; grows with the ring |
| Scan one output with a view key | 0.11 ms someone else's, 0.7 ms your own | wallet, per new output only |
| Wallet re-check when nothing is new | about 15 ms | wallet, each time it opens |
| Restart a node on blocks it already checked | 0.035 ms per block | about 40 s for a year of 30-second blocks |
| Switch branches on a 200,000-output ledger | 1.5 ms | every node, on a reorganisation |
| Check a block's proof of work | 11 ms | one Argon2id evaluation |
| Mining rate | about 90 tries per second per core; 300 to 420 on eight | Argon2id, 32 MiB; worker processes |
| Memory | newest 1,000 blocks whole; about 0.65 kB per output for the ledger | older blocks read back from disk |
| One payment on disk | about 4 kB binary, 9.5 kB as JSON (3.1 and 7.3 at 32; 2.2 and 5.1 at 16) | 1,600 bytes ring signature, one 736-byte range proof |
| Cost per layer on a node | 4 ms, then 8.4, then 18.6, then 15.1, then 23, then 33 | receivers, amounts, senders (ring 16), one joint proof per payment, ring of 32, ring of 48 |

With the demo settings (30-second blocks, 200 payments per block) the chain moves about seven payments a second, Bitcoin's range. The real limit is the Python node, not the math, which is why the hardened node comes before genesis.

# 5. Running it

## 5.1 First run

1. `selftest.bat`: 44 checks, all should pass.
2. `wallet.bat`: creates your wallet, two secret numbers behind one password, and shows your `tvsp2...` testnet-1 address and a 55-character recovery code. Write the code on paper: it is the wallet (`python coin.py wallet restore` rebuilds it on any computer), and anyone who sees it can spend. The file is `data\wallets\default.json`. There is no password reset.
3. `start_node.bat`: node, explorer and miner at http://127.0.0.1:8880, mining to your wallet on half your cores. It joins testnet-1 through the seed node listed in `config.json` once that address is in; until then it runs a chain of its own.
4. `explorer.bat`: watch blocks arrive. Payments show as sealed amounts to one-time keys. There is no address search because the chain has no addresses.
5. `wallet.bat` again: your balance, found by reading the blocks it has not seen yet and opening the outputs that are yours.
6. `testdrive.bat`: the whole test drive by itself on two throwaway nodes, a payment each way, a search of the raw chain, five break-it attempts, about five minutes; nothing of yours is touched.

## 5.2 Commands

- `python coin.py send tvspTHEIRADDRESS 12.5` pays someone; the output ends by saying whether your node passed it quietly to one peer (the stem) or had to broadcast it itself.
- `python coin.py wallet new-address --label carol` makes one more address for one payer; `wallet addresses` lists them.
- `python coin.py wallet export-view` writes a view-key file; `python coin.py watch FILE` shows what its holder sees.
- `python coin.py proof pay TXID` proves one payment to one person; `proof receive TXID` does it from the view key; `proof check FILE` verifies.
- `python coin.py wallet restore --name again` rebuilds a wallet from its recovery code.
- `python node.py --proxy socks5h://127.0.0.1:9050` reaches every peer through Tor; the same flag on `coin.py` hides your wallet's address from the node it talks to.
- `python leaktest.py` measures the network and ring leaks with the node's own code.
- `python coin.py devfund init` creates the fund wallet and writes its address into the config (one time, before any real genesis); `devfund show` prints the public ledger.
- `python coin.py reset-chain` starts a fresh chain and keeps your wallets. Never delete the data folder; wallets live there.
- `python coin.py validate` re-checks every block, signature, proof and marker from genesis.
- `python demo.py` walks through one private payment step by step with timings.
- `start_node2.bat` runs a second node on port 8881 that downloads and follows the first; for Bob, create a wallet with `--data-dir data2` and add `--node http://127.0.0.1:8881 --data-dir data2` to his commands.

## 5.3 The two-person test, as recorded

Recorded on node v0.9.0 at testnet-1 settings on 19 October 2026 by `python testdrive.py`, which runs the whole test on two throwaway nodes with a throwaway network of their own. Alice mined 57 blocks (48 coins old enough after 499 seconds of fast test mining) and paid Bob 12.5 tVESP; her node handed the payment quietly to one peer instead of broadcasting it; Bob read it on his own node among 61 outputs in 0.0 seconds; his accountant's view key saw the same payment and could not spend; a search of the raw chain file for both addresses and the amount found nothing; the transaction on chain showed a ring of 48, a key image, a 48-response signature, two sealed outputs and one 736-byte range proof, 9,479 bytes of JSON; Bob paid 3 back from his node once his coin was 10 blocks old, and his node passed it to one peer rather than broadcasting; his wallet then showed 9.49999 tVESP; node 2 re-validated all 70 blocks offline in 2.0 seconds; an overspend, a replayed transaction, a mistyped address and a view-key file trying to spend were all refused with plain-English reasons, and a doctored chain file was named by block and repaired from the other node. The script ends "14 of 14 checks behaved as the test drive page says." The full transcript with commands is on the test-drive page.

# 6. The launch plan

## 6.1 The rules, enforced by code

1. Zero coins before block 1. The genesis block is computed from the published rules and contains no outputs. No founder allocation, no treasury, no presale, ever.
2. Anyone mines from block 1 with the same software everyone downloads.
3. 10% of each block reward to the development fund for 4,204,800 blocks, then 0% forever. Fees never included.
4. Every fund payment is auditable, and the fund's own spending is public on chain.
5. The fund can only receive. It cannot mint, freeze, or change rules.

## 6.2 Why no presale

A privacy-coin community treats any pre-launch allocation as a sign the coin exists to enrich insiders, and it is usually right. Selling a privacy coin to the public is also the most heavily scrutinised form of token sale under securities law. A mined launch with a visible fund avoids both and is how every privacy coin people trust was born. A premine or a secret mining head start (an instamine) is detectable from timestamps and difficulty and would end the project.

## 6.3 Economics still to decide, with recommendations

| Parameter | Demo today | Recommendation for mainnet | Why |
|---|---|---|---|
| Block time | 30 s | 60 to 120 s | fewer accidental forks, still fast confirmation |
| Emission | 50 per block, halving every 2,000 blocks | DECIDED: a smooth curve (each block pays 1/4,194,304 of an 18 M main curve not yet issued, 4.29 per 30 s block at first), then a tail from about year 13 of 0.15 per 30 s block, down 0.01 every 6 years to 0.01 at about year 97, then 0.01 forever | miners are always paid, so the chain is always defended; no reward cliffs |
| Supply cap | about 200,000 | DECIDED: no hard cap, but nearly fixed: about 21.4 M at year 43, 24.9 M at year 100 | inflation about 1% at year 13, 0.54% at year 43, about 0.04% from year 98, without a cliff |
| Decimals | 8 | 8 or 12 | readability of everyday amounts; decide with the curve |
| Difficulty algorithm | per-block ASERT-style step (done) | keep; retune the half-life with the mainnet block time | small chains get wrecked by hash-and-run miners otherwise |
| Block size | at most 200 payments and 4,000,000 bytes | flexible with a penalty for sudden growth (Monero style) | privacy payments are large; fee auctions hurt; the byte cap keeps every block relayable |
| Spend lock | 10 blocks for rewards and payments (done) | keep one lock; consider a longer one for rewards before mainnet | reorganisations cannot invalidate payments made with fresh coins; one number keeps ring lookups simple |
| Ring size | 48 (decided 19 October 2026, three times Monero's) | keep 48 unless stage two replaces the ring | hashed into block 0; 16 / 32 / 48 / 64 measured at 45 / 54 / 64 / 82 ms per payment, 5.1 / 7.3 / 9.5 / 11.7 kB, and 6.2 / 3.0 / 2.1 / 1.8% for an informed attacker |
| Proof of work | Argon2id 32 MiB | RandomX likely | closes the GPU gap; needs a C library |
| Development fund | 10% for 4,204,800 blocks | as decided | capped, public, ends |
| Burning | none | none | not provable on a private chain without glass-box outputs, and it starves miners |

These go in the code, so they are agreed with the code session and published with the genesis block, never before.

## 6.4 Gates before genesis, in order

1. Testnet-1 (decided 18 October 2026, launching with the publication; ring 48 from 19 October, phase 4 and its leak test shipped 15 October) with a standing bounty for anyone who can trace a payment.
2. The seed node on a rented server, so the network has a first peer that never points at your home.
3. An independent cryptographic audit of the protocol and the implementation.
4. The hardened production node, built from the Python reference once the protocol is frozen.
5. A legal entity to hold the fund and sign contracts, and legal advice on the launch.
6. Then a genesis date, announced in advance, with seed-node addresses published. The launch procedure: the genesis message carries something nobody could know earlier (the newest Bitcoin block ID at that moment), the genesis timestamp is the launch moment, and the starting difficulty comes from the testnet's measured mining rate, so no miner can start early.

No date is published because none of these has a fixed duration, and a date without them is a promise the code cannot keep.

# 7. Timeline, with the uncertainty stated

| Milestone | Realistic range | What decides it |
|---|---|---|
| Phase 4 and first node hardening | done, 15 October 2026 | leak measured and published; the open internet is still untested |
| Code public on GitHub | done, 18 October 2026 | the dated public record |
| Stage two research decision | months; may not be ready for genesis | whether a proof system fits the speed budget |
| Testnet-1 | launching with the publication, 19 October 2026 | the seed node on a rented server (your step), then node runners and the bounty pool |
| Audit | 2 to 4 months once funded and scheduled | funding (see chapter 9), firm availability |
| Hardened node | months, in parallel with the audit | a developer or two, paid from somewhere |
| Legal entity and advice | weeks to set up, once started | you, a lawyer, a few thousand dollars |
| Mainnet genesis | not before the second half of 2027 at the earliest | all of the above |

If you need a number in your own head, July 2027 is the earliest I would call honest. March and May are not reachable with an audit in the path, and launching without the audit is launching a privacy coin on hope.

# 8. Your to-do list

## 8.1 Must do

1. Learn the six lessons on the test-drive page until you can answer each question out loud. You will be the one defending this to strangers.
2. Decide the genesis economics with the code session (chapter 6.3). Do not publish numbers before they are in the code.
3. Form the legal entity and get legal advice on the launch, the fund and the trademark. Budget $5,000 to $15,000 and start it before the testnet, because signing contracts, including with an auditor, needs a signer.
4. Fund the audit: $30,000 to $100,000 depending on scope. Your own money, a public donation drive for exactly this (the Monero way, every payment public), or a narrowly scoped first audit of the privacy math with a fuller one paid by the fund after launch.
5. Run `devfund init` before any real genesis so the fund address is in the rules; keep that wallet and your own wallet backed up offline, encrypted, in two places.
6. Keep the GitHub repository public and current under the Vesper organisation; the commit history is what lets anyone outside trust the code, and it is the proof of who was first.
7. Rent the seed server (a small Ubuntu machine, paid in a way that does not point at you), run `deploy/setup-seed.sh` on it as `deploy/README.md` describes, and send back its address so it goes into `config.json` and onto the Join page.
8. Mine from block 1 with every machine you can, and disclose it. A line on the launch page that says the founder mines and roughly what share he holds turns the biggest suspicion about new coins into a non-story.
9. Keep every public sentence about what Vesper does for someone's privacy, never about what it will be worth.

## 8.2 Should do

- Trademark search and registration for Vesper and VESP; Vesper Finance already exists in DeFi, so a lawyer should look.
- Open one community room (Matrix or a forum rather than Discord, for this crowd) before the testnet, even if it is twelve people.
- Keep a weekly dev log on the site: what shipped, what broke, what is next, with numbers.
- Recruit friends and family as testnet node runners, and tell them plainly the coins are worthless and the project may never launch.
- Plan the trace-me bounty: prize pool, rules, how to claim, published the day the testnet opens.
- Post the whitepaper where privacy people already are, as "here is our design, break it," never as "check out our coin."
- Prepare the founding-node roll: a public list of everyone who ran a node through the testnet.

## 8.3 Could do, later

- A "Breaking Vesper" page that lists every known leak and the phase that closes it, updated with every release.
- Talks at security and privacy meetups once the testnet is live.
- Outreach to wallet makers and swap services before genesis so integrations land early.
- Mining pool support and documentation for the first month after genesis.
- An attestation standard written up for exchanges and accountants: exactly what a view key or per-payment proof shows and how to verify it.

## 8.4 Must not do

- Sell coins, promise coins, or take money for coins, in any form, before or after genesis.
- Mine before the public genesis or hold back any allocation.
- Pay anyone, in cash or coins, for bringing in buyers, or run spend-tier bonuses; the chain cannot even see amounts, and the shape is a pyramid.
- Use the fund or your own coins to hold a price, buy your own coins to fake volume, or coordinate buying with friends.
- Say "untraceable," "ASIC-proof," "CPU-only," "guaranteed," or anything about future price.
- Delete the data folder as a "reset"; wallets live there. Use `reset-chain`.
- Run a public seed node from your home connection, ever: a server paid for in a way that does not point at you, or Tor, so the project's nodes never lead to your door. Expose a node to the internet only on the testnet, where that is the point.

# 9. Money: what it costs and what the fund pays for

## 9.1 Before genesis, the fund is worth nothing

The fund earns VESP from block 1, and VESP has no price until a market exists months later. So pre-genesis costs are paid with real money from elsewhere: the entity, the audit, a domain and hosting (tens of dollars a month), seed servers at genesis (a few dollars a month each). Your 20 computers mining cost roughly 2 to 3 kilowatts, about $8 to $10 a day in electricity at typical rates, once genesis happens; do not buy hardware before the proof-of-work algorithm is final.

## 9.2 After genesis, in priority order

1. Security: the audit if not yet done, a second after major upgrades, a standing bounty pool.
2. Core development: the hardened node, phase 4 follow-ups, stage two research, possibly as a grant to an academic group; developer pay, yours included, in the public log.
3. Wallets: desktop first, then mobile, then hardware-wallet support. Likely the biggest line after the node.
4. Infrastructure: seed nodes, explorer, website, testnet.
5. Ecosystem: atomic swaps, swap-service integrations, mining pools, merchant tools; exchange listing fees only when earned.
6. Legal and compliance: the entity, counsel, trademark.
7. Community: grants paid on delivery, documentation, translations, conference presence.

A first-year shape if the fund becomes worth real money: about a quarter on security, a third on the node and protocol, a fifth on wallets, the rest across the remaining lines, every payment logged publicly.

## 9.3 Never

Paid influencers, advertising, airdrops to farm users, price support, listings on exchanges nobody has heard of, or any spend that moves a number instead of building a tool.

# 10. Marketing is the community

You are not selling anything, so the only thing you can offer anyone is a place in the project, and that is the only kind of growth privacy coins have ever had. The community forms in this order: readers and reviewers who open the code; node runners and miners; builders who deliver against the fund's grants; users who need private payments, who arrive last and are the only ones who make it money.

What you do: publish the code, keep the heartbeat (the dev log), open the room, run the contest, show up where privacy people already talk as a participant, and be honest everywhere. What to expect: a few dozen demanding people at first. Monero started with a dozen on a forum. That is the stage that makes the project strong enough for the crowd later.

# 11. Trading, exchanges and what "bridge" means for Vesper

There is no bridge from Ethereum to Vesper and should not be one. Vesper has no premined pile to hand out, so VESP only comes from mining, being paid, or buying from someone who was. The trading ladder, in the order it can happen: mining on day one; person-to-person atomic swaps (the first post-launch deliverable); swap services that hold reserves (months after genesis, once there is circulating supply); mid-size exchanges after a track record and a legal entity; the largest exchanges only if the view-key compliance argument wins, which is a years-long conversation since most of them have delisted privacy coins. A wrapped VESP on another chain is possible, transparent, a hack target, and not planned.

On your "Coinbase to MetaMask to VESP" path: Coinbase knows your identity and the address you withdrew to; the Ethereum address is public forever; whoever swaps your ETH for VESP knows that pairing; from the Vesper output onward the trail goes cold at today's privacy level except for the ring's statistics; a payment to your own second wallet is indistinguishable from any other payment; and the exits, any exchange you show ID to, re-identify you. Private from the public and from chain analysis; not from an exchange you identified yourself to.

# 12. Risks, stated plainly

- Rings of 16 have known statistical weaknesses. Stage two fixes it; until then the honest claim is Monero-level.
- The Python node is a reference. Its limits, bans and peer table have never faced the open internet; the testnet is that test, and a production rewrite follows.
- Graphics cards beat CPUs on the current proof of work; RandomX is the likely fix.
- In the first weeks one party, possibly you, may hold more than half the mining power. The chain is then only as honest as that party. Disclose it and recruit miners to get below half fast.
- Major exchanges have delisted privacy coins; the compliance argument is the view key, and it will take years.
- Regulation is moving and differs by country; the lines that keep you safe are no sale, no price talk, and disclosure.
- Homemade cryptography fails silently. The audit is not optional. The second review pass re-read the cryptography line by line and found nothing new, which is not an audit.
- A dishonest remote node can feed your wallet chosen decoys. Run your own node for real privacy, as Monero users do.
- Key loss is permanent. Back up every wallet, encrypted, in two places.
- The coin may be worth nothing, ever. Everyone you recruit must hear that from you first.

# 13. The team and how it works

You own the project, the decisions, the entity, the mining, and the public face. One Claude session owns the code: phases, consensus, tests, the memory of design decisions in `DECISIONS.md`. The other owns everything public: the six pages, the whitepaper, this document, the GitHub publication, and the site in `vesper\site`. They coordinate by message; the code session reports what is true after each change and the page session rewrites to match the same day. Neither edits the other's files. When they disagree, the code wins on facts and the pages win on wording, and you win on everything else.

# 14. Glossary, Vesper edition

| Term | In Vesper |
|---|---|
| Address | `tvsp2...` on testnet-1 (a real network would have its own prefix): two public keys with a checksum, 98 characters; one wallet has as many as it likes, none linkable. Never appears on the chain. |
| tVESP | Testnet-1's coin. Test money with no value, ever. |
| Recovery code | 55 characters shown once when a wallet is made; rebuilds the wallet, with all its addresses, on any computer. |
| View tag | One byte per output that lets a wallet skip outputs that are not its own after a single hash. |
| Stem | The quiet node-to-node path a payment takes before any node broadcasts it (phase 4). |
| Payment proof | A small file proving one output paid one address an amount, made by payer or receiver, checked against any node. |
| View key | Private view scalar plus public spend key. Finds and reads your incoming payments; cannot spend. Exported files carry key images of outputs held at export. |
| Spend key | The private number that, with the view key, derives the one-time key that spends an output. |
| One-time key | The key a payment is locked to; fresh for every output; recognisable only by the receiver. |
| Commitment | The sealed amount. Adds up so nodes can check balance without reading it. |
| Range proof | One 736-byte proof per payment that none of its sealed amounts is negative. Batch-verified per block. |
| Ring | The 48 outputs an input could be spending; sorted; the real one is among them. |
| Key image | The one-way spent marker of the real output. Repeated means double spend. |
| Pseudo-output | A commitment that lets the amount arithmetic work inside a ring. |
| Development fund | 10% of each reward for 4,204,800 blocks, auditable, glass-box spending. |
| Auditable output | A fund output whose derivation secret is published so anyone can verify it. |
| Argon2id | The memory-hard proof-of-work function; 32 MiB per try; interim. |
| Genesis | Block 0, computed from the published rules, containing no coins. |
| reset-chain | Starts a fresh chain and keeps wallets. The data folder is never deleted. |
| Spend lock | A coin can be spent or used as a decoy only once it is 10 blocks old. |
| Scan notebook | The encrypted `<wallet>.scan` file where a wallet keeps what it found in blocks it already read. |

# Appendix: links and files

- Main page: https://claude.ai/artifact/2bLkKHnReatDcQB336cz3W
- Launch plan: https://claude.ai/artifact/TsgQmS5JGhauoe7v8PDSfg
- Whitepaper and threat model: https://claude.ai/artifact/TTjb7MkdhuuJq1EHc64eAc
- Test drive: https://claude.ai/artifact/FeXRWSy8uixzQYRAh2xifF
- Join Vesper and Breaking Vesper: linked from the main page.
- Code: public on GitHub under the Vesper organisation (the link is on the Join page); locally `~/projects/vesper` (curve.py, privacy.py, amounts.py, rangeproof.py, ringsig.py, chain.py, wallet.py, node.py, relay.py, proofs.py, socksproxy.py, powcore.py, powpool.py, leaktest.py, launch_genesis.py, coin.py, selftest.py, testdrive.py, demo.py, README.md, DECISIONS.md, and `deploy/` for the seed node)
- Site and documents: `~/projects/vesper\site` and `~/projects/vesper\docs`, also served from the repository by GitHub Pages.

The six pages are also published from the repository, so the GitHub Pages copies are the public ones.
