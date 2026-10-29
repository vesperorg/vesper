# Vesper: how it works, measured

The technical companion to the [README](README.md): what each part does, what it costs, and what
still leaks, with the numbers measured on this code. Every design choice and its reason is in
[DECISIONS.md](DECISIONS.md).

## The three hidden things

Vesper is a cryptocurrency whose public ledger records a payment without recording who paid, who
was paid, or how much. It does this with three pieces, each of which you can read in the code:

- **Who was paid is hidden.** A payment is not sent to your address. The sender uses your address
  to compute a fresh one-time lock that only your wallet can recognise and only your spend key can
  open. Your address itself never appears on the chain, and two payments to you look unrelated.
- **How much is hidden.** Each amount is sealed inside a *commitment*: a value the chain can add up
  (so it can check that what went in equals what came out, plus the fee) but cannot read. A short
  proof attached to each payment shows no sealed amount is negative, so nobody can print coins.
- **Which coin was spent is hidden.** A payment does not name the coin it spends. It points at 48
  possible coins (its own plus 47 decoys) and carries a *ring signature*, a proof that the sender
  owns one of the 48 without saying which, plus a one-way *spent marker* that lets every node
  refuse a second spend of the same coin without ever learning which coin it was.


**Not audited. Do not put real value on it yet.** Privacy cryptography written by a small team is
exactly where real coins have leaked user data and lost money, sometimes years after launch, because
privacy failures are silent: the chain keeps working while it leaks. Before any real use this needs
a public test network (this one), the stronger sender proof described below, a review by an
independent cryptographer, and legal advice.

**How private is it today, honestly:** it is Monero's design with three times Monero's ring. A sender
hides among 48 coins, not among everyone on the chain, so a statistician with the whole chain still
has a 1-in-48 shaped problem, not an impossible one. On the network, your payment is first handed
quietly from node to node before any node announces it to everyone, so the node that announces it
first is not yours; but an attacker who runs, say, a tenth of all nodes still guesses the right
origin about a tenth of the time (`python leaktest.py` measures this), and the traffic between nodes
is not encrypted. If your internet address matters to you, run your node with `--proxy` through Tor
(built in, see below) or a VPN. Give each person who pays you their own address
(`coin.py wallet new-address`): the addresses share nothing, so payers who compare notes learn
nothing.

## Where it is

| Phase | Hides | Status |
|---|---|---|
| 1. Stealth addresses + view keys | **who received** | done |
| 2. Sealed amounts + range proofs | **how much** | done |
| 3a. Key images + ring signatures (ring of 48) | **which output was spent**, among 48 | done |
| 3b. Membership proof over ALL outputs | the same, among everyone | research: no design chosen |
| 4. Network privacy: a quiet relay before the broadcast (Dandelion++), limits per peer | **whose computer announced it** | done: measured, not perfect (see below) |

**Phase 4, measured.** A payment first travels quietly from node to single node (the "stem")
and only then gets broadcast. `python leaktest.py` runs the node's own routing code in a
simulated network of 200 nodes and lets an attacker who controls some of them name, for each
payment, the first node that handed it to one of the attacker's nodes:

| Attacker's share of nodes | Guess right, plain broadcast | Guess right, stem then broadcast |
|---|---|---|
| 5% | 15% | 7% |
| 10% | 25% | 11% |
| 20% | 39% | 23% |
| 30% | 51% | 32% |

That is what Dandelion++ promises: about the attacker's share of nodes, no better.

A node answers every stem hand-off at once and in the same words, before checking it, and quietly
drops a payment it already holds. Phase 4 first answered such a payment with "loop": a spy on the
stem could then have asked every node and traced the stem back, up to 38% of payments at 5% spies
and 78% at 20% (an upper bound, `leaktest.py` prints it). Found in review on the day it was built,
before any network ran it.

**The ring, measured.** The same script checks how often an attacker can name the real coin in a
ring of 16 (the size this table was measured at), when real coins are spent the way people actually spend (Moser et al. 2018, fitted to
real Monero spends) and the attacker knows both that and the decoy rule. Fair would be 6.2%:

| Chain | Decoys by rank (Vesper until 2026-10-15) | Decoys by age (now) |
|---|---|---|
| Young: 3 outputs a block, 1 week | 7.3% | 7.2% |
| Busy: 40 outputs a block, 1 month | 11.9% | 6.5% |
| Busy: 40 outputs a block, 1 year | 22.1% | 6.1% |

Decoys are now drawn as ages from that spending model, the way Monero's wallets draw them, and
placed in the line of outputs with the chain's recent pace. If people on Vesper turn out to spend
differently, the right column drifts, so real spending gets re-measured once a network exists. Doing better
needs encryption and mixing between nodes, which is outside this code. Each node also limits how
much any one internet address may ask of it, ignores for an hour an address that sends blocks or
payments that break the rules, and serves at most 64 requests at once, 8 from any one address,
closing connections that go silent for 20 seconds (this computer is never turned away). Addresses that peers pass
around are only candidates: a node checks a couple at a time, keeps its peers spread over
different networks, and passes payments on their stem only to peers it chose itself.

**Your own address.** The stem hides which node broadcast a payment first; it does not hide each
node's internet address from the peers it talks to. `python node.py --proxy socks5h://127.0.0.1:9050`
sends every connection to a peer through Tor (name lookups too, so not even a DNS question leaves
your computer), and the node stops telling peers its address. Keep `--host` at 127.0.0.1 to stay
hidden; your own wallet still reaches the node. Tor itself is not part of Vesper: install the Tor
Browser or the Tor service, which listens on 9150 or 9050.

**Use your own node.** A wallet trusts the node it talks to (`--node`). Someone else's node sees
when your wallet looks and what it sends, and could answer a ring lookup with outputs of its own
choosing, which would quietly shrink your crowd. `coin.py --proxy` hides your address from such
a node, not your activity. Monero's remote nodes carry the same warning.

Still visible, by design or until later: the fee (every wallet pays the same one), mining-reward
amounts, how many inputs and outputs a payment has, which block it landed in, and the 48
candidates for each spend. A payment no longer says when it was made, and its inputs come in
key-image order, not the order the wallet picked them. `selftest.py` has a test that lists
exactly this.

## Commands and the first wait

Needs Python 3.10+ and two packages: `pip install -r requirements.txt` (`cryptography`, `pynacl`).
Without `pynacl` everything still works on the built-in pure-Python curve, about 5x slower.

| Step | Double-click | What happens |
|---|---|---|
| 1 | `selftest.bat` | 46 checks. Tries to double-spend, forge ring signatures, print coins four different ways, rewrite history and cheat the development fund; and confirms no address, amount or spent output is readable on the chain. |
| 2 | `wallet.bat` | Creates your wallet (two secret keys, one password). Shows your `tvsp...` address and a 55-character RECOVERY CODE: write it on paper, it is the wallet. |
| 3 | `start_node.bat` | Node + explorer at http://127.0.0.1:8880, mining to your wallet. |
| 4 | `explorer.bat` | Watch blocks arrive. Payments show as "one of a ring of 48 -> sealed amount -> one-time key". |
| 5 | `wallet.bat` | Your balance: your wallet reads the blocks it has not seen yet, opens the outputs that are yours, and works out which of those it has spent. |
| Any time | `testdrive.bat` | The whole test drive by itself: two throwaway nodes, a payment each way, a search of the raw chain, five break-it attempts. About 5 minutes; nothing of yours is touched. |

Two waits, both short and both on purpose. A coin can be spent 10 blocks after it arrives (about
5 minutes; Monero's wait is 20). And a brand-new chain cannot hide a payment until 48 outputs are
that old, so the very first payment has to wait for about 58 blocks (roughly 15 to 30 minutes of
mining). The wallet says so if you try earlier.

```bash
python demo.py                               # one private payment explained step by step, with timings
python testdrive.py                          # the whole test drive on two throwaway nodes (~5 min), 14 checks
python testdrive.py --more                   # ... then one address per payer, the recovery code and a payment proof, live
python coin.py send tvspTHEIRADDRESS 12.5    # pay someone; about 0.25 s to seal, prove and ring-sign
python coin.py wallet new-address --label carol   # one more address for one payer; nobody can link it to the others
python coin.py wallet restore --name again   # rebuild a wallet from its recovery code, on any computer
python coin.py proof pay <txid>              # prove ONE payment to ONE person (a shop that says it never arrived)
python coin.py proof check <file>            # check such a proof against your own node
python coin.py wallet export-view            # a view-key file: sees your payments, amounts and (for today's coins) spends
python coin.py watch data/wallets/default.viewkey.json
python coin.py devfund show                  # the development fund (off unless you turned it on)
python coin.py reset-chain                   # start the chain over; removes saved blocks, never wallets
python node.py --proxy socks5h://127.0.0.1:9050   # reach every peer through Tor: peers never see your address
```

**Wallets live in `data/wallets`. Never delete the `data` folder to "reset"; use `reset-chain`.**

## How it works

**Who (phase 1, `privacy.py`).** A wallet has two secrets, a view scalar a and a spend scalar
b, and hands out as many addresses as you like. Address i is two public keys, D_i = b*G + m_i*G
(m_i comes from a and i; m_0 = 0) and C_i = a*D_i. A payer picks a random anchor, derives r from it
and the address, publishes R = r*D_i, and pays the one-time key P = H(r*C_i)*G + D_i. Only you can
recognise P, because a*R = r*C_i: your wallet computes P - H(a*R)*G and finds it among its D_i, at
the cost of one multiplication per output however many addresses it has. Spending needs b.

Give every person who pays you their own address (`python coin.py wallet new-address --label NAME`):
the addresses share no key and look exactly like the main one, so nobody can tell they belong
together, even several payers comparing notes. One byte per output, the view tag, lets a wallet
skip almost every output that is not its own after one hash. The anchor travels sealed in the
output, and the wallet checks R was made from it for that very address, which shuts out the
"Janus" trick: an output built from one of your addresses that lands on another, to learn they
are both yours if you ever confirm it arrived.

**How much (phase 2, `amounts.py`, `rangeproof.py`).** The amount is sealed as
C = amount*H + blinding*G. Envelopes add up unopened, so a node checks
`inputs - outputs - fee*H` and requires what is left to be a plain public key the sender can sign
with. A Bulletproof shows every envelope holds a number between 0 and 2^64, so nobody can balance
the books with a negative amount. One proof covers all of a payment's envelopes: 736 bytes for the
usual two, where a proof each would take 2 x 672.

**Which coin (phase 3, `ringsig.py`).** Every output has one spent marker, its key image
I = x*Hp(position, P), which only its owner can compute and nobody can link back to it. The
marker is tied to where the output sits on the chain, not just to its key, so two payments to
the same one-time key are two spendable coins. (In Monero they share one marker and one is lost,
the "burning bug"; Zcash fixed the same flaw, "Faerie Gold", the way Vesper does.) A payment lists a
ring of 48 outputs and carries a CLSAG ring signature proving three things at once: the signer
owns one of the 48, the key image is that one's marker, and the input is worth exactly what that
one is worth. Nodes remember every key image; seeing one twice is a double spend. Because nobody
can tell which outputs are spent, nothing is ever removed from the ledger.

**Mining (`chain.py`, `pow_digest`).** Proof of work is Argon2id with 32 MiB of memory per try,
not Bitcoin's SHA-256. Bitcoin's function is computed by purpose-built machines about a hundred
million times faster than a laptop, so a small coin using it can be overrun by anyone renting a
sliver of that hardware. A memory-hard function cannot run on those machines at all and is slow
on purpose everywhere, about 90 tries a second per laptop core, which puts ordinary computers back
in the game. Graphics cards still have an edge; a production coin would likely use RandomX, which
closes that gap too. Checking a block costs one try (about 11 ms), so a node remembers which blocks
it has already checked and redoes neither their work nor their signatures at every start
(`coin.py validate` redoes it all), and when it falls behind it fetches and checks only the new
blocks, however long the chain is.
A block's ID is a plain hash of its header and does not start with zeros; the work is a separate
number.

**Difficulty (`chain.py`, `step_difficulty`).** Each block's difficulty is the previous block's,
multiplied by 2^((30 s - how long that block took) / 600 s). Early blocks push it up, late ones
pull it down, and there is no window of old blocks to average, so nothing swings back later. It is
the step-by-step form of the ASERT rule Bitcoin Cash adopted in 2020, with a 10-minute half-life
and one limit: a single block can at most double the difficulty or cut it to a quarter. In a
simulation against the rule used before (average of the last 30 blocks), Zcash's and the common
small-coin rule, it kept the average block at 30.0 s, wandered a quarter less, paid honest miners
90 to 99% of their fair share against a hit-and-run miner (85 to 95% before), and recovered from
losing 99% of its miners in about 1.8 hours instead of 4.6. Losing nine miners in ten still means
one 5-minute block, then 3.7, 2.9, 2.5, and back under 45 s after about 40 minutes: no rule can
know miners left before the next block is late.

**Reorganisations.** When another branch wins, the node undoes its own newest blocks and checks
the winning ones. It does not replay the ledger and does not rewrite the chain file, so the cost
is the length of the two branches (1.5 ms to undo a block of 20 payments), not of the chain.

**What goes beyond a straight copy of Monero or Zcash, so far**

- Privacy is mandatory. There is no transparent transaction type, so the crowd is everyone (Zcash's optional privacy is its main weakness).
- View keys open amounts, and a view-key file can carry spent markers, so a private wallet can be audited on demand without being public.
- All range proofs in a block are verified as one combined equation, and a transaction's proofs and signatures are never checked twice (once on arrival, then cached by txid).
- Every point arriving from the network, key images included, must be in the prime-order group. Monero once had a real money-printing bug from skipping that check on key images.
- Spent markers are tied to an output's position, so the "burning bug" cannot happen and no "keys must be unique" rule is needed. Such a rule would let a stranger cancel a waiting payment by getting a copy of its key mined first.
- A wallet remembers the ring it first used for each coin and reuses it on a retry. Fresh decoys on a second attempt would leave the real coin as the only one in both rings. If a reorganisation took one decoy away, only that one is replaced.
- A wallet keeps an encrypted notebook of what it has found and reads only new blocks, and it fetches the 48 members of a ring by their place in line instead of downloading every output. It asks for whole blocks and whole rings, its own coin included, so the node it talks to cannot tell which outputs are its.
- Every output a payment touches, its own coin and all 47 decoys, must be 10 blocks old. A payment therefore survives any reorganisation shorter than that and simply returns to the queue. (Monero has the same rule; its blocks are four times slower, so the wait is 20 minutes instead of 5.)
- A payment carries no timestamp, and wallets pay exactly the minimum fee for the payment's size, so neither the clock nor the fee fingerprints a wallet.
- The fee grows with the number of inputs and outputs. Outputs stay on the ledger forever, so filling it up is never free.
- Difficulty moves a little with every block and has no averaging window (see above). Monero averages 720 blocks, a full day, and needs hours to follow miners leaving.
- Two different blocks can never share an ID. Bitcoin's transaction tree lets a block and a doctored twin hash the same (CVE-2012-2459); Vesper's tree does not, and a node only remembers a block under an ID it computed itself, after accepting it.
- The miner rebuilds the block it is searching for when a payment arrives, so a payment does not sit out a block that was started a second before it came in.
- Switching to a winning branch costs the two branches, not the chain, and a branch is checked block by block as it downloads, so a peer cannot make a node hold a long branch of rubbish.
- The node refuses anything a web page could make your browser send, so a site you visit cannot point your miner at someone else's wallet, and it does not reveal its owner's address to peers.
- Every payment has the same shape: rings of exactly 48, at least two outputs in random order, change included even when it is zero.
- All consensus settings are hashed into the genesis block, so two nodes with different rules can never mistake each other's chain for their own.

None of that beats Monero on the thing that matters most. The part meant to, hiding the sender
among the whole chain instead of 47 decoys, is stage 3b, and it is research.

## Development fund (off by default)

A fair launch has no premine and nothing for sale. To pay for development, a fixed share of each
block reward can go to one published address for a fixed number of blocks, enforced by every
node: 10% for 4,204,800 blocks by default (`consensus.dev_fund` in `config.json`).

- It is a glass box, the one public account on the chain. Each fund payment is a public amount with a revealed secret that lets anyone verify it went to the published address. Fund outputs never join rings and are spent by naming them, so the fund's spending is public too. What it pays out lands sealed, like any payment.
- Miners cannot skip it and the fund cannot take more; a block that gets it wrong is rejected.
- `python coin.py devfund init` creates the fund wallet and writes its address into `config.json`. That changes the genesis block, so do it before the chain starts and back up the wallet file.
- `python coin.py devfund show` and the explorer show received, unspent and spent totals.

## Mining together: a pool with no operator (built; runs on a network whose rules allow it)

With many miners, one ordinary computer wins a block rarely and at random: at 100 miners like
it, about once every 50 minutes on average, sometimes hours apart. Miners pool their work to be
paid steadily. An ordinary pool is a company: it builds every block, holds everyone's payouts and
learns every member's address, so a handful of pools end up choosing which payments get in and
are one subpoena from a list of miners. Vesper's pool is decentralized instead, after Monero's
P2Pool, and it is the only pool the Vesper software will support.

How it is meant to work:

1. **A share chain beside the main chain.** Pool members mine the same Vesper blocks, but a
   block also counts as a *share* when it meets a much lower target, one share about every 10 s
   across the pool. Shares form their own small chain, kept by the members' nodes; nobody runs it.
2. **Every candidate block pays the recent shares.** Each member builds its own block, and its
   coinbase pays the owners of the last N shares (a window of about N = 2,160, six hours at 10 s),
   in proportion to the work behind each share. Each member checks the others' shares follow
   that rule.
3. **When a share also meets the real difficulty, it is a real Vesper block.** Its coinbase
   already pays everyone in the window, straight to their own wallets. There is no pool balance,
   nothing held for anyone, and no operator who could stop paying or run off.
4. **No addresses on the share chain.** Monero's P2Pool publishes every member's wallet address
   on its share chain. A Vesper share carries a fresh one-time payout key instead, made by the
   member's own wallet for that share, so nobody can tell two shares came from the same member.
5. **Members choose their payments.** Every member builds its own block template, so no pool can
   leave payments out.

What it needs from the protocol (all of it changes the genesis block, so it is decided before
mainnet): a coinbase with many outputs (today at most 16; a pool coinbase needs hundreds, each a
one-time key with a public amount, like every mining reward today), a share format and its
difficulty rule, and rules for shares that collide (Monero P2Pool counts them as "uncles" at a
reduced weight so a slow connection is not punished).

What it cannot do: the protocol cannot forbid an ordinary pool. A pool operator only hands out
block templates, and on the chain the result looks like any block. Proofs of work that stop
outsourcing exist in research (the finder of a block could take the whole reward, so no operator
can trust its workers), but they would let a P2Pool member take the whole reward too, and they
would break P2Pool along with the ordinary pools. So "the only pool" means: built into the node,
the easiest way to mine together, and the only one Vesper's software, pages and community will
support.

Stage 1 is built (`pool.py`, a self-test check): the share chain and its difficulty, the split, the payout stubs, the check every member runs on every share, and a block a pool coinbase pays. Two details settled on the way. A stub is made at index 0, because nobody knows in advance where in a coinbase it will sit; a wallet that does not find a public-amount output at its own index tries index 0 (one hash more per mining reward). And `consensus.max_coinbase_outputs` is read only when a network's rules name it, so testnet-1 keeps 16 and its genesis is unchanged.

Stage 2 is built too: `python node.py --mine --pool` mines shares instead of whole blocks, hands each share to its peers (`POST /api/pool/share`), and when a peer lacks the shares one builds on, hands those over as well, so a member behind a home router or Tor takes part like any other. Each sync round fetches the peers' recent shares (`GET /api/pool/chain`); `/api/info` shows the pool. Measured on two nodes on a throwaway pool network, two cores each, for three minutes: 70 shares, 9 blocks, both nodes on the same share and block, and the two wallets paid 260.67 and 189.33 of the 450 mined, in step with their 40 and 30 shares. Not built yet: uncles (a share that loses a race earns nothing), keeping the share chain on disk (a restarted member fetches it from its peers), and a network that allows pool blocks: testnet-1's rules allow 16 reward outputs, so the pool needs a new test network.

Order of work: a test pool on the test network first, then the coinbase change, then measured
results (payout regularity, coinbase size, how much a pool block costs to check) before mainnet.

## Speed (this PC, libsodium backend, ring size 48)

| Operation | Time |
|---|---|
| One curve multiplication | 0.11 ms |
| One proof-of-work try (Argon2id, 32 MiB) | 11 ms, about 90 tries a second per core |
| Mining on 8 cores (worker processes, `--processes N`) | 300 to 420 tries a second on this PC; memory speed limits it beyond about 8 |
| Build a payment (seal and prove 2 amounts, ring-sign 1 input) | 204 ms, once, on the sender's PC |
| Node accepts a payment (every check) | 64 ms |
| Fresh node validates a block of 20 payments | 33 ms per payment |
| Mine a block of 20 payments already seen | 4 ms total |
| Re-check a waiting payment against a 200,000-output ledger | 0.03 ms (does not grow with the chain) |
| Restart a node (blocks it already checked) | 0.035 ms per block: about 40 s for a year of 30-second blocks |
| Memory for blocks | the newest 1,000 whole, about 100 bytes for each older one; older blocks are read back from the file when asked for |
| Memory for the ledger | about 0.65 kB per output: only what checking payments needs (was 1.2 kB) |
| Switch branches, undoing a block of 20 payments, same ledger | 1.5 ms (does not grow with the chain) |
| Wallet scans one output | 0.11 ms someone else's, 0.7 ms one of its own; once: the wallet remembers what it has read |
| Wallet looks again when nothing is new | about 15 ms (it rereads the newest 20 blocks, which could still be reorganised) |
| One payment on disk | about 9.5 kB of JSON (about 4 kB in binary; the ring signature alone is 1,600 bytes) |

What each phase cost on the node: phase 1 alone about 4 ms per payment in a block, sealed amounts
took it to 8.4 ms, hidden senders to 18.6 ms, and one joint range proof per payment brought it back
to 15.1 ms. A ring signature is about 9 ms to check per input and, unlike range proofs, cannot be
batched. The joint proof has one cost: a payment checked on its own takes about 13 ms longer (35 to 45
ms), because its proof spans 128 bit positions instead of 64, and this backend multiplies points one by
one. Each node checks a payment alone once; blocks, syncing and disk all get cheaper.

## Files

| File | Role |
|---|---|
| `curve.py` | Ed25519 twice: readable pure Python, and libsodium. Strict point checks, hash-to-point, Schnorr signatures. |
| `amounts.py` | Pedersen commitments and the encrypted amount note. |
| `rangeproof.py` | Bulletproofs: prove, verify, batch verify. |
| `ringsig.py` | Key images, CLSAG ring signatures, decoy selection. |
| `privacy.py` | Addresses (as many per wallet as you like), one-time keys, view tags, view keys, auditable (fund) outputs. |
| `chain.py` | The ledger: every output, every key image, validation, difficulty, mining, branch switching, dev fund rules, disk. |
| `wallet.py` | Encrypted wallet files, view-key export, incremental scanning with an encrypted notebook, spent detection. |
| `node.py` | HTTP API, explorer, peer sync, miner, the stem relay, limits per address. |
| `relay.py` | Phase 4: the stem-then-broadcast routing (Dandelion++), its timers, rate limits and bans. No networking of its own, so it can be tested and simulated. |
| `leaktest.py` | Measures the network leak: the node's routing code in a simulated network with an attacker. |
| `launch_genesis.py` | Gives a new network its genesis block at launch: names the newest Bitcoin block (two explorers must agree) and the launch moment. |
| `deploy/` | A seed node on a rented Linux server: guide, setup script, locked-down system service. |
| `proofs.py` | Payment proofs: the payer or the receiver shows one person that one output paid one address an amount, and nothing else. |
| `socksproxy.py` | Reaching peers through Tor or another SOCKS5 proxy, name lookups included, with nothing to install. |
| `powcore.py` | The proof-of-work function alone, so mining workers start fast. |
| `powpool.py` | Mining on several CPU cores with worker processes (Python threads cannot run the tries side by side). |
| `coin.py` | Command line. |
| `selftest.py` | 46 checks, including phase 4 relays between nodes, a speed report and an honest list of what still leaks. |
| `demo.py` | One private payment as a story. |
| `testdrive.py` | The public test drive, run for you: two throwaway nodes, a payment each way, the view key, a search of the raw chain, five break-it attempts. Deletes its folders afterwards. |
| `DECISIONS.md` | Why each choice was made. |
