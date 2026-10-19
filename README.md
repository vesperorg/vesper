# Vesper

[![self-test](https://github.com/vesperorg/vesper/actions/workflows/selftest.yml/badge.svg)](https://github.com/vesperorg/vesper/actions/workflows/selftest.yml) Code: https://github.com/vesperorg/vesper - Site: https://vesperorg.github.io/vesper/

**Vesper is a privacy cryptocurrency on its own new blockchain (not a token on someone else's),
built to outdo both Monero and Zcash.** It is money you can use without anyone watching what you
earn, what you spend or who you pay, and without having to explain where every coin came from as
if you were under investigation. Cash once gave people that freedom, but cash cannot reach someone
on the other side of the world. Vesper is built to be its modern, legitimate successor: privacy
that is never optional, for everyone, on every payment.

## How it works

Like Bitcoin, Vesper is money kept on a shared record by a network of ordinary computers instead
of a bank. Unlike Bitcoin, that record proves every payment is genuine without showing who paid,
who was paid, or how much:

1. **A fresh lock for every payment.** Your address is never written on the record. Each payment
   to you goes into a brand-new one-time lock that only your wallet recognises, so two payments
   to you look completely unrelated.
2. **Sealed amounts.** Every amount is sealed like an envelope that the network can add up but
   never open. It can still check that nobody spent more than they had, and a short proof stops
   anyone from printing money with a "negative" amount.
3. **A crowd of 32.** When you spend, your payment points at a **ring of 32** coins, yours and 31
   others, and proves you own one of them without saying which. A one-way "spent" stamp stops
   anyone from spending the same coin twice.
4. **A quiet hand-off.** Your computer does not announce your payment to everyone. It passes it
   quietly through a few other computers first, so the one that announces it is not yours. For
   more, Vesper can send all its traffic through Tor.

Your balance and your payments stay yours. A read-only **view key** lets you show them to whoever
you choose, such as an accountant, without giving anyone the power to spend.

**Where it stands today, honestly:** it is Monero's design with twice Monero's ring, so a payment
hides among 32 coins, not yet among everyone. It is **not audited**. It runs as a public test
network, **testnet-1**, whose coins, **tVESP** (addresses start `tvsp`), are test coins with
**no value, ever**: anyone can try it, try to break it, and help make it solid before it ever
carries real money.

## Why we are doing this

There is nothing to buy and nothing for sale, not yet even a coin worth anything, because Vesper
first has to be as secure and as private as it can possibly be. This is not a joke or a game to
us. We want real privacy in our money and our payments, without being asked to account for every
coin we receive or send. Your pay, your rent, your doctor and your donations are your business:
with a public coin like Bitcoin, one payment to a shop is enough for that shop to follow your
wallet forever. And privacy only works when everyone has it. On coins where it is optional, the
few who use it stand out; on Vesper every payment is private, so everyone hides in the same crowd.

## How Vesper aims to outdo Monero and Zcash

- **Every payment is private, always.** Zcash makes privacy optional, so most of its payments are
  public and the private ones stand out. Vesper has no public payments at all, like Monero.
- **A bigger crowd.** A ring of 32 coins for every payment, twice Monero's.
- **You can prove your own history when you choose.** A view key for your accountant, and a
  receipt for one payment when a shop says it never arrived.
- **Network privacy measured, not promised.** We publish how often an attacker can guess where a
  payment came from, and Tor is built in.

## What the shared record shows

| | Bitcoin | Vesper |
|---|---|---|
| Who was paid | visible to everyone | **hidden** |
| How much | visible to everyone | **hidden** |
| Who paid | visible to everyone | **hidden among 32 possible payers** |
| Your balance | anyone can look it up | **only you**, and anyone you give your view key |

## Made for everyday use

- **One address per person.** Give each person or shop their own address. They all land in
  one wallet, and nobody can tell they belong together.
- **A recovery code on paper.** Your wallet is 55 characters you can write down. Lose your
  computer, keep your money.
- **Receipts when you need them.** Prove one payment to one person, such as a shop that says it
  never arrived, without revealing anything else.
- **A read-only key for your accountant.** It shows your incoming payments and amounts, and can
  never spend.
- **Mining on an ordinary computer.** Vesper's mining is built so a normal PC can take part, not
  just warehouses of special machines.
- **A fair start.** No coins were made in advance, none are for sale, and the network's first
  block names a Bitcoin block that did not exist until launch day, so nobody could have mined
  in secret beforehand.

## Try it in five minutes

You need Python 3.10 or newer.

1. Download the code: the green **Code** button above, then **Download ZIP**, and unzip it.
2. Install the two helpers it needs: `pip install -r requirements.txt`
3. Double-click **`testdrive.bat`** (or run `python testdrive.py`).

It starts two throwaway nodes on your computer, sends private payments between them, searches
the raw record for the names and amounts (and finds nothing), tries to cheat five different
ways, and shows each attempt being refused. Nothing of yours is touched, and it cleans up after
itself. `python testdrive.py --more` also shows extra addresses, the recovery code and a payment
receipt.

## Join the test network

| Step | Double-click | What happens |
|---|---|---|
| 1 | `selftest.bat` | 44 checks that try to break the rules: double spending, forged signatures, counterfeit coins, rewritten history. |
| 2 | `wallet.bat` | Makes your wallet and shows your address (`tvsp...`) and your **recovery code**. Write the code on paper: it is your wallet. |
| 3 | `start_node.bat` | Starts your node. It joins the network and mines test coins for you. |
| 4 | `explorer.bat` | Watch new blocks arrive, and see that no payment shows a name or an amount. |
| 5 | `wallet.bat` | Your balance. To pay someone: `python coin.py send <their address> <amount>` |

New coins can be spent 10 blocks after they arrive, about 5 minutes. The first public seed node,
the address new nodes use to find the network, is being set up; once it is listed in
`config.json`, a new node finds the others by itself.

**Check the fair start yourself.** The network is called testnet-1. Its first block names
Bitcoin block 972,096 (`000000000000000000016fadf5ba032191be819fb3ce74179e420ace9166dec4`), which
did not exist until minutes before launch. The first block's own ID is
`c1b12e33659264634e4e2be4bbaba5fcc637ef59ef6168d1c2db72f6f2830252`, and every node checks it.

## Honest status

- **This is a test network.** tVESP coins have no value and never will. A real network, if there
  is one, will start fresh with its own first block and its own addresses.
- **Nobody independent has checked the cryptography yet.** Do not trust Vesper with real money.
  Before that: a stronger way to hide the payer among everyone instead of 32, a review by an
  independent cryptographer, and legal advice.
- **The network can still give hints.** Someone who runs many of the network's computers can
  sometimes guess where a payment started, and we measure how often (see
  [TECHNICAL.md](TECHNICAL.md)). If your internet address matters, run your node through Tor
  (`--proxy`).
- **Still visible to everyone:** the fee (the same for everyone), mining rewards, how many coins
  a payment uses, which block it is in, and the 32 coins it points at.

## How fast is it

- Making a payment takes about a quarter of a second on an ordinary PC.
- A node checks a payment in about 1/20 of a second.
- A new block comes about every 30 seconds.

## Learn more

- **[TECHNICAL.md](TECHNICAL.md)**: how each part works, the leaks measured, the speed table,
  and every command.
- **[DECISIONS.md](DECISIONS.md)**: every design choice and why it was made.
- **[deploy/](deploy/README.md)**: running an always-on seed node on a rented server.
- Found a weakness? See [SECURITY.md](SECURITY.md). Want to help? See
  [CONTRIBUTING.md](CONTRIBUTING.md). License: MIT.

The code is plain Python, written so that each trick can be read and followed line by line.
