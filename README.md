# Vesper

**Private digital cash. Every payment is sealed: nobody watching can see who paid, who was paid, or how much.**

[![self-test](https://github.com/vesperorg/vesper/actions/workflows/selftest.yml/badge.svg)](https://github.com/vesperorg/vesper/actions/workflows/selftest.yml)
Website: https://vesperorg.github.io/vesper/ · Code: https://github.com/vesperorg/vesper

## What we are building

Vesper is a new cryptocurrency: money that lives on a network of ordinary computers instead of
in a bank, the way Bitcoin does. The difference is privacy. On Bitcoin, every payment ever made
stays public forever: anyone can look up an address and see its balance and everyone it paid.
Vesper keeps a shared record that proves every payment is genuine, without showing who sent it,
who received it, or how much it was. You decide who sees your payments, not the whole internet.

Vesper is running today as a **public test network**. Its coins, **tVESP**, are test coins with
no value, so anyone can try it, try to break it, and help make it solid before it ever carries
real money.

## Why it matters

- **Your money is your business.** Your pay, your rent, your doctor, your donations. With a
  public coin, one payment to a shop is enough for that shop to follow your wallet forever.
- **Cash is private. Digital money should be too.** Vesper aims to be the digital version of
  paying in cash.
- **Privacy only works when everyone has it.** On coins where privacy is optional, the few who
  use it stand out. On Vesper every payment is private, so everyone hides in the same crowd.

## What the shared record shows

| | Bitcoin | Vesper |
|---|---|---|
| Who was paid | visible to everyone | **hidden** |
| How much | visible to everyone | **hidden** |
| Who paid | visible to everyone | **hidden among 32 possible payers** |
| Your balance | anyone can look it up | **only you**, and anyone you give your view key |

## How it works, in four ideas

1. **A fresh lock for every payment.** Your address is never written on the record. Each payment
   to you goes into a brand-new one-time lock that only your wallet recognises, so two payments
   to you look completely unrelated.
2. **Sealed amounts.** Every amount is sealed like an envelope that the network can add up but
   never open. It can still check that nobody spent more than they had, and a short proof stops
   anyone from printing money with a "negative" amount.
3. **A crowd of 32.** When you spend, your payment points at 32 coins, yours and 31 others, and
   proves you own one of them without saying which. A one-way "spent" stamp stops anyone from
   spending the same coin twice.
4. **A quiet hand-off.** Your computer does not announce your payment to everyone. It passes it
   quietly through a few other computers first, so the one that announces it is not yours. For
   more, Vesper can send all its traffic through Tor.

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
- **How private it is today:** the same design as Monero, the best-known private coin, with
  twice Monero's crowd. Someone who runs many of the network's computers can still sometimes
  guess where a payment started, and we measure how often (see [TECHNICAL.md](TECHNICAL.md)).
  If your internet address matters, run your node through Tor (`--proxy`).
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
