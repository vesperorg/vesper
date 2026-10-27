# Start here: test Vesper yourself in about 15 minutes

No experience needed. These are Windows steps; Mac and Linux are at the end. Nothing here costs
anything and nothing here is worth anything: testnet-1 coins (tVESP) are test coins, forever.

## 1. Install Python (once)

1. Go to https://www.python.org/downloads/ and download Python 3.10 or newer.
2. Run the installer. On the first screen tick **"Add Python to PATH"**, then Install.

## 2. Get Vesper

1. On https://github.com/vesperorg/vesper click the green **Code** button, then **Download ZIP**.
2. Unzip it somewhere easy, for example `Desktop\vesper`. Every step below happens in that folder.
3. Open the folder, right-click an empty spot and choose **Open in Terminal** (or hold Shift and
   right-click, then "Open PowerShell window here"). Type:

```
pip install -r requirements.txt
```

That installs the two small libraries Vesper uses. It takes under a minute.

## 3. Watch the whole thing work, hands off (5 minutes)

Double-click **`testdrive.bat`**.

It starts two throwaway nodes on your computer, mines until there are enough coins to hide a
payment in, sends a private payment from one to the other, shows the receiver finding it and an
accountant's view key reading it, searches the raw chain file for the addresses and the amount
(and finds nothing), shows what the payment really contains, pays some back, re-checks every block
from scratch, and then tries to cheat five different ways and shows each attempt refused. It ends
with **"14 of 14 checks behaved as the test drive page says."** and deletes its own folders. The
test-drive page on the site walks through the same output line by line:
https://vesperorg.github.io/vesper/testdrive.html

## 4. Run the 45 checks (2 minutes)

Double-click **`selftest.bat`**. It tries to double-spend, forge signatures, print coins four ways,
rewrite history and cheat the development fund, and confirms that no address, amount or spent coin
is readable on the chain. All 45 should pass. If one does not, that is worth reporting (step 9).

## 5. Make your wallet

Double-click **`wallet.bat`**. Choose a password. It shows your address (it starts with `tvsp`)
and a 55-character **recovery code**. Write the code on paper and keep it somewhere safe: the code
is the wallet. Anyone who sees it can spend your coins; if you lose it and your computer, the coins
are gone. Nobody can reset it.

## 6. Run a node and mine test coins

Double-click **`start_node.bat`** and leave the window open. Your node is now part of the network
and mines tVESP to your wallet. Double-click **`explorer.bat`** to watch blocks arrive in your
browser: payments show as sealed amounts to one-time keys, and there is no address search because
there are no addresses on the chain.

Run **`wallet.bat`** again any time to see your balance. A new coin can be spent 10 blocks after
it arrives, about 5 minutes.

Your node finds the rest of testnet-1 through the seed node listed in `config.json`. Until that
address is published (it is announced on the Join page), your node mines a chain of its own; to
connect to a friend's node directly, start yours with
`python node.py --peer http://THEIR-ADDRESS:8880 --mine`.

## 7. Pay someone

Ask for their address (it starts with `tvsp`), then in the terminal:

```
python coin.py send tvsp2THEIRADDRESS 1
```

The output tells you what was written to the chain (no address, no amount, no spent coin) and that
your node handed the payment quietly to one peer instead of announcing it. Give each person who pays
you their own address with `python coin.py wallet new-address --label NAME`; nobody can tell the
addresses belong together.

## 8. Try to break it

Every weakness we know of is listed at https://vesperorg.github.io/vesper/breaking.html. The
test-drive page has a "Now try to break it" section with exercises you can do yourself: overspend,
replay a payment, mistype an address, spend with a view key, edit the chain file. Run
`python leaktest.py` to see the measured privacy leaks printed as numbers.

## 9. Tell us

- Ran a node? Open an issue titled **"founding node"** with your handle to be listed on the
  founding-node roll.
- Found a weakness? Read `SECURITY.md`: open an issue titled "security: contact requested" with no
  details, and a private channel is arranged from there. Credit is public; bounties are announced
  with the seed node.
- Something on a page did not match what your computer did? That is a bug in the page or the code,
  and we want to know which. Open an issue.

## Mac and Linux

Same steps with these changes: install Python with your package manager or from python.org; in a
terminal in the Vesper folder run `pip3 install -r requirements.txt`; instead of the `.bat` files
run `python3 testdrive.py`, `python3 selftest.py`, `python3 coin.py wallet new`,
`python3 node.py --mine`, and open http://127.0.0.1:8880 in your browser for the explorer.

## Honest reminders

Vesper is not audited. Test coins have no value, ever. Today it is Monero's design with a bigger
crowd for every spend, not more; anyone who tells you it is "untraceable" is not us. If your
internet address matters to you, run your node through Tor: `python node.py --proxy
socks5h://127.0.0.1:9050 --mine` with the Tor Browser or Tor service running.
