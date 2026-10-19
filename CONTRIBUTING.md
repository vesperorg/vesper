# Contributing to Vesper

Four ways in, in the order they matter before genesis:

- **Review.** Read `privacy.py`, `amounts.py`, `rangeproof.py`, `ringsig.py` and the whitepaper. Tell us what is wrong. This is the most valuable hour anyone can give.
- **Run.** Follow the README; run the self-test and the two-node test drive. When the public testnet opens, run a node through it and you go on the founding-node roll.
- **Build.** Wallets, atomic swaps, mining-pool support, a better explorer, translations. Open an issue describing what you want to build before you start; the development fund pays on delivery once it exists.
- **Use.** Later, after the audit and a wallet that does not need a terminal.

Rules of the road:

- Privacy is mandatory. No change may add a transparent transaction type or an optional on-chain marker.
- Every consensus change updates `selftest.py`, including the test that lists what the chain still leaks, and `DECISIONS.md` with the reason.
- Every phase reports its cost in milliseconds. A design that cannot keep a payment well under a second does not ship.
- Never commit anything from `data/`: wallets, scan notebooks and view-key files live there.
- Commit messages describe what changed and why, in plain words.

There is no token, no presale and no sale. Pull requests that add one will be closed.
