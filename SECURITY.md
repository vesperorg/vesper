# Reporting a weakness in Vesper

Vesper publishes what its chain still reveals (see `site/breaking.html`, "Breaking Vesper").
If you can show more than that list allows: trace a receiver, amount or sender with better
odds than published, create coins, spend coins you do not own, or double spend, we want to
hear from you first and privately.

1. Check the register and the whitepaper's threat model. If it is listed, tell us anyway if you can show it is worse than described.
2. Write it up so we can reproduce it: what you saw, how, with what data (chain file, transaction IDs, a script if you have one).
3. Send it privately. Until the testnet opens, open a GitHub issue titled "security: contact requested" with no details and we will reply with a private channel.
4. You are credited by name or handle when the fix ships. Public disclosure before a fix forfeits the bounty, never the credit.

Out of scope: items on the published leak list, phishing a wallet file, compromising a user's
machine, and denial of service against the unhardened test node (it is not internet-ready yet).

The bounty pool and payment rules are on the Join page and become final when the public
testnet opens. Nothing here is a promise of payment before that.
