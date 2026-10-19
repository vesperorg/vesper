# Before the first push to GitHub

## Decided (2026-10-13)

- **Identity: the pseudonym "Vesper". No real name anywhere.** LICENSE says "The Vesper developers"; the pages and documents credit "Vesper"; the explainer's example person is Bob; the transparent coin this grew from is named only as "the learning chain" in public material, because its name carries a first name. Git commits are authored `Vesper <vesper@users.noreply.github.com>` (set in this repository's config, so both Claude sessions commit under it).
- **History is squashed at publish.** `publish_github.bat` turns everything into ONE fresh commit before the first push. The older local commits, which carried a real name as author, stay on the local branch `private-history` and never leave this PC.
- **Owner: a GitHub organisation.** "vesper org" as asked. Checked 2026-10-13: `vesper-org` and `vesper` are taken; `vesperorg`, `vesper-coin` and `vespercoin` are free. The script defaults to `vesperorg`.

## Published

2026-10-19 20:23 UTC: https://github.com/vesperorg/vesper, one commit (b85ed4f) authored Vesper, pushed by the pseudonymous account; the self-test workflow passed on Windows and Linux on the first run. The site is served by GitHub Pages from `site/` through `.github/workflows/pages.yml` at https://vesperorg.github.io/vesper/ (branch-based Pages can only serve `/` or `/docs`, so the publish script's original Pages call failed and was replaced). Private history is in `../vesper-private/private-history-20261019-2023.bundle`. Steps 0 to 7 below are done; 8 and 9 remain.

## Still to do (one line back to Claude for each)

0. **Install the GitHub CLI** (it is not on this PC yet): open a terminal and run `winget install GitHub.cli`, then close and reopen the terminal. The publish script checks for it and stops with this same instruction if it is missing.
1. **A new GitHub account for the pseudonym** (fresh email address, username such as `vesper-dev`), not a personal account: the organisation's owner and whoever pushes are tied to the signed-in account. After creating the organisation, set your membership to Private (organisation page, People, your row).
2. **Create the organisation** from that account at github.com/account/organizations/new, Free plan, name `vesperorg` (or tell Claude the name you got).
3. Optional, for linked commits: GitHub Settings, Emails, tick "Keep my email addresses private"; the page shows an `ID+login@users.noreply.github.com` address. Tell Claude and it goes into the commit identity before publishing.
4. **Licence.** MIT is in place. BSD-3-Clause (Monero's) adds "do not use our name to endorse your fork" and slightly favours the "they are copying Vesper" story. One word back: MIT or BSD.
5. **Trademark search** on "Vesper" for software and financial services (Vesper Finance exists). Not a blocker for the code; a blocker for the name on an exchange.
6. **Run `publish_github.bat`.** It signs you in (`gh auth login`, pick the NEW account), runs two gates (no identifying text in the tree, no secret-looking file tracked), checks the organisation exists, asks once before doing anything, squashes to one commit, creates the public repository and pushes, and turns on GitHub Pages from `/site`.
7. **Send Claude the repository and Pages URLs** so the Join page placeholder and the dev log can point at them.
8. **Rent the seed server** (a small Ubuntu machine from a provider that does not need your name, paid in a way that does not point at you; never your home connection). Follow `deploy/README.md`: copy the repository there and run `deploy/setup-seed.sh`; it refuses to start if the self-test fails, opens only SSH and port 8880, and mines on one core.
9. **Send back the seed address** (`http://IP:8880`). It goes into `config.json` "peers" and the Join page, and that commit is pushed. Testnet-1 is open from that moment.

Testnet-1 facts the pages rely on (from the code session, node v0.9.0): ring size 48 (raised from 32 on 2026-10-19 before the first peer); test coins tVESP, addresses start `tvsp2`, 98 characters, no value ever; genesis made by `launch_genesis.py` and tied to the newest Bitcoin block at launch. If publishing is more than a day or two after the genesis was made, the code session re-makes it (`python launch_genesis.py testnet-1`) so the genesis ID changes: the pages describe the method and point to README for the exact block and ID, and quote them only once final.

## Already done

- Secrets scan: no wallets, keys, `.env` or chain data in the tree; `data*/`, `*.scan`, `*.viewkey.json` ignored; the script re-checks before every publish.
- Name scan: no real name, email or Windows user path in any tracked file; the script re-checks before every publish.
- Development fund address in `config.json` is empty (fund off), so no personal address ships in the code.
- `.gitattributes` normalises line endings; `.docx` is binary.
- LICENSE, SECURITY.md, CONTRIBUTING.md present.
- `PROOF_OF_EXISTENCE.txt` holds sha256 fingerprints of the README, whitepaper and both walkthroughs; the first public commit's GitHub date is the timestamp. (OpenTimestamps was attempted; the client does not run on this PC's Python build. It can be added later from any machine.)
- Six pages in `site/` with relative links, ready for GitHub Pages from `/site`. Corrected on 2026-10-15 after the code session's check pass (position-bound key images, no key-uniqueness rule, test drive re-recorded on node v0.3.0).
- Pages and both walkthroughs brought to node v0.8.0 (44 checks, phase 4 built and measured, addresses v2, aggregated range proofs, payment proofs, recovery codes, Tor) on 2026-10-18.
- Pages brought to node v0.9.0 / testnet-1 (ring 32, tVESP, testnet announcement and join steps) on 2026-10-19.
- `.github/workflows/selftest.yml`: GitHub runs the self-test on every push on Windows and Linux (both required; seed nodes run Linux). After publishing, add the badge to README: `![self-test](https://github.com/ORG/vesper/actions/workflows/selftest.yml/badge.svg)`.
