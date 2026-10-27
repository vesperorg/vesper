"""
coin.py - the Vesper command line: wallets, sending, mining, looking things up.

  python coin.py wallet new [--name N]        create a wallet (asks for a password)
  python coin.py wallet show                  address + balance (scans the chain with your keys)
  python coin.py wallet list
  python coin.py wallet export-view [--out F] write a view-key file: can SEE payments, cannot spend
  python coin.py watch VIEWKEY.json           balance and outputs using only a view key
  python coin.py send ADDRESS AMOUNT [--fee]  pay someone (change comes back to you, unlinkably)
  python coin.py mine start|stop|status|once
  python coin.py devfund init|show            the development fund (off until you run init)
  python coin.py info | chain | block N|HASH | tx TXID | peers [add URL] | validate
  python coin.py reset-chain                  start the chain over (removes saved blocks, NEVER wallets)

There is no `balance ADDRESS` command.  Nobody can look up anyone's balance on this chain,
not even the node: receivers are one-time keys and amounts are sealed.  Your own balance comes from scanning every output with your view
key, which is what privacy costs: a little work on your side instead of a public ledger.
"""

from __future__ import annotations

import argparse
import getpass
import glob
import json
import os
import sys
import time
import urllib.error
import urllib.request

import socksproxy
from curve import scalar_from_hex
from chain import Blockchain, ChainError, build_transfer, format_units, load_config, lock_data_dir, resolve_data_dir, to_units
from privacy import LOOKAHEAD, is_valid_address
from wallet import Wallet, WalletError, WalletLocked, sync_outputs


class CliError(Exception):
    pass


class Ctx:
    def __init__(self, args):
        self.config = load_config(args.config)
        coin = self.config["coin"]
        self.name, self.ticker = coin["name"], coin["ticker"]
        self.decimals = int(coin["decimals"])
        self.prefix = coin["address_prefix"]
        self.min_fee = to_units(self.config["consensus"]["min_fee"], self.decimals)
        self.data_dir = resolve_data_dir(self.config, args.data_dir)
        net = self.config["network"]
        self.node_url = (args.node or "http://%s:%d" % (net["host"], int(net["port"]))).rstrip("/")
        try:
            self.opener = socksproxy.opener(getattr(args, "proxy", None))   # a node elsewhere, reached through Tor
        except ValueError as exc:
            raise CliError("--proxy: %s" % exc)

    def fmt(self, units: int) -> str:
        return format_units(units, self.decimals, self.ticker)

    def wallet_path(self, name: str) -> str:
        return os.path.join(self.data_dir, "wallets", "%s.json" % name)

    def api(self, method: str, path: str, payload=None, timeout=60):
        data = json.dumps(payload).encode("utf-8") if payload is not None else None
        req = urllib.request.Request(self.node_url + path, data=data, method=method, headers={"Content-Type": "application/json"})
        try:
            with self.opener.open(req, timeout=timeout) as resp:
                body = resp.read().decode("utf-8")
            return json.loads(body) if body else {}
        except urllib.error.HTTPError as exc:
            try:
                message = json.loads(exc.read().decode("utf-8")).get("error") or str(exc)
            except ValueError:
                message = str(exc)
            raise CliError("node said: %s" % message)
        except urllib.error.URLError as exc:
            raise CliError("cannot reach the node at %s (%s). Start it with start_node.bat first." % (self.node_url, exc.reason))
        except OSError as exc:                          # the proxy, if one is used, said no
            raise CliError("cannot reach the node at %s (%s)" % (self.node_url, exc))
        except TimeoutError:
            raise CliError("the node did not answer in time")

    def scan_page(self, start: int) -> dict:
        """The outputs and spent markers of blocks start, start+1, ...  Whole blocks, always:
        the node never learns which outputs are yours."""
        return self.api("GET", "/api/scan?start=%d" % start, timeout=180)

    def block_hash_at(self, height: int):
        hashes = self.api("GET", "/api/hashes?start=%d&limit=1" % height).get("hashes", [])
        return hashes[0] if hashes else None

    def sync(self, wallet: Wallet, name: str):
        """Bring a wallet up to date with the chain: (its outputs, what the node said about the
        chain).  Only blocks it has not seen before are read; what it found earlier is kept in
        an encrypted notebook next to the wallet file."""
        path = os.path.join(self.data_dir, "wallets", "%s.scan" % name)
        owned, notebook, tip = wallet.sync(wallet.load_notebook(path), self.scan_page, self.block_hash_at)
        wallet.save_notebook(path, notebook)
        return owned, tip


class NodeRings:
    """Ring members fetched from the node, a ring at a time (see chain.assemble_ring).  The
    wallet never downloads the list of all outputs, and it always asks for a whole ring - its
    own coin included - so the node cannot tell which member is the real one."""

    def __init__(self, ctx: Ctx, eligible: int, tip: dict | None = None):
        self.ctx, self.eligible = ctx, eligible
        tip = tip or {}
        self.outputs_per_block = float(tip.get("outputs_per_block") or 1.0)       # the chain's recent pace,
        self.lock_blocks = int(tip.get("output_lock_blocks") or 0)                # the same public numbers
        self.block_seconds = float(tip.get("target_block_seconds") or 30)        # every wallet uses

    def eligible_count(self) -> int:
        return self.eligible

    def by_positions(self, positions: list) -> list:
        return self.ctx.api("POST", "/api/outputs/lookup", {"positions": positions})["positions"]

    def by_refs(self, refs: list) -> list:
        return self.ctx.api("POST", "/api/outputs/lookup", {"refs": refs})["refs"]


def waiting_refs(tip: dict) -> set:
    return set(tip.get("pending_key_images") or []) | set(tip.get("pending_fund_spent") or [])


def is_waiting(u: dict, waiting: set) -> bool:
    return u.get("key_image") in waiting or "%s:%d" % (u["txid"], u["index"]) in waiting


def shown(path: str) -> str:
    """A path as short as it can be said: relative to where the command was run when it lies
    inside it.  Output gets copied into chats and screenshots; a full Windows path names the
    account it lives under."""
    try:
        rel = os.path.relpath(path)
        return path if rel.startswith("..") else rel
    except ValueError:                       # another drive
        return path


def when(ts) -> str:
    return time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(ts))


def short(text: str, n: int = 16) -> str:
    return text if len(text) <= n else text[:n] + "..."


def prompt_new_password() -> str:
    while True:
        first = getpass.getpass("Choose a wallet password (leave empty for NO encryption): ")
        if not first:
            return ""
        if first == getpass.getpass("Type it again: "):
            return first
        print("They did not match - try again.")


def load_wallet(ctx: Ctx, name: str, password: str | None) -> Wallet:
    path = ctx.wallet_path(name)
    if not os.path.exists(path):
        raise CliError("no wallet named %r - create one with:  python coin.py wallet new --name %s" % (name, name))
    if not Wallet.public_info(path, ctx.prefix)["encrypted"]:
        return Wallet.load(path, prefix=ctx.prefix)
    for _ in range(3):
        pw = password or getpass.getpass("Password for wallet %r: " % name)
        try:
            return Wallet.load(path, pw, ctx.prefix)
        except WalletLocked as exc:
            if password:
                raise CliError(str(exc))
            print(str(exc))
    raise CliError("too many wrong passwords")


def print_owned(ctx: Ctx, owned: list, tip: dict, started: float) -> None:
    """owned: outputs a wallet or view key found.  u["spent"] is True, False, or None (cannot tell)."""
    unspent = [u for u in owned if not u.get("spent")]
    spent = [u for u in owned if u.get("spent")]
    print("Balance : %s   (%d unspent output(s) of yours among %d on the chain; %d new one(s) read in %.1fs)" % (
        ctx.fmt(sum(u["amount"] for u in unspent)), len(unspent), tip.get("output_count", 0), tip.get("scanned", 0), time.time() - started))
    if spent:
        print("          %d more output(s) were yours and are spent (%s)" % (len(spent), ctx.fmt(sum(u["amount"] for u in spent))))
    young = [u for u in unspent if u["output"]["position"] >= tip.get("spendable_outputs", 0)]
    if young:
        print("          %d of them (%s) arrived in the last %d blocks and can be spent once they are that old" % (
            len(young), ctx.fmt(sum(u["amount"] for u in young)), tip.get("output_lock_blocks", 0)))
    for u in sorted(unspent, key=lambda u: -u["amount"])[:10]:
        kind = "fund share" if "ephemeral_secret" in u["output"] else ("mining reward" if "amount" in u["output"] else "sealed")
        to = "  to address #%d" % u["address"] if u.get("address") else ""
        print("   %18s   %-13s one-time key %s   from tx %s%s" % (ctx.fmt(u["amount"]), kind, short(u["output"]["one_time_pub"], 14), short(u["txid"], 12), to))
    if len(unspent) > 10:
        print("   ... and %d more" % (len(unspent) - 10))


# ----------------------------------------------------------------------------- wallet commands
def cmd_wallet_new(ctx: Ctx, args) -> Wallet:
    path = ctx.wallet_path(args.name)
    if os.path.exists(path):
        raise CliError("a wallet named %r already exists at %s" % (args.name, path))
    print("Creating wallet %r" % args.name)
    print("A Vesper wallet is two secret numbers: a VIEW key (finds your payments) and a SPEND key")
    print("(moves them). The password encrypts both. Your address is public and safe to share.")
    password = args.password if args.password is not None else prompt_new_password()
    wallet = Wallet.generate(ctx.prefix)
    wallet.save(path, password or None)
    print("")
    print("Address : %s" % wallet.address)
    print("File    : %s" % shown(path))
    print("Status  : %s" % ("encrypted. No password reset exists." if password else "WARNING - saved UNENCRYPTED."))
    print("Nothing on the chain will ever show this address. Payments to it land at one-time keys only you can recognise.")
    print("")
    print("RECOVERY CODE - write it on paper and keep it safe:")
    print("")
    print("    %s" % wallet.recovery_code())
    print("")
    print("These 55 characters ARE the wallet. With them you can rebuild it on any computer")
    print("(python coin.py wallet restore). Anyone who sees them can spend everything in it.")
    print("Show it again later with:  python coin.py wallet recovery-code")
    return wallet


def cmd_wallet_restore(ctx: Ctx, args) -> None:
    path = ctx.wallet_path(args.name)
    if os.path.exists(path):
        raise CliError("a wallet named %r already exists at %s - restore under another name with --name" % (args.name, path))
    code = args.code or getpass.getpass("Recovery code (it does not show as you type): ")
    wallet = Wallet.from_code(code, ctx.prefix)
    password = args.password if args.password is not None else prompt_new_password()
    wallet.save(path, password or None)
    print("Wallet %r restored." % args.name)
    print("Address : %s" % wallet.address)
    print("File    : %s" % shown(path))
    print("It finds its payments the next time it looks (it reads the chain from the start), including those")
    print("to the first %d extra addresses. If you handed out more, make that many again with wallet new-address." % LOOKAHEAD)


def cmd_wallet_recovery_code(ctx: Ctx, args) -> None:
    wallet = load_wallet(ctx, args.name, args.password)
    code = wallet.recovery_code()
    if code is None:
        print("This wallet was made before recovery codes existed, so it has none. Back up its file instead:")
        print("  %s  (and remember its password)" % shown(ctx.wallet_path(args.name)))
        print("Or move its coins to a new wallet (python coin.py wallet new --name ...), which comes with a code.")
        return
    print("Recovery code of wallet %r - anyone who sees it can spend everything in it:" % args.name)
    print("")
    print("    %s" % code)


def cmd_wallet_show(ctx: Ctx, args) -> None:
    path = ctx.wallet_path(args.name)
    if not os.path.exists(path):
        print("No wallet named %r yet - creating one." % args.name)
        print("")
        cmd_wallet_new(ctx, args)
        return
    info = Wallet.public_info(path, ctx.prefix)
    print("Wallet  : %s" % args.name)
    print("Address : %s" % info["address"])
    print("File    : %s  (%s)" % (shown(path), "encrypted" if info["encrypted"] else "UNENCRYPTED"))
    try:
        wallet = load_wallet(ctx, args.name, args.password)
        if wallet.labels:
            print("Also    : %d more address(es) of this wallet - list them with:  python coin.py wallet addresses" % len(wallet.labels))
        started = time.time()
        owned, tip = ctx.sync(wallet, args.name)
    except CliError as exc:
        print("Balance : (%s)" % exc)
        return
    print_owned(ctx, owned, tip, started)
    waiting = waiting_refs(tip)
    busy = [u for u in owned if not u["spent"] and is_waiting(u, waiting)]
    if busy:
        print("          %d of those output(s) (%s) are in a payment of yours that is waiting to be mined" % (len(busy), ctx.fmt(sum(u["amount"] for u in busy))))


def cmd_wallet_new_address(ctx: Ctx, args) -> None:
    path = ctx.wallet_path(args.name)
    password = args.password
    if os.path.exists(path) and Wallet.public_info(path, ctx.prefix)["encrypted"] and not password:
        password = getpass.getpass("Password for wallet %r: " % args.name)      # needed twice: to open and to save
    wallet = load_wallet(ctx, args.name, password)
    number, address = wallet.new_address(args.label or "")
    wallet.save(path, password or None)
    print("Address #%d%s:" % (number, " (%s)" % args.label if args.label else ""))
    print(address)
    print("Give it to one person or one shop. Payments to it land in this wallet, and nobody - not even")
    print("everyone you gave an address to, comparing notes - can tell that your addresses belong together.")


def cmd_wallet_addresses(ctx: Ctx, args) -> None:
    wallet = load_wallet(ctx, args.name, args.password)
    for number, address, label in wallet.addresses():
        print("#%-5d %-12s %s" % (number, short(label, 12), address))
    if not wallet.labels:
        print("Only the main address so far. Make one per person who pays you:  python coin.py wallet new-address --label NAME")


def cmd_wallet_list(ctx: Ctx, args) -> None:
    files = sorted(glob.glob(os.path.join(ctx.data_dir, "wallets", "*.json")))
    if not files:
        print("No wallets yet. Create one with:  python coin.py wallet new")
        return
    for path in files:
        try:
            info = Wallet.public_info(path, ctx.prefix)
            kind = "view-key" if info["kind"] == "view-key" else ("" if info["encrypted"] else "(UNENCRYPTED)")
            print("%-12s %s  %s" % (os.path.splitext(os.path.basename(path))[0], short(info["address"], 40), kind))
        except (OSError, ValueError, KeyError):
            print("%-12s (unreadable)" % os.path.basename(path))


def cmd_wallet_export_view(ctx: Ctx, args) -> None:
    wallet = load_wallet(ctx, args.name, args.password)
    out = args.out or os.path.join(ctx.data_dir, "wallets", "%s.viewkey.json" % args.name)
    owned = None
    try:
        owned, _ = ctx.sync(wallet, args.name)
    except CliError:
        pass                                   # node offline: export the key without spent markers
    wallet.export_view_key(out, owned)
    print("View key written to %s" % shown(out))
    print("Whoever holds that file can SEE every payment to your address and its amount, forever, and can never spend any of it.")
    if owned is None:
        print("The node was not reachable, so the file has no spent markers: its holder will see what arrives, not what leaves.")
    else:
        print("It also carries the spent markers of the %d output(s) you hold today, so its holder can see when those are spent." % len(owned))
        print("Outputs you receive later show as 'spent status unknown' to them until you export a fresh file.")
    print("Check it:  python coin.py watch \"%s\"" % shown(out))


def cmd_watch(ctx: Ctx, args) -> None:
    view = Wallet.load_view_key(args.viewkey, ctx.prefix)
    print("Watching address %s with a view key only" % short(view.address, 40))
    started = time.time()
    markers = Wallet.load_view_markers(args.viewkey)
    owned, _, tip = sync_outputs(view, None, None, ctx.scan_page, ctx.block_hash_at, markers=markers)
    unknown = sum(1 for u in owned if u["spent"] is None)
    print_owned(ctx, owned, tip, started)
    print("(A view key opens the sealed amounts of this address. It still cannot spend any of it.)")
    if unknown:
        print("%d of these output(s) arrived after the view-key file was made: whether they were spent since cannot" % unknown)
        print("be seen with it, so they are counted as unspent. Ask the owner for a fresh file to update.")


# ----------------------------------------------------------------------------- money
def cmd_send(ctx: Ctx, args) -> None:
    if not is_valid_address(args.to, ctx.prefix):
        raise CliError("%r is not a valid %s address (they start with %r and are long: two keys plus a checksum)" % (args.to, ctx.ticker, ctx.prefix))
    try:
        amount = to_units(args.amount, ctx.decimals)
        fee = to_units(args.fee, ctx.decimals) if args.fee else None       # None = exactly the minimum for the size
    except ValueError as exc:
        raise CliError(str(exc))
    if fee is not None:
        print("Note: a fee you choose yourself stands out on the chain. Leave --fee off to pay what everyone pays.")
    wallet = load_wallet(ctx, args.name, args.password)
    owned, tip = ctx.sync(wallet, args.name)
    # What can be spent right now: not spent, not already in a payment that is waiting to be
    # mined (never use a coin twice), and old enough (see output_lock_blocks).
    waiting = waiting_refs(tip)
    unspent = [u for u in owned if not u["spent"]]
    spendable = [u for u in unspent if not is_waiting(u, waiting) and u["output"]["position"] < tip["spendable_outputs"]]
    ring_size = int(ctx.config["consensus"]["ring_size"])
    rings_path = os.path.join(ctx.data_dir, "wallets", "%s.rings" % args.name)
    rings = wallet.load_rings(rings_path)
    started = time.time()
    proof_secrets: list = []
    try:
        tx = build_transfer(wallet.keys, spendable, [(args.to, amount)], fee, ctx.prefix, NodeRings(ctx, tip["spendable_outputs"], tip),
                            ring_size, min_fee=ctx.min_fee, known_rings=rings, fmt=ctx.fmt, sent=proof_secrets)
    except ValueError as exc:
        held_back = sum(u["amount"] for u in unspent) - sum(u["amount"] for u in spendable)
        if held_back and "insufficient" in str(exc):
            raise CliError("%s. Another %s is yours but cannot be spent yet: it is less than %d blocks old, or already in a "
                           "payment that is waiting to be mined. Try again in a few minutes."
                           % (exc, ctx.fmt(held_back), tip.get("output_lock_blocks", 0)))
        raise CliError(str(exc))
    built = time.time() - started
    used = {i["key_image"] for i in tx["inputs"] if "key_image" in i}
    mixed = sorted({u.get("address", 0) for u in spendable if u.get("key_image") in used})
    wallet.save_rings(rings_path, rings)       # before sending: a retry must reuse these exact decoys
    fee = tx["fee"]
    sent = ctx.api("POST", "/api/tx", tx)
    sent_path = os.path.join(ctx.data_dir, "wallets", "%s.sent" % args.name)
    log = wallet.load_sent(sent_path)
    log[tx["txid"]] = proof_secrets              # lets this wallet prove the payment later: coin.py proof pay
    wallet.save_sent(sent_path, log)
    print("Sent %s" % ctx.fmt(amount))
    print("Fee  %s (goes to whoever mines the block)" % ctx.fmt(fee))
    print("txid %s" % tx["txid"])
    hidden = sum(1 for i in tx["inputs"] if "ring" in i)
    print("On the chain this is: %d input(s) -> %d sealed output(s). No address, no amount, and no spent output" % (len(tx["inputs"]), len(tx["outputs"])))
    if hidden:
        print("appears anywhere: each input points at a ring of %d outputs and proves it owns one, without saying which." % ring_size)
    if hidden < len(tx["inputs"]):
        print("(Development fund inputs are the exception: the fund spends by name, in the open.)")
    print("Only the fee is public. One output is the payment, one is your change (even when the change is zero),")
    print("in random order. Sealing, proving and ring-signing took %.2fs." % built)
    if len(mixed) > 1:
        print("Note: no single address of yours held enough, so this payment spends coins that came to addresses %s"
              % ", ".join("#%d" % a for a in mixed))
        print("together. Two people who paid those addresses could each spot their own coin among its rings and guess")
        print("that both addresses are yours.")
    if sent.get("relay") == "stem":
        print("On the network: your node passed it quietly to ONE peer, which passes it on in turn, and another node,")
        print("usually several hops away, broadcasts it. The first broadcast does not come from your computer.")
    elif sent.get("relay") == "fluff":
        print("On the network: your node broadcast it directly, because it has no peers to pass it through first.")
        print("Anyone listening can see it came from this computer. Connect to peers before sending for the network privacy.")


# ----------------------------------------------------------------------------- mining / explorer
def _miner_line(status: dict) -> str:
    if not status.get("running"):
        return "Miner   : stopped (%d block(s) found this session)" % status.get("blocks_found", 0)
    return "Miner   : RUNNING  %s tries/s  %d block(s) found" % (format(status.get("hashrate", 0), ","), status.get("blocks_found", 0))


def cmd_mine(ctx: Ctx, args) -> None:
    address = args.address
    if not address:
        path = ctx.wallet_path(args.name)
        if os.path.exists(path):
            address = Wallet.public_info(path, ctx.prefix)["address"]
    if address and not is_valid_address(address, ctx.prefix):
        raise CliError("%r is not a valid %s address" % (address, ctx.ticker))
    if args.action == "start":
        print(_miner_line(ctx.api("POST", "/api/miner/start", {"address": address})))
        print("Mining continues inside the node window. Stop with:  python coin.py mine stop")
    elif args.action == "stop":
        print(_miner_line(ctx.api("POST", "/api/miner/stop", {})))
    elif args.action == "status":
        print(_miner_line(ctx.api("GET", "/api/miner")))
    elif args.action == "once":
        print("Mining %d block(s)..." % args.blocks)
        result = ctx.api("POST", "/api/mine", {"address": address, "blocks": args.blocks}, timeout=None)
        for block in result["mined"]:
            print("  block %d  reward %s  %d tx  hash %s" % (block["index"], ctx.fmt(block["reward"]), block["tx_count"], short(block["hash"], 24)))


def cmd_info(ctx: Ctx, args) -> None:
    d = ctx.api("GET", "/api/info")
    p = d["privacy"]
    print("%s (%s)  node %s  v%s" % (d["coin"], d["ticker"], d["node_url"], d["version"]))
    if d.get("network"):
        print("Network      : %s%s" % (d["network"], "   (test coins: no value, ever)" if "test" in d["network"] else ""))
    print("Privacy      : receivers %s, amounts %s, senders %s" % tuple("HIDDEN" if p[k] else "visible" for k in ("receivers_hidden", "amounts_hidden", "senders_hidden")))
    print("Ring size    : every input hides among %d outputs" % d.get("ring_size", 0))
    lock = d.get("output_lock_blocks", 0)
    print("Spend lock   : a new output can be used %d block(s) after the one that made it (about %d min); %s of %s are old enough now" % (
        lock, round(lock * d["target_block_seconds"] / 60), format(d.get("spendable_outputs", 0), ","), format(d.get("output_count", 0), ",")))
    print("Curve maths  : %s" % d.get("curve_backend", "?"))
    w = d.get("pow") or {}
    print("Proof of work: %s%s" % (w.get("algorithm", "?"), (", %d MiB of memory per try" % (w["memory_kib"] // 1024)) if w.get("algorithm") == "argon2id" else " (Bitcoin's hash: testing only)"))
    f = d.get("dev_fund") or {}
    if f.get("enabled"):
        print("Dev fund     : %d%% of each block reward, %d block(s) left; received %s, unspent %s" % (
            f["percent"], f["blocks_remaining"], ctx.fmt(f["total_received"]), ctx.fmt(f["unspent"])))
    else:
        print("Dev fund     : off")
    print("Height       : %d   (tip %s)" % (d["height"], short(d["tip_hash"], 20)))
    print("Difficulty   : %s tries per block now, %s next   (chain work 2^%s)" % (
        format(d["difficulty"], ","), format(d["next_difficulty"], ","), d["work_log2"]))
    avg = d.get("avg_block_seconds_recent")
    print("Block time   : target %ds, recent average %s" % (d["target_block_seconds"], ("%ss" % avg) if avg is not None else "n/a"))
    print("Supply       : %s of %s max, in %d output(s); %d spent so far, and nobody can tell which" % (
        ctx.fmt(d["circulating_supply"]), ctx.fmt(d["max_supply"]), d["output_count"], d["spend_count"]))
    print("Next reward  : %s   (halving in %d blocks)" % (ctx.fmt(d["next_reward"]), d["blocks_until_halving"]))
    print("Mempool      : %d waiting transaction(s)" % d["mempool_size"])
    print("Peers        : %s" % (", ".join(d["peers"]) or "none"))
    print(_miner_line(d["miner"]))


def cmd_chain(ctx: Ctx, args) -> None:
    d = ctx.api("GET", "/api/chain?limit=%d" % args.last)
    print("height %d - newest first" % d["height"])
    print("%6s  %-19s  %4s  %4s  %4s  %10s  %s" % ("block", "time", "txs", "in", "out", "difficulty", "id"))
    for b in d["blocks"]:
        print("%6d  %-19s  %4d  %4d  %4d  %10d  %s" % (b["index"], when(b["timestamp"]), b["tx_count"], b["inputs"], b["outputs"], b["difficulty"], short(b["hash"], 24)))


def cmd_block(ctx: Ctx, args) -> None:
    print(json.dumps(ctx.api("GET", "/api/block/%s" % args.key), indent=2))


def cmd_tx(ctx: Ctx, args) -> None:
    """What one transaction says on the chain, in plain words.  --json prints all of it."""
    d = ctx.api("GET", "/api/tx/%s" % args.txid)
    if args.json:
        print(json.dumps(d, indent=2))
        return
    tx = d["tx"]
    where = ("in block %d, %d confirmation(s)" % (d["block"], d["confirmations"])) if d["block"] is not None else "waiting to be mined"
    print("txid %s | %s | %s | inputs: %d | outputs: %d | fee: %s" % (
        short(tx["txid"], 16), tx["type"], where, len(tx["inputs"]), len(tx["outputs"]), ctx.fmt(tx["fee"])))
    for i, inp in enumerate(tx["inputs"]):
        if "ring" in inp:
            print("  input %d  : one of a ring of %d outputs, e.g. %s" % (i, len(inp["ring"]), ", ".join(short(r, 10) for r in inp["ring"][:3])))
            print("            spent marker (key image) %s   pseudo commitment %s" % (short(inp["key_image"], 24), short(inp["pseudo_commitment"], 16)))
            print("            signature: c + %d s-values + D   (which of the %d it was: not written anywhere)" % (len(inp["signature"]["s"]), len(inp["ring"])))
        else:
            print("  input %d  : development fund output %s:%d, spent in the open" % (i, short(inp["txid"], 12), inp["index"]))
    for out in tx["outputs"]:
        if "amount" in out:
            what = "%s, public (%s)" % (ctx.fmt(out["amount"]), "development fund share" if "ephemeral_secret" in out else "mining reward")
        else:
            what = "sealed amount"
        print("  output %d : one-time key %s   %s" % (out["index"], short(out["one_time_pub"], 14), what))
    proof = tx.get("range_proof")
    if proof:
        print("  one %d-byte proof that none of the %d sealed amounts is negative" % (
            32 * (9 + len(proof["L"]) + len(proof["R"])), len(tx["outputs"])))
    print("  size: %d bytes of JSON   (add --json to see every field)" % len(json.dumps(tx, separators=(",", ":"))))


# ----------------------------------------------------------------------------- payment proofs
def _write_proofs(proofs: list, out: str | None, txid: str, kind: str) -> None:
    for proof in proofs:
        path = out if out and len(proofs) == 1 else "%s-%s-%d.json" % (txid[:12], kind, proof["index"])
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(proof, fh, indent=2)
        print("Proof written to %s" % shown(path))
    print("It shows whoever gets it that this payment went to that address, and how much - nothing else.")
    print("Give it only to the person who needs it. They check it with:  python coin.py proof check <file>")


def cmd_proof(ctx: Ctx, args) -> None:
    import proofs
    if args.action == "check":
        try:
            with open(args.target, "r", encoding="utf-8") as fh:
                proof = json.load(fh)
        except (OSError, ValueError) as exc:
            raise CliError("cannot read %s (%s)" % (args.target, exc))
        d = ctx.api("GET", "/api/tx/%s" % proof.get("txid"))
        outputs = d["tx"]["outputs"]
        index = proof.get("index")
        if type(index) is not int or not 0 <= index < len(outputs):
            raise CliError("that transaction has no output %r" % (index,))
        try:
            amount = proofs.check_proof(proof, outputs[index], ctx.prefix)
        except ValueError as exc:
            raise CliError("the proof does NOT hold: %s" % exc)
        where = "in block %d, %d confirmation(s)" % (d["block"], d["confirmations"]) if d["block"] is not None else "NOT mined yet"
        print("The proof holds: output %d of transaction %s paid" % (index, short(proof["txid"], 16)))
        print("  %s" % proof["address"])
        print("  %s   (%s; proof made by the %s)" % (ctx.fmt(amount), where, "payer" if proof["kind"] == "payment" else "receiver"))
        return
    txid = args.target
    wallet = load_wallet(ctx, args.name, args.password)
    if args.action == "pay":
        entries = wallet.load_sent(os.path.join(ctx.data_dir, "wallets", "%s.sent" % args.name)).get(txid)
        if not entries:
            raise CliError("this wallet has no record of paying in %s (payments made before proofs existed have none)" % short(txid, 16))
        made = [proofs.payment_proof(txid, e["index"], e["address"], scalar_from_hex(e["r"]), ctx.prefix) for e in entries]
        _write_proofs(made, args.out, txid, "payment")
    else:
        d = ctx.api("GET", "/api/tx/%s" % txid)
        view = wallet.view_key()
        made = []
        for out in d["tx"]["outputs"]:
            opened = view.open(out)
            if opened is not None:
                made.append(proofs.receipt_proof(txid, out["index"], view.address_at(opened["address"]), out["ephemeral_pub"],
                                                 view.view_priv, ctx.prefix))
        if not made:
            raise CliError("no output of %s was paid to this wallet" % short(txid, 16))
        _write_proofs(made, args.out, txid, "receipt")


def cmd_peers(ctx: Ctx, args) -> None:
    if args.action == "add":
        if not args.url:
            raise CliError("usage: peers add http://host:port")
        d = ctx.api("POST", "/api/peers", {"peer": args.url})
        print("added" if d["added"] else "already known / not valid")
    else:
        d = ctx.api("GET", "/api/peers")
    print("Peers: %s" % (", ".join(d["peers"]) or "none"))


def cmd_reset_chain(ctx: Ctx, args) -> None:
    """Start the chain over.  Removes the saved blocks, mempool and peer list - never the wallets."""
    try:
        held = lock_data_dir(ctx.data_dir)        # never pull the chain file from under a running node
    except ChainError:
        raise CliError("a node is running on %s: stop it first (Ctrl+C in its window), then run reset-chain again"
                       % shown(ctx.data_dir))
    held.close()
    removed = []
    for name in ("chain.jsonl", "mempool.json", "peers.json", "verified_tip.json", "chain.jsonl.tmp", "mempool.json.tmp"):
        path = os.path.join(ctx.data_dir, name)
        if os.path.exists(path):
            os.remove(path)
            removed.append(name)
    print("Removed from %s: %s" % (ctx.data_dir, ", ".join(removed) or "nothing (no saved chain was there)"))
    wallets = sorted(glob.glob(os.path.join(ctx.data_dir, "wallets", "*.json")))
    print("Kept %d wallet file(s) in %s" % (len(wallets), shown(os.path.join(ctx.data_dir, "wallets"))))
    print("Stop the node first if it is running, then start it again: it begins from a fresh genesis block.")
    print("Coins on the old chain are gone; the wallet ADDRESSES still work on the new one.")


def cmd_validate(ctx: Ctx, args) -> None:
    print("Re-checking every block in %s from the genesis block (every proof of work, signature and sum)..." % shown(ctx.data_dir))
    started = time.time()
    try:
        chain = Blockchain(ctx.config, ctx.data_dir, recheck_work=True)
    except ChainError as exc:
        print("INVALID: %s" % exc)
        sys.exit(1)
    info = chain.info()
    print("Chain OK: %d blocks (height %d), %d transactions, %d outputs, %d spends, chain work 2^%s, supply %s - checked in %.1fs" % (
        len(chain.blocks), chain.height, len(chain.known_txids), info["output_count"], info["spend_count"], info["work_log2"], ctx.fmt(info["circulating_supply"]), time.time() - started))


def cmd_devfund(ctx: Ctx, args) -> None:
    """The development fund: a fixed share of each block reward, for a fixed number of blocks,
    paid to one published address and enforced by every node.  No premine, nothing for sale."""
    if args.action == "init":
        path = ctx.wallet_path("devfund")
        if os.path.exists(path):
            address = Wallet.public_info(path, ctx.prefix)["address"]
            print("A devfund wallet already exists: %s" % shown(path))
        else:
            print("Creating the development fund wallet. Its ADDRESS becomes part of the coin's rules;")
            print("its password protects every coin the fund will ever receive. Choose a strong one.")
            args.name = "devfund"
            address = cmd_wallet_new(ctx, args).address
        cfg_path = ctx.config["_path"]
        raw = {}
        if os.path.exists(cfg_path):
            with open(cfg_path, "r", encoding="utf-8") as fh:
                raw = json.load(fh)
        fund = raw.setdefault("consensus", {}).setdefault("dev_fund", dict(ctx.config["consensus"]["dev_fund"]))
        if fund.get("address") == address:
            print("config.json already names this address as the fund.")
        else:
            fund["address"] = address
            with open(cfg_path, "w", encoding="utf-8") as fh:
                json.dump(raw, fh, indent=2)
            print("")
            print("Wrote the fund address into %s" % shown(cfg_path))
            print("The fund is now part of the consensus rules: %d%% of each block reward for %d blocks." % (
                int(fund.get("percent", 0)), int(fund.get("duration_blocks", 0))))
            print("This changes the genesis block, so any chain already saved here no longer fits. Before starting the")
            print("node run:  python coin.py reset-chain   (removes the saved chain only - it never touches wallets).")
            print("Do NOT delete the data folder by hand: the fund wallet lives in %s" % shown(os.path.join(ctx.data_dir, "wallets")))
            print("Every other node needs the same config.json. BACK UP the devfund wallet file now.")
        return
    f = ctx.api("GET", "/api/info")["dev_fund"]
    if not f["enabled"]:
        print("Development fund: OFF. Turn it on with:  python coin.py devfund init")
        return
    print("Development fund: %d%% of each block reward for %d blocks, then nothing, forever." % (f["percent"], f["duration_blocks"]))
    print("Address   : %s" % f["address"])
    print("Status    : %s, %d block(s) remaining" % ("active" if f["active"] else "finished", f["blocks_remaining"]))
    print("Received  : %s   (lifetime total will be %s)" % (ctx.fmt(f["total_received"]), ctx.fmt(f["lifetime_total"])))
    print("Unspent   : %s" % ctx.fmt(f["unspent"]))
    print("Spent     : %s   (moved out of the fund's public outputs)" % ctx.fmt(f["spent"]))
    print("Every fund payment is a public amount to a publicly verifiable address. Nothing else on this chain is.")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Vesper wallet and node control.")
    parser.add_argument("--node")
    parser.add_argument("--proxy", help="reach a node on another computer through Tor, e.g. socks5h://127.0.0.1:9050 "
                                        "(that node still sees your payments; only your address is hidden from it)")
    parser.add_argument("--data-dir")
    parser.add_argument("--config")
    sub = parser.add_subparsers(dest="command", required=True)

    w = sub.add_parser("wallet", help="create / inspect wallets")
    w.add_argument("action", nargs="?", default="show",
                   choices=["new", "show", "list", "export-view", "new-address", "addresses", "restore", "recovery-code"])
    w.add_argument("--name", default="default")
    w.add_argument("--password")
    w.add_argument("--out")
    w.add_argument("--label", help="new-address: who this address is for (kept encrypted in the wallet)")
    w.add_argument("--code", help="restore: the recovery code (asked for, unseen, if left out)")
    w.set_defaults(func=lambda c, a: {"new": cmd_wallet_new, "show": cmd_wallet_show, "list": cmd_wallet_list,
                                      "export-view": cmd_wallet_export_view, "new-address": cmd_wallet_new_address,
                                      "addresses": cmd_wallet_addresses, "restore": cmd_wallet_restore,
                                      "recovery-code": cmd_wallet_recovery_code}[a.action](c, a))

    p = sub.add_parser("watch", help="balance using a view-key file only")
    p.add_argument("viewkey")
    p.set_defaults(func=cmd_watch)

    p = sub.add_parser("send", help="send coins")
    p.add_argument("to")
    p.add_argument("amount")
    p.add_argument("--fee")
    p.add_argument("--name", default="default")
    p.add_argument("--password")
    p.set_defaults(func=cmd_send)

    p = sub.add_parser("proof", help="prove one payment to one person: pay / receive / check")
    p.add_argument("action", choices=["pay", "receive", "check"])
    p.add_argument("target", help="pay, receive: the txid; check: the proof file")
    p.add_argument("--name", default="default")
    p.add_argument("--password")
    p.add_argument("--out")
    p.set_defaults(func=cmd_proof)

    p = sub.add_parser("mine", help="control mining on the node")
    p.add_argument("action", nargs="?", default="status", choices=["start", "stop", "status", "once"])
    p.add_argument("--blocks", type=int, default=1)
    p.add_argument("--address")
    p.add_argument("--name", default="default")
    p.set_defaults(func=cmd_mine)

    p = sub.add_parser("devfund", help="the development fund: init (one time) or show")
    p.add_argument("action", nargs="?", default="show", choices=["init", "show"])
    p.add_argument("--password")
    p.set_defaults(func=cmd_devfund)

    sub.add_parser("info").set_defaults(func=cmd_info)
    p = sub.add_parser("chain"); p.add_argument("--last", type=int, default=15); p.set_defaults(func=cmd_chain)
    p = sub.add_parser("block"); p.add_argument("key"); p.set_defaults(func=cmd_block)
    p = sub.add_parser("tx"); p.add_argument("txid"); p.add_argument("--json", action="store_true"); p.set_defaults(func=cmd_tx)
    p = sub.add_parser("peers"); p.add_argument("action", nargs="?", default="list", choices=["list", "add"]); p.add_argument("url", nargs="?"); p.set_defaults(func=cmd_peers)
    sub.add_parser("validate").set_defaults(func=cmd_validate)
    sub.add_parser("reset-chain", help="delete the saved chain (never the wallets) to start from a fresh genesis").set_defaults(func=cmd_reset_chain)
    return parser


def main(argv=None) -> None:
    args = build_parser().parse_args(argv)
    try:
        ctx = Ctx(args)
        args.func(ctx, args)
    except (CliError, WalletError, ChainError) as exc:
        print("ERROR: %s" % exc)
        sys.exit(1)
    except KeyboardInterrupt:
        print("")
        sys.exit(130)


if __name__ == "__main__":
    main()
