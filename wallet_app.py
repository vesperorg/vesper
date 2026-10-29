"""
wallet_app.py - the Vesper wallet for people who do not use a terminal.

Double-click wallet_app.bat (or run `python wallet_app.py`) and your browser opens a wallet page
served by this program, on this computer only (127.0.0.1).  It does the same things as
`coin.py wallet ...`, `coin.py send`, `coin.py proof ...`, with buttons instead of commands, and
it talks to the same node (start_node.bat) the command line talks to.

Safety, in plain words:
  - Nothing leaves this computer except what the command line would send too: requests to your
    node.  The page is served from 127.0.0.1 and refuses any other host or origin.
  - Every request from the page carries a token that is made fresh each time the program
    starts and exists only in the address the program opened for you.  A web page you visit
    elsewhere cannot talk to this program.
  - Your wallet is unlocked in this program's memory only while you use it (20 minutes of
    silence lock it again).  The password is never written anywhere.  Recovery codes and
    view keys are shown or downloaded; nothing is stored unencrypted.
  - It changes nothing in the node, except starting or stopping the miner when you ask.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import secrets
import sys
import threading
import time
import webbrowser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

import coin
import proofs
from chain import ChainError, build_transfer, to_units
from curve import scalar_from_hex
from privacy import is_valid_address
from wallet import Wallet, WalletError, WalletLocked

APP_VERSION = "0.1.0"
LOCK_AFTER_SECONDS = 20 * 60
HERE = os.path.dirname(os.path.abspath(__file__))


class AppError(Exception):
    pass


class Session:
    """The one unlocked wallet, held in memory while the person is using the page."""

    def __init__(self):
        self.lock = threading.Lock()
        self.name = None
        self.wallet = None
        self.password = None
        self.touched = 0.0
        self.last_owned = None
        self.last_tip = None

    def open(self, name: str, wallet: Wallet, password: str | None):
        self.name, self.wallet, self.password = name, wallet, password
        self.touched = time.time()
        self.last_owned, self.last_tip = None, None

    def close(self):
        self.name = self.wallet = self.password = None
        self.last_owned = self.last_tip = None

    def current(self) -> Wallet:
        if self.wallet is None:
            raise AppError("no wallet is open")
        if time.time() - self.touched > LOCK_AFTER_SECONDS:
            self.close()
            raise AppError("the wallet locked itself after 20 minutes without use; unlock it again")
        self.touched = time.time()
        return self.wallet


class App:
    def __init__(self, args):
        self.ctx = coin.Ctx(args)
        self.session = Session()
        self.token = secrets.token_urlsafe(24)
        self.port = int(args.port)
        self.sync_lock = threading.Lock()

    # ---- helpers -----------------------------------------------------------------------
    def fmt(self, units: int) -> str:
        return self.ctx.fmt(units)

    def wallet_files(self) -> list:
        folder = os.path.join(self.ctx.data_dir, "wallets")
        out = []
        if os.path.isdir(folder):
            for fn in sorted(os.listdir(folder)):
                if not fn.endswith(".json") or fn.endswith(".viewkey.json"):
                    continue
                path = os.path.join(folder, fn)
                name = fn[:-5]
                try:
                    info = Wallet.public_info(path, self.ctx.prefix)
                except (OSError, ValueError, KeyError):
                    out.append({"name": name, "unreadable": True})
                    continue
                if info.get("kind") == "view-key":
                    continue
                out.append({"name": name, "address": info["address"], "encrypted": info["encrypted"]})
        return out

    def node_info(self):
        try:
            d = self.ctx.api("GET", "/api/info", timeout=8)
        except coin.CliError as exc:
            return {"reachable": False, "error": str(exc), "url": self.ctx.node_url}
        miner = d.get("miner") or {}
        return {"reachable": True, "url": self.ctx.node_url, "network": d.get("network"), "version": d.get("version"),
                "height": d.get("height"), "peers": len(d.get("peers") or []), "ring_size": d.get("ring_size"),
                "lock_blocks": d.get("output_lock_blocks"), "block_seconds": d.get("target_block_seconds"),
                "mempool": d.get("mempool_size"), "miner_running": bool(miner.get("running")),
                "hashrate": miner.get("hashrate", 0), "blocks_found": miner.get("blocks_found", 0),
                "coin": d.get("coin"), "ticker": d.get("ticker")}

    def synced(self):
        """The open wallet's outputs and the node's view of the chain (one sync at a time)."""
        wallet = self.session.current()
        with self.sync_lock:
            started = time.time()
            for attempt in range(3):
                try:
                    owned, tip = self.ctx.sync(wallet, self.session.name)
                    break
                except coin.CliError as exc:
                    # a first scan is about a hundred requests; one dropped connection should not fail the whole thing
                    if attempt == 2 or "cannot reach the node" not in str(exc):
                        raise
                    time.sleep(1.5)
            self.session.last_owned, self.session.last_tip = owned, tip
            return owned, tip, time.time() - started

    def describe(self, owned: list, tip: dict, seconds: float) -> dict:
        waiting = coin.waiting_refs(tip)
        unspent = [u for u in owned if not u.get("spent")]
        spent = [u for u in owned if u.get("spent")]
        spendable_at = tip.get("spendable_outputs", 0)
        young = [u for u in unspent if u["output"]["position"] >= spendable_at]
        busy = [u for u in unspent if coin.is_waiting(u, waiting)]
        usable = [u for u in unspent if u not in young and u not in busy]
        rows = []
        for u in sorted(owned, key=lambda u: -u["output"]["position"]):
            kind = "fund share" if "ephemeral_secret" in u["output"] else ("mining reward" if "amount" in u["output"] else "payment")
            status = "spent" if u.get("spent") else ("locked" if u in young else ("waiting" if u in busy else "ready"))
            rows.append({"txid": u["txid"], "index": u["index"], "amount": self.fmt(u["amount"]), "units": u["amount"],
                         "kind": kind, "status": status, "address": u.get("address", 0), "position": u["output"]["position"]})
        return {"balance": self.fmt(sum(u["amount"] for u in unspent)), "balance_units": sum(u["amount"] for u in unspent),
                "usable": self.fmt(sum(u["amount"] for u in usable)), "usable_units": sum(u["amount"] for u in usable),
                "locked": self.fmt(sum(u["amount"] for u in young)),
                "waiting": self.fmt(sum(u["amount"] for u in busy)), "spent_total": self.fmt(sum(u["amount"] for u in spent)),
                "counts": {"unspent": len(unspent), "locked": len(young), "waiting": len(busy), "spent": len(spent)},
                "chain_outputs": tip.get("output_count", 0), "height": tip.get("height"), "scanned": tip.get("scanned", 0),
                "lock_blocks": tip.get("output_lock_blocks", 0), "seconds": round(seconds, 1), "outputs": rows}

    # ---- routes ------------------------------------------------------------------------
    def route(self, method: str, path: str, body: dict) -> dict:
        s = self.session
        ctx = self.ctx
        if method == "GET" and path == "/app/state":
            open_name = s.name if (s.wallet is not None and time.time() - s.touched <= LOCK_AFTER_SECONDS) else None
            if s.wallet is not None and open_name is None:
                s.close()
            return {"app_version": APP_VERSION, "coin": ctx.name, "ticker": ctx.ticker, "prefix": ctx.prefix,
                    "decimals": ctx.decimals, "data_dir": coin.shown(ctx.data_dir), "wallets": self.wallet_files(),
                    "open": open_name, "node": self.node_info()}

        if method == "POST" and path == "/app/wallet/create":
            name = clean_name(body.get("name") or "default")
            password = str(body.get("password") or "")
            if password != str(body.get("confirm") or ""):
                raise AppError("the two passwords are not the same")
            if len(password) < 8:
                raise AppError("choose a password of at least 8 characters; it is the only thing between a thief and your coins")
            path_ = ctx.wallet_path(name)
            if os.path.exists(path_):
                raise AppError("a wallet named %r already exists" % name)
            wallet = Wallet.generate(ctx.prefix)
            wallet.save(path_, password)
            s.open(name, wallet, password)
            return {"name": name, "address": wallet.address, "recovery_code": wallet.recovery_code()}

        if method == "POST" and path == "/app/wallet/restore":
            name = clean_name(body.get("name") or "default")
            password = str(body.get("password") or "")
            if password != str(body.get("confirm") or ""):
                raise AppError("the two passwords are not the same")
            if len(password) < 8:
                raise AppError("choose a password of at least 8 characters")
            path_ = ctx.wallet_path(name)
            if os.path.exists(path_):
                raise AppError("a wallet named %r already exists; restore under another name" % name)
            wallet = Wallet.from_code(str(body.get("code") or ""), ctx.prefix)
            wallet.save(path_, password)
            s.open(name, wallet, password)
            return {"name": name, "address": wallet.address}

        if method == "POST" and path == "/app/unlock":
            name = clean_name(body.get("name") or "default")
            path_ = ctx.wallet_path(name)
            if not os.path.exists(path_):
                raise AppError("no wallet named %r" % name)
            info = Wallet.public_info(path_, ctx.prefix)
            password = str(body.get("password") or "")
            if info["encrypted"]:
                if not password:
                    raise AppError("this wallet needs its password")
                try:
                    wallet = Wallet.load(path_, password, ctx.prefix)
                except WalletLocked:
                    raise AppError("wrong password")
            else:
                wallet = Wallet.load(path_, prefix=ctx.prefix)
                password = None
            s.open(name, wallet, password)
            return {"name": name, "address": wallet.address, "encrypted": info["encrypted"],
                    "has_code": wallet.recovery_code() is not None, "addresses": len(wallet.labels) + 1}

        if method == "POST" and path == "/app/lock":
            s.close()
            return {"ok": True}

        if method == "GET" and path == "/app/balance":
            owned, tip, seconds = self.synced()
            return self.describe(owned, tip, seconds)

        if method == "GET" and path == "/app/addresses":
            wallet = s.current()
            return {"addresses": [{"number": n, "address": a, "label": label} for n, a, label in wallet.addresses()]}

        if method == "POST" and path == "/app/addresses/new":
            wallet = s.current()
            label = str(body.get("label") or "").strip()[:60]
            number, address = wallet.new_address(label)
            wallet.save(ctx.wallet_path(s.name), s.password)
            return {"number": number, "address": address, "label": label}

        if method == "POST" and path == "/app/send/check":
            return self.check_payment(body)

        if method == "POST" and path == "/app/send":
            return self.send(body)

        if method == "GET" and path == "/app/history":
            wallet = s.current()
            owned = s.last_owned
            tip = s.last_tip
            if owned is None:
                owned, tip, _ = self.synced()
            incoming = self.describe(owned, tip or {}, 0)["outputs"]
            log = wallet.load_sent(os.path.join(ctx.data_dir, "wallets", "%s.sent" % s.name))
            outgoing = [{"txid": txid, "to": [{"address": e["address"], "amount": self.fmt(int(e["amount"]))} for e in entries]}
                        for txid, entries in log.items()]
            return {"incoming": incoming, "outgoing": list(reversed(outgoing))}

        if method == "POST" and path == "/app/proof/pay":
            wallet = s.current()
            txid = str(body.get("txid") or "").strip().lower()
            entries = wallet.load_sent(os.path.join(ctx.data_dir, "wallets", "%s.sent" % s.name)).get(txid)
            if not entries:
                raise AppError("this wallet has no record of paying in that transaction")
            made = [proofs.payment_proof(txid, e["index"], e["address"], scalar_from_hex(e["r"]), ctx.prefix) for e in entries]
            return {"proofs": made}

        if method == "POST" and path == "/app/proof/receive":
            wallet = s.current()
            txid = str(body.get("txid") or "").strip().lower()
            d = ctx.api("GET", "/api/tx/%s" % txid)
            view = wallet.view_key()
            made = []
            for out in d["tx"]["outputs"]:
                opened = view.open(out)
                if opened is not None:
                    made.append(proofs.receipt_proof(txid, out["index"], view.address_at(opened["address"]), out["ephemeral_pub"],
                                                     view.view_priv, ctx.prefix))
            if not made:
                raise AppError("no output of that transaction was paid to this wallet")
            return {"proofs": made}

        if method == "POST" and path == "/app/proof/check":
            proof = body.get("proof")
            if isinstance(proof, str):
                try:
                    proof = json.loads(proof)
                except ValueError:
                    raise AppError("that is not a Vesper payment proof (not valid JSON)")
            if not isinstance(proof, dict) or "txid" not in proof:
                raise AppError("that is not a Vesper payment proof")
            try:
                d = ctx.api("GET", "/api/tx/%s" % proof.get("txid"))
            except coin.CliError as exc:
                if "no such transaction" in str(exc):
                    raise AppError("the node does not know this payment yet. A payment just sent can take a minute or two to be "
                                   "announced and mined; try again then. If it never appears, this receipt is for a payment that was never made.")
                raise
            outputs = d["tx"]["outputs"]
            index = proof.get("index")
            if type(index) is not int or not 0 <= index < len(outputs):
                raise AppError("that transaction has no output %r" % (index,))
            try:
                amount = proofs.check_proof(proof, outputs[index], ctx.prefix)
            except ValueError as exc:
                raise AppError("the proof does NOT hold: %s" % exc)
            return {"holds": True, "address": proof["address"], "amount": self.fmt(amount), "txid": proof["txid"],
                    "block": d.get("block"), "confirmations": d.get("confirmations"), "stem": bool(d.get("stem")),
                    "made_by": "payer" if proof.get("kind") == "payment" else "receiver"}

        if method == "GET" and path == "/app/viewkey":
            wallet = s.current()
            owned = s.last_owned
            markers = {"%s:%d" % (u["txid"], u["index"]): u["key_image"] for u in (owned or []) if "key_image" in u}
            return {"file": {"version": 3, "kind": "view-key", "address_prefix": ctx.prefix, "address": wallet.address,
                             "view_key": wallet.view_key().to_dict(), "key_images": markers,
                             "note": "This key can FIND payments to the address above and to the wallet's %d other address(es), "
                                     "and open their amounts. It can never spend them." % len(wallet.labels)},
                    "with_markers": owned is not None}

        if method == "POST" and path == "/app/recovery":
            wallet = s.current()
            if s.password is not None and str(body.get("password") or "") != s.password:
                raise AppError("wrong password")
            code = wallet.recovery_code()
            if code is None:
                raise AppError("this wallet was made before recovery codes existed; back up its file instead")
            return {"recovery_code": code}

        if method == "POST" and path == "/app/mine":
            wallet = s.current()
            action = body.get("action")
            if action == "start":
                st = ctx.api("POST", "/api/miner/start", {"address": wallet.address})
            elif action == "stop":
                st = ctx.api("POST", "/api/miner/stop", {})
            else:
                st = ctx.api("GET", "/api/miner")
            own = {a for _, a, _ in wallet.addresses()}
            addr = str(st.get("address") or "")
            return {"running": bool(st.get("running")), "hashrate": st.get("hashrate", 0), "blocks_found": st.get("blocks_found", 0),
                    "to_this_wallet": bool(st.get("running")) and addr in own, "miner_address_start": addr[:12]}

        raise AppError("unknown request %s %s" % (method, path))

    # ---- paying -------------------------------------------------------------------------
    def check_payment(self, body: dict) -> dict:
        ctx = self.ctx
        wallet = self.session.current()
        to = str(body.get("to") or "").strip()
        if not is_valid_address(to, ctx.prefix):
            raise AppError("that is not a valid %s address (they start with %r and are %d characters: two keys plus a checksum)"
                           % (ctx.ticker, ctx.prefix, len(wallet.address)))
        try:
            amount = to_units(str(body.get("amount") or ""), ctx.decimals)
        except ValueError as exc:
            raise AppError(str(exc))
        if amount <= 0:
            raise AppError("the amount must be more than zero")
        own = {a for _, a, _ in wallet.addresses()}
        last_owned = getattr(self.session, "last_owned", None)
        last_tip = getattr(self.session, "last_tip", None)
        if last_owned is not None and last_tip:
            # checked against the last balance the app read, so the "you cannot afford this" answer comes before the confirm step
            view = self.describe(last_owned, last_tip, 0)
            if amount + ctx.min_fee > view["usable_units"]:
                extra = []
                if view["counts"]["locked"]:
                    extra.append("%s more unlocks within %d blocks" % (view["locked"], view["lock_blocks"]))
                if view["counts"]["waiting"]:
                    extra.append("%s is in a payment still being mined" % view["waiting"])
                raise AppError("that is more than you can spend right now: %s ready to spend, and a fee of at least %s%s"
                               % (view["usable"], self.fmt(ctx.min_fee), (" (" + "; ".join(extra) + ")") if extra else ""))
        return {"to": to, "amount": self.fmt(amount), "amount_units": amount, "own_address": to in own,
                "fee_note": "the fee is the fixed minimum for a payment of this size, the same for everyone; it is shown after sending"}

    def send(self, body: dict) -> dict:
        ctx = self.ctx
        checked = self.check_payment(body)
        if checked["own_address"] and not body.get("allow_self"):
            raise AppError("that is one of your own addresses; paying yourself only costs the fee")
        wallet = self.session.current()
        name = self.session.name
        owned, tip, _ = self.synced()
        waiting = coin.waiting_refs(tip)
        unspent = [u for u in owned if not u["spent"]]
        spendable = [u for u in unspent if not coin.is_waiting(u, waiting) and u["output"]["position"] < tip["spendable_outputs"]]
        ring_size = int(ctx.config["consensus"]["ring_size"])
        rings_path = os.path.join(ctx.data_dir, "wallets", "%s.rings" % name)
        rings = wallet.load_rings(rings_path)
        proof_secrets: list = []
        started = time.time()
        try:
            tx = build_transfer(wallet.keys, spendable, [(checked["to"], checked["amount_units"])], None, ctx.prefix,
                                coin.NodeRings(ctx, tip["spendable_outputs"], tip), ring_size, min_fee=ctx.min_fee,
                                known_rings=rings, fmt=ctx.fmt, sent=proof_secrets)
        except ValueError as exc:
            held_back = sum(u["amount"] for u in unspent) - sum(u["amount"] for u in spendable)
            if held_back and "insufficient" in str(exc):
                raise AppError("%s. Another %s is yours but cannot be spent yet: it is less than %d blocks old, or already in a "
                               "payment that is waiting to be mined. Try again in a few minutes."
                               % (exc, self.fmt(held_back), tip.get("output_lock_blocks", 0)))
            raise AppError(str(exc))
        built = time.time() - started
        used = {i["key_image"] for i in tx["inputs"] if "key_image" in i}
        mixed = sorted({u.get("address", 0) for u in spendable if u.get("key_image") in used})
        wallet.save_rings(rings_path, rings)
        sent = ctx.api("POST", "/api/tx", tx)
        sent_path = os.path.join(ctx.data_dir, "wallets", "%s.sent" % name)
        log = wallet.load_sent(sent_path)
        log[tx["txid"]] = proof_secrets
        wallet.save_sent(sent_path, log)
        self.session.last_owned = None            # the balance changed; read it again next time
        return {"txid": tx["txid"], "amount": checked["amount"], "fee": self.fmt(tx["fee"]), "to": checked["to"],
                "inputs": len(tx["inputs"]), "outputs": len(tx["outputs"]), "ring_size": ring_size,
                "seconds": round(built, 2), "relay": sent.get("relay"), "mixed_addresses": mixed if len(mixed) > 1 else []}


def clean_name(name: str) -> str:
    name = str(name).strip()
    # the same rule as coin.Ctx.wallet_path, so a name never gets as far as a file-system error
    if not re.fullmatch(r"[A-Za-z0-9_][A-Za-z0-9_.-]{0,39}", name):
        raise AppError("a wallet name is 1 to 40 letters, digits, '_', '-' or '.', with no spaces; for example: savings")
    return name


class Handler(BaseHTTPRequestHandler):
    app: App = None   # set by serve()
    server_version = "VesperWallet/" + APP_VERSION
    sys_version = ""

    def log_message(self, fmt, *args):           # quiet; errors still reach the console
        return

    def _reject(self, code: int, message: str):
        self._json(code, {"error": message})

    def _json(self, code: int, payload):
        data = json.dumps(payload).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("Referrer-Policy", "no-referrer")
        self.end_headers()
        self.wfile.write(data)

    def _local(self) -> bool:
        host = (self.headers.get("Host") or "").lower()
        allowed = {"127.0.0.1:%d" % self.app.port, "localhost:%d" % self.app.port}
        if host not in allowed:
            return False
        origin = self.headers.get("Origin")
        if origin and origin.lower() not in {"http://127.0.0.1:%d" % self.app.port, "http://localhost:%d" % self.app.port}:
            return False
        return True

    def _authorised(self) -> bool:
        return secrets.compare_digest(self.headers.get("X-App-Token") or "", self.app.token)

    def do_GET(self):
        if not self._local():
            return self._reject(403, "this wallet page is served to this computer only")
        url = urlparse(self.path)
        if url.path == "/":
            token = (parse_qs(url.query).get("t") or [""])[0]
            if not secrets.compare_digest(token, self.app.token):
                return self._html(403, "<p style='font-family:sans-serif'>Open the wallet from the window that started it "
                                       "(wallet_app.bat prints the address), not from a bookmark: the address changes every start.</p>")
            try:
                with open(os.path.join(HERE, "wallet_app.html"), "r", encoding="utf-8") as fh:
                    page = fh.read()
            except OSError:
                return self._html(500, "<p>wallet_app.html is missing next to wallet_app.py</p>")
            return self._html(200, page)
        if url.path.startswith("/app/"):
            if not self._authorised():
                return self._reject(401, "missing or stale token; reopen the wallet from its window")
            return self._dispatch("GET", url.path, {})
        return self._reject(404, "not found")

    def do_POST(self):
        if not self._local():
            return self._reject(403, "this wallet page is served to this computer only")
        if not self._authorised():
            return self._reject(401, "missing or stale token; reopen the wallet from its window")
        length = int(self.headers.get("Content-Length") or 0)
        if length > 1_000_000:
            return self._reject(413, "request too large")
        raw = self.rfile.read(length) if length else b""
        try:
            body = json.loads(raw.decode("utf-8")) if raw else {}
        except ValueError:
            return self._reject(400, "bad JSON")
        if not isinstance(body, dict):
            return self._reject(400, "bad request")
        return self._dispatch("POST", urlparse(self.path).path, body)

    def _dispatch(self, method, path, body):
        try:
            return self._json(200, self.app.route(method, path, body))
        except (AppError, coin.CliError, WalletError, ChainError) as exc:
            return self._json(400, {"error": str(exc)})
        except Exception as exc:                                   # never show a traceback to the person
            sys.stderr.write("wallet_app: %s %s failed: %r\n" % (method, path, exc))
            return self._json(500, {"error": "something went wrong inside the wallet (%s); the details are in its window" % type(exc).__name__})

    def _html(self, code: int, page: str):
        data = page.encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Content-Security-Policy", "default-src 'self'; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
                                                    "font-src https://fonts.gstatic.com; script-src 'self' 'unsafe-inline'; connect-src 'self'; img-src 'self' data:")
        self.end_headers()
        self.wfile.write(data)


def serve(args) -> None:
    app = App(args)
    Handler.app = app
    try:
        httpd = ThreadingHTTPServer(("127.0.0.1", app.port), Handler)
    except OSError as exc:
        print("Cannot listen on 127.0.0.1:%d (%s). Is another wallet window already open? Close it, or run with --port 8887." % (app.port, exc))
        sys.exit(1)
    url = "http://127.0.0.1:%d/?t=%s" % (app.port, app.token)
    print("Vesper wallet (app v%s) for %s on %s" % (APP_VERSION, app.ctx.ticker, coin.shown(app.ctx.data_dir)))
    print("Node: %s" % app.ctx.node_url)
    print("")
    print("Open this address in your browser (it is only reachable from this computer):")
    print("  %s" % url)
    print("")
    print("Keep this window open while you use the wallet. Close it to stop the wallet.", flush=True)
    if not args.no_browser:
        threading.Timer(0.6, lambda: webbrowser.open(url)).start()
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        app.session.close()
        httpd.server_close()


def main(argv=None) -> None:
    parser = argparse.ArgumentParser(description="The Vesper wallet, as a page in your browser (this computer only).")
    parser.add_argument("--node", help="the node to talk to (default: the one in config.json, usually your own)")
    parser.add_argument("--proxy", help="reach a node elsewhere through Tor, e.g. socks5h://127.0.0.1:9150")
    parser.add_argument("--data-dir")
    parser.add_argument("--config")
    parser.add_argument("--port", type=int, default=8886, help="where the wallet page listens on this computer (default 8886)")
    parser.add_argument("--no-browser", action="store_true", help="do not open the browser automatically")
    args = parser.parse_args(argv)
    try:
        serve(args)
    except coin.CliError as exc:
        print("ERROR: %s" % exc)
        sys.exit(1)


if __name__ == "__main__":
    main()
