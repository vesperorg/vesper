"""
node.py - one Vesper node: HTTP API + block explorer + peer sync + optional miner.

Run:  python node.py --mine               (or double-click start_node.bat)
      python node.py --port 8881 --data-dir data2 --peer http://127.0.0.1:8880

What a node knows: every block, every output ever made, the proof-of-work.  What a node does
NOT know: who owns anything, how much any payment was, or which outputs have been spent.

Who may ask it what:
  anyone who can reach the port   read the chain, submit a transaction or a block
  this computer only              start or stop the miner, see which address the rewards go to
  a web page in your browser      nothing.  Requests that come from another site are refused,
                                  so a page you happen to visit cannot point your miner at
                                  somebody else's wallet or read your node on your behalf.

Phase 4 (relay.py): a payment handed in by a wallet is not broadcast from here.  It is passed
quietly to one peer, which passes it to one more, and so on for about ten hops, before some
node broadcasts it.  The first broadcast therefore does not point at the sender's computer.
Every address that talks to the node is limited in how much it may ask, and one that sends
blocks or payments that break the rules is ignored for an hour.

Still missing before this faces the open internet: encryption between nodes (run it behind Tor
or a VPN for that), and a node written in a faster language.
"""

from __future__ import annotations

import argparse
import ipaddress
import json
import logging
import os
import sys
import threading
import time
import urllib.error
import urllib.request
from collections import deque
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

from chain import (BLOCK_KEYS, HERE, MAX_LOOKUP, Blockchain, ChainError, compute_block_hash, disable_windows_power_throttling,
                   load_config, lock_data_dir, resolve_data_dir)
import socket
import socksproxy
from pool import PoolError, ShareChain, mine_share
from powpool import PowPool, default_processes
from privacy import is_valid_address
from relay import LOCAL, BanList, RateLimiter, StemRouter
from wallet import Wallet

VERSION = "0.9.1"
PEERS_FILE = "peers.json"
SYNC_BATCH = 100
BRANCH_HOLD_SECONDS = 120              # a branch handed over in batches is forgotten if the next batch is this late
MAX_ANSWER = 16 * 1024 * 1024          # the most this node reads of one peer's answer (big blocks: asked for fewer at a time)


class AnswerTooBig(Exception):
    pass
LOOPBACK = ("127.0.0.1", "::1", "::ffff:127.0.0.1")
LOCAL_NAMES = ("127.0.0.1", "localhost", "::1")
MAX_BODY = 8 * 1024 * 1024             # a full block of payments is about 2 MB of JSON
MAX_CONNECTIONS = 64                   # requests handled at once; the rest are turned away
MAX_PER_ADDRESS = 8                    # of those, from any one internet address (this computer: no limit)
REQUEST_TIMEOUT = 20                   # seconds a connection may sit silent before it is closed
# The peer table.  A node that takes every address a peer hands it can have all its slots filled
# by one attacker (an "eclipse"): then the attacker decides what the node sees, and every stem
# starts on an attacker's node.  So gossip only suggests; this node checks, and keeps its peers spread.
MAX_PEERS = 50                         # peers kept (the ones you configure yourself do not count against it)
MAX_CANDIDATES = 500                   # addresses heard about but not yet checked
GOSSIP_PER_PEER = 8                    # new addresses taken from one peer's list per round
PROMOTE_PER_ROUND = 2                  # candidates checked and taken on per round
MAX_PER_GROUP = 2                      # peers from one network block (IPv4 /16, IPv6 /32, one domain)
DROP_AFTER_FAILURES = 20               # rounds a peer may fail to answer before it is dropped (your own: never)


def address_kind(peer: str) -> str:
    """"loopback", "private" (home or office network), "public", or "name" for a host name."""
    host = (urlparse(peer).hostname or "").lower()
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        return "loopback" if host in LOCAL_NAMES else "name"
    if ip.is_loopback:
        return "loopback"
    if ip.is_private or ip.is_link_local or ip.is_reserved or ip.is_multicast or ip.is_unspecified:
        return "private"
    return "public"


def network_group(peer: str) -> str | None:
    """Peers in one group are probably run by one party: the same IPv4 /16, IPv6 /32 or domain.
    None for addresses on this computer or a home network: a test network there is no attack."""
    if address_kind(peer) in ("loopback", "private"):
        return None
    host = (urlparse(peer).hostname or "").lower()
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        return "name:" + ".".join(host.split(".")[-2:])
    return "ip:" + ip.packed[:2 if ip.version == 4 else 4].hex()
log = logging.getLogger("node")


class Miner:
    def __init__(self, node: "Node"):
        self.node = node
        self.address: str | None = None
        self._thread: threading.Thread | None = None
        self._stop = threading.Event()
        self._lock = threading.Lock()
        self.total_hashes = 0
        self.blocks_found = 0
        self.started_at: float | None = None
        self._window: deque = deque()
        configured = node.config["mining"].get("processes")
        self.processes = int(configured) if configured else default_processes()
        self.pool: PowPool | None = None

    @property
    def running(self) -> bool:
        return self._thread is not None and self._thread.is_alive()

    def start_mining(self, address: str | None = None) -> dict:
        address = address or self.node.reward_address
        if not address:
            raise ChainError("no reward address: create a wallet first (wallet.bat) or pass an address")
        if not is_valid_address(address, self.node.chain.prefix):
            raise ChainError("not a valid %s address: %s" % (self.node.chain.ticker, address))
        with self._lock:
            if self.running:
                if address == self.address:
                    return self.status()
                self.stop()
            self.address = address
            self._stop.clear()
            self.started_at = time.time()
            self._window.clear()
            self._thread = threading.Thread(target=self._run, name="miner", daemon=True)
            self._thread.start()
        log.info("miner started - rewards go to %s...", address[:16])
        return self.status()

    def stop(self) -> dict:
        was_running = self.running
        self._stop.set()
        thread = self._thread
        if thread and thread.is_alive() and thread is not threading.current_thread():
            thread.join(timeout=10)
        self._thread = None
        if was_running:
            log.info("miner stopped")
        return self.status()

    def _run(self) -> None:
        per_check = int(self.node.config["mining"].get("hashes_per_check", 20000))
        chain = self.node.chain
        if self.processes > 1 and chain.pow_algorithm != "sha256d":
            try:
                self.pool = PowPool(self.processes, chain.pow_algorithm, chain.pow_memory_kib, chain.pow_passes)
                log.info("mining on %d CPU cores (change with --processes)", self.processes)
            except Exception as exc:
                log.warning("could not start mining processes (%s); mining on one core", exc)
                self.pool = None
        try:
            self._mine(per_check)
        finally:
            if self.pool is not None:
                self.pool.close()
                self.pool = None

    def may_mine(self) -> bool:
        """Not while this node is catching up with a peer that is ahead of it, nor before it has
        asked its peers once (two minutes at most).  Blocks mined on an old tip are thrown away,
        and a node that mines while it downloads keeps clashing with the chain it is fetching."""
        if self.node.catching_up.is_set():
            return False
        return self.node.first_sync_done.is_set() or time.time() - (self.started_at or 0) > 120

    def _mine(self, per_check: int) -> None:
        waiting = False
        while not self._stop.is_set():
            if not self.may_mine():
                if not waiting:
                    log.info("mining waits until this node has caught up with the network")
                    waiting = True
                self._stop.wait(1)
                continue
            if waiting:
                log.info("caught up - mining")
                waiting = False
            if self.node.sharechain is not None:
                self._mine_share()
                continue
            try:
                block = self.node.chain.mine_block(self.address,
                                                   should_abort=lambda: self._stop.is_set() or self.node.catching_up.is_set(),
                                                   hashes_per_check=per_check, on_progress=self._progress, pool=self.pool)
            except RuntimeError as exc:                  # the worker processes died: carry on, on one core
                log.warning("%s; mining continues on one core", exc)
                if self.pool is not None:
                    self.pool.close()
                self.pool = None
                continue
            except ChainError as exc:
                log.warning("mining problem: %s", exc)
                self._stop.wait(2)
                continue
            if block is not None:
                self.blocks_found += 1
                self.node.on_block_mined(block)

    def _mine_share(self) -> None:
        """One round of pool mining: search for a share until one is found or what it builds on changes."""
        try:
            result = mine_share(self.node.sharechain, self.address, pow_pool=self.pool, on_progress=self._progress,
                                should_abort=lambda: self._stop.is_set() or self.node.catching_up.is_set())
        except RuntimeError as exc:                      # the worker processes died: carry on, on one core
            log.warning("%s; mining continues on one core", exc)
            if self.pool is not None:
                self.pool.close()
            self.pool = None
            return
        except ChainError as exc:
            log.warning("pool mining problem: %s", exc)
            self._stop.wait(2)
            return
        if result is not None:
            self.node.on_share_mined(*result)

    def _progress(self, hashes: int) -> None:
        self.total_hashes += hashes
        now = time.time()
        self._window.append((now, hashes))
        while self._window and now - self._window[0][0] > 10:
            self._window.popleft()

    def hashrate(self) -> float:
        if len(self._window) < 2:
            return 0.0
        span = self._window[-1][0] - self._window[0][0]
        return sum(h for _, h in self._window) / span if span > 0 else 0.0

    def status(self, private: bool = True) -> dict:
        """private=False leaves out the reward address: that is the owner's wallet address, and
        a privacy coin's node has no business handing it to every peer that asks."""
        return {"running": self.running, "address": self.address if private else None, "hashrate": round(self.hashrate()),
                "processes": self.processes,
                "total_hashes": self.total_hashes, "blocks_found": self.blocks_found, "started_at": self.started_at}


class Node:
    def __init__(self, config: dict, data_dir: str, host: str, port: int,
                 extra_peers: list[str] | None, reward_address: str | None, public_url: str | None = None):
        self.config = config
        self.data_dir = data_dir
        self.host, self.port = host, port
        self.url = public_url or "http://%s:%d" % ("127.0.0.1" if host in ("0.0.0.0", "") else host, port)
        self.reward_address = reward_address
        self.started = time.time()
        self.stop_event = threading.Event()
        self.sync_interval = int(config["network"].get("sync_interval_seconds", 15))
        self.proxy = config["network"].get("proxy") or None
        self.opener = socksproxy.opener(self.proxy)          # every connection to a peer goes through this
        # Behind a proxy the node keeps its own address to itself, unless it is an onion address.
        hidden = bool(self.proxy) and not (urlparse(self.url).hostname or "").endswith(".onion")
        self.announce_url = None if hidden else self.url
        self.chain = Blockchain(config, data_dir)
        if self.chain.repaired:
            height, reason, damaged = self.chain.repaired
            log.warning("block %d in the saved chain was damaged (%s). Kept the %d block(s) before it; the rest will "
                        "be fetched from peers and checked again. The damaged file was kept as %s",
                        height, reason, height, os.path.basename(damaged))
        self.miner = Miner(self)
        self.peers: set[str] = set()
        self.peer_origin: dict[str, str] = {}         # "anchor" (yours), "gossip" (checked), "announced" (came to us)
        self.candidates: dict[str, float] = {}        # heard about, not yet checked (oldest first)
        self.peer_failures: dict[str, int] = {}
        self._seen: dict[str, float] = {}
        self._seen_lock = threading.Lock()
        self._sync_lock = threading.Lock()
        self.sharechain = None                        # set when this node mines in a pool (--pool)
        pool_rules = config.get("pool") or {}
        if pool_rules.get("enabled"):
            try:
                self.sharechain = ShareChain(self.chain, {k: v for k, v in pool_rules.items() if k != "enabled"})
            except PoolError as exc:
                raise ChainError("this network's rules do not allow pool blocks (%s). A pool runs on a network whose "
                                 "rules set consensus.max_coinbase_outputs." % exc)
        self.shares_found = 0
        self.catching_up = threading.Event()          # set while a peer ahead of us is being caught up with
        self.first_sync_done = threading.Event()      # set once every peer has been asked
        self._inbound = None                          # (sender, fork, last batch time): a branch being handed to us
        self._inbound_lock = threading.Lock()
        # phase 4: payments on their way along a stem, and the limits per internet address
        self.router = StemRouter()
        self.stempool: dict[str, dict] = {}            # txid -> {"tx", "deadline", "spends"}
        self._stem_lock = threading.Lock()
        self.limits = RateLimiter()
        self.bans = BanList()
        self.spawn = lambda fn, *args: threading.Thread(target=fn, args=args, daemon=True).start()
        for peer in list(config["network"].get("peers", [])) + list(extra_peers or []):
            self.add_peer(peer, announce=False, save=False, origin="anchor")
        for peer, origin in self._load_peers():
            self.add_peer(peer, announce=False, save=False, origin=origin)
        self._save_peers()
        if not self.peers:
            self.first_sync_done.set()                # nobody to ask: nothing to wait for

    # ---- peers --------------------------------------------------------------
    @staticmethod
    def normalize_peer(url) -> str | None:
        if not isinstance(url, str):
            return None
        url = url.strip().rstrip("/")
        if not url:
            return None
        if "://" not in url:
            url = "http://" + url
        parsed = urlparse(url)
        if parsed.scheme not in ("http", "https") or not parsed.netloc or parsed.path not in ("", "/"):
            return None
        return "%s://%s" % (parsed.scheme, parsed.netloc.replace("localhost", "127.0.0.1"))

    def add_peer(self, url, announce: bool = True, save: bool = True, origin: str = "announced") -> bool:
        """`origin`: "anchor" for a peer you named (config, --peer, by hand on this computer),
        "gossip" for one this node checked after another peer mentioned it, "announced" for one
        that came and introduced itself.  Only anchors may go past the limits."""
        peer = self.normalize_peer(url)
        if not peer or peer == self.url or peer in self.peers:
            return False
        if origin != "anchor":
            if len(self.peers) >= MAX_PEERS:
                return False
            group = network_group(peer)
            if group and sum(1 for p in self.peers if network_group(p) == group) >= MAX_PER_GROUP:
                return False
        self.peers.add(peer)
        self.peer_origin[peer] = origin
        self.candidates.pop(peer, None)
        log.info("new peer %s (%s)", peer, origin)
        if save:
            self._save_peers()
        if announce:
            if self.announce_url:
                threading.Thread(target=self._post, args=(peer, "/api/peers", {"peer": self.announce_url}), daemon=True).start()
        return True

    def claimed_peer(self, claimed, client_ip: str) -> str | None:
        """A node that says "I am http://X" is believed only if the connection really comes from
        X.  Otherwise anyone could make this node go and fetch things from an address of their
        choosing - including machines on your home network that are not on the internet."""
        peer = self.normalize_peer(claimed)
        if not peer:
            return None
        host = (urlparse(peer).hostname or "").lower()
        if host == client_ip.lower() or (host in LOCAL_NAMES and client_ip in LOOPBACK):
            return peer
        return None

    def _load_peers(self) -> list[tuple[str, str]]:
        try:
            with open(os.path.join(self.data_dir, PEERS_FILE), "r", encoding="utf-8") as fh:
                data = json.load(fh)
        except (OSError, ValueError):
            return []
        if isinstance(data, list):                       # the old file: a plain list, origin unknown
            return [(p, "gossip") for p in data if isinstance(p, str)]
        rows = data.get("peers") if isinstance(data, dict) else None
        return [(r["url"], r.get("origin") if r.get("origin") in ("anchor", "gossip", "announced") else "gossip")
                for r in rows or [] if isinstance(r, dict) and isinstance(r.get("url"), str)]

    def _save_peers(self) -> None:
        try:
            with open(os.path.join(self.data_dir, PEERS_FILE), "w", encoding="utf-8") as fh:
                json.dump({"peers": [{"url": p, "origin": self.peer_origin.get(p, "gossip")} for p in sorted(self.peers)]}, fh, indent=2)
        except OSError as exc:
            log.warning("could not save peers: %s", exc)

    def consider(self, url, budget: list) -> None:
        """An address another peer mentioned.  Only noted down; promote_candidates checks it."""
        peer = self.normalize_peer(url)
        if not peer or peer == self.url or peer in self.peers or peer in self.candidates or budget[0] <= 0:
            return
        if address_kind(peer) in ("loopback", "private") and address_kind(self.url) not in ("loopback", "private"):
            return                     # a public node is never sent to machines on someone's home network
        budget[0] -= 1
        self.candidates[peer] = time.time()
        while len(self.candidates) > MAX_CANDIDATES:
            del self.candidates[next(iter(self.candidates))]

    def promote_candidates(self) -> int:
        """Check a couple of noted addresses: they must answer, and be on this coin's chain."""
        taken = 0
        genesis = self.chain.blocks.hash_at(0)
        for peer in list(self.candidates):
            if taken >= PROMOTE_PER_ROUND or len(self.peers) >= MAX_PEERS:
                break
            del self.candidates[peer]
            group = network_group(peer)
            if group and sum(1 for p in self.peers if network_group(p) == group) >= MAX_PER_GROUP:
                continue
            try:
                info = self._get(peer, "/api/info", timeout=5)
            except Exception:
                continue
            if isinstance(info, dict) and info.get("genesis_hash") == genesis and self.add_peer(peer, announce=True, origin="gossip"):
                taken += 1
        return taken

    def relay_peers(self) -> list[str]:
        """Who stems may be passed to: peers this node chose itself.  One that merely introduced
        itself could be an attacker collecting the first hop of every payment."""
        own = [p for p in self.peers if self.peer_origin.get(p) != "announced"]
        return sorted(own or self.peers)

    def _request(self, peer: str, method: str, path: str, payload=None, timeout: float = 5):
        data = json.dumps(payload).encode("utf-8") if payload is not None else None
        req = urllib.request.Request(peer + path, data=data, method=method,
                                     headers=dict({"Content-Type": "application/json"}, **({"X-Node-Url": self.announce_url} if self.announce_url else {})))
        try:
            with self.opener.open(req, timeout=timeout) as resp:
                raw = resp.read(MAX_ANSWER + 1)               # a peer cannot make this node swallow gigabytes
            if len(raw) > MAX_ANSWER:
                raise AnswerTooBig("%s sent more than %d bytes" % (peer, MAX_ANSWER))
            body = raw.decode("utf-8")
            self.peer_failures[peer] = 0
            return json.loads(body) if body else {}
        except Exception:
            failures = self.peer_failures.get(peer, 0) + 1
            self.peer_failures[peer] = failures
            if failures == 3:
                log.warning("peer %s is not answering", peer)
            raise

    def _get(self, peer: str, path: str, timeout: float = 5):
        return self._request(peer, "GET", path, None, timeout)

    def _post(self, peer: str, path: str, payload, timeout: float = 5):
        try:
            return self._request(peer, "POST", path, payload, timeout)
        except Exception as exc:
            log.debug("post %s%s failed: %s", peer, path, exc)
            return None

    def broadcast(self, path: str, payload, skip: str | None = None) -> None:
        for peer in list(self.peers):
            if peer != skip:
                self.spawn(self._post, peer, path, payload)

    def _mark_seen(self, key: str) -> bool:
        with self._seen_lock:
            if key in self._seen:
                return False
            self._seen[key] = time.time()
            if len(self._seen) > 20000:
                cutoff = sorted(self._seen.values())[len(self._seen) // 2]
                self._seen = {k: v for k, v in self._seen.items() if v > cutoff}
            return True

    # ---- payments: the stem (quiet, one peer at a time) and the fluff (broadcast) ----------
    @staticmethod
    def _spends(tx: dict) -> set:
        """The spent markers a payment uses: key images, and fund outputs spent by name."""
        out = set()
        for inp in tx.get("inputs") or []:
            if isinstance(inp, dict):
                out.add(inp.get("key_image") or "%s:%s" % (inp.get("txid"), inp.get("index")))
        return out

    def submit_tx(self, tx, source: str = LOCAL, discreet: bool = False) -> dict:
        """A payment handed in by a wallet (source LOCAL) or passed along a stem by a peer.
        It is checked in full, then either passed quietly to ONE peer or, if this node ends
        stems this epoch (or has nobody to pass it to), broadcast.  Returns {"new", "relay"}.

        `discreet`: the wallet handing it in is on another computer.  Then a payment this node
        already holds on a stem is checked all the same and reported as new, so neither the
        answer nor its timing tells a stranger what is on this node's stems."""
        if not isinstance(tx, dict) or not isinstance(tx.get("txid"), str):
            raise ChainError("malformed transaction")
        txid = tx["txid"]
        with self._stem_lock:
            held = txid in self.stempool
        if held:
            # Already on its stem here: the stem came round in a circle (it happens in small
            # networks), or someone is asking.  Drop it without a word.  The timers settle a
            # circle; an answer that differed would tell anyone holding the payment which
            # nodes carry it - a trail back to the sender.
            if discreet:
                self.chain.check_new_transfer(tx)
            return {"new": discreet, "relay": "stem"}
        if not self.chain.check_new_transfer(tx):
            return {"new": False, "relay": "fluff"}
        spends = self._spends(tx)
        nxt = self.router.route(source, self.relay_peers())
        with self._stem_lock:
            if any(spends & other["spends"] for other in self.stempool.values()):
                raise ChainError("key image already used: a payment waiting here spends the same coin (double spend)")
            if nxt is not None:
                self.stempool[txid] = {"tx": tx, "deadline": time.time() + self.router.embargo(source == LOCAL), "spends": spends}
        if nxt is None:
            self.fluff(tx, "no peers to pass it through" if source == LOCAL else "this node ends stems this epoch")
            return {"new": True, "relay": "fluff"}
        log.info("payment %s passed on quietly to one peer (stem)", txid[:12])
        self.spawn(self._stem_to, nxt, tx, source)
        return {"new": True, "relay": "stem"}

    def accept_stem(self, tx, source: str, address: str, local: bool) -> dict:
        """One hop of somebody's stem, from a peer.  The answer comes at once and is always the
        same - before anything is checked, whether or not this node already holds the payment -
        so neither its words nor its timing say anything.  The work happens afterwards."""
        if not isinstance(tx, dict) or not isinstance(tx.get("txid"), str):
            raise ChainError("malformed transaction")
        self.spawn(self._take_stem, tx, source, address, local)
        return {"new": None, "relay": "stem"}

    def _take_stem(self, tx: dict, source: str, address: str, local: bool) -> None:
        try:
            self.submit_tx(tx, source)
        except ChainError as exc:
            self.penalise(address, 5, local, "payments that break the rules")
            log.info("stem payment from %s refused: %s", source, exc)

    def _stem_to(self, peer: str, tx: dict, source: str = LOCAL) -> None:
        if self._post(peer, "/api/tx/stem", tx) is not None:
            return
        # The next node did not answer.  Broadcasting now would, on the sender's own node, show
        # the world where the payment started - so try another relay once, and otherwise leave
        # it to the timer.
        others = [p for p in self.relay_peers() if p != peer]
        alternative = self.router.route(source, others) if others else None
        if alternative is not None and self._post(alternative, "/api/tx/stem", tx) is not None:
            return
        log.info("payment %s: the next node on its stem did not answer; it goes out when its timer runs out", tx["txid"][:12])

    def fluff(self, tx: dict, why: str = "") -> bool:
        """Broadcast a payment the ordinary way: into the mempool and out to every peer."""
        with self._stem_lock:
            self.stempool.pop(tx["txid"], None)
        try:
            added = self.chain.add_to_mempool(tx)
        except ChainError as exc:
            log.info("payment %s is no longer valid, dropped: %s", tx["txid"][:12], exc)
            return False
        if added:
            log.info("new transaction %s: %d input(s) -> %d output(s), fee %s - broadcast%s",
                     tx["txid"][:12], len(tx["inputs"]), len(tx["outputs"]), self.chain.fmt(tx["fee"]),
                     " (%s)" % why if why else "")
            self.broadcast("/api/tx/fluff", tx)
        return added

    def receive_tx(self, tx, from_peer: str | None = None) -> bool:
        """A payment a peer broadcast (the fluff phase)."""
        if not isinstance(tx, dict) or not isinstance(tx.get("txid"), str):
            raise ChainError("malformed transaction")
        with self._stem_lock:
            self.stempool.pop(tx["txid"], None)          # it came back as a broadcast: our timer can stop
        added = self.chain.add_to_mempool(tx)
        if added:
            log.info("new transaction %s: %d input(s) -> %d output(s), fee %s",
                     tx["txid"][:12], len(tx["inputs"]), len(tx["outputs"]), self.chain.fmt(tx["fee"]))
            self.broadcast("/api/tx/fluff", tx, skip=from_peer)
        return added

    def check_embargoes(self, now: float | None = None) -> int:
        """Broadcast every stem payment whose timer ran out without it coming back as a
        broadcast; forget the ones that were broadcast or mined.  Returns how many it sent."""
        now = time.time() if now is None else now
        with self._stem_lock:
            entries = list(self.stempool.items())
        sent = 0
        for txid, entry in entries:
            if txid in self.chain.mempool or txid in self.chain.known_txids:
                with self._stem_lock:
                    self.stempool.pop(txid, None)
            elif now >= entry["deadline"]:
                if self.fluff(entry["tx"], "its stem went quiet, so this node broadcast it after the waiting time"):
                    sent += 1
        return sent

    def stem_watch(self) -> None:
        while not self.stop_event.wait(1.0):
            try:
                self.check_embargoes()
            except Exception:
                log.exception("stem watch error")

    def pending_markers(self, local: bool) -> dict:
        """Spent markers of payments that are waiting.  Payments still on their stem are only
        shown to this computer's own wallet: telling anyone else would announce that this node
        is on the stem, which is exactly what the stem is for hiding."""
        markers = self.chain.pending_markers()
        if local:
            with self._stem_lock:
                for entry in self.stempool.values():
                    for spend in entry["spends"]:
                        (markers["fund_spent"] if ":" in spend else markers["key_images"]).append(spend)
        return markers

    # ---- who may ask what ---------------------------------------------------
    def admit(self, address: str, kind: str, local: bool) -> None:
        """Turn away an address that is banned or asking too much.  This computer always passes."""
        if local:
            return
        if self.bans.banned(address):
            raise Refused(403, "refused: this address sent blocks or payments that break the rules; try again in an hour")
        if not self.limits.allow(address, kind):
            raise Refused(429, "too many requests from this address; slow down")

    def penalise(self, address: str, points: float, local: bool, why: str) -> None:
        if not local and self.bans.penalise(address, points):
            log.warning("ignoring %s for an hour: %s", address, why)

    def receive_block(self, block, from_peer: str | None = None) -> bool:
        # A block is only ever remembered under an ID this node worked out itself, and only
        # once the block has been accepted.  Remembering the ID a sender CLAIMS, before
        # checking anything, would let anyone who has just seen a real block send rubbish
        # under its ID first - and this node would then ignore the real block when it came.
        if not isinstance(block, dict) or set(block) != BLOCK_KEYS or type(block["index"]) is not int:
            raise ChainError("malformed block")
        block_id = compute_block_hash(block)
        if block["hash"] != block_id:
            raise ChainError("block hash does not match its header")
        chain = self.chain
        with chain.lock:
            if 0 <= block["index"] <= chain.height and chain.blocks.hash_at(block["index"]) == block_id:
                return False                                   # we have it
            if block["index"] == chain.height + 1 and block["previous_hash"] == chain.tip["hash"]:
                chain.add_block(block)                         # raises if it breaks a rule; nothing is remembered then
                self._mark_seen("b:" + block_id)
                log.info("accepted block %d from %s (%d tx, difficulty %d)",
                         block["index"], from_peer or "a client", len(block["transactions"]), block["difficulty"])
                self.broadcast("/api/block", block)
                return True
        if not self._mark_seen("b:" + block_id):                # an off-tip block we already reacted to
            return False
        if from_peer:                       # it does not fit on our tip: we are behind, or on another fork
            self.add_peer(from_peer, announce=False, origin="announced")      # it came to us: limits apply
            threading.Thread(target=self.sync_from, args=(from_peer,), daemon=True).start()
        return False

    def on_block_mined(self, block: dict) -> None:
        self._mark_seen("b:" + block["hash"])
        reward = sum(o["amount"] for o in block["transactions"][0]["outputs"])
        log.info("MINED block %d  reward %s  %d tx  difficulty %d  id %s...",
                 block["index"], self.chain.fmt(reward), len(block["transactions"]), block["difficulty"], block["hash"][:16])
        self.broadcast("/api/block", block)

    # ---- the pool: shares in and out -------------------------------------------------
    def on_share_mined(self, share: dict, block: dict | None) -> None:
        try:
            self.sharechain.add(share)
        except PoolError as exc:                          # the share chain moved while it was being mined
            log.debug("own share dropped: %s", exc)
            return
        self.shares_found += 1
        log.info("SHARE %d  difficulty %d  pays %d share(s)%s", self.sharechain.meta[compute_block_hash(share["header"])]["height"],
                 self.sharechain.meta[compute_block_hash(share["header"])]["difficulty"], len(share["coinbase"]["outputs"]),
                 "  - and it is a BLOCK" if block else "")
        for peer in list(self.peers):
            self.spawn(self._push_share, peer, share)
        if block is not None:
            try:
                self.chain.add_block(block)
            except ChainError as exc:
                log.info("pool block %d came too late: %s", block["index"], exc)
                return
            self.on_block_mined(block)

    def _push_share(self, peer: str, share: dict) -> None:
        """Hand a share to a peer; if the peer lacks the shares it builds on, hand those over too
        (a peer may be unable to reach this node to fetch them, as with blocks)."""
        try:
            self._request(peer, "POST", "/api/pool/share", share, 30)
        except Exception as exc:
            if "unknown parent" in str(exc) or "409" in str(exc):
                try:
                    self._request(peer, "POST", "/api/pool/shares", {"shares": self.sharechain.recent(int(self.sharechain.rules["window"]))}, 60)
                except Exception as more:
                    log.debug("handing shares to %s failed: %s", peer, more)
            else:
                log.debug("handing a share to %s failed: %s", peer, exc)

    def receive_share(self, share, sender: str | None = None) -> bool:
        if self.sharechain is None:
            raise Refused(404, "this node is not in a pool")
        if not isinstance(share, dict) or not isinstance(share.get("header"), dict):
            raise PoolError("malformed share")
        share_id = compute_block_hash(share["header"])
        if not self._mark_seen("s:" + share_id):
            return False
        try:
            new_tip = self.sharechain.add(share)
        except PoolError:
            with self._seen_lock:
                self._seen.pop("s:" + share_id, None)    # it may fit later, once its parent is here
            raise
        for peer in list(self.peers):
            if peer != sender:
                self.spawn(self._push_share, peer, share)
        return new_tip

    def receive_shares(self, shares) -> dict:
        """Several shares, oldest first (a member catching this node up).  Ones it has, and ones
        that do not fit, are skipped; the first that breaks a rule ends it."""
        if self.sharechain is None:
            raise Refused(404, "this node is not in a pool")
        if not isinstance(shares, list) or len(shares) > 2 * int(self.sharechain.rules["window"]):
            raise PoolError("send at most %d shares at a time" % (2 * int(self.sharechain.rules["window"])))
        added = 0
        for share in shares:
            try:
                self.sharechain.add(share)
                added += 1
            except PoolError as exc:
                if "unknown parent" not in str(exc) and "too old" not in str(exc):
                    raise
        return {"added": added, "tip": self.sharechain.tip}

    def sync_shares(self, peer: str) -> None:
        if self.sharechain is None:
            return
        try:
            shares = self._get(peer, "/api/pool/chain?limit=%d" % int(self.sharechain.rules["window"]), timeout=30).get("shares", [])
            self.receive_shares(shares if isinstance(shares, list) else [])
        except Exception as exc:
            log.debug("fetching shares from %s failed: %s", peer, exc)

    def mine_now(self, address: str | None, count: int) -> list[dict]:
        address = address or self.reward_address
        if not address:
            raise ChainError("no reward address: create a wallet first (wallet.bat) or pass an address")
        per_check = int(self.config["mining"].get("hashes_per_check", 20000))
        mined = []
        while len(mined) < count and not self.stop_event.is_set():
            block = self.chain.mine_block(address, hashes_per_check=per_check)
            if block is not None:
                mined.append(block)
                self.on_block_mined(block)
        return mined

    # ---- catching up ----------------------------------------------------------
    def sync_from(self, peer: str) -> bool:
        """Catch up with a peer that has more work behind its chain.  Only what is new is
        fetched and only what is new is verified: a node one block behind does one block's
        worth of work, however long the chain has grown."""
        if not self._sync_lock.acquire(blocking=False):
            return False                                  # one catch-up at a time
        try:
            info = self._get(peer, "/api/info")
            their_work = int(info.get("work", 0))
            if their_work <= self.chain.cumulative_work():
                return False
            log.info("peer %s has more work (height %s vs our %d) - catching up", peer, info.get("height"), self.chain.height)
            self.catching_up.set()
            changed = self._extend_from(peer)
            if their_work > self.chain.cumulative_work() and self._switch_fork(peer):
                changed = True
                self._extend_from(peer)                   # the rest of its chain, one batch at a time
            if changed:
                log.info("caught up with %s: now at height %d", peer, self.chain.height)
                self.broadcast("/api/block", self.chain.tip)
            return changed
        except ChainError as exc:
            log.warning("rejected blocks from %s: %s", peer, exc)
            host = urlparse(peer).hostname or peer
            if host not in LOCAL_NAMES and self.bans.penalise(host, 50):
                log.warning("dropping peer %s: it keeps sending blocks that break the rules", peer)
                self.peers.discard(peer)
                self._save_peers()
        except Exception as exc:
            log.debug("sync from %s failed: %s", peer, exc)
        finally:
            self.catching_up.clear()
            self._sync_lock.release()
        return False

    def push_to(self, peer: str) -> bool:
        """The other direction of catching up.  A node behind a home router or Tor has no address
        a peer can reach, so a peer that falls behind it can never fetch its blocks, and the two
        would stay on different branches for good.  When this node has more work than the peer,
        it hands the peer its side of the chain itself, a batch at a time (`receive_branch`)."""
        info = self._get(peer, "/api/info")
        if info.get("genesis_hash") != self.chain.blocks.hash_at(0):
            return False
        if self.chain.cumulative_work() <= int(info.get("work", 0)):
            return False
        with self.chain.lock:
            ours = self.chain.blocks.hashes[:]
        common, top = 0, min(len(ours), int(info.get("height", 0)) + 1)
        while top > 1 and common == 0:                    # walk back from the peer's tip, as _switch_fork does
            start = max(1, top - 500)
            theirs = self._get(peer, "/api/hashes?start=%d&limit=%d" % (start, top - start), timeout=30).get("hashes", [])
            for offset in range(min(len(theirs), top - start) - 1, -1, -1):
                if theirs[offset] == ours[start + offset]:
                    common = start + offset
                    break
            top = start
        log.info("peer %s is behind us since block %d - handing it our side", peer, common)
        nxt, switched = common + 1, False
        while nxt < len(ours) and not self.stop_event.is_set():          # to our tip, also after it switches
            batch = self.chain.blocks_from(nxt, SYNC_BATCH)
            while len(batch) > 1 and len(json.dumps(batch)) > MAX_BODY // 2:
                batch = batch[:len(batch) // 2]
            answer = self._request(peer, "POST", "/api/branch", {"blocks": batch}, 60)
            nxt += len(batch)
            switched = switched or bool(answer.get("switched"))
        if switched:
            log.info("peer %s took our side of the chain", peer)
        return switched

    def receive_branch(self, blocks, sender: str) -> dict:
        """A peer this node cannot reach hands it the peer's side of the chain (see push_to).
        Every block is checked as it arrives, against the ledger where the two sides part, and
        the node switches only once that side has more work than its own.  One sender at a time;
        a side left unfinished for two minutes is forgotten."""
        if not isinstance(blocks, list) or not 0 < len(blocks) <= SYNC_BATCH:
            raise ChainError("a branch comes in batches of 1 to %d blocks" % SYNC_BATCH)
        for block in blocks:
            if not isinstance(block, dict) or set(block) != BLOCK_KEYS or type(block["index"]) is not int:
                raise ChainError("malformed block")
        chain, now = self.chain, time.time()
        with self._inbound_lock:
            held = self._inbound
            if held and now - held[2] > BRANCH_HOLD_SECONDS:
                held = self._inbound = None
            if held and held[0] != sender:
                raise Refused(409, "busy with another peer's branch; try again in a few minutes")
            first = blocks[0]
            fork = held[1] if held else None
            if fork is None or first["previous_hash"] != fork.added[-1]["hash"]:
                parent = first["index"] - 1
                with chain.lock:
                    if not 0 <= parent <= chain.height or chain.blocks.hash_at(parent) != first["previous_hash"]:
                        self._inbound = None
                        raise ChainError("the branch does not start from a block this node has")
                fork = chain.begin_fork(parent)
            try:
                for block in blocks:
                    fork.add(block)                       # the first block that breaks a rule ends it
            except ChainError:
                self._inbound = None
                raise
            if fork.work <= chain.work:
                self._inbound = (sender, fork, now)
                return {"switched": False, "height": chain.height, "held": len(fork.added)}
            self._inbound = None
            switched = chain.switch_to(fork.common, fork.added, checked=True)
        if switched:
            for block in fork.added:
                self._mark_seen("b:" + block["hash"])
            log.info("switched to the branch %s handed us: now at height %d", sender, chain.height)
            self.broadcast("/api/block", chain.tip)
        return {"switched": switched, "height": chain.height}

    def _extend_from(self, peer: str) -> bool:
        """The usual case: the peer is ahead of us on the same chain.  Add its blocks one by one."""
        changed = False
        while not self.stop_event.is_set():
            batch, asked = self._fetch_blocks(peer, self.chain.height + 1)
            if not batch or not isinstance(batch[0], dict) or batch[0].get("previous_hash") != self.chain.tip["hash"]:
                return changed
            for block in batch:
                self.chain.add_block(block)               # raises ChainError if the block breaks a rule
                self._mark_seen("b:" + block["hash"])
                changed = True
            if len(batch) < asked:
                return changed
        return changed

    def _fetch_blocks(self, peer: str, start: int):
        """Blocks from `start` on, as many as fit in one answer: big blocks are asked for fewer
        at a time.  Returns (blocks, how many were asked for)."""
        for limit in (SYNC_BATCH, 20, 4, 1):
            try:
                answer = self._get(peer, "/api/blocks?start=%d&limit=%d" % (start, limit), timeout=60).get("blocks", [])
                return (answer if isinstance(answer, list) else []), limit
            except AnswerTooBig:
                continue
        raise ChainError("%s sends blocks bigger than this node reads (%d bytes)" % (peer, MAX_ANSWER))

    def _switch_fork(self, peer: str) -> bool:
        """The peer's chain split from ours somewhere.  Find where, fetch only its side, and
        switch if that side has more work.  The shared part is not verified again."""
        with self.chain.lock:
            ours = self.chain.blocks.hashes[:]            # a copy: other threads may add blocks meanwhile
        common, top = 0, len(ours)
        while top > 1 and common == 0:                    # walk back from our tip, 500 block IDs at a time
            start = max(1, top - 500)
            theirs = self._get(peer, "/api/hashes?start=%d&limit=%d" % (start, top - start), timeout=30).get("hashes", [])
            for offset in range(min(len(theirs), top - start) - 1, -1, -1):
                if theirs[offset] == ours[start + offset]:
                    common = start + offset
                    break
            top = start
        # Check the peer's side block by block AS IT ARRIVES, against the ledger as it stood
        # at the common block.  A bad block ends it at once, so a peer cannot make this node
        # hold a long branch of rubbish in memory: every block it keeps cost real work.
        fork = self.chain.begin_fork(common)
        log.info("peer %s is on a different branch since block %d - checking its side", peer, common)
        while not self.stop_event.is_set():
            batch, asked = self._fetch_blocks(peer, common + 1 + len(fork.added))
            for block in batch:
                fork.add(block)
            if len(batch) < asked:
                break
            # Switch as soon as its side has more work than ours, and fetch the rest the usual
            # way: over a slow link (Tor) a long side fetched in one go is lost to one timeout.
            if fork.work > self.chain.cumulative_work():
                break
        if not fork.added:
            return False
        # Our own chain may have grown while that was going on, so the switch itself is done
        # in one locked step against the chain as it is NOW (cheap: the heavy checks are done).
        return self.chain.switch_to(common, fork.added, checked=True)

    def sync_once(self) -> None:
        for peer in list(self.peers):
            self.sync_from(peer)
            try:
                self.push_to(peer)
            except Exception as exc:
                log.debug("handing our side to %s failed: %s", peer, exc)
            self.sync_shares(peer)
            if self.announce_url:
                self._post(peer, "/api/peers", {"peer": self.announce_url})
            try:
                listed = self._get(peer, "/api/peers").get("peers", [])
                budget = [GOSSIP_PER_PEER]
                for other in listed[:500] if isinstance(listed, list) else []:
                    self.consider(other, budget)
            except Exception:
                pass
            if self.peer_failures.get(peer, 0) > DROP_AFTER_FAILURES and self.peer_origin.get(peer) != "anchor":
                log.info("dropping peer %s: it stopped answering", peer)
                self.peers.discard(peer)
                self.peer_origin.pop(peer, None)
                self._save_peers()
        self.promote_candidates()

    def sync_loop(self) -> None:
        while not self.stop_event.is_set():
            try:
                self.sync_once()
            except Exception:
                log.exception("sync loop error")
            self.first_sync_done.set()
            self.stop_event.wait(self.sync_interval)

    def info(self, private: bool = False) -> dict:
        data = self.chain.info()
        data.update({"coin": self.chain.name, "ticker": self.chain.ticker, "decimals": self.chain.decimals,
                     "address_prefix": self.chain.prefix, "version": VERSION, "node_url": self.url,
                     "uptime_seconds": int(time.time() - self.started), "peers": sorted(self.peers),
                     "reward_address": self.reward_address if private else None,
                     "miner": self.miner.status(private)})
        if self.sharechain is not None:
            data["pool"] = dict(self.sharechain.status(), shares_found_here=self.shares_found if private else None)
        if private:          # the stem role would help an attacker map the relay graph: owner only
            data["relay"] = {"stem_payments_held": len(self.stempool), "ends_stems_this_epoch": self.router.diffuser,
                             "stem_relays": list(self.router.relays)}
        return data

    @staticmethod
    def dashboard_html() -> str:
        try:
            with open(os.path.join(HERE, "dashboard.html"), "r", encoding="utf-8") as fh:
                return fh.read()
        except OSError:
            return "<h1>dashboard.html is missing</h1><p>The API still works at /api/info</p>"

    def serve(self, auto_mine: bool) -> None:
        Handler.node = self
        CappedServer.allow_reuse_address = True
        try:
            server = CappedServer((self.host, self.port), Handler)
        except OSError as exc:
            log.error("cannot listen on %s:%d (%s) - is another node already running on that port?", self.host, self.port, exc)
            sys.exit(1)
        threading.Thread(target=self.sync_loop, name="sync", daemon=True).start()
        threading.Thread(target=self.stem_watch, name="stem", daemon=True).start()
        mining_line = "OFF  (double-click mine.bat, or start with --mine)"
        if auto_mine:
            if self.reward_address:
                self.miner.start_mining()
                mining_line = "ON   rewards -> %s..." % self.reward_address[:20]
            else:
                mining_line = "OFF  (no wallet yet - run wallet.bat first, then restart)"
        chain = self.chain
        log.info("=" * 64)
        log.info(" %s node v%s  (private by default)", chain.name, VERSION)
        if "test" in chain.network:
            log.info(" Network        : %s - TEST COINS (%s), they have no value and never will", chain.network, chain.ticker)
        log.info(" Explorer / API : %s", self.url)
        if self.proxy:
            log.info(" Peers reached  : through the proxy %s only (peers never see this computer's address)", self.proxy)
            if self.host not in ("127.0.0.1", "localhost", "::1"):
                log.warning(" This node also accepts connections on %s: anyone who connects sees its real address. "
                            "Keep --host 127.0.0.1 to stay hidden.", self.host)
            if not self.announce_url:
                log.info(" This node does not tell peers its own address (only an .onion address would be told).")
        inside = os.path.relpath(self.data_dir, HERE)          # short, and does not name the Windows account
        log.info(" Data folder    : %s", self.data_dir if inside.startswith("..") else inside + "  (in the Vesper folder)")
        log.info(" Chain height   : %d   difficulty %d   outputs %d   mempool %d   ring size %d",
                 chain.height, chain.tip["difficulty"], len(chain.state.outputs), len(chain.mempool), chain.ring_size)
        log.info(" Peers          : %s", ", ".join(sorted(self.peers)) or "none")
        log.info(" Mining         : %s", mining_line)
        fund = chain.dev_fund_info()
        log.info(" Dev fund       : %s", ("%d%% of each block reward, %d block(s) left" % (fund["percent"], fund["blocks_remaining"]))
                 if fund["enabled"] else "off  (python coin.py devfund init)")
        log.info(" Curve maths    : %s", chain.info()["curve_backend"])
        log.info(" Proof of work  : %s%s", chain.pow_algorithm,
                 (", %d MiB of memory per try" % (chain.pow_memory_kib // 1024)) if chain.pow_algorithm == "argon2id" else " (testing only)")
        if self.host not in LOCAL_NAMES:
            log.warning(" Listening on %s: other computers can reach this node. It is not hardened for the open internet.", self.host)
        log.info(" Press Ctrl+C to stop")
        log.info("=" * 64)
        try:
            server.serve_forever(poll_interval=0.5)
        except KeyboardInterrupt:
            pass
        finally:
            log.info("shutting down")
            self.stop_event.set()
            self.miner.stop()
            self.chain.flush()
            server.server_close()


class CappedServer(ThreadingHTTPServer):
    """At most MAX_CONNECTIONS requests at once, MAX_PER_ADDRESS of them from any one internet
    address, and a connection that goes quiet is closed after REQUEST_TIMEOUT seconds (see
    Handler.timeout).  Without these, anyone could open a few dozen connections, send nothing,
    and lock every peer and wallet out (a "slowloris" attack).  This computer is never turned
    away: the owner's wallet must always get in."""

    daemon_threads = True
    request_queue_size = 64        # connections waiting to be accepted; Windows resets new ones when this is full
    exempt = LOOPBACK
    max_per_address = MAX_PER_ADDRESS

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._slots = threading.BoundedSemaphore(MAX_CONNECTIONS)
        self._count_lock = threading.Lock()
        self._active: dict[str, int] = {}

    def process_request(self, request, client_address):
        address = client_address[0]
        own = address in self.exempt
        with self._count_lock:
            if not own and self._active.get(address, 0) >= self.max_per_address:
                self.shutdown_request(request)
                return
            if not own and not self._slots.acquire(blocking=False):
                self.shutdown_request(request)
                return
            self._active[address] = self._active.get(address, 0) + 1

        def run():
            try:
                self.finish_request(request, client_address)
            except Exception:
                self.handle_error(request, client_address)
            finally:
                self.shutdown_request(request)
                with self._count_lock:
                    left = self._active.get(address, 1) - 1
                    if left:
                        self._active[address] = left
                    else:
                        self._active.pop(address, None)
                if not own:
                    self._slots.release()
        threading.Thread(target=run, daemon=True).start()


class Refused(Exception):
    def __init__(self, status: int, message: str):
        super().__init__(message)
        self.status = status


class Handler(BaseHTTPRequestHandler):
    timeout = REQUEST_TIMEOUT            # a silent connection is closed, not kept forever
    node: Node = None  # type: ignore[assignment]
    server_version = "VesperNode/" + VERSION
    sys_version = ""

    def log_message(self, fmt, *args):
        log.debug("http %s " + fmt, self.address_string(), *args)

    # ---- who is asking ------------------------------------------------------------
    def _is_local(self) -> bool:
        return self.client_address[0] in LOOPBACK

    def _guard(self, control: bool = False) -> bool:
        """Refuse what a web page could make your browser send.  Returns "this is the owner"."""
        host_header = self.headers.get("Host") or ""
        host = host_header.rsplit(":", 1)[0].strip("[]").lower() if not host_header.endswith("]") else host_header.strip("[]").lower()
        local = self._is_local()
        # A page can point its own domain name at 127.0.0.1 and talk to your node as if it were
        # its own server.  The Host header gives that away: it still carries the page's name.
        if local and host not in LOCAL_NAMES:
            raise Refused(403, "refused: this node is being addressed by a name that is not its own")
        origin = self.headers.get("Origin")
        if origin and origin.lower() != "http://" + host_header.lower():
            raise Refused(403, "refused: requests from other web sites are not accepted")
        if control and not local:
            raise Refused(403, "refused: this action is only allowed from the computer the node runs on")
        return local

    def _json(self, obj, status: int = 200) -> None:
        body = json.dumps(obj).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers()
        self.wfile.write(body)

    def _html(self, text: str) -> None:
        body = text.encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Content-Security-Policy", "default-src 'self'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; frame-ancestors 'none'")
        self.end_headers()
        self.wfile.write(body)

    def _error(self, status: int, message: str) -> None:
        self._json({"error": message}, status)

    def _body(self):
        length = int(self.headers.get("Content-Length") or 0)
        if length < 0 or length > MAX_BODY:          # a negative length would read until the sender stops
            raise ChainError("request body too large")
        raw = self.rfile.read(length) if length else b""
        if not raw:
            return {}
        try:
            return json.loads(raw.decode("utf-8"))
        except ValueError:
            raise ChainError("request body is not valid JSON")
        except RecursionError:                       # "[[[[..." thousands deep: refused, not a crash report
            raise ChainError("request body is nested too deeply")

    def _route(self):
        parsed = urlparse(self.path)
        return [p for p in parsed.path.split("/") if p], parse_qs(parsed.query)

    def do_OPTIONS(self) -> None:           # no cross-site permission is ever granted
        self.send_response(403)
        self.send_header("Content-Length", "0")
        self.end_headers()

    def do_GET(self) -> None:
        parts, query = self._route()
        node, chain = self.node, self.node.chain
        try:
            local = self._guard()
            node.admit(self.client_address[0], "scan" if parts[1:2] == ["scan"] else "read", local)
            if not parts:
                return self._html(node.dashboard_html())
            if parts == ["favicon.ico"]:
                self.send_response(204)
                self.end_headers()
                return
            if parts[0] != "api":
                return self._error(404, "not found")
            route = parts[1:]
            if route == ["info"]:
                return self._json(node.info(private=local))
            if route == ["chain"]:
                limit = max(1, min(200, int(query.get("limit", ["20"])[0])))
                before = int(query.get("before", [chain.height + 1])[0])
                with chain.lock:
                    before = max(0, min(chain.height + 1, before))
                    blocks = [chain.block_summary(b) for b in chain.blocks[max(0, before - limit):before]]
                blocks.reverse()
                return self._json({"height": chain.height, "blocks": blocks})
            if route == ["blocks"]:                   # full blocks, for a peer that is catching up
                start = int(query.get("start", ["0"])[0])
                limit = int(query.get("limit", [str(SYNC_BATCH)])[0])
                return self._json({"height": chain.height, "blocks": chain.blocks_from(start, limit)})
            if route == ["hashes"]:                   # block IDs only, for finding where two chains part
                start = max(0, int(query.get("start", ["0"])[0]))
                limit = max(1, min(2000, int(query.get("limit", ["500"])[0])))
                with chain.lock:
                    return self._json({"height": chain.height, "hashes": chain.blocks.hashes[start:start + limit]})
            if len(route) == 2 and route[0] == "block":
                block = chain.get_block(route[1])
                return self._json(block) if block else self._error(404, "no such block")
            if len(route) == 2 and route[0] == "tx":
                found = chain.find_tx(route[1])
                held = node.stempool.get(route[1]) if not found and local else None
                if held:                              # this computer's own payment, still on its stem: only its owner may know
                    return self._json({"tx": held["tx"], "block": None, "confirmations": 0, "stem": True})
                if not found:
                    return self._error(404, "no such transaction")
                tx, index = found
                return self._json({"tx": tx, "block": index, "confirmations": (chain.height - index + 1) if index is not None else 0})
            if route == ["scan"]:                     # for wallets: the outputs and spent markers of whole blocks
                with chain.lock:
                    page = chain.scan_page(int(query.get("start", ["1"])[0]))
                pending = node.pending_markers(local)
                page["pending_key_images"], page["pending_fund_spent"] = pending["key_images"], pending["fund_spent"]
                return self._json(page)
            if route == ["mempool"]:
                with chain.lock:
                    txs = list(chain.mempool.values())
                return self._json({"count": len(txs), "transactions": txs})
            if route == ["peers"]:
                return self._json({"peers": sorted(node.peers)})
            if route == ["miner"]:
                return self._json(node.miner.status(private=local))
            if route[:1] == ["pool"]:                 # the pool's share chain, for members
                if node.sharechain is None:
                    return self._error(404, "this node is not in a pool")
                if route == ["pool"]:
                    return self._json(node.sharechain.status())
                if route == ["pool", "chain"]:
                    limit = max(1, min(2 * int(node.sharechain.rules["window"]), int(query.get("limit", ["60"])[0])))
                    return self._json({"shares": node.sharechain.recent(limit)})
            if len(route) == 2 and route[0] == "address":
                return self._error(404, "there are no addresses on this chain to look up - that is the point. Scan with your view key instead.")
            return self._error(404, "not found")
        except Refused as exc:
            return self._error(exc.status, str(exc))
        except ChainError as exc:
            return self._error(400, str(exc))
        except (ValueError, KeyError, TypeError) as exc:
            return self._error(400, "bad request: %s" % exc)
        except (ConnectionError, BrokenPipeError):
            return
        except Exception:
            log.exception("GET %s failed", self.path)
            return self._error(500, "internal error")

    def do_POST(self) -> None:
        parts, _ = self._route()
        node, chain = self.node, self.node.chain
        try:
            if not parts or parts[0] != "api":
                return self._error(404, "not found")
            route = parts[1:]
            control = route in (["mine"], ["miner", "start"], ["miner", "stop"])
            local = self._guard(control)
            client_ip = self.client_address[0]
            kind = "tx" if route[:1] == ["tx"] else "block" if route in (["block"], ["branch"]) or route[:1] == ["pool"] else "lookup" if route[:1] == ["outputs"] else "read"
            node.admit(client_ip, kind, local)
            body = self._body()
            if not isinstance(body, dict):
                return self._error(400, "request body must be a JSON object")
            if route[:1] == ["tx"]:
                try:
                    if route == ["tx"]:                       # a wallet hands in its payment: start a stem
                        result = node.submit_tx(body, LOCAL, discreet=not local)
                    elif route == ["tx", "stem"]:              # one hop of somebody's stem: answered at once, the same way
                        source = node.claimed_peer(self.headers.get("X-Node-Url"), client_ip) or "unknown:" + client_ip
                        result = node.accept_stem(body, source, client_ip, local)
                    elif route == ["tx", "fluff"]:             # a broadcast
                        result = {"new": node.receive_tx(body, node.claimed_peer(self.headers.get("X-Node-Url"), client_ip)), "relay": "fluff"}
                    else:
                        return self._error(404, "not found")
                except ChainError:
                    node.penalise(client_ip, 5, local, "payments that break the rules")
                    raise
                return self._json({"accepted": True, "new": result["new"], "relay": result["relay"], "txid": body.get("txid")})
            if route == ["outputs", "lookup"]:        # for wallets: the members of a ring, by place in line or by reference
                positions, refs = body.get("positions") or [], body.get("refs") or []
                if not isinstance(positions, list) or not isinstance(refs, list) or len(positions) > MAX_LOOKUP or len(refs) > MAX_LOOKUP:
                    return self._error(400, "ask for at most %d outputs at a time" % MAX_LOOKUP)
                return self._json(chain.lookup_outputs(positions, refs))
            if route == ["block"]:
                sender = node.claimed_peer(self.headers.get("X-Node-Url"), client_ip)
                try:
                    accepted = node.receive_block(body, from_peer=sender)
                except ChainError:
                    node.penalise(client_ip, 50, local, "blocks that break the rules")
                    raise
                return self._json({"accepted": accepted, "height": chain.height})
            if route in (["pool", "share"], ["pool", "shares"]):     # pool members hand each other shares
                sender = node.claimed_peer(self.headers.get("X-Node-Url"), client_ip)
                try:
                    if route == ["pool", "share"]:
                        return self._json({"accepted": node.receive_share(body, sender)})
                    return self._json(node.receive_shares(body.get("shares")))
                except PoolError as exc:
                    if "unknown parent" in str(exc):
                        return self._error(409, str(exc))
                    node.penalise(client_ip, 20, local, "shares that break the pool's rules")
                    raise
            if route == ["branch"]:                   # a peer we cannot reach hands us its side of the chain
                try:
                    return self._json(node.receive_branch(body.get("blocks"), client_ip))
                except ChainError:
                    node.penalise(client_ip, 50, local, "blocks that break the rules")
                    raise
            if route == ["peers"]:
                peer = node.claimed_peer(body.get("peer"), client_ip)
                origin = "announced"
                if peer is None and self._is_local():
                    peer, origin = node.normalize_peer(body.get("peer")), "anchor"     # the owner may add any peer by hand
                return self._json({"added": bool(peer) and node.add_peer(peer, origin=origin), "peers": sorted(node.peers)})
            if route == ["mine"]:
                if node.miner.running:
                    return self._error(409, "the background miner is already running - stop it first")
                count = max(1, min(10, int(body.get("blocks", 1))))
                mined = node.mine_now(body.get("address") or None, count)
                return self._json({"mined": [chain.block_summary(b) for b in mined], "height": chain.height})
            if route == ["miner", "start"]:
                return self._json(node.miner.start_mining(body.get("address") or None))
            if route == ["miner", "stop"]:
                return self._json(node.miner.stop())
            return self._error(404, "not found")
        except Refused as exc:
            return self._error(exc.status, str(exc))
        except ChainError as exc:
            return self._error(400, str(exc))
        except (ValueError, KeyError, TypeError) as exc:
            return self._error(400, "bad request: %s" % exc)
        except (ConnectionError, BrokenPipeError):
            return
        except Exception:
            log.exception("POST %s failed", self.path)
            return self._error(500, "internal error")


def default_reward_address(data_dir: str, prefix: str | None = None) -> str | None:
    path = os.path.join(data_dir, "wallets", "default.json")
    if not os.path.exists(path):
        return None
    try:
        return Wallet.public_info(path, prefix)["address"]
    except (OSError, ValueError, KeyError):
        return None


def setup_logging(data_dir: str, verbose: bool) -> None:
    fmt = logging.Formatter("%(asctime)s %(levelname)-7s %(message)s", "%H:%M:%S")
    root = logging.getLogger()
    root.setLevel(logging.DEBUG if verbose else logging.INFO)
    console = logging.StreamHandler(sys.stdout)
    console.setFormatter(fmt)
    root.addHandler(console)
    try:
        os.makedirs(data_dir, exist_ok=True)
        file_handler = logging.FileHandler(os.path.join(data_dir, "node.log"), encoding="utf-8")
        file_handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)-7s %(message)s"))
        root.addHandler(file_handler)
    except OSError:
        pass


def main(argv=None) -> None:
    parser = argparse.ArgumentParser(description="Run a Vesper node (API + explorer + peer sync + optional miner).")
    parser.add_argument("--config")
    parser.add_argument("--host")
    parser.add_argument("--port", type=int)
    parser.add_argument("--data-dir")
    parser.add_argument("--peer", action="append", default=[])
    parser.add_argument("--public-url")
    parser.add_argument("--mine", action="store_true")
    parser.add_argument("--mine-to")
    parser.add_argument("--processes", type=int, help="CPU cores to mine on (default: half the cores, at most 8)")
    parser.add_argument("--proxy", help="reach every peer through Tor or another SOCKS5 proxy, e.g. socks5h://127.0.0.1:9050")
    parser.add_argument("--pool", action="store_true", help="mine in the pool with no operator (needs a network whose rules allow pool blocks)")
    parser.add_argument("--verbose", action="store_true")
    args = parser.parse_args(argv)

    try:
        config = load_config(args.config)
    except ChainError as exc:
        print(exc)
        sys.exit(2)
    if args.processes:
        config["mining"]["processes"] = max(1, args.processes)
    if args.pool:
        config.setdefault("pool", {})["enabled"] = True
    if args.proxy:
        config["network"]["proxy"] = args.proxy
    if config["network"].get("proxy"):
        try:
            socksproxy.parse_proxy(config["network"]["proxy"])
        except ValueError as exc:
            print("--proxy: %s" % exc)
            sys.exit(2)
        proxy_host, proxy_port, _ = socksproxy.parse_proxy(config["network"]["proxy"])
        try:
            socket.create_connection((proxy_host, proxy_port), timeout=5).close()
        except OSError:
            print("Nothing is listening at the proxy %s. Is Tor running? Open the Tor Browser and connect "
                  "(it listens on 9150), or start the Tor service (9050), then start the node again."
                  % config["network"]["proxy"])
            sys.exit(1)
    host = args.host or config["network"]["host"]
    port = args.port or int(config["network"]["port"])
    data_dir = resolve_data_dir(config, args.data_dir)
    try:
        data_lock = lock_data_dir(data_dir)       # kept open for as long as the node runs
    except ChainError as exc:
        print(exc)
        sys.exit(1)
    setup_logging(data_dir, args.verbose)
    if disable_windows_power_throttling():
        log.info("opted out of Windows power throttling (keeps the miner on fast cores)")
    reward = args.mine_to or config["mining"].get("reward_address") or default_reward_address(data_dir, config["coin"]["address_prefix"])
    if reward and not is_valid_address(reward, config["coin"]["address_prefix"]):
        log.error("reward address is not a valid %s address", config["coin"]["ticker"])
        sys.exit(2)
    try:
        node = Node(config, data_dir, host, port, args.peer, reward, args.public_url)
        node.data_lock = data_lock
    except ChainError as exc:
        log.error("%s", exc)
        sys.exit(1)
    node.serve(auto_mine=args.mine or bool(config["mining"].get("auto_start")))


if __name__ == "__main__":
    main()
