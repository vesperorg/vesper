"""
relay.py - phase 4: hiding which computer a payment came from, and keeping peers in line.

The ledger hides who paid whom and how much.  The network can still give the sender away: the
node that first tells everyone about a payment is usually the sender's own.  Anyone who runs
many listening nodes notes who announced each payment first, and that is a list of senders'
internet addresses.

The fix here is Dandelion++ (Fanti et al., 2018; Monero runs it since 2020).  A payment travels
in two phases:

  stem   it is passed along a line of single nodes, quietly, one peer at a time.  No node on
         the line knows whether its neighbour made the payment or only passed it on.
  fluff  after a random number of hops a node broadcasts it the ordinary way, to everyone.

So the first broadcast comes from a node about ten hops away from the sender, in a direction
nobody can predict.  Three details make it hold up against an attacker who runs many nodes:

  - Every node chooses, for an "epoch" of ten minutes at a time, whether it relays stems or
    ends them, and which one or two peers it relays to.  Each incoming peer is tied to one of
    those for the whole epoch.  Routes that changed with every payment would let an attacker
    learn the graph by sending payments of their own.
  - A node never fluffs its own payment.  It always starts a stem.
  - Every node on a stem starts a timer (the "embargo").  If the payment has not come back to
    it as a broadcast before the timer runs out, it broadcasts the payment itself.  A peer
    that swallows stems can delay a payment by a minute; it cannot make one disappear.  The
    sender's own timer is the longest, so when a stem dies or goes round in a circle, the
    broadcast nearly always comes from a node that only passed the payment on.
  - A node answers every stem the same way, at once, before checking anything, and quietly
    drops one it already holds.  Otherwise anyone holding a payment could ask each node "do
    you have this one?" and trace the stem back to the sender.

Nothing here uses the network directly: the node (node.py) asks this module where a payment
goes next, and `leaktest.py` runs the very same code in a simulated network to measure how
well it hides senders.

Also here: limits on how much any one internet address may ask of a node, and a ban for
peers that send blocks or payments that break the rules.  A node on the open internet needs
both before anyone points a public test network at it.
"""

from __future__ import annotations

import math
import secrets
import threading
import time
from typing import Callable

LOCAL = "local"              # a payment handed in by a wallet, not passed on by a peer

# ---------------------------------------------------------------- Dandelion++ settings
EPOCH_SECONDS = 600          # how long a node keeps the same role and the same relays
FLUFF_PROBABILITY = 0.1      # chance a node spends an epoch ending stems: about ten hops a stem
STEM_RELAYS = 2              # peers a node relays stems to during one epoch
EMBARGO_BASE = 30.0          # a stem node waits at least this long before broadcasting itself ...
EMBARGO_MEAN_EXTRA = 15.0    # ... plus a random wait averaging this
EMBARGO_OWN_BASE = 60.0      # the sender's node waits longer, so a dead stem is broadcast by a relay


class StemRouter:
    """The routing decisions of one node.  `peers` is always the node's current peer list."""

    def __init__(self, epoch_seconds: float = EPOCH_SECONDS, fluff_probability: float = FLUFF_PROBABILITY,
                 relays: int = STEM_RELAYS, rng=None, clock: Callable[[], float] = time.time):
        self.epoch_seconds = epoch_seconds
        self.fluff_probability = fluff_probability
        self.relay_count = relays
        self.rng = rng or secrets.SystemRandom()
        self.clock = clock
        self.lock = threading.Lock()
        self.epoch_ends = 0.0
        self.diffuser = False                # True: this epoch, stems from peers end here
        self.relays: list[str] = []
        self.routes: dict[str, str] = {}     # incoming peer (or LOCAL) -> the relay its stems go to

    def _new_epoch(self, peers: list[str]) -> None:
        self.epoch_ends = self.clock() + self.epoch_seconds
        self.diffuser = self.rng.random() < self.fluff_probability
        pool = sorted(peers)
        self.relays = self.rng.sample(pool, min(self.relay_count, len(pool)))
        self.routes = {}

    def route(self, source: str, peers: list[str]) -> str | None:
        """Where a stem payment that came from `source` goes next: a peer, or None to broadcast
        it now.  Payments from this node's own wallet (`LOCAL`) always go on a stem if there
        is anyone to send them to."""
        with self.lock:
            if self.clock() >= self.epoch_ends or any(r not in peers for r in self.relays) or (not self.relays and peers):
                self._new_epoch(peers)
            if source != LOCAL and self.diffuser:
                return None
            choices = [r for r in self.relays if r != source]      # never straight back where it came from
            if not choices:
                return None
            relay = self.routes.get(source)
            if relay not in choices:
                relay = self.rng.choice(choices)
                self.routes[source] = relay
            return relay

    def embargo(self, own: bool = False) -> float:
        """Seconds this node waits for the payment to come back as a broadcast before
        broadcasting it itself.  Random, so the timers along one stem do not run out in order;
        longer for the node's own payments (`own`), so the sender is almost never the one whose
        timer runs out first."""
        return (EMBARGO_OWN_BASE if own else EMBARGO_BASE) + self.rng.expovariate(1.0 / EMBARGO_MEAN_EXTRA)


# ---------------------------------------------------------------- limits per internet address
class RateLimiter:
    """Token buckets per (address, kind of request): each kind allows a burst, then a steady
    rate.  Requests from this computer are never limited."""

    LIMITS = {                      # kind: (requests per second, burst)
        "tx": (2.0, 40),            # payments handed in or passed on
        "block": (2.0, 60),         # blocks pushed by peers (catching up uses "read")
        "lookup": (5.0, 100),       # ring members for a wallet
        "scan": (5.0, 200),         # wallet sync pages
        "read": (20.0, 400),        # everything else that only reads
    }

    MAX_TRACKED = 50_000            # buckets remembered at most; a full bucket costs nothing to forget

    def __init__(self, clock: Callable[[], float] = time.time):
        self.clock = clock
        self.lock = threading.Lock()
        self.buckets: dict[tuple, list] = {}

    def allow(self, address: str, kind: str) -> bool:
        rate, burst = self.LIMITS.get(kind, self.LIMITS["read"])
        now = self.clock()
        with self.lock:
            tokens, last = self.buckets.pop((address, kind), (burst, now))
            tokens = min(burst, tokens + (now - last) * rate)
            ok = tokens >= 1
            self.buckets[(address, kind)] = [tokens - 1 if ok else tokens, now]     # re-inserted: newest last
            while len(self.buckets) > self.MAX_TRACKED:      # forget the longest-quiet ones, oldest first,
                del self.buckets[next(iter(self.buckets))]   # a few at a time, never a scan of them all
            return ok


class BanList:
    """Misbehaviour points per address.  A block that breaks the rules costs a lot (it is never
    an accident), a payment that breaks them a little (a payment can turn invalid innocently,
    when another one spending the same coin wins the race).  At 100 points the address is
    ignored for an hour, then forgiven."""

    BAN_POINTS = 100
    BAN_SECONDS = 3600
    HALF_LIFE = 3600.0               # points fade: an honest peer's rare slip is forgotten, not added up forever
    MAX_TRACKED = 50_000

    def __init__(self, clock: Callable[[], float] = time.time):
        self.clock = clock
        self.lock = threading.Lock()
        self.points: dict[str, tuple] = {}           # address -> (points, when last changed)
        self.banned_until: dict[str, float] = {}

    def penalise(self, address: str, points: float) -> bool:
        """Returns True if this pushed the address over the line."""
        now = self.clock()
        with self.lock:
            old, when = self.points.pop(address, (0.0, now))
            total = old * 0.5 ** ((now - when) / self.HALF_LIFE) + points
            if total >= self.BAN_POINTS:
                self.banned_until[address] = now + self.BAN_SECONDS
                return True
            self.points[address] = (total, now)
            while len(self.points) > self.MAX_TRACKED:
                del self.points[next(iter(self.points))]
            while len(self.banned_until) > self.MAX_TRACKED:
                del self.banned_until[next(iter(self.banned_until))]
            return False

    def banned(self, address: str) -> bool:
        with self.lock:
            until = self.banned_until.get(address)
            if until is None:
                return False
            if self.clock() >= until:
                del self.banned_until[address]
                return False
            return True


def expected_stem_length(fluff_probability: float = FLUFF_PROBABILITY) -> float:
    """Average number of hops before a stem is broadcast (the origin's own hop included)."""
    return 1.0 / fluff_probability if fluff_probability > 0 else math.inf
