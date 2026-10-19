"""
leaktest.py - the two places a sender can still leak, measured.  Numbers, not claims.

    python leaktest.py                 (about a minute; prints two tables)

Part 1, the network: which computer sent a payment (phase 4).
Part 2, the ring: which of the 16 coins in a ring is the real one (decoy selection).

It builds a simulated network of nodes, hands a share of them to an attacker ("spies"), sends
payments from random honest nodes, and lets the attacker guess each sender with the standard
"first spy" rule: whoever handed a spy the payment first is named as its sender.  Then it
counts how often that guess is right, once with plain broadcasting (how every node worked
before phase 4) and once with the stem-then-broadcast relay in relay.py - the same routing
code the node runs, driven by a simulated clock.

What it does not model, stated so nobody reads more into the numbers than is there: an
attacker who watches internet traffic directly (the stem is not encrypted; run nodes over Tor
for that), many payments from the same sender in one epoch being linked to each other, or
timing tricks beyond "who was first".
"""

from __future__ import annotations

import heapq
import random
import sys

import math

import ringsig
from relay import EMBARGO_BASE, EMBARGO_MEAN_EXTRA, EMBARGO_OWN_BASE, LOCAL, StemRouter


def build_network(nodes: int, degree: int, rng: random.Random) -> list[list[int]]:
    """Each node opens `degree` connections to random others; connections work both ways."""
    links = [set() for _ in range(nodes)]
    for a in range(nodes):
        while len(links[a]) < degree:
            b = rng.randrange(nodes)
            if b != a:
                links[a].add(b)
                links[b].add(a)
    return [sorted(x) for x in links]


def first_spy_guess(start: int, start_sender: int | None, links, spies: set, rng: random.Random):
    """Broadcast from `start` (who received it from `start_sender`, or created it).  Returns
    the attacker's guess: the node that delivered the payment to the first spy to see it."""
    if start in spies:
        return start_sender
    queue = [(0.0, start, start_sender)]
    seen = set()
    while queue:
        t, node, sender = heapq.heappop(queue)
        if node in seen:
            continue
        seen.add(node)
        if node in spies:
            return sender
        for peer in links[node]:
            if peer not in seen:
                heapq.heappush(queue, (t + rng.expovariate(1.0), peer, node))     # random network delay per hop
    return None


def run(mode: str, nodes: int = 200, degree: int = 8, spy_share: float = 0.2, payments: int = 2000, seed: int = 1) -> dict:
    rng = random.Random(seed)
    links = build_network(nodes, degree, rng)
    spies = set(rng.sample(range(nodes), int(nodes * spy_share)))
    honest = [n for n in range(nodes) if n not in spies]
    names = ["n%d" % i for i in range(nodes)]
    index = {name: i for i, name in enumerate(names)}
    routers = [StemRouter(rng=random.Random(seed * 1000 + i), clock=lambda: 0.0) for i in range(nodes)]
    right, hops_total, loops = 0, 0, 0
    for _ in range(payments):
        origin = rng.choice(honest)
        if mode == "broadcast":
            guess = first_spy_guess(origin, None, links, spies, rng)
        else:
            node, source, hops = origin, LOCAL, 0
            path = [origin]
            guess = None
            while True:
                nxt = routers[node].route(source, [names[p] for p in links[node]])
                if nxt is None or hops > 60:
                    guess = first_spy_guess(node, index[source] if source != LOCAL else None, links, spies, rng)
                    break
                nxt_i = index[nxt]
                hops += 1
                if nxt_i in spies:                     # a spy on the stem names whoever handed it over
                    # mode "probe": the answer phase 4 first gave to a stem a node already held
                    # ("loop") let that spy ask every node and trace the stem back to its start.
                    guess = origin if mode == "probe" else node
                    break
                if nxt_i in path:
                    # The stem came round in a circle: the node that holds it drops it quietly, and
                    # the first timer on the stem to run out broadcasts it.  The sender's is longest.
                    deadlines = [(EMBARGO_OWN_BASE if i == 0 else EMBARGO_BASE) + 0.1 * i
                                 + rng.expovariate(1.0 / EMBARGO_MEAN_EXTRA) for i in range(len(path))]
                    first = path[min(range(len(path)), key=deadlines.__getitem__)]
                    guess = first_spy_guess(first, None, links, spies, rng)
                    loops += 1
                    break
                path.append(nxt_i)
                node, source = nxt_i, names[node]
            hops_total += hops
        right += guess == origin
    return {"mode": mode, "nodes": nodes, "spies": len(spies), "payments": payments,
            "right": right / payments, "avg_stem_hops": hops_total / payments if mode != "broadcast" else 0.0,
            "circles": loops / payments}


# ----------------------------------------------------------------------------- part 2: the ring
def _rank_decoy(rng, eligible, *_):
    """The decoy rule Vesper used until 2026-10-15: a rank in the line of outputs, n x u^3."""
    return min(eligible - 1, int(eligible * rng.random() ** 3))


def _time_decoy(rng, eligible, per_second, lock_seconds):
    """The rule in ringsig.draw_positions: an age drawn from how people spend."""
    rank = int((ringsig.decoy_age(rng, lock_seconds) - lock_seconds) * per_second)
    return rank if rank < eligible else rng.randrange(eligible)


def _spend_logpdf(age: float) -> float:
    x = math.log(age)
    k, r = ringsig.SPEND_SHAPE, ringsig.SPEND_RATE
    return k * math.log(r) - math.lgamma(k) + (k - 1) * math.log(x) - r * x - math.log(age)


def ring_leak(rule: str, outputs_per_block: float, chain_blocks: int, payments: int = 3000, ring: int = 16,
              lock_blocks: int = 10, block_seconds: float = 30.0, seed: int = 1) -> dict:
    """How often an attacker names the real coin in a ring.  Real coins are spent at ages drawn
    from the measured spending model; the attacker knows that model AND the decoy rule, and
    names the member whose age is likeliest to be a real spend rather than a decoy."""
    rng = random.Random(seed)
    pick = _rank_decoy if rule == "rank" else _time_decoy
    per_second = outputs_per_block / block_seconds
    lock_seconds = lock_blocks * block_seconds
    eligible = max(ring, int((chain_blocks - lock_blocks) * outputs_per_block))
    max_age = lock_seconds + eligible / per_second

    def age_of(rank):
        return lock_seconds + (rank + 0.5) / per_second

    bins, lo, hi = 400, math.log(lock_seconds or 1.0), math.log(max_age)
    counts = [1e-9] * bins
    for _ in range(100_000):                      # the attacker's picture of where decoys fall
        a = age_of(pick(rng, eligible, per_second, lock_seconds))
        counts[min(bins - 1, max(0, int((math.log(a) - lo) / (hi - lo) * bins)))] += 1
    total, width = sum(counts), (hi - lo) / bins

    def decoy_logpdf(age):
        b = min(bins - 1, max(0, int((math.log(age) - lo) / (hi - lo) * bins)))
        return math.log(counts[b] / total / width) - math.log(age)

    named = newest = 0
    for _ in range(payments):
        real = ringsig.decoy_age(rng, lock_seconds)
        if real > max_age:                         # a coin older than the chain: anywhere
            real = age_of(rng.randrange(eligible))
        members = [real] + [age_of(pick(rng, eligible, per_second, lock_seconds)) for _ in range(ring - 1)]
        scores = [_spend_logpdf(a) - decoy_logpdf(a) for a in members]
        named += max(range(ring), key=scores.__getitem__) == 0
        newest += min(range(ring), key=members.__getitem__) == 0
    return {"rule": rule, "right": named / payments, "newest_right": newest / payments, "fair": 1 / ring}


def main() -> int:
    print("Who sent it?  An attacker runs a share of the nodes and names the first node that handed each payment")
    print("to one of its spies.  How often that guess is right:")
    print("")
    print("  attacker's share of nodes   plain broadcast   stem, then broadcast (phase 4)   stem length")
    for share in (0.05, 0.1, 0.2, 0.3):
        plain = run("broadcast", spy_share=share)
        stem = run("stem", spy_share=share)
        print("  %24.0f%%   %14.0f%%   %29.0f%%   %8.1f hops" % (share * 100, plain["right"] * 100, stem["right"] * 100, stem["avg_stem_hops"]))
    print("")
    print("Phase 4 first answered a stem it already held with 'loop'.  A spy on the stem could then ask every")
    print("node and trace the stem back to the sender; at most this often (5%%, 10%%, 20%%, 30%% spies): %s."
          % ", ".join("%.0f%%" % (run("probe", spy_share=share)["right"] * 100) for share in (0.05, 0.1, 0.2, 0.3)))
    print("Fixed on 2026-10-15: every stem is now answered the same way, at once, and a held one is dropped.")
    print("")
    print("200 simulated nodes with 8 connections each, 2,000 payments per cell, random delay on every hop.")
    print("Plain broadcast: the sender's own node tells all its neighbours at once, so a spy next door hears")
    print("it first from the sender.  With the stem, a spy is only right when it happens to be the very first hop.")
    print("")
    print("Which coin in a ring of 16 is the real one?  Real coins are spent at ages drawn from how people")
    print("actually spend (Moser et al. 2018, fitted to real Monero spends); the attacker knows that and the")
    print("decoy rule, and names the likeliest member.  Fair would be 6.2%.")
    print("")
    print("  chain                              decoys by rank (old rule)   decoys by age (now)")
    for label, per_block, blocks in (("young: 3 outputs a block, 1 week", 3, 20160),
                                     ("busy: 40 outputs a block, 1 month", 40, 86400),
                                     ("busy: 40 outputs a block, 1 year", 40, 1051200)):
        old = ring_leak("rank", per_block, blocks)
        new = ring_leak("time", per_block, blocks)
        print("  %-34s %22.1f%%   %18.1f%%" % (label, old["right"] * 100, new["right"] * 100))
    print("")
    print("If people on Vesper spend differently from Monero's measured habits, the second column drifts;")
    print("re-measuring real spending once a network exists is part of the road to genesis.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
