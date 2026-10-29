"""
pool.py - mining together with no operator: the rules of a P2Pool-style share chain.

An ordinary mining pool is a company: it builds every block, holds everyone's payouts and learns
every member's address.  Here there is no company.  Members mine ordinary Vesper blocks, but a
block also counts as a SHARE when its proof of work meets a much easier target.  Shares form a
small chain of their own, kept by the members' nodes.  Every member's candidate block pays the
owners of the last `window` shares straight from the block reward, in proportion to the work
behind each share, so when any share also meets the real difficulty it is a real Vesper block
that has already paid everyone.  Nobody holds anything for anybody.

A share names no address.  It carries a payout STUB: a one-time key its owner's wallet made for
that share alone (index 0, see privacy.ViewKey.open), so nobody can tell two shares came from
the same member.  The amount is filled in by whoever builds the block, and it is public, like
every mining reward.

What a share commits to, and why that is enough: its block's coinbase pays exactly the split
that follows from its parent share's window, so the proof of work over the header (which commits
to the coinbase through the merkle root) also commits to the parent and to the split.  Moving a
share to another parent, or changing anyone's amount, breaks its proof of work.

This module is the rules (stage 1).  The node does not run a pool yet; see TECHNICAL.md,
"Mining together".
"""

from __future__ import annotations

import hashlib
import secrets
import threading
import time
from typing import Callable, Optional

from amounts import commit
from chain import (HEADER_KEYS, Blockchain, ChainError, block_header, canonical, compute_block_hash, compute_txid,
                   difficulty_target, merkle_root, pow_digest, step_difficulty)
from privacy import make_auditable_output, make_outputs

STUB_KEYS = ("one_time_pub", "ephemeral_pub", "view_tag", "enc_anchor")
SHARE_KEYS = frozenset({"header", "coinbase", "branch", "parent", "stub"})
DEFAULT_RULES = {
    "window": 60,                     # shares paid by each block (Monero P2Pool: 2,160)
    "share_seconds": 10,              # one share about this often, across the whole pool
    "initial_share_difficulty": 64,
    "halflife_seconds": 600,          # 0 = a fixed share difficulty (tests)
    "max_main_lag": 2,                # a share may build on a main block this many blocks below the tip
}


class PoolError(ChainError):
    pass


# ----------------------------------------------------------------------------- payouts
def payout_stub(address: str, prefix: str) -> dict:
    """A fresh one-time payout key for one share, made by the member's own wallet.  Nothing in
    it names the address, and two stubs to one address cannot be linked."""
    out = make_outputs([(address, 1)], prefix, hidden=False)[0][0]
    return {k: out[k] for k in STUB_KEYS}


def split(total: int, weights: list[int]) -> list[int]:
    """`total` in proportion to `weights`, rounded down; what the rounding leaves goes to the
    last one (the share that found the block)."""
    whole = sum(weights)
    amounts = [total * w // whole for w in weights]
    amounts[-1] += total - sum(amounts)
    return amounts


def pool_coinbase(paid: list, total: int, height: int, prefix: str, fund_address: str = "", fund_amount: int = 0) -> dict:
    """The coinbase of a pool block.  paid: [(stub, weight)], oldest share first, the share being
    mined last.  A share whose part rounds down to nothing gets no output (an output of 0 is not
    allowed); its part stays with the others."""
    amounts = split(total - fund_amount, [w for _, w in paid])
    outputs = []
    for (stub, _), amount in zip(paid, amounts):
        if amount > 0:
            outputs.append(dict(stub, index=len(outputs), amount=amount, commitment=commit(amount, 0).hex()))
    if fund_amount > 0:
        outputs.append(make_auditable_output(fund_address, fund_amount, len(outputs), prefix))
    tx = {"type": "coinbase", "inputs": [], "outputs": outputs, "fee": 0, "height": height, "excess_sig": None}
    tx["txid"] = compute_txid(tx)
    return tx


# ----------------------------------------------------------------------------- merkle branch
def _leaf(txid: str) -> bytes:
    return hashlib.sha256(b"\x00" + bytes.fromhex(txid)).digest()


def coinbase_branch(txids: list[str]) -> list[str]:
    """The hashes that join the first transaction (the coinbase) to the merkle root, so a share
    can prove its coinbase is in the block without carrying the block's payments."""
    level, branch = [_leaf(t) for t in txids], []
    while len(level) > 1:
        branch.append(level[1].hex())                 # the first node always has a partner while the level has two
        paired = [hashlib.sha256(b"\x01" + a + b).digest() for a, b in zip(level[0::2], level[1::2])]
        if len(level) % 2:
            paired.append(level[-1])
        level = paired
    return branch


def root_from_branch(coinbase_txid: str, branch: list[str]) -> str:
    node = _leaf(coinbase_txid)
    for sibling in branch:
        node = hashlib.sha256(b"\x01" + node + bytes.fromhex(sibling)).digest()
    return node.hex()


# ----------------------------------------------------------------------------- the share chain
class ShareChain:
    """Every share this member knows, and which one is the tip: the end of the chain with the
    most work behind it, as on the main chain."""

    def __init__(self, chain: Blockchain, rules: dict | None = None):
        self.chain = chain
        self.rules = dict(DEFAULT_RULES, **(rules or {}))
        if self.rules["window"] < 1 or self.rules["window"] + 1 > chain.max_coinbase_outputs:
            raise PoolError("a window of %d shares does not fit in a coinbase of %d outputs (one is kept for the fund)"
                            % (self.rules["window"], chain.max_coinbase_outputs))
        self.shares: dict[str, dict] = {}            # id -> share
        self.meta: dict[str, dict] = {}              # id -> {"parent", "difficulty", "timestamp", "work", "height"}
        self.tip: str | None = None
        self.lock = threading.RLock()

    # ---- what follows from the chain so far ----------------------------------------
    def difficulty_after(self, parent: str | None) -> int:
        """The share difficulty for a share on top of `parent` (its own rule, like the main chain's:
        about one share every `share_seconds` across the pool)."""
        if parent is None:
            return int(self.rules["initial_share_difficulty"])
        p = self.meta[parent]
        if not self.rules["halflife_seconds"] or p["parent"] is None:
            return p["difficulty"]
        solve = p["timestamp"] - self.meta[p["parent"]]["timestamp"]
        return step_difficulty(p["difficulty"], solve, int(self.rules["share_seconds"]), int(self.rules["halflife_seconds"]))

    def window(self, parent: str | None, n: int) -> list:
        """[(stub, weight)] of the last `n` shares ending at `parent`, oldest first."""
        out, at = [], parent
        while at is not None and len(out) < n:
            out.append((self.shares[at]["stub"], self.meta[at]["difficulty"]))
            at = self.meta[at]["parent"]
        out.reverse()
        return out

    def paid_by(self, parent: str | None, stub: dict) -> list:
        """Who a share on top of `parent` with payout `stub` must pay: the window, itself last."""
        return self.window(parent, int(self.rules["window"]) - 1) + [(stub, self.difficulty_after(parent))]

    # ---- checking and adding --------------------------------------------------------
    def check(self, share: dict) -> int:
        """Raises PoolError if `share` breaks a rule.  Returns its share difficulty."""
        if not isinstance(share, dict) or set(share) != SHARE_KEYS:
            raise PoolError("a share has the fields %s" % sorted(SHARE_KEYS))
        header, coinbase, parent, stub = share["header"], share["coinbase"], share["parent"], share["stub"]
        if not isinstance(header, dict) or set(header) != set(HEADER_KEYS) or \
                not all(type(header[k]) is int for k in ("index", "timestamp", "difficulty", "nonce")):
            raise PoolError("malformed share header")
        if not isinstance(stub, dict) or sorted(stub) != sorted(STUB_KEYS):
            raise PoolError("malformed payout stub")
        if parent is not None and parent not in self.meta:
            raise PoolError("unknown parent share (fetch it first)")
        chain = self.chain
        index = header["index"]
        with chain.lock:
            if type(index) is not int or not chain.height + 1 - int(self.rules["max_main_lag"]) <= index <= chain.height + 1:
                raise PoolError("the share builds on a main block that is too old or not there")
            if chain.blocks.hash_at(index - 1) != header["previous_hash"]:
                raise PoolError("the share builds on a block that is not on this node's chain")
            reward, fund_due = chain.reward_at(index), chain.dev_fund_at(index)
        # its coinbase is in the block it would be
        if not isinstance(coinbase, dict) or coinbase.get("type") != "coinbase" or coinbase.get("height") != index:
            raise PoolError("malformed coinbase")
        if coinbase.get("txid") != compute_txid(coinbase):
            raise PoolError("coinbase txid does not match")
        branch = share["branch"]
        if not isinstance(branch, list) or root_from_branch(coinbase["txid"], branch) != header["merkle_root"]:
            raise PoolError("the coinbase is not in the share's block")
        # enough work for a share
        difficulty = self.difficulty_after(parent)
        digest = int.from_bytes(pow_digest(canonical(header), chain.pow_algorithm, chain.pow_memory_kib, chain.pow_passes), "big")
        if digest >= difficulty_target(difficulty):
            raise PoolError("not enough work for a share (difficulty %d)" % difficulty)
        # and it pays exactly the window it builds on
        outputs = coinbase.get("outputs")
        if not isinstance(outputs, list) or not outputs:
            raise PoolError("malformed coinbase")
        fund = [o for o in outputs if isinstance(o, dict) and "ephemeral_secret" in o]
        if fund_due:
            if len(fund) != 1 or outputs[-1] is not fund[0] or fund[0].get("amount") != fund_due:
                raise PoolError("the development fund's share is missing or wrong")
        elif fund:
            raise PoolError("no development fund share is due")
        pool_outputs = outputs[:-1] if fund_due else outputs
        try:
            total = sum(int(o["amount"]) for o in outputs)
        except (KeyError, TypeError, ValueError):
            raise PoolError("malformed coinbase amounts")
        if total < reward:
            raise PoolError("the coinbase pays less than the block reward")
        expected = pool_coinbase(self.paid_by(parent, stub), total, index, chain.prefix)["outputs"]
        if len(expected) != len(pool_outputs) or any(
                {k: o.get(k) for k in STUB_KEYS + ("index", "amount", "commitment")} != {k: e[k] for k in STUB_KEYS + ("index", "amount", "commitment")}
                for o, e in zip(pool_outputs, expected)):
            raise PoolError("the coinbase does not pay the shares it builds on, in proportion to their work")
        return difficulty

    def add(self, share: dict) -> bool:
        """Check and remember a share.  Returns whether it became the new tip."""
        share_id = compute_block_hash(share["header"]) if isinstance(share, dict) and isinstance(share.get("header"), dict) else None
        with self.lock:
            if share_id in self.shares:
                return False
            difficulty = self.check(share)
            parent = share["parent"]
            work = difficulty + (self.meta[parent]["work"] if parent else 0)
            self.shares[share_id] = share
            self.meta[share_id] = {"parent": parent, "difficulty": difficulty, "timestamp": share["header"]["timestamp"],
                                   "work": work, "height": (self.meta[parent]["height"] + 1) if parent else 0}
            if self.tip is None or work > self.meta[self.tip]["work"]:
                self.tip = share_id
                return True
            return False


# ----------------------------------------------------------------------------- mining a share
def mine_share(sharechain: ShareChain, address: str, should_abort: Optional[Callable[[], bool]] = None,
               max_tries: int | None = None) -> tuple[dict, dict | None] | None:
    """Search for one share.  Returns (share, block): `block` is the whole main block when the
    share also met the real difficulty (hand it to the node), else None.  None if stopped."""
    chain = sharechain.chain
    with sharechain.lock:
        parent = sharechain.tip
        stub = payout_stub(address, chain.prefix)
        paid = sharechain.paid_by(parent, stub)
        share_target = difficulty_target(sharechain.difficulty_after(parent))

    def build(height, total, fund_address, fund_amount):
        return pool_coinbase(paid, total, height, chain.prefix, fund_address, fund_amount)

    block = chain.create_candidate_block(address, coinbase_builder=build)
    header = block_header(block)
    branch = coinbase_branch([tx["txid"] for tx in block["transactions"]])
    main_target = difficulty_target(block["difficulty"])
    nonce, tries = secrets.randbelow(1 << 32), 0
    while True:
        header["nonce"] = nonce
        digest = int.from_bytes(pow_digest(canonical(header), chain.pow_algorithm, chain.pow_memory_kib, chain.pow_passes), "big")
        if digest < share_target:
            share = {"header": dict(header), "coinbase": block["transactions"][0], "branch": branch, "parent": parent, "stub": stub}
            if digest < main_target:
                found = dict(block, nonce=nonce)
                found["hash"] = compute_block_hash(found)
                return share, found
            return share, None
        nonce += 1
        tries += 1
        if (max_tries is not None and tries >= max_tries) or (should_abort and should_abort()):
            return None
        if tries % 64 == 0 and int(time.time()) > header["timestamp"]:
            header["timestamp"] = int(time.time())
