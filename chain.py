"""
chain.py - Vesper's ledger.

The engine (blocks, proof-of-work, halvings, fork choice, mempool, disk) started as a transparent learning chain's.
What is different is what a node can SEE:

  phase 1  nothing on the chain says who received a payment.  Outputs are locked to one-time
           keys (privacy.py).
  phase 2  nothing on the chain says how much.  Amounts are sealed in commitments
           (amounts.py); a node checks that inputs = outputs + fee by adding the sealed
           envelopes together, and that no envelope holds a negative number with a range
           proof (rangeproof.py).  Only the fee and the mining reward are public numbers.
  phase 3  nothing on the chain says which output was spent.  A payment points at a RING of
           outputs and proves it owns one of them (ringsig.py), leaving behind a key image:
           an anonymous marker that makes a second spend of the same output impossible.
           Because nobody can tell what was spent, nothing is ever removed from the ledger.

So a transfer on the chain reads: "one output from each of these rings is being spent - I will
not say which - here are the markers, here are new sealed outputs, the fee is F, and here is
proof that it all adds up."  No names, no amounts, no trail, and no clock: a payment does not
even say when it was made, only which block it landed in.

The one exception is the development fund.  Its income is public, so its spending is too: fund
outputs are never ring members and are spent by naming them.  The fund is a glass box.

Every public number is an integer in the smallest unit.  Never floats.
"""

from __future__ import annotations

import copy
import hashlib
import json
import math
import os
import re
import secrets
import threading
import time
from collections import OrderedDict
from typing import Callable, Optional

import rangeproof
import ringsig
from amounts import MAX_AMOUNT, commit, value_generator
from curve import BACKEND, IDENTITY, L, Point, random_scalar, scalar_to_hex, sign, verify

from powcore import POW_ALGORITHMS, PowError, disable_windows_power_throttling  # noqa: F401 (re-exported)
from powcore import pow_digest as _pow_digest
from privacy import (is_valid_address, make_auditable_output, make_outputs, verify_auditable_output,
                     verify_input_signature)

ZERO_HASH = "0" * 64
MAX_TARGET = (1 << 256) - 1
MAX_MEMPOOL = 5000
MAX_MEMPOOL_BYTES = 32_000_000    # and at most this many bytes of them: 5,000 of the largest would be 450 MB
MAX_INPUTS = 32
MAX_OUTPUTS = 16
# A block may be at most this many bytes of JSON.  The transaction limit alone allowed a block of
# 200 of the largest payments, about 18 MB: valid, yet too big for nodes to pass on (8 MB) or
# fetch (16 MB), which would split the network.  200 ordinary payments are about 1 MB.
MAX_BLOCK_BYTES = 4_000_000
COINBASE_ROOM = 8_000             # what a miner keeps free for the header and the coinbase
SCAN_PAGE_BLOCKS = 200            # what one wallet-sync request may return at most ...
SCAN_PAGE_OUTPUTS = 4000          # ... whichever limit is reached first
MAX_LOOKUP = 512                  # outputs one ring lookup may ask for
RECENT_WINDOW = 720               # blocks over which "the chain's recent pace" is measured (6 hours)
MIN_TRANSFER_OUTPUTS = 2          # payment + change, always: every payment has the same shape
CHAIN_FILE = "chain.jsonl"
MEMPOOL_FILE = "mempool.json"
MARKER_FILE = "verified_tip.json"          # "this node already checked everything up to here"
NO_CLOCK = 1 << 62                         # "now", when replaying blocks this node already accepted

TX_KEYS = frozenset({"type", "inputs", "outputs", "fee", "height", "excess_sig", "txid"})
TRANSFER_KEYS = TX_KEYS | {"range_proof"}          # one range proof covers all of a payment's outputs
# What the ledger keeps of each output: only what checking payments needs.  The rest (the parts
# a wallet uses to recognise and open its own) stays in the block, and is read from there.
LEDGER_KEYS = ("one_time_pub", "commitment", "amount", "ephemeral_secret")
RING_INPUT_KEYS = frozenset({"ring", "key_image", "pseudo_commitment", "signature"})
FUND_INPUT_KEYS = frozenset({"txid", "index", "signature"})        # the development fund spends in the open
_HEX64 = re.compile(r"[0-9a-f]{64}")
HIDDEN_OUTPUT_KEYS = frozenset({"index", "one_time_pub", "ephemeral_pub", "view_tag", "enc_anchor", "commitment", "enc_amount"})
COINBASE_OUTPUT_KEYS = frozenset({"index", "one_time_pub", "ephemeral_pub", "view_tag", "enc_anchor", "commitment", "amount"})
_HEX2 = re.compile(r"[0-9a-f]{2}")
_HEX32 = re.compile(r"[0-9a-f]{32}")
AUDITABLE_OUTPUT_KEYS = COINBASE_OUTPUT_KEYS | {"ephemeral_secret"}     # the development fund's share of a block
HEADER_KEYS = ("index", "timestamp", "previous_hash", "merkle_root", "difficulty", "nonce")
BLOCK_KEYS = frozenset(HEADER_KEYS + ("transactions", "hash"))

HERE = os.path.dirname(os.path.abspath(__file__))

DEFAULT_CONFIG = {
    "coin": {"name": "Vesper", "ticker": "VESP", "decimals": 8, "address_prefix": "vesp"},
    "consensus": {
        "genesis_timestamp": 1791590400,
        "genesis_message": "Vesper genesis - 2026-10-10 - private by default",
        "block_reward": "50",
        "halving_interval_blocks": 2000,
        "target_block_seconds": 30,
        "difficulty_halflife_seconds": 600,
        "initial_difficulty": 1024,
        "min_difficulty": 16,
        "max_block_transactions": 200,
        "min_fee": "0.00001",
        "max_future_seconds": 120,
        "ring_size": 16,
        "output_lock_blocks": 10,
        "pow": {"algorithm": "argon2id", "memory_kib": 32768, "passes": 1},
        "dev_fund": {"percent": 10, "duration_blocks": 4204800, "address": ""},
    },
    "network": {"host": "127.0.0.1", "port": 8880, "peers": [], "sync_interval_seconds": 15},
    "mining": {"reward_address": "", "auto_start": False, "hashes_per_check": 20000, "processes": 0},
    "data_dir": "data",
}


class ChainError(Exception):
    """A block or transaction broke the rules."""


class BadBlock(ChainError):
    """A chain that is fine up to `height`, where block `height` breaks a rule."""

    def __init__(self, height: int, reason: str):
        super().__init__("block %d: %s" % (height, reason))
        self.height, self.reason = height, reason


# ----------------------------------------------------------------------------- config
def lock_data_dir(data_dir: str):
    """Claim the data folder for this process.  Two nodes on one folder write the same chain
    file at once and corrupt it, and `reset-chain` under a running node pulls the file away
    from under it.  Returns an open file whose lock lasts as long as it stays open (or the
    process lives); raises ChainError if another process holds the folder."""
    os.makedirs(data_dir, exist_ok=True)
    fh = open(os.path.join(data_dir, "node.lock"), "a+")
    try:
        if os.name == "nt":
            import msvcrt
            fh.seek(0)
            msvcrt.locking(fh.fileno(), msvcrt.LK_NBLCK, 1)
        else:
            import fcntl
            fcntl.flock(fh.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
    except OSError:
        fh.close()
        raise ChainError("another Vesper node is already using the data folder %s. Only one node can use a "
                         "data folder: close the other node window first." % os.path.abspath(data_dir))
    return fh


def deep_merge(base: dict, override: dict) -> dict:
    out = copy.deepcopy(base)
    for key, value in (override or {}).items():
        if isinstance(value, dict) and isinstance(out.get(key), dict):
            out[key] = deep_merge(out[key], value)
        else:
            out[key] = value
    return out


def load_config(path: str | None = None) -> dict:
    path = path or os.path.join(HERE, "config.json")
    user = {}
    if os.path.exists(path):
        with open(path, "r", encoding="utf-8") as fh:
            user = json.load(fh)
    cfg = deep_merge(DEFAULT_CONFIG, user)
    cfg["_path"] = path
    return cfg


def resolve_data_dir(config: dict, override: str | None = None) -> str:
    folder = override or config.get("data_dir") or "data"
    if not os.path.isabs(folder):
        folder = os.path.join(HERE, folder)
    return folder


# ----------------------------------------------------------------------------- hashing
def sha256d_hex(data: bytes) -> str:
    return hashlib.sha256(hashlib.sha256(data).digest()).hexdigest()


def canonical(obj) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode("utf-8")


# ----------------------------------------------------------------------------- amounts
def to_units(text, decimals: int) -> int:
    s = str(text).strip()
    if not s or s.startswith("-") or s.startswith("+"):
        raise ValueError("amount must be a positive number like 1.5")
    whole, _, frac = s.partition(".")
    whole = whole or "0"
    if not whole.isdigit() or (frac and not frac.isdigit()):
        raise ValueError("not a valid amount: %r" % text)
    if len(frac) > decimals:
        raise ValueError("too many decimal places (max %d)" % decimals)
    return int(whole) * 10 ** decimals + int(frac.ljust(decimals, "0") or "0")


def format_units(units: int, decimals: int, ticker: str | None = None) -> str:
    sign_ = "-" if units < 0 else ""
    units = abs(int(units))
    whole, frac = divmod(units, 10 ** decimals)
    text = str(whole)
    if decimals:
        frac_text = str(frac).rjust(decimals, "0").rstrip("0")
        if frac_text:
            text += "." + frac_text
    text = sign_ + text
    return text + " " + ticker if ticker else text


# ----------------------------------------------------------------------------- transactions
def outpoint(txid: str, index: int) -> str:
    return "%s:%d" % (txid, index)


def _is_hex64(value) -> bool:
    """Exactly 32 bytes in lowercase hex.  Key images are compared as text, so there must be
    only one way to write each of them."""
    return isinstance(value, str) and _HEX64.fullmatch(value) is not None


def fee_weight(n_inputs: int, n_outputs: int) -> int:
    """How many times the minimum fee a transfer must pay.  The ordinary payment - one input,
    two outputs - costs one unit; every extra input or output costs one more.  Outputs stay on
    the ledger forever and inputs cost every node a ring check, so neither may be free."""
    return max(1, n_inputs + n_outputs - 2)


def input_order_key(inp) -> str:
    """Inputs are listed in this order, never in the order a wallet picked them: wallets pick
    the biggest coins first, so that order would say which hidden input holds more."""
    if isinstance(inp, dict) and isinstance(inp.get("key_image"), str):
        return inp["key_image"]
    if isinstance(inp, dict):
        return "fund:%s:%s" % (inp.get("txid"), inp.get("index"))
    return ""


def tx_signing_bytes(tx: dict) -> bytes:
    """What every signature in a transaction covers: everything except the signatures.
    The outputs are included whole - one-time keys and sealed amounts - and so are the range
    proof, the rings and the key images of the inputs."""
    body = {
        "type": tx["type"],
        "inputs": [{k: v for k, v in i.items() if k != "signature"} for i in tx["inputs"]],
        "outputs": tx["outputs"],
        "fee": tx["fee"],
        "height": tx["height"],
    }
    if "range_proof" in tx:
        body["range_proof"] = tx["range_proof"]
    return canonical(body)


def compute_txid(tx: dict) -> str:
    body = {k: tx[k] for k in TX_KEYS if k != "txid"}
    if tx.get("type") == "transfer":
        body["range_proof"] = tx.get("range_proof")
    return sha256d_hex(canonical(body))


def make_coinbase_tx(miner_address: str, amount: int, height: int, prefix: str,
                     fund_address: str = "", fund_amount: int = 0) -> dict:
    """New coins, paid to a one-time key.  The AMOUNT of a mining reward is public (everyone
    must be able to check it); WHO mined is not.

    `amount` is the whole block payout (reward + fees).  When a development-fund share is due,
    it is split off into a second output whose recipient anyone can verify (see privacy.py)."""
    outputs = []
    if amount - fund_amount > 0:
        outputs, _ = make_outputs([(miner_address, amount - fund_amount)], prefix, hidden=False)
    if fund_amount > 0:
        outputs.append(make_auditable_output(fund_address, fund_amount, len(outputs), prefix))
    tx = {"type": "coinbase", "inputs": [], "outputs": outputs, "fee": 0, "height": height, "excess_sig": None}
    tx["txid"] = compute_txid(tx)
    return tx


class LocalRings:
    """Where ring members come from when the whole list of outputs is at hand: the tests, the
    demo, a small chain.  A wallet talking to a node asks the same three questions over the
    network instead (coin.py), and never has to download the list.

    `spend_height` and `lock`: only outputs at least `lock` blocks older than the block the
    payment would land in may be used.  `block_seconds`: the chain's target block time."""

    def __init__(self, all_outputs: list, spend_height: int | None = None, lock: int = 0, block_seconds: int = 30):
        self._by_position = {u["output"]["position"]: u for u in all_outputs}
        self._by_ref = {outpoint(u["txid"], u["index"]): u for u in all_outputs}
        self._eligible = len(all_outputs) if spend_height is None else sum(
            1 for u in all_outputs if u["output"]["height"] + lock <= spend_height)
        heights = [u["output"].get("height", 0) for u in all_outputs]
        tip = max(heights) if heights else 0
        window = max(1, min(RECENT_WINDOW, tip))
        self.outputs_per_block = max(0.01, sum(1 for h in heights if h > tip - window) / window)
        self.lock_blocks, self.block_seconds = lock, block_seconds

    def eligible_count(self) -> int:
        """How many outputs, counted from the oldest, are old enough to use."""
        return self._eligible

    def by_positions(self, positions: list) -> list:
        return [self._by_position.get(p) for p in positions]

    def by_refs(self, refs: list) -> list:
        return [self._by_ref.get(r) for r in refs]


def _usable_decoy(record, eligible: int) -> bool:
    out = record.get("output") if isinstance(record, dict) else None
    return (isinstance(out, dict) and "ephemeral_secret" not in out            # fund outputs never join rings
            and type(out.get("position")) is int and 0 <= out["position"] < eligible
            and isinstance(record.get("txid"), str) and type(record.get("index")) is int)


def assemble_ring(rings, real: dict, remembered, ring_size: int) -> dict:
    """The crowd one input hides in: {reference: output}, `ring_size` of them, `real` included.

    remembered: the ring this wallet used for this output before, if any.  Its members are
    kept; only members that no longer exist (a reorganisation took them) are replaced.  Two
    rings for one coin that share nothing but the real output would give it away, so as much
    as possible stays the same.

    Whatever is asked of `rings`, the real output is asked for along with the decoys, so the
    one answering cannot tell it apart."""
    eligible = rings.eligible_count()
    real_ref = outpoint(real["txid"], real["index"])
    position = real["output"].get("position")
    if type(position) is not int or not 0 <= position < eligible:
        raise ValueError("that coin is too new to spend yet: it has to be a few blocks old first")
    members = {real_ref: real["output"]}
    taken = {position}
    fresh_ring = True
    if (isinstance(remembered, list) and len(remembered) == ring_size and real_ref in remembered
            and all(isinstance(r, str) for r in remembered)):
        fresh_ring = False
        for ref, record in zip(remembered, rings.by_refs(remembered)):
            if ref == real_ref:
                if record is None:
                    raise ValueError("the output being spent is not on the chain the node showed: scan again")
            elif _usable_decoy(record, eligible) and outpoint(record["txid"], record["index"]) == ref:
                members[ref] = record["output"]
                taken.add(record["output"]["position"])
    rng = secrets.SystemRandom()
    for _ in range(40):
        need = ring_size - len(members)
        if need <= 0:
            break
        draws = ringsig.draw_positions(eligible, taken, need + 2,           # two spare: some draws hit fund outputs
                                       getattr(rings, "outputs_per_block", 1.0), getattr(rings, "lock_blocks", 0),
                                       getattr(rings, "block_seconds", 30))
        if not draws:
            break
        ask = sorted(draws + [position]) if fresh_ring else draws
        found = dict(zip(ask, rings.by_positions(ask)))
        if fresh_ring:
            mine = found.get(position)
            if not isinstance(mine, dict) or outpoint(mine.get("txid"), mine.get("index", -1)) != real_ref:
                raise ValueError("the output being spent is not where the node's chain has it: scan again")
            fresh_ring = False
        taken.update(draws)
        decoys = [found[p] for p in draws if _usable_decoy(found[p], eligible) and found[p]["output"]["position"] == p]
        rng.shuffle(decoys)
        for record in decoys[:need]:
            members[outpoint(record["txid"], record["index"])] = record["output"]
    if len(members) < ring_size:
        raise ValueError("the chain is too young to hide a payment: a ring needs %d other outputs that are old enough "
                         "to use, and only %d exist yet" % (ring_size - 1, len(members) - 1))
    return members


def build_transfer(keys, owned: list, payments: list, fee: int | None, prefix: str, rings,
                   ring_size: int, min_fee: int = 0, known_rings: dict | None = None, fmt=str, sent: list | None = None) -> dict:
    """keys: StealthKeys.  owned: the wallet's SPENDABLE outputs, as its scan returned them
    (unspent, not already in a waiting payment, old enough).  payments: [(address, amount), ...].
    rings: where ring members come from - a LocalRings, anything answering the same three
    questions, or simply the list of every output on the chain ([{"txid","index","output"}]).

    fee=None pays exactly the minimum for the transaction's size (given `min_fee`, the price
    of an ordinary payment).  That is the private choice: an unusual fee is a fingerprint.

    sent: if a list is given, one entry per payment output (not the change) is appended to it,
    {"index", "address", "amount", "r"}: what the payer keeps to prove the payment later.

    known_rings: {key image: ring} this wallet used before.  If an output was put in a ring
    once, the SAME ring is used again (see assemble_ring).  Otherwise a retried payment would
    show two different rings whose only common member is the real output - and the sender
    would be exposed.  New rings are added to the dict; the caller should save it before
    sending anything.

    Always adds a change output back to the sender, even when the change is zero, and shuffles
    the outputs, so an observer cannot tell which output is the payment or whether there was
    any change at all."""
    payments = [(address, int(amount)) for address, amount in payments]
    total_out = sum(amount for _, amount in payments)
    if not payments or total_out <= 0 or any(amount < 0 for _, amount in payments):
        raise ValueError("nothing to pay")
    n_outputs = len(payments) + 1
    if n_outputs > MAX_OUTPUTS:
        raise ValueError("too many recipients in one transaction (max %d)" % (MAX_OUTPUTS - 1))

    def fee_for(n_inputs: int) -> int:
        return int(fee) if fee is not None else min_fee * fee_weight(n_inputs, n_outputs)

    def pick(coins):
        chosen, total = [], 0
        for u in sorted(coins, key=lambda u: -u["amount"]):
            if chosen and total >= total_out + fee_for(len(chosen)):
                break
            chosen.append(u)
            total += u["amount"]
        return chosen, total

    # Coins that came to different addresses of this wallet are spent together only when no one
    # address holds enough.  Two payers who each find their own coin among the rings of one
    # payment could otherwise guess that the addresses they paid belong together.
    groups: dict = {}
    for u in owned:
        groups.setdefault(u.get("address", 0), []).append(u)
    alone = [(c, t) for c, t in map(pick, groups.values()) if c and t >= total_out + fee_for(len(c))]
    chosen, total_in = min(alone, key=lambda ct: (len(ct[0]), ct[1])) if alone else pick(owned)   # fewest coins, least change
    fee = fee_for(max(1, len(chosen)))
    if not chosen or total_in < total_out + fee:
        raise ValueError("insufficient funds: have %s, need %s (amount + fee)" % (fmt(total_in), fmt(total_out + fee)))
    if len(chosen) > MAX_INPUTS:
        raise ValueError("too many small outputs to spend at once; consolidate first")
    if fee < min_fee * fee_weight(len(chosen), n_outputs):
        raise ValueError("fee too low: %d input(s) and %d output(s) need at least %s"
                         % (len(chosen), n_outputs, fmt(min_fee * fee_weight(len(chosen), n_outputs))))

    change = (keys.address, total_in - total_out - fee)
    all_payments = payments + [change]
    secrets.SystemRandom().shuffle(all_payments)
    payer_secrets: list = []
    outputs, openings = make_outputs(all_payments, prefix, hidden=True, secrets_out=payer_secrets)
    if sent is not None:                 # what the payer needs to prove these payments later (proofs.py)
        sent.extend({"index": i, "address": pay[0], "amount": pay[1], "r": scalar_to_hex(r)}
                    for i, (pay, r) in enumerate(zip(all_payments, payer_secrets)) if pay is not change)
    proof = rangeproof.prove_many([amount for amount, _ in openings], [blinding for _, blinding in openings])

    if isinstance(rings, list):
        rings = LocalRings(rings)
    eligible = rings.eligible_count()
    known_rings = {} if known_rings is None else known_rings
    inputs, plans, blinding_in = [], [], 0
    for u in chosen:
        ref = outpoint(u["txid"], u["index"])
        x = keys.owns(u["output"])
        if x is None:
            raise ValueError("this wallet does not own one of the outputs it was asked to spend")
        if "ephemeral_secret" in u["output"]:
            if not 0 <= u["output"].get("position", eligible) < eligible:
                raise ValueError("that coin is too new to spend yet: it has to be a few blocks old first")
            inputs.append({"txid": u["txid"], "index": u["index"], "signature": None})
            plans.append(("fund", x, None))
            blinding_in += u["blinding"]
            continue
        image = ringsig.key_image(x, ref, u["output"]["one_time_pub"]).hex()
        members = assemble_ring(rings, u, known_rings.get(image), ring_size)
        ring = sorted(members)
        known_rings[image] = ring
        pseudo_blinding = random_scalar()                         # a fresh envelope for the same amount
        inputs.append({"ring": ring, "key_image": image,
                       "pseudo_commitment": commit(u["amount"], pseudo_blinding).hex(), "signature": None})
        plans.append(("ring", x, (ring.index(ref), (u["blinding"] - pseudo_blinding) % L, [members[r] for r in ring])))
        blinding_in += pseudo_blinding

    order = sorted(range(len(inputs)), key=lambda i: input_order_key(inputs[i]))
    inputs, plans = [inputs[i] for i in order], [plans[i] for i in order]
    tx = {"type": "transfer", "inputs": inputs, "outputs": outputs, "fee": fee, "height": 0, "excess_sig": None,
          "range_proof": proof}
    message = tx_signing_bytes(tx)
    # The blindings do not cancel, on purpose: what is left over is a private key, and signing
    # with it proves the leftover contains no hidden coins.
    tx["excess_sig"] = sign((blinding_in - sum(blinding for _, blinding in openings)) % L, message)
    for inp, (kind, x, extra) in zip(tx["inputs"], plans):
        if kind == "fund":
            inp["signature"] = sign(x, message)
        else:
            position, z, members = extra
            inp["signature"] = ringsig.sign(
                message, inp["ring"],
                [Point.from_hex_unchecked(m["one_time_pub"]) for m in members],
                [Point.from_hex_unchecked(m["commitment"]) for m in members],
                Point.from_hex(inp["pseudo_commitment"]), position, x, z)
    tx["txid"] = compute_txid(tx)
    return tx


# ----------------------------------------------------------------------------- merkle / blocks / PoW
def merkle_root(txids) -> str:
    """One hash that commits to an ordered list of transaction IDs.

    Two details matter.  Leaves and inner nodes are hashed with different prefixes, so an inner
    node can never be passed off as a transaction.  And an odd node moves up unchanged instead
    of being paired with a copy of itself: Bitcoin pairs it with a copy, which lets a block and
    a doctored twin that repeats a transaction share one ID (CVE-2012-2459)."""
    level = [hashlib.sha256(b"\x00" + bytes.fromhex(txid)).digest() for txid in txids]
    if not level:
        return ZERO_HASH
    while len(level) > 1:
        paired = [hashlib.sha256(b"\x01" + a + b).digest() for a, b in zip(level[0::2], level[1::2])]
        if len(level) % 2:
            paired.append(level[-1])
        level = paired
    return level[0].hex()


def block_header(block: dict) -> dict:
    return {k: block[k] for k in HEADER_KEYS}


def compute_block_hash(block: dict) -> str:
    return sha256d_hex(canonical(block_header(block)))


def difficulty_target(difficulty: int) -> int:
    """`difficulty` is the average number of tries a block takes.  A try succeeds when its
    256-bit result is below this target."""
    return MAX_TARGET // max(1, difficulty)


def step_difficulty(previous: int, solve_seconds: int, target_seconds: int, halflife: int) -> int:
    """The next block's difficulty:  previous x 2^((target - solve) / halflife).

    A block that came early pushes the difficulty up, a late one pulls it down, and `halflife`
    seconds of being early (or late) doubles (or halves) it.  There is no window of old blocks
    to average, so nothing "falls out of the window" later and makes the difficulty swing
    again - the echo that hit-and-run miners feed on.  And the steps multiply out: whatever
    order a miner puts timestamps in, the difficulty ends up where honest ones would have put
    it.  (This is the step-by-step form of the ASERT rule Bitcoin Cash adopted in 2020.)

    Two limits.  One block can at most double the difficulty or cut it to a quarter, so a
    network that was simply switched off for a day does not come back to a flood of free
    blocks.  And the arithmetic is integers only, with the same cubic stand-in for 2^x that
    Bitcoin Cash uses (off by less than 0.013%), so every computer gets the same answer."""
    lead = max(-2 * halflife, min(halflife, target_seconds - solve_seconds))
    exponent = (lead * 65536) // halflife                  # 16-bit fixed point; floors for negatives too
    shifts, frac = exponent >> 16, exponent & 0xFFFF
    factor = 65536 + ((195766423245049 * frac + 971821376 * frac * frac + 5127 * frac ** 3 + (1 << 47)) >> 48)
    value = previous * factor
    value = (value << shifts if shifts >= 0 else value >> -shifts) >> 16
    if lead > 0:
        value = max(value, previous + 1)                   # tiny difficulties must still be able to climb
    elif lead < 0:
        value = min(value, previous - 1)
    return max(1, min(MAX_TARGET, value))


def pow_digest(header_bytes: bytes, algorithm: str, memory_kib: int = 0, passes: int = 1) -> bytes:
    """The number a miner has to get below the target (powcore.pow_digest, with the coin's error type)."""
    try:
        return _pow_digest(header_bytes, algorithm, memory_kib, passes)
    except PowError as exc:
        raise ChainError(str(exc))


# ----------------------------------------------------------------------------- ledger state
class State:
    """What every node remembers.

    Since phase 3 nobody can tell which outputs have been spent, so nothing is ever removed:
    the ledger is every output ever made, plus the set of key images - one anonymous "this was
    spent" marker per spend.  (The development fund is the exception: it spends by name.)"""

    __slots__ = ("outputs", "order", "key_images", "fund_spent", "fund_unspent")

    def __init__(self):
        # every output ever: reference -> the output, plus the block that made it ("height")
        # and its place in the line of all outputs ("position")
        self.outputs: dict[str, dict] = {}
        self.order: list[str] = []                   # position -> reference
        self.key_images: set[str] = set()            # spent markers
        self.fund_spent: set[str] = set()            # fund outputs spent in the open
        self.fund_unspent = 0

    def get_output(self, ref: str):
        return self.outputs.get(ref)

    def count(self) -> int:
        return len(self.order)

    def has_key_image(self, image: str) -> bool:
        return image in self.key_images

    def fund_is_spent(self, ref: str) -> bool:
        return ref in self.fund_spent

    def absorb(self, view: "StateView") -> None:
        """Make a validated scratch layer permanent."""
        self.outputs.update(view.outputs)
        self.order.extend(view.outputs)
        self.key_images |= view.key_images
        self.fund_spent |= view.fund_spent
        self.fund_unspent += view.fund_delta

    def rewind(self, blocks: list) -> None:
        """Take the newest blocks back out again (they lost to another branch).  Nothing is
        ever removed from the ledger otherwise, so undoing a block is just forgetting what it
        added - no need to replay the chain from the start."""
        removed = 0
        for block in reversed(blocks):
            for tx in reversed(block["transactions"]):
                for inp in tx["inputs"]:
                    if "key_image" in inp:
                        self.key_images.discard(inp["key_image"])
                    else:
                        ref = outpoint(inp["txid"], inp["index"])
                        self.fund_spent.discard(ref)
                        self.fund_unspent += self.outputs[ref]["amount"]
                for out in tx["outputs"]:
                    gone = self.outputs.pop(outpoint(tx["txid"], out["index"]))
                    removed += 1
                    if "ephemeral_secret" in gone:
                        self.fund_unspent -= gone["amount"]
        if removed:
            del self.order[-removed:]           # the newest outputs are always the last in line


class Rewound:
    """The ledger as it was before some of its newest blocks: a read-only mask, so another
    branch can be checked against the past without touching the present."""

    __slots__ = ("base", "outputs", "key_images", "fund_spent")

    def __init__(self, base: State, blocks: list):
        self.base = base
        self.outputs, self.key_images, self.fund_spent = set(), set(), set()
        for block in blocks:
            for tx in block["transactions"]:
                self.outputs.update(outpoint(tx["txid"], out["index"]) for out in tx["outputs"])
                for inp in tx["inputs"]:
                    if "key_image" in inp:
                        self.key_images.add(inp["key_image"])
                    else:
                        self.fund_spent.add(outpoint(inp["txid"], inp["index"]))

    def get_output(self, ref: str):
        return None if ref in self.outputs else self.base.get_output(ref)

    def has_key_image(self, image: str) -> bool:
        return image not in self.key_images and self.base.has_key_image(image)

    def fund_is_spent(self, ref: str) -> bool:
        return ref not in self.fund_spent and self.base.fund_is_spent(ref)

    def count(self) -> int:
        return self.base.count() - len(self.outputs)


class StateView:
    """A scratch layer on top of the ledger: "the ledger as it would be if these transactions
    were added".  Validating a block or a mempool transaction writes here and never copies the
    ledger itself, so the cost depends on the size of the block, not the size of the chain."""

    __slots__ = ("base", "outputs", "key_images", "fund_spent", "fund_delta")

    def __init__(self, base):
        self.base = base
        self.outputs: dict[str, dict] = {}
        self.key_images: set[str] = set()
        self.fund_spent: set[str] = set()
        self.fund_delta = 0

    def get_output(self, ref: str):
        out = self.outputs.get(ref)
        return out if out is not None else self.base.get_output(ref)

    def has_key_image(self, image: str) -> bool:
        return image in self.key_images or self.base.has_key_image(image)

    def fund_is_spent(self, ref: str) -> bool:
        return ref in self.fund_spent or self.base.fund_is_spent(ref)

    def count(self) -> int:
        return self.base.count() + len(self.outputs)

    def absorb(self, view: "StateView") -> None:
        """Fold a layer that was stacked on this one into it."""
        self.outputs.update(view.outputs)
        self.key_images |= view.key_images
        self.fund_spent |= view.fund_spent
        self.fund_delta += view.fund_delta

    def apply(self, tx: dict, height: int) -> None:
        """Add a transaction that block `height` contains (or would contain)."""
        for inp in tx["inputs"]:
            if "key_image" in inp:
                self.key_images.add(inp["key_image"])
            else:
                ref = outpoint(inp["txid"], inp["index"])
                self.fund_spent.add(ref)
                self.fund_delta -= self.get_output(ref)["amount"]
        for out in tx["outputs"]:
            kept = {k: out[k] for k in LEDGER_KEYS if k in out}
            kept["height"], kept["position"] = height, self.count()
            self.outputs[outpoint(tx["txid"], out["index"])] = kept
            if "ephemeral_secret" in out:
                self.fund_delta += out["amount"]


# ----------------------------------------------------------------------------- where the blocks are kept
class BlockStore:
    """The chain's blocks, oldest first, used like a list: len(), [i], [a:b], append, iteration.

    Only the newest KEEP blocks are held whole in memory (and the genesis block).  For every
    block the store remembers its ID and where its line ends in chain.jsonl, and an older block
    is read back from the file when something asks for it: a peer catching up, a wallet
    scanning, the explorer.  The last CACHED blocks read back are kept too.  So a node's memory
    no longer grows with every block it has ever seen - only the IDs and offsets do, about a
    hundred bytes a block.  Without a file (the tests, a chain kept in memory) nothing is
    dropped."""

    KEEP = 1000          # newest blocks held whole: far more than a reorganisation or the difficulty rule needs
    CACHED = 256         # older blocks kept after being read back

    def __init__(self, path: str | None = None):
        self.path = path
        self.hashes: list[str] = []                # block IDs, by height
        self.ends: list[int] = []                  # where each block's line ends in the file (bytes)
        self._heights: dict[str, int] = {}         # block ID -> height
        self._whole: dict[int, dict] = {}
        self._cache: OrderedDict = OrderedDict()

    def __len__(self) -> int:
        return len(self.hashes)

    @property
    def end(self) -> int:
        """Where the newest block's line ends in the file."""
        return self.ends[-1] if self.ends else 0

    def hash_at(self, height: int) -> str:
        return self.hashes[height]

    def height_of(self, block_id: str):
        return self._heights.get(block_id)

    def append(self, block: dict, end: int = 0) -> None:
        height = len(self.hashes)
        self.hashes.append(block["hash"])
        self.ends.append(end)
        self._heights[block["hash"]] = height
        self._whole[height] = block
        if self.path and height - self.KEEP > 0:
            self._whole.pop(height - self.KEEP, None)

    def truncate(self, length: int) -> None:
        """Forget the blocks from height `length` on (they lost to another branch)."""
        for block_id in self.hashes[length:]:
            self._heights.pop(block_id, None)
        del self.hashes[length:], self.ends[length:]
        for height in [h for h in self._whole if h >= length]:
            del self._whole[height]
        for height in [h for h in self._cache if h >= length]:
            del self._cache[height]

    def __getitem__(self, key):
        if isinstance(key, slice):
            return [self._get(i) for i in range(*key.indices(len(self)))]
        if key < 0:
            key += len(self)
        if not 0 <= key < len(self):
            raise IndexError("no block at height %d" % key)
        return self._get(key)

    def __iter__(self):
        for i in range(len(self)):
            yield self._get(i)

    def __reversed__(self):
        for i in range(len(self) - 1, -1, -1):
            yield self._get(i)

    def _get(self, height: int) -> dict:
        block = self._whole.get(height)
        if block is not None:
            return block
        block = self._cache.get(height)
        if block is not None:
            self._cache.move_to_end(height)
            return block
        start = self.ends[height - 1] if height else 0
        with open(self.path, "rb") as fh:
            fh.seek(start)
            line = fh.read(self.ends[height] - start)
        try:
            block = json.loads(line)
        except ValueError:
            block = None
        if not isinstance(block, dict) or block.get("hash") != self.hashes[height]:
            raise ChainError("block %d in %s was changed on disk while the node was running; restart the node and it "
                             "will check the file again" % (height, self.path))
        self._cache[height] = block
        if len(self._cache) > self.CACHED:
            self._cache.popitem(last=False)
        return block


class _Branch:
    """The chain up to block `common`, plus the blocks of another branch being checked on top
    of it - without copying the chain."""

    def __init__(self, base: BlockStore, common: int):
        self.base, self.common, self.tail = base, common, []

    def __len__(self) -> int:
        return self.common + 1 + len(self.tail)

    def __getitem__(self, key):
        if isinstance(key, slice):
            return [self[i] for i in range(*key.indices(len(self)))]
        if key < 0:
            key += len(self)
        if not 0 <= key < len(self):
            raise IndexError("no block at height %d" % key)
        return self.base[key] if key <= self.common else self.tail[key - self.common - 1]

    def append(self, block: dict) -> None:
        self.tail.append(block)


# ----------------------------------------------------------------------------- the blockchain
class Blockchain:
    def __init__(self, config: dict, data_dir: str | None = None, recheck_work: bool = False):
        self.config = config
        coin, rules = config["coin"], config["consensus"]
        self.name = coin["name"]
        self.ticker = coin["ticker"]
        self.decimals = int(coin["decimals"])
        self.prefix = coin["address_prefix"]
        self.block_reward_units = to_units(rules["block_reward"], self.decimals)
        self.min_fee_units = to_units(rules["min_fee"], self.decimals)
        self.halving_interval = int(rules["halving_interval_blocks"])
        self.target_seconds = int(rules["target_block_seconds"])
        self.difficulty_halflife = int(rules["difficulty_halflife_seconds"])
        self.initial_difficulty = int(rules["initial_difficulty"])
        self.min_difficulty = int(rules["min_difficulty"])
        if self.initial_difficulty < 1 or self.min_difficulty < 1 or self.target_seconds < 1 or self.difficulty_halflife < 0:
            raise ChainError("consensus difficulty settings must be positive (difficulty_halflife_seconds may be 0 for a fixed difficulty)")
        work = rules.get("pow") or {}
        self.pow_algorithm = str(work.get("algorithm", "argon2id"))
        self.pow_memory_kib = int(work.get("memory_kib", 32768))
        self.pow_passes = int(work.get("passes", 1))
        if self.pow_algorithm not in POW_ALGORITHMS or self.pow_memory_kib < 8 or self.pow_passes < 1:
            raise ChainError("consensus.pow must be one of %s with memory_kib >= 8 and passes >= 1" % (POW_ALGORITHMS,))
        self.recheck_work = recheck_work                 # True: re-verify every block in full on load
        self.repaired = None                             # (height, reason, where the damaged file went), if any
        self.work_checks = 0                             # how many proofs of work this node has computed
        self.max_block_txs = int(rules["max_block_transactions"])
        self.max_future_seconds = int(rules["max_future_seconds"])
        self.ring_size = int(rules.get("ring_size", 16))
        if not 2 <= self.ring_size <= 64:
            raise ChainError("consensus.ring_size must be between 2 and 64")
        self.output_lock = int(rules.get("output_lock_blocks", 10))
        if self.output_lock < 0:
            raise ChainError("consensus.output_lock_blocks must not be negative")
        self.genesis_timestamp = int(rules["genesis_timestamp"])
        self.genesis_message = str(rules["genesis_message"])
        self.network = str(rules.get("network", ""))     # e.g. "testnet-1"; hashed into genesis like every rule
        self.rules_fingerprint = sha256d_hex(canonical(rules))      # every consensus setting, hashed into the genesis block
        fund = rules.get("dev_fund") or {}
        self.dev_fund_percent = int(fund.get("percent", 0))
        self.dev_fund_blocks = int(fund.get("duration_blocks", 0))
        self.dev_fund_address = str(fund.get("address") or "")
        if not 0 <= self.dev_fund_percent <= 99 or self.dev_fund_blocks < 0:
            raise ChainError("development fund: percent must be 0-99 and duration_blocks must not be negative")
        if self.dev_fund_address and not is_valid_address(self.dev_fund_address, self.prefix):
            raise ChainError("development fund: consensus.dev_fund.address is not a valid %s address" % self.ticker)

        self.lock = threading.RLock()
        self.data_dir = data_dir
        self.blocks = BlockStore(self._path(CHAIN_FILE) if data_dir else None)
        genesis = self.make_genesis()
        self.blocks.append(genesis, len(self._block_line(genesis)) if data_dir else 0)
        self.state = State()
        self.known_txids: dict[str, int] = {}            # txid -> the block it is in
        self.output_counts: list[int] = [0]              # how many outputs exist after each block
        self.work = 0                                    # total tries behind the chain: what fork choice compares
        # since this node started: switches to another branch, the blocks those switches threw away,
        # and valid competing blocks that lost (what tells whether the block time is too short)
        self.forks = {"reorganisations": 0, "blocks_orphaned": 0, "competing_blocks_lost": 0}
        self.mempool: dict[str, dict] = {}
        self.mempool_bytes = 0
        self.mempool_version = 0                         # goes up with every change; the miner watches it
        self._pending = StateView(self.state)            # the ledger plus everything waiting in the mempool
        self.refresh_seconds = 1.0                       # how often a miner may rebuild its block for new payments
        self._mempool_saved = 0.0
        # txids whose signatures and range proofs were already checked.  A txid is a hash of
        # the whole transaction, so the same txid can never need checking twice.  This is what
        # keeps mining and block validation fast: the heavy maths is done once, on arrival.
        self._verified: set[str] = set()
        if self.data_dir:
            os.makedirs(self.data_dir, exist_ok=True)
            self._load()

    # ---- basics ---------------------------------------------------------------
    def make_genesis(self) -> dict:
        block = {
            "index": 0, "timestamp": self.genesis_timestamp, "previous_hash": ZERO_HASH,
            "merkle_root": sha256d_hex((self.genesis_message + "|" + self.rules_fingerprint).encode("utf-8")),
            "difficulty": self.initial_difficulty, "nonce": 0, "transactions": [],
        }
        block["hash"] = compute_block_hash(block)
        return block

    @property
    def tip(self) -> dict:
        return self.blocks[-1]

    @property
    def height(self) -> int:
        return len(self.blocks) - 1

    def fmt(self, units: int) -> str:
        return format_units(units, self.decimals, self.ticker)

    def reward_at(self, height: int) -> int:
        era = height // self.halving_interval
        return self.block_reward_units >> era if era < 64 else 0

    def max_supply(self) -> int:
        total, reward = 0, self.block_reward_units
        while reward:
            total += reward * self.halving_interval
            reward >>= 1
        return total

    def _sum_over_blocks(self, last_block: int, per_block) -> int:
        """sum of per_block(reward of that block) for blocks 1..last_block, one halving era at a time."""
        total = 0
        for era in range(64):
            first = max(1, era * self.halving_interval)
            last = min(last_block, (era + 1) * self.halving_interval - 1)
            if first > last_block:
                break
            if first <= last:
                total += (last - first + 1) * per_block(self.block_reward_units >> era)
        return total

    def supply_at(self, height: int) -> int:
        """Coins in existence after block `height`.  Amounts are hidden, so this cannot be
        counted from the ledger - it is known because every block mints exactly its reward
        (fees are paid from existing coins, and the range proofs guarantee nobody minted more)."""
        return self._sum_over_blocks(height, lambda reward: reward)

    def dev_fund_at(self, height: int) -> int:
        """The development fund's share of block `height`: a fixed percent of the block reward
        (never of the fees) for a fixed number of blocks, then nothing, forever.  Enforced by
        every node; the miner cannot skip it and the fund cannot take more."""
        if not self.dev_fund_address or not 1 <= height <= self.dev_fund_blocks:
            return 0
        return self.reward_at(height) * self.dev_fund_percent // 100

    def dev_fund_total_at(self, height: int) -> int:
        if not self.dev_fund_address:
            return 0
        return self._sum_over_blocks(min(height, self.dev_fund_blocks), lambda reward: reward * self.dev_fund_percent // 100)

    def circulating_supply(self) -> int:
        return self.supply_at(self.height)

    def cumulative_work(self, blocks: list[dict] | None = None) -> int:
        if blocks is None:
            return self.work
        return sum(b["difficulty"] for b in blocks[1:])

    def required_fee(self, n_inputs: int, n_outputs: int) -> int:
        return self.min_fee_units * fee_weight(n_inputs, n_outputs)

    def pow_value(self, block: dict) -> int:
        """The block's proof-of-work number.  Its ID (`hash`) is a plain, fast hash of the header;
        this is the slow one that mining has to get below the target."""
        self.work_checks += 1
        return int.from_bytes(pow_digest(canonical(block_header(block)), self.pow_algorithm,
                                         self.pow_memory_kib, self.pow_passes), "big")

    def proof_of_work_ok(self, block: dict) -> bool:
        return self.pow_value(block) < difficulty_target(block["difficulty"])

    def _remember_verified(self, txids) -> None:
        if len(self._verified) > 100_000:
            self._verified.clear()
        self._verified.update(txids)

    # ---- consensus rules ------------------------------------------------------
    def expected_difficulty(self, height: int, blocks: list[dict]) -> int:
        """The difficulty block `height` must carry: the previous block's, nudged by how early
        or late that block arrived (see step_difficulty).  It needs only the two blocks before
        it, so checking it costs the same on block ten as on block ten million.

        Blocks 1 and 2 start at `initial_difficulty`: the time since the genesis block says
        nothing about how fast anyone is mining."""
        if self.difficulty_halflife <= 0 or height <= 2:
            return self.initial_difficulty                        # halflife 0 = fixed difficulty (tests)
        parent, grandparent = blocks[height - 1], blocks[height - 2]
        return max(self.min_difficulty, step_difficulty(parent["difficulty"], parent["timestamp"] - grandparent["timestamp"],
                                                        self.target_seconds, self.difficulty_halflife))

    @staticmethod
    def median_time_past(blocks: list[dict], height: int) -> int:
        recent = sorted(b["timestamp"] for b in blocks[max(0, height - 11):height])
        return recent[len(recent) // 2]

    @staticmethod
    def _check_output_keys(out, index: int, expected_keys, what: str) -> None:
        if not isinstance(out, dict) or set(out) != expected_keys:
            raise ChainError("%s output %d has the wrong fields" % (what, index))
        if out["index"] != index:
            raise ChainError("%s output indexes must be 0,1,2..." % what)
        if not _is_hex64(out["one_time_pub"]):
            raise ChainError("%s output %d has a malformed key" % (what, index))
        try:
            Point.from_hex(out["one_time_pub"])
            Point.from_hex(out["ephemeral_pub"])
        except (ValueError, TypeError):
            raise ChainError("%s output %d has a malformed key" % (what, index))
        if not (isinstance(out["view_tag"], str) and _HEX2.fullmatch(out["view_tag"])
                and isinstance(out["enc_anchor"], str) and _HEX32.fullmatch(out["enc_anchor"])):
            raise ChainError("%s output %d has a malformed view tag or anchor" % (what, index))

    def _check_hidden_outputs(self, outputs) -> list:
        """Structure of a transfer's outputs.  Returns their commitments as points."""
        commitments = []
        for i, out in enumerate(outputs):
            self._check_output_keys(out, i, HIDDEN_OUTPUT_KEYS, "transfer")
            try:
                commitments.append(Point.from_hex(out["commitment"]))
                if len(bytes.fromhex(out["enc_amount"])) != 8:
                    raise ValueError
            except (ValueError, TypeError):
                raise ChainError("transfer output %d has a malformed sealed amount" % i)
        return commitments

    def validate_transfer(self, tx: dict, state, height: int, deferred: list | None = None, trusted: bool = False) -> None:
        """Raise ChainError unless `tx` spends outputs it really owns, each only once, creates
        no coins, and hides no negative amounts.

        What this never learns: who paid, who was paid, how much, when, or which outputs were spent.

        `state`: the ledger (or a scratch layer over it) the transaction must fit into.
        `height`: the block the transaction is in, or would be in if mined next.  Every output
        it uses - its own coin and all the decoys - must be at least `output_lock_blocks` old.
        That is what keeps a payment valid through a short reorganisation: an output that
        young could still vanish, and a ring with a vanished member cannot be checked.
        `deferred`: when a list is given (block validation), the range proof is not checked
        here but appended to it as (txid, [(commitments, proof)]) so the whole block can be
        checked in one batch.
        `trusted`: this node fully checked this exact block before (see _load / replace_chain),
        so only the ledger-dependent checks are repeated."""
        if not isinstance(tx, dict) or set(tx) != (TRANSFER_KEYS if tx.get("type") == "transfer" else TX_KEYS):
            raise ChainError("transaction has the wrong set of fields")
        if tx["type"] != "transfer":
            raise ChainError("only one coinbase is allowed per block")
        if not isinstance(tx["range_proof"], dict):
            raise ChainError("transfer has no range proof")
        if tx["height"] != 0 or type(tx["fee"]) is not int:
            raise ChainError("transfer fields are malformed")
        inputs, outputs = tx["inputs"], tx["outputs"]
        if not isinstance(inputs, list) or not inputs or len(inputs) > MAX_INPUTS:
            raise ChainError("a transfer must have 1 to %d inputs" % MAX_INPUTS)
        if not isinstance(outputs, list) or not MIN_TRANSFER_OUTPUTS <= len(outputs) <= MAX_OUTPUTS:
            raise ChainError("a transfer must have %d to %d outputs" % (MIN_TRANSFER_OUTPUTS, MAX_OUTPUTS))
        required = self.required_fee(len(inputs), len(outputs))
        if tx["fee"] < required:
            raise ChainError("fee below the minimum of %s for %d input(s) and %d output(s)"
                             % (self.fmt(required), len(inputs), len(outputs)))
        if tx["fee"] > MAX_AMOUNT:
            raise ChainError("fee is absurdly large")
        if not isinstance(tx["txid"], str) or tx["txid"] != compute_txid(tx):
            raise ChainError("txid does not match the transaction contents")

        order = [input_order_key(inp) for inp in inputs]
        if any(a > b for a, b in zip(order, order[1:])):            # equal ones: caught below as "twice"
            raise ChainError("inputs must be listed in order of their key images (the order a wallet picked them would leak)")

        # 1. everything that depends on the current ledger (cheap, and re-checked every time)
        ring_inputs, fund_inputs = [], []
        seen_images, seen_refs = set(), set()
        for inp in inputs:
            keys = set(inp) if isinstance(inp, dict) else None
            if keys == RING_INPUT_KEYS:
                ring, image = inp["ring"], inp["key_image"]
                if (not isinstance(ring, list) or len(ring) != self.ring_size or not all(isinstance(r, str) for r in ring)
                        or any(a >= b for a, b in zip(ring, ring[1:]))):
                    raise ChainError("a ring must list exactly %d different outputs, in sorted order" % self.ring_size)
                members = []
                for ref in ring:
                    member = state.get_output(ref)
                    if member is None:
                        raise ChainError("ring member %s is not an output on this chain" % ref[:20])
                    if "ephemeral_secret" in member:
                        raise ChainError("development fund outputs cannot be ring members (the fund spends in the open)")
                    if member["height"] + self.output_lock > height:
                        raise ChainError("ring member %s is too new: an output can be used %d block(s) after the one that made it"
                                         % (ref[:20], self.output_lock))
                    members.append(member)
                if not _is_hex64(image):
                    raise ChainError("input has a malformed key image")
                if image in seen_images:
                    raise ChainError("the same key image appears twice in one transaction")
                if state.has_key_image(image):
                    raise ChainError("key image already used: that output was spent before (double spend)")
                seen_images.add(image)
                ring_inputs.append((inp, members))
            elif keys == FUND_INPUT_KEYS and isinstance(inp["txid"], str) and type(inp["index"]) is int:
                ref = outpoint(inp["txid"], inp["index"])
                spent = state.get_output(ref)
                if spent is None or "ephemeral_secret" not in spent:
                    raise ChainError("only development fund outputs may be spent by naming them; every other input must be a ring")
                if spent["height"] + self.output_lock > height:
                    raise ChainError("development fund output %s is too new: an output can be used %d block(s) after the one that made it"
                                     % (ref[:20], self.output_lock))
                if ref in seen_refs or state.fund_is_spent(ref):
                    raise ChainError("development fund output %s was already spent (double spend)" % ref[:20])
                seen_refs.add(ref)
                fund_inputs.append((inp, ref, spent))
            else:
                raise ChainError("input is malformed")
        if trusted or tx["txid"] in self._verified:
            return                                   # the maths below was already done for this exact transaction

        # 2. the sealed amounts balance:  inputs - outputs - fee  must contain no coins.
        #    A ring input is counted by its pseudo output, a fresh envelope the ring signature
        #    proves holds exactly what the (hidden) real input holds.
        commitments = self._check_hidden_outputs(outputs)
        message = tx_signing_bytes(tx)
        excess = IDENTITY
        ring_points = []
        for inp, _ in ring_inputs:
            try:
                pseudo = Point.from_hex(inp["pseudo_commitment"])
                image = Point.from_hex(inp["key_image"])
            except (ValueError, TypeError):
                raise ChainError("ring input has a malformed key image or pseudo output")
            ring_points.append((pseudo, image))
            excess = excess + pseudo
        for _, _, spent in fund_inputs:
            excess = excess + Point.from_hex_unchecked(spent["commitment"])
        for c in commitments:
            excess = excess - c
        excess = excess - value_generator() * tx["fee"]
        if not verify(excess, message, tx["excess_sig"]):
            raise ChainError("sealed amounts do not balance: inputs must equal outputs plus the fee (no coins may be created)")

        # 3. every input is spent by its owner
        for (inp, members), (pseudo, image) in zip(ring_inputs, ring_points):
            if not ringsig.verify(message, inp["ring"],
                                  [Point.from_hex_unchecked(m["one_time_pub"]) for m in members],
                                  [Point.from_hex_unchecked(m["commitment"]) for m in members],
                                  pseudo, image, inp["signature"]):
                raise ChainError("bad ring signature: the signer owns no output in the ring, or the key image or amount is not that output's")
        for inp, ref, spent in fund_inputs:
            if not verify_input_signature(spent, message, inp["signature"]):
                raise ChainError("bad signature on development fund input %s" % ref[:20])

        # 4. no output hides a negative amount: ONE proof covers every output, in order
        proofs = [(commitments, tx["range_proof"])]
        if deferred is not None:
            deferred.append((tx["txid"], proofs))
        else:
            if not rangeproof.verify_batch(proofs):
                raise ChainError("invalid range proof: an output is not provably between 0 and 2^64")
            self._remember_verified([tx["txid"]])

    def validate_coinbase(self, tx: dict, height: int, fees: int, trusted: bool = False) -> None:
        """`trusted`: this node checked this exact block before (see validate_transfer), so the
        point and commitment maths is not redone; the amounts and the fund's share still are."""
        if not isinstance(tx, dict) or set(tx) != TX_KEYS:
            raise ChainError("coinbase has the wrong set of fields")
        if tx["type"] != "coinbase" or tx["inputs"] != [] or tx["fee"] != 0 or tx["excess_sig"] is not None:
            raise ChainError("first transaction in a block must be the coinbase")
        if tx["height"] != height:
            raise ChainError("coinbase fields are malformed")
        outputs = tx["outputs"]
        if not isinstance(outputs, list) or len(outputs) > MAX_OUTPUTS:
            raise ChainError("coinbase must have at most %d outputs" % MAX_OUTPUTS)
        total, fund_outputs = 0, []
        for i, out in enumerate(outputs):
            auditable = isinstance(out, dict) and "ephemeral_secret" in out
            if trusted:
                if not isinstance(out, dict) or set(out) != (AUDITABLE_OUTPUT_KEYS if auditable else COINBASE_OUTPUT_KEYS):
                    raise ChainError("coinbase output %d has the wrong fields" % i)
            else:
                self._check_output_keys(out, i, AUDITABLE_OUTPUT_KEYS if auditable else COINBASE_OUTPUT_KEYS, "coinbase")
            if auditable:
                fund_outputs.append(out)
            if type(out["amount"]) is not int or not 0 < out["amount"] <= MAX_AMOUNT:
                raise ChainError("coinbase output amounts must be positive integers")
            if not trusted:
                try:
                    matches = Point.from_hex(out["commitment"]) == commit(out["amount"], 0)
                except (ValueError, TypeError):
                    matches = False
                if not matches:
                    raise ChainError("coinbase commitment does not match its public amount")
            total += out["amount"]
        allowed = self.reward_at(height) + fees
        if total != allowed:
            raise ChainError("coinbase pays %s but only %s is allowed" % (self.fmt(total), self.fmt(allowed)))
        fund_due = self.dev_fund_at(height)
        if fund_due > 0:
            if len(fund_outputs) != 1:
                raise ChainError("development fund: block %d must pay the fund exactly once (%s)" % (height, self.fmt(fund_due)))
            if fund_outputs[0]["amount"] != fund_due:
                raise ChainError("development fund: block %d must pay the fund exactly %s, not %s"
                                 % (height, self.fmt(fund_due), self.fmt(fund_outputs[0]["amount"])))
            if not trusted and not verify_auditable_output(fund_outputs[0], self.dev_fund_address, self.prefix):
                raise ChainError("development fund: the fund output does not pay the fund's published address")
        elif fund_outputs:
            raise ChainError("development fund: no fund payment is due in block %d" % height)
        if tx["txid"] != compute_txid(tx):
            raise ChainError("coinbase txid does not match")

    def validate_block(self, block: dict, blocks: list[dict], height: int, state, known_txids: set[str],
                       now: int | None = None, trusted: bool = False) -> StateView:
        """Check `block` as block number `height` on top of blocks[:height] and the ledger
        `state`.  Returns a scratch layer holding what the block adds; the caller makes it
        permanent with state.absorb().  `trusted`: see validate_transfer."""
        now = int(time.time()) if now is None else now
        prev = blocks[height - 1]
        if not isinstance(block, dict) or set(block) != BLOCK_KEYS:
            raise ChainError("block has the wrong set of fields")
        for key in ("index", "timestamp", "difficulty", "nonce"):
            if type(block[key]) is not int or block[key] < 0:
                raise ChainError("block %s must be a non-negative integer" % key)
        for key in ("previous_hash", "merkle_root", "hash"):
            if not isinstance(block[key], str):
                raise ChainError("block %s must be a string" % key)
        if block["index"] != height or block["index"] != prev["index"] + 1:
            raise ChainError("block index %d does not follow %d" % (block["index"], prev["index"]))
        if block["previous_hash"] != prev["hash"]:
            raise ChainError("block %d does not link to the previous block" % height)
        if block["timestamp"] <= self.median_time_past(blocks, height):
            raise ChainError("block %d timestamp is not later than recent blocks" % height)
        if block["timestamp"] > now + self.max_future_seconds:
            raise ChainError("block %d timestamp is too far in the future" % height)
        expected = self.expected_difficulty(height, blocks)
        if block["difficulty"] != expected:
            raise ChainError("block %d difficulty is %d, rules require %d" % (height, block["difficulty"], expected))
        if block["hash"] != compute_block_hash(block):
            raise ChainError("block %d hash does not match its contents" % height)
        if not trusted and len(json.dumps(block, separators=(",", ":"))) > MAX_BLOCK_BYTES:
            raise ChainError("block %d is bigger than %d bytes" % (height, MAX_BLOCK_BYTES))
        txs = block["transactions"]
        if not isinstance(txs, list) or not txs:
            raise ChainError("block %d has no transactions (needs at least the coinbase)" % height)
        if len(txs) > self.max_block_txs:
            raise ChainError("block %d has too many transactions" % height)
        seen = set()
        for tx in txs:
            if not isinstance(tx, dict) or not _is_hex64(tx.get("txid")):
                raise ChainError("block %d contains a malformed transaction" % height)
            if tx["txid"] in seen or tx["txid"] in known_txids:
                raise ChainError("block %d repeats transaction %s" % (height, tx["txid"][:16]))
            seen.add(tx["txid"])
        if block["merkle_root"] != merkle_root([tx["txid"] for tx in txs]):
            raise ChainError("block %d merkle root does not match its transactions" % height)
        if not trusted and not self.proof_of_work_ok(block):        # the expensive check, so it comes last of the cheap ones
            raise ChainError("block %d does not meet the difficulty (no valid proof-of-work)" % height)
        view = StateView(state)
        fees = 0
        deferred: list = []
        for tx in txs[1:]:
            self.validate_transfer(tx, view, height, deferred, trusted)
            view.apply(tx, height)
            fees += tx["fee"]
        self.validate_coinbase(txs[0], height, fees, trusted)
        view.apply(txs[0], height)
        if deferred:
            # every range proof in the block, checked as ONE combined equation
            if not rangeproof.verify_batch([item for _, proofs in deferred for item in proofs]):
                raise ChainError("block %d contains an invalid range proof (an amount is not provably between 0 and 2^64)" % height)
            self._remember_verified(txid for txid, _ in deferred)
        return view

    def validate_chain(self, blocks: list[dict], now: int | None = None, trusted_through: int = 0):
        """Validation from genesis.  `trusted_through`: this node already fully checked the
        blocks up to that height (they are byte-for-byte the ones it holds), so their proof of
        work and signatures are not redone - only the ledger is replayed."""
        if not blocks or blocks[0] != self.blocks[0]:
            raise ChainError("genesis block does not match this coin's configuration")
        state, known, work, counts = State(), {}, 0, [0]
        for height in range(1, len(blocks)):
            try:
                view = self.validate_block(blocks[height], blocks, height, state, known, now, trusted=height <= trusted_through)
            except ChainError as exc:
                raise BadBlock(height, str(exc))
            state.absorb(view)
            known.update((tx["txid"], height) for tx in blocks[height]["transactions"])
            work += blocks[height]["difficulty"]
            counts.append(state.count())
        return state, known, work, counts

    # ---- growing the chain ----------------------------------------------------
    def add_block(self, block: dict) -> None:
        with self.lock:
            height = len(self.blocks)
            view = self.validate_block(block, self.blocks, height, self.state, self.known_txids)
            line = self._block_line(block) if self.data_dir else b""
            self.blocks.append(block, self.blocks.end + len(line))
            self.state.absorb(view)
            self.known_txids.update((tx["txid"], height) for tx in block["transactions"])
            self.output_counts.append(self.state.count())
            self.work += block["difficulty"]
            self._rebuild_mempool(list(self.mempool.values()))
            if self.data_dir:
                self._append_block_file(line)
                self._save_mempool()
                self._save_marker()

    def common_height(self, blocks: list[dict]) -> int:
        """How far another chain is identical to ours (block IDs chain into each other, so equal
        IDs at a height mean everything before it is equal too)."""
        common = 0
        for i in range(1, min(len(blocks), len(self.blocks))):
            if not isinstance(blocks[i], dict) or blocks[i].get("hash") != self.blocks.hash_at(i):
                break
            common = i
        return common

    def begin_fork(self, common: int) -> "Fork":
        """Start checking another branch that leaves ours after block `common`."""
        return Fork(self, common)

    def switch_to(self, common: int, blocks: list[dict], checked: bool = False) -> bool:
        """Check a whole branch and switch to it, in one step that nothing can interleave with.
        `checked`: this node verified these exact blocks a moment ago (see node.py), so only
        the parts that depend on the ledger are repeated."""
        with self.lock:
            fork = Fork(self, common)
            for block in blocks:
                fork.add(block, trusted=checked)
            return fork.commit()

    def replace_chain(self, blocks: list[dict]) -> bool:
        """Switch to another chain if it is valid and has more work behind it.  Only the part
        that differs from ours is looked at: the cost depends on the length of the two
        branches, not on the length of the chain."""
        with self.lock:
            if not blocks or blocks[0] != self.blocks[0]:
                raise ChainError("genesis block does not match this coin's configuration")
            fork = self.begin_fork(self.common_height(blocks))
            for block in blocks[fork.common + 1:]:
                fork.add(copy.deepcopy(block))
            return fork.commit()

    # ---- mempool ----------------------------------------------------------------
    def pending_state(self) -> StateView:
        """The ledger as it will be once everything in the mempool is mined."""
        return self._pending

    def flush(self) -> None:
        """Write the mempool to disk now (it is otherwise saved at most every few seconds)."""
        with self.lock:
            if self.data_dir:
                self._save_mempool()

    def check_new_transfer(self, tx: dict) -> bool:
        """Would `tx` be accepted into the mempool right now?  Checks everything, keeps nothing
        (the heavy maths is remembered by txid, so accepting it later costs nothing).  False if
        the mempool already has it.  A payment on its way along a stem (relay.py) is checked
        like this before it is passed on, so nodes never relay rubbish."""
        with self.lock:
            txid = tx.get("txid") if isinstance(tx, dict) else None
            if not isinstance(txid, str):
                raise ChainError("transaction has no txid")
            if txid in self.mempool:
                return False
            if txid in self.known_txids:
                raise ChainError("transaction is already in the chain")
            self.validate_transfer(tx, self._pending, self.height + 1)
            return True

    def add_to_mempool(self, tx: dict) -> bool:
        with self.lock:
            txid = tx.get("txid") if isinstance(tx, dict) else None
            if not isinstance(txid, str):
                raise ChainError("transaction has no txid")
            if txid in self.mempool:
                return False
            if txid in self.known_txids:
                raise ChainError("transaction is already in the chain")
            size = len(json.dumps(tx, separators=(",", ":")))
            if len(self.mempool) >= MAX_MEMPOOL or self.mempool_bytes + size > MAX_MEMPOOL_BYTES:
                raise ChainError("mempool is full")
            height = self.height + 1
            self.validate_transfer(tx, self._pending, height)
            self.mempool[txid] = tx
            self.mempool_bytes += size
            self._pending.apply(tx, height)
            self.mempool_version += 1
            if self.data_dir and time.time() - self._mempool_saved > 5:     # not on every arrival: that is a
                self._save_mempool()                                         # full rewrite of a file that can be megabytes
            return True

    def _rebuild_mempool(self, candidates: list[dict]) -> None:
        pool: dict[str, dict] = {}
        sim = StateView(self.state)
        height = self.height + 1
        remaining = [tx for tx in candidates
                     if isinstance(tx, dict) and isinstance(tx.get("txid"), str) and tx["txid"] not in self.known_txids]
        progress, size = True, 0
        while remaining and progress and len(pool) < MAX_MEMPOOL:
            progress, still = False, []
            for tx in remaining:
                if tx["txid"] in pool:
                    continue
                tx_size = len(json.dumps(tx, separators=(",", ":")))
                if len(pool) >= MAX_MEMPOOL or size + tx_size > MAX_MEMPOOL_BYTES:
                    continue
                try:
                    self.validate_transfer(tx, sim, height)
                except ChainError:
                    still.append(tx)
                    continue
                sim.apply(tx, height)
                pool[tx["txid"]] = tx
                size += tx_size
                progress = True
            remaining = still
        self.mempool, self.mempool_bytes = pool, size
        self._pending = sim
        self.mempool_version += 1

    def select_transactions(self) -> list[dict]:
        """Highest fee first; equal fees in the order they arrived."""
        candidates = sorted(self.mempool.values(), key=lambda t: -t["fee"])
        chosen, chosen_ids = [], set()
        sim = StateView(self.state)
        height = self.height + 1
        room = self.max_block_txs - 1
        size = COINBASE_ROOM
        progress = True
        while progress and len(chosen) < room:
            progress = False
            for tx in candidates:
                if tx["txid"] in chosen_ids:
                    continue
                tx_size = len(json.dumps(tx, separators=(",", ":"))) + 1
                if size + tx_size > MAX_BLOCK_BYTES:
                    continue
                try:
                    self.validate_transfer(tx, sim, height)
                except ChainError:
                    continue
                sim.apply(tx, height)
                size += tx_size
                chosen.append(tx)
                chosen_ids.add(tx["txid"])
                progress = True
                if len(chosen) >= room:
                    break
        return chosen

    # ---- mining -----------------------------------------------------------------
    def create_candidate_block(self, miner_address: str) -> dict:
        with self.lock:
            height = len(self.blocks)
            txs = self.select_transactions()
            fees = sum(tx["fee"] for tx in txs)
            timestamp = max(int(time.time()), self.median_time_past(self.blocks, height) + 1)
            coinbase = make_coinbase_tx(miner_address, self.reward_at(height) + fees, height, self.prefix,
                                        self.dev_fund_address, self.dev_fund_at(height))
            all_txs = [coinbase] + txs
            return {
                "index": height, "timestamp": timestamp, "previous_hash": self.tip["hash"],
                "merkle_root": merkle_root([tx["txid"] for tx in all_txs]),
                "difficulty": self.expected_difficulty(height, self.blocks),
                "nonce": 0, "transactions": all_txs, "hash": "",
            }

    def mine_block(self, miner_address: str, should_abort: Optional[Callable[[], bool]] = None,
                   hashes_per_check: int = 20000, on_progress: Optional[Callable[[int], None]] = None,
                   pool=None) -> dict | None:
        """Search for the next block and add it.  Returns it, or None if the chain moved on or
        `should_abort` said stop.  `pool` (powpool.PowPool): run the tries on several CPU cores."""
        if not is_valid_address(miner_address, self.prefix):
            raise ChainError("miner address is not a valid %s address" % self.ticker)
        algorithm, memory, passes = self.pow_algorithm, self.pow_memory_kib, self.pow_passes
        if algorithm != "sha256d":
            hashes_per_check = max(1, min(hashes_per_check, 8))     # each try is slow: look up more often
        while True:
            # Build the block to search for.  If payments arrive while the search runs, come
            # back here and build it again with them in it.  That costs nothing: every try is
            # its own lottery ticket, so no progress is lost by changing what is being mined -
            # and a payment no longer has to sit out a whole block that was started without it.
            version, built = self.mempool_version, time.time()
            block = self.create_candidate_block(miner_address)
            difficulty = block["difficulty"]
            target = difficulty_target(difficulty)
            head = ('{"difficulty":%d,"index":%d,"merkle_root":"%s","nonce":' % (difficulty, block["index"], block["merkle_root"])).encode()
            tail = (',"previous_hash":"%s","timestamp":%d}' % (block["previous_hash"], block["timestamp"])).encode()
            nonce = secrets.randbelow(1 << 32)
            while True:
                found = None
                if pool is not None:
                    candidate = pool.step(head, tail, target, wait=0.5)
                    if candidate is not None and int.from_bytes(
                            pow_digest(head + str(candidate).encode() + tail, algorithm, memory, passes), "big") < target:
                        found = candidate                        # a worker's find, checked once more here
                    if on_progress:
                        on_progress(pool.take_tries())
                else:
                    for _ in range(hashes_per_check):
                        header = head + str(nonce).encode() + tail
                        if int.from_bytes(pow_digest(header, algorithm, memory, passes), "big") < target:
                            found = nonce
                            break
                        nonce += 1
                    if on_progress:
                        on_progress(hashes_per_check)
                if found is not None:
                    block["nonce"] = found
                    block["hash"] = compute_block_hash(block)
                    with self.lock:
                        if self.tip["hash"] != block["previous_hash"]:
                            return None
                        self.add_block(block)
                    return block
                if should_abort and should_abort():
                    return None
                if self.tip["hash"] != block["previous_hash"]:
                    return None
                now = time.time()
                if self.mempool_version != version and now - built >= self.refresh_seconds:
                    break                                        # new payments are waiting: rebuild
                if int(now) > block["timestamp"]:
                    block["timestamp"] = int(now)
                    tail = (',"previous_hash":"%s","timestamp":%d}' % (block["previous_hash"], block["timestamp"])).encode()

    # ---- queries ----------------------------------------------------------------
    def get_block(self, key) -> dict | None:
        with self.lock:
            if isinstance(key, int) or (isinstance(key, str) and key.isdigit()):
                index = int(key)
                return self.blocks[index] if 0 <= index < len(self.blocks) else None
            height = self.blocks.height_of(key) if isinstance(key, str) else None
            return self.blocks[height] if height is not None else None

    def blocks_from(self, start: int, limit: int = 100) -> list[dict]:
        """Blocks start, start+1, ... for a peer that is catching up."""
        with self.lock:
            start = max(0, start)
            return self.blocks[start:start + max(1, min(500, limit))]

    def find_tx(self, txid: str):
        with self.lock:
            if txid in self.mempool:
                return self.mempool[txid], None
            height = self.known_txids.get(txid)
            if height is None:
                return None
            for tx in self.blocks[height]["transactions"]:
                if tx["txid"] == txid:
                    return tx, height
        return None

    def all_outputs(self) -> list[dict]:
        """Every output ever made, whole, oldest first: what wallets scan and what rings are
        drawn from.  Nothing here says whose they are, what they are worth (rewards aside), or
        whether they have been spent.  Read from the blocks: for tests and small chains."""
        with self.lock:
            return [record for height in range(1, len(self.blocks)) for record in self._block_outputs(height)]

    def _block_outputs(self, height: int) -> list[dict]:
        """The outputs block `height` made, whole, in their places in the line of all outputs.
        A block's payments come first and its coinbase last: that is the order the ledger
        takes them in (validate_block)."""
        block, first = self.blocks[height], self.output_counts[height - 1]
        txs = block["transactions"]
        made = [(tx["txid"], out) for tx in txs[1:] + txs[:1] for out in tx["outputs"]]
        return [{"txid": txid, "index": out["index"], "output": dict(out, height=height, position=first + i)}
                for i, (txid, out) in enumerate(made)]

    def _record(self, ref: str) -> dict:
        txid, _, index = ref.rpartition(":")
        return {"txid": txid, "index": int(index), "output": self.state.outputs[ref]}

    def outputs_per_block(self) -> float:
        """How many outputs the chain has been making per block lately.  Wallets turn decoy ages
        into places in the line of outputs with it, so every wallet uses the same public number."""
        with self.lock:
            if self.height < 1:
                return 0.01
            window = max(1, min(RECENT_WINDOW, self.height))
            return round(max(0.01, (self.output_counts[-1] - self.output_counts[-1 - window]) / window), 4)

    def spendable_count(self) -> int:
        """How many outputs, counted from the oldest, are old enough to be used in a block
        mined right now.  Wallets pick their decoys - and their own coins - from these only."""
        with self.lock:
            return self.output_counts[max(0, min(self.height, self.height + 1 - self.output_lock))]

    def scan_page(self, start: int, max_blocks: int = SCAN_PAGE_BLOCKS, max_outputs: int = SCAN_PAGE_OUTPUTS) -> dict:
        """What a wallet needs from blocks start, start+1, ...: the outputs they made (to look
        for its own) and the spent markers they carry (to see which of its own are gone).
        A wallet that remembers where it stopped asks only for what is new, and it asks for
        whole blocks, never for particular outputs - so the node learns nothing about which
        ones are its."""
        with self.lock:
            height = max(1, int(start))
            page, count = [], 0
            while height <= self.height and len(page) < max_blocks and (count < max_outputs or not page):
                block = self.blocks[height]
                outputs = self._block_outputs(height)
                inputs = [inp for tx in block["transactions"] for inp in tx["inputs"]]
                page.append({"height": height, "hash": block["hash"],
                             "outputs": outputs,
                             "key_images": [inp["key_image"] for inp in inputs if "key_image" in inp],
                             "fund_spent": [outpoint(inp["txid"], inp["index"]) for inp in inputs if "key_image" not in inp]})
                count += len(outputs)
                height += 1
            return {"height": self.height, "tip_hash": self.tip["hash"], "next": height, "blocks": page,
                    "output_count": self.state.count(), "spendable_outputs": self.spendable_count(),
                    "output_lock_blocks": self.output_lock, "outputs_per_block": self.outputs_per_block(),
                    "target_block_seconds": self.target_seconds}

    def lookup_outputs(self, positions=(), refs=()) -> dict:
        """Outputs by their place in the line of all outputs, or by reference.  None for any
        that do not exist.  This is how a wallet fetches the members of a ring - and it always
        asks for the whole ring, its own coin included, so the question gives nothing away."""
        with self.lock:
            order, outputs = self.state.order, self.state.outputs
            return {"positions": [self._record(order[p]) if type(p) is int and 0 <= p < len(order) else None for p in positions],
                    "refs": [self._record(r) if isinstance(r, str) and r in outputs else None for r in refs]}

    def spent_markers(self) -> dict:
        """The key images seen so far (and the fund outputs spent by name).  A wallet compares
        these with the key images of its own outputs to learn what it has spent."""
        with self.lock:
            return {"key_images": sorted(self.state.key_images), "fund_spent": sorted(self.state.fund_spent)}

    def pending_markers(self) -> dict:
        """Spent markers of payments still waiting in the mempool, so a wallet does not try to
        spend the same coin twice while its first payment is on the way."""
        with self.lock:
            inputs = [inp for tx in self.mempool.values() for inp in tx["inputs"]]
            return {"key_images": [inp["key_image"] for inp in inputs if "key_image" in inp],
                    "fund_spent": [outpoint(inp["txid"], inp["index"]) for inp in inputs if "key_image" not in inp]}

    def block_summary(self, block: dict) -> dict:
        coinbase = block["transactions"][0] if block["transactions"] else None
        return {
            "index": block["index"], "hash": block["hash"], "previous_hash": block["previous_hash"],
            "merkle_root": block["merkle_root"], "timestamp": block["timestamp"],
            "difficulty": block["difficulty"], "nonce": block["nonce"],
            "tx_count": len(block["transactions"]),
            "reward": sum(o["amount"] for o in coinbase["outputs"]) if coinbase else 0,
            "outputs": sum(len(tx["outputs"]) for tx in block["transactions"]),
            "inputs": sum(len(tx["inputs"]) for tx in block["transactions"]),
            "fees": sum(tx["fee"] for tx in block["transactions"]),
            "dev_fund": sum(o["amount"] for o in coinbase["outputs"] if "ephemeral_secret" in o) if coinbase else 0,
        }

    def info(self) -> dict:
        with self.lock:
            height = self.height
            recent = [b for b in self.blocks[-11:] if b["index"] > 0]
            average = None
            if len(recent) > 1:
                average = round((recent[-1]["timestamp"] - recent[0]["timestamp"]) / (len(recent) - 1), 1)
            work = self.cumulative_work()
            next_height = height + 1
            return {
                "height": height, "tip_hash": self.tip["hash"], "tip_timestamp": self.tip["timestamp"],
                "difficulty": self.tip["difficulty"], "next_difficulty": self.expected_difficulty(next_height, self.blocks),
                "work": work, "work_log2": round(math.log2(work), 2) if work else 0,
                "circulating_supply": self.circulating_supply(), "max_supply": self.max_supply(),
                "block_reward": self.block_reward_units, "next_reward": self.reward_at(next_height),
                "halving_interval": self.halving_interval,
                "blocks_until_halving": self.halving_interval - (next_height % self.halving_interval),
                "target_block_seconds": self.target_seconds, "avg_block_seconds_recent": average,
                "min_fee": self.min_fee_units, "mempool_size": len(self.mempool),
                "output_count": len(self.state.outputs),
                "spendable_outputs": self.spendable_count(), "output_lock_blocks": self.output_lock,
                "spend_count": len(self.state.key_images) + len(self.state.fund_spent),
                "ring_size": self.ring_size,
                "privacy": {"receivers_hidden": True, "amounts_hidden": True, "senders_hidden": True},
                "curve_backend": BACKEND, "genesis_hash": self.blocks.hash_at(0), "network": self.network,
                "pow": {"algorithm": self.pow_algorithm, "memory_kib": self.pow_memory_kib, "passes": self.pow_passes},
                "dev_fund": self.dev_fund_info(),
                "forks_since_start": dict(self.forks),
            }

    def dev_fund_info(self) -> dict:
        """Everything about the development fund is public, on purpose: what it is owed, what
        it has received, and how much of that it has spent."""
        with self.lock:
            received = self.dev_fund_total_at(self.height)
            return {
                "enabled": bool(self.dev_fund_address),
                "active": bool(self.dev_fund_address) and self.height < self.dev_fund_blocks,
                "percent": self.dev_fund_percent,
                "duration_blocks": self.dev_fund_blocks,
                "blocks_remaining": max(0, self.dev_fund_blocks - self.height) if self.dev_fund_address else 0,
                "address": self.dev_fund_address,
                "total_received": received,
                "unspent": self.state.fund_unspent,
                "spent": received - self.state.fund_unspent,
                "lifetime_total": self.dev_fund_total_at(self.dev_fund_blocks),
            }

    # ---- persistence ------------------------------------------------------------
    def _path(self, name: str) -> str:
        return os.path.join(self.data_dir, name)

    @staticmethod
    def _atomic_write(path: str, text: str) -> None:
        tmp = path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as fh:
            fh.write(text)
        os.replace(tmp, path)

    @staticmethod
    def _block_line(block: dict) -> bytes:
        return json.dumps(block, separators=(",", ":")).encode("utf-8") + b"\n"

    def _append_block_file(self, line: bytes) -> None:
        with open(self._path(CHAIN_FILE), "ab") as fh:
            fh.write(line)

    def _start_chain_file(self) -> None:
        """A chain file holding the genesis block only."""
        genesis = self.blocks[0]
        tmp = self._path(CHAIN_FILE) + ".tmp"
        with open(tmp, "wb") as fh:                      # bytes, never text: offsets must be exact on every OS
            fh.write(self._block_line(genesis))
        os.replace(tmp, self._path(CHAIN_FILE))
        self.blocks = BlockStore(self._path(CHAIN_FILE))
        self.blocks.append(genesis, len(self._block_line(genesis)))

    def _replace_file_tail(self, common: int, blocks: list[dict]) -> None:
        """A reorganisation on disk: cut the file after block `common` and write the winning
        branch behind it.  The rest of the file - nearly all of it - is not touched."""
        self.blocks.truncate(common + 1)
        with open(self._path(CHAIN_FILE), "r+b") as fh:
            fh.truncate(self.blocks.end)
            fh.seek(self.blocks.end)
            for block in blocks:
                line = self._block_line(block)
                fh.write(line)
                self.blocks.append(block, self.blocks.end + len(line))

    def _save_marker(self) -> None:
        """Remember the tip this node has fully checked.  Block IDs chain into each other, so
        if the saved chain still ends in this ID, every block before it is unchanged, and its
        proof of work and signatures need not be redone at the next start.  Changing any byte
        of a saved block breaks that chain of IDs and is caught without redoing the maths.
        (`coin.py validate` redoes all of it anyway.)"""
        self._atomic_write(self._path(MARKER_FILE), json.dumps({"height": self.height, "hash": self.tip["hash"]}))

    def _read_marker(self):
        """(height, block ID) of the tip this node last fully checked, or (0, None)."""
        try:
            with open(self._path(MARKER_FILE), "r", encoding="utf-8") as fh:
                marker = json.load(fh)
            if type(marker["height"]) is int and marker["height"] > 0 and isinstance(marker["hash"], str):
                return marker["height"], marker["hash"]
        except (OSError, ValueError, KeyError, TypeError):
            pass
        return 0, None

    def _save_mempool(self) -> None:
        self._atomic_write(self._path(MEMPOOL_FILE), json.dumps(list(self.mempool.values())))
        self._mempool_saved = time.time()

    def _replay_file(self, chain_path: str, trusted: int, marker_id):
        """Read the saved chain line by line and replay it into a fresh ledger, keeping only the
        newest blocks in memory.  Blocks up to `trusted` were fully checked by this node before
        (if block `trusted` still has the ID `marker_id`), so only the ledger is replayed for them.

        Returns (store, state, known, work, counts, problem): problem is None, ("torn", None) for
        a half-written last line, ("bad", BadBlock) for a block that breaks a rule, or
        ("untrusted", None) if the marker turned out not to fit the file."""
        store = BlockStore(chain_path)
        state, known, work, counts = State(), {}, 0, [0]
        size, offset = os.path.getsize(chain_path), 0
        with open(chain_path, "rb") as fh:
            for line in fh:
                offset += len(line)
                if not line.strip():
                    continue
                try:
                    block = json.loads(line)
                except ValueError:
                    if offset >= size and len(store):
                        return store, state, known, work, counts, ("torn", None)   # the power went while the newest
                    raise ChainError("%s is corrupt (bad JSON). To start a new chain: python coin.py reset-chain "  # block was saved
                                     "(removes the saved chain only; your wallets are kept)." % chain_path)
                height = len(store)
                if height == 0:
                    if block != self.blocks[0]:
                        raise ChainError("genesis block does not match this coin's configuration")
                    store.append(block, offset)
                    continue
                if height == trusted and (not isinstance(block, dict) or block.get("hash") != marker_id):
                    return store, state, known, work, counts, ("untrusted", None)
                try:
                    # now=NO_CLOCK: "too far in the future" is a rule for blocks ARRIVING.  A block this
                    # node saved was fine when it came; a clock that is now behind (a flat CMOS battery,
                    # a wrong time zone) must not make the node set its own chain aside as damaged.
                    view = self.validate_block(block, store, height, state, known, now=NO_CLOCK, trusted=height <= trusted)
                except ChainError as exc:
                    problem = BadBlock(height, str(exc))
                    return store, state, known, work, counts, ("untrusted" if height <= trusted else "bad", problem)
                state.absorb(view)
                known.update((tx["txid"], height) for tx in block["transactions"])
                work += block["difficulty"]
                counts.append(state.count())
                store.append(block, offset)
        if len(store) - 1 < trusted:
            return store, state, known, work, counts, ("untrusted", None)
        return store, state, known, work, counts, None

    def _load(self) -> None:
        chain_path = self._path(CHAIN_FILE)
        if os.path.exists(chain_path) and os.path.getsize(chain_path) > 0:
            trusted, marker_id = (0, None) if self.recheck_work else self._read_marker()
            try:
                result = self._replay_file(chain_path, trusted, marker_id)
                if result[5] and result[5][0] == "untrusted":
                    result = self._replay_file(chain_path, 0, None)       # the marker does not fit: check everything
            except ChainError as exc:
                raise ChainError("the chain saved in %s does not belong to this coin's rules (%s). "
                                 "If you changed consensus settings in config.json, run: python coin.py reset-chain "
                                 "(it removes the saved chain only; your wallets are kept. NEVER delete the wallets folder)."
                                 % (chain_path, exc)) if "genesis" in str(exc) else exc
            store, state, known, work, counts, problem = result
            if problem and problem[0] == "bad":
                bad = problem[1]
                if self.recheck_work:                # `coin.py validate` reports; it never changes files
                    raise ChainError("block %d of the saved chain breaks a rule: %s" % (bad.height, bad.reason))
                # Damaged on disk (a bad sector, a hand edit, an interrupted copy): keep every block
                # before the damaged one, set the file aside untouched, and let the network supply
                # the rest.  Nothing is deleted, and the node says so loudly (see node.py).
                damaged = chain_path + ".damaged-" + time.strftime("%Y%m%d-%H%M%S")
                os.replace(chain_path, damaged)
                with open(damaged, "rb") as src, open(chain_path + ".tmp", "wb") as dst:
                    left = store.end
                    while left > 0:
                        chunk = src.read(min(left, 1 << 20))
                        if not chunk:
                            break
                        dst.write(chunk)
                        left -= len(chunk)
                os.replace(chain_path + ".tmp", chain_path)
                self.repaired = (bad.height, bad.reason, damaged)
            elif problem and problem[0] == "torn":
                with open(chain_path, "r+b") as fh:          # drop the half-written line; the network has that block
                    fh.truncate(store.end)
            if not len(store):                               # nothing but blank lines
                self._start_chain_file()
                return self._load_mempool()
            self.blocks, self.state, self.known_txids = store, state, known
            self.work, self.output_counts = work, counts
            self._pending = StateView(self.state)
            self._save_marker()
        else:
            self._start_chain_file()
        self._load_mempool()

    def _load_mempool(self) -> None:
        mempool_path = self._path(MEMPOOL_FILE)
        if os.path.exists(mempool_path):
            try:
                with open(mempool_path, "r", encoding="utf-8") as fh:
                    saved = json.load(fh)
            except (ValueError, OSError):
                saved = []
            self._rebuild_mempool(saved if isinstance(saved, list) else [])


# ----------------------------------------------------------------------------- switching branches
class _Known:
    """The chain's transaction IDs with one branch taken out and another being added."""

    __slots__ = ("base", "removed", "added")

    def __init__(self, base: dict, removed: set):
        self.base, self.removed, self.added = base, removed, {}

    def __contains__(self, txid) -> bool:
        return txid in self.added or (txid in self.base and txid not in self.removed)


class Fork:
    """Another branch of the chain, checked block by block against the ledger as it stood
    where the two branches parted.  Nothing the node runs on is touched until commit(), and
    commit() switches only if the new branch has more work behind it.

    Blocks are checked as they are added, so a peer cannot make a node store a long branch of
    rubbish: the first bad block ends it, and every good one cost real proof of work."""

    def __init__(self, chain: Blockchain, common: int):
        with chain.lock:
            if type(common) is not int or not 0 <= common <= chain.height:
                raise ChainError("cannot fork from block %r: no such block" % (common,))
            self.chain, self.common = chain, common
            self.tip_hash = chain.tip["hash"]
            self.orphaned = chain.blocks[common + 1:]
            self.blocks = _Branch(chain.blocks, common)
            self.added: list[dict] = []
            self.counts: list[int] = []
            self.work = chain.work - sum(b["difficulty"] for b in self.orphaned)
            self.known = _Known(chain.known_txids, {tx["txid"] for b in self.orphaned for tx in b["transactions"]})
            self.view = StateView(Rewound(chain.state, self.orphaned))

    def add(self, block: dict, trusted: bool = False) -> None:
        """Check the next block of the branch.  Raises ChainError if it breaks a rule."""
        chain = self.chain
        with chain.lock:
            height = len(self.blocks)
            layer = chain.validate_block(block, self.blocks, height, self.view, self.known, trusted=trusted)
            self.view.absorb(layer)
            self.blocks.append(block)
            self.added.append(block)
            self.known.added.update((tx["txid"], height) for tx in block["transactions"])
            self.counts.append(self.view.count())
            self.work += block["difficulty"]

    def commit(self) -> bool:
        """Switch the node to this branch if it has more work.  Returns whether it switched."""
        chain = self.chain
        with chain.lock:
            if chain.tip["hash"] != self.tip_hash:
                raise ChainError("the chain moved on while another branch was being checked; it will be looked at again")
            if not self.added or self.work <= chain.work:
                if self.added and self.orphaned:
                    chain.forks["competing_blocks_lost"] += len(self.added)
                return False
            if self.orphaned:
                chain.forks["reorganisations"] += 1
                chain.forks["blocks_orphaned"] += len(self.orphaned)
            returning = [tx for b in self.orphaned for tx in b["transactions"][1:]]
            chain.state.rewind(self.orphaned)
            chain.state.absorb(self.view)
            for txid in self.known.removed:
                chain.known_txids.pop(txid, None)
            chain.known_txids.update(self.known.added)
            if chain.data_dir:
                chain._replace_file_tail(self.common, self.added)
            else:
                chain.blocks.truncate(self.common + 1)
                for block in self.added:
                    chain.blocks.append(block)
            del chain.output_counts[self.common + 1:]
            chain.output_counts.extend(self.counts)
            chain.work = self.work
            chain._rebuild_mempool(returning + list(chain.mempool.values()))   # orphaned payments go back in the queue
            if chain.data_dir:
                chain._save_mempool()
                chain._save_marker()
            return True
