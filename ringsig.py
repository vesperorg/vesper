"""
ringsig.py - hidden senders (phase 3, stage one): key images and ring signatures.

The problem: phases 1 and 2 hid who was paid and how much, but a payment still said "I am
spending output X".  Follow those links and you can walk the money through the chain.

The fix has two halves.

KEY IMAGE.  Every output has exactly one "spent marker":

        I = x * Hp(where the output sits on the chain, P)
                             (x = the output's one-time private key, P = its public key)

Only the owner can compute it, nobody can tell which output it belongs to, and it is always
the same for the same output.

The marker is tied to the output's POSITION (its transaction id and index), not just to its
key.  That is a lesson taken from both older coins.  In Monero the marker depends on the key
alone, so two outputs paid to the same one-time key share one marker and only one of them can
ever be spent (the "burning bug"; wallets have to watch for it).  Zcash met the same problem
as the "Faerie Gold" attack and fixed it by making the marker depend on position.  Vesper does
that from the start: every output has its own marker, a copied key harms nobody, and no
"keys must be unique" rule is needed - a rule that would let an attacker cancel a stranger's
pending payment by getting a copy of its key mined first.  Nodes keep the set of markers they have seen.  A second spend
of the same output would show the same marker and be refused.  So double spending is caught
without anyone learning what was spent.

RING SIGNATURE.  Instead of naming one output, a payment names a RING of 16 and proves

        "I own the private key of ONE of these, and this key image is its marker,
         and my input is worth exactly what that one is worth"

without revealing which.  The other 15 are decoys picked from the chain; their owners do
nothing and never know.  The scheme here is CLSAG (Goodell, Noether et al., 2019), the one
Monero uses today: one signature covers both the key and the amount.

The amount part works through a "pseudo output": a fresh envelope C' holding the same amount
as the real input but with a new blinding.  The signature proves C_real - C' contains no
coins.  The node then balances the pseudo outputs against the real outputs exactly as in
phase 2, never learning which ring member each one came from.

THE KNOWN WEAKNESS, stated plainly: the crowd is 16.  Decoys are a guess at what real
spending looks like, and statistics on output ages have de-anonymised ring users before.
Rings are the proven first step, not the destination.  The destination is proving membership
among EVERY output on the chain; that is stage two and it is research, not code, today.

Not audited.  Learning code.
"""

from __future__ import annotations

import math
import secrets
from functools import lru_cache

from curve import G, L, Point, hash_bytes, hash_to_point, hash_to_scalar, random_scalar, scalar_from_hex, scalar_to_hex

SIGNATURE_KEYS = frozenset({"c", "s", "D"})


@lru_cache(maxsize=1 << 18)
def key_image_base(ref: str, one_time_pub_hex: str):
    """Hp(position, P): a point nobody knows the private key of, different for every output.
    `ref` is the output's "txid:index"."""
    return hash_to_point("vesper/key-image", ref, bytes.fromhex(one_time_pub_hex))


def key_image(one_time_priv: int, ref: str, one_time_pub_hex: str):
    """The output's one and only spent marker.  Needs the private key."""
    return key_image_base(ref, one_time_pub_hex) * one_time_priv


def _context(message: bytes, ring_refs, ring_keys, ring_commitments, pseudo, image, aux):
    base = hash_bytes("vesper/clsag/v1", message, pseudo, image, aux, len(ring_keys), *ring_refs, *ring_keys, *ring_commitments)
    return base, hash_to_scalar("vesper/clsag/mu-key", base), hash_to_scalar("vesper/clsag/mu-amount", base)


def sign(message: bytes, ring_refs: list, ring_keys: list, ring_commitments: list, pseudo, index: int, x: int, z: int) -> dict:
    """Sign as ONE member of the ring without revealing which.

    ring_refs[i] / ring_keys[i] / ring_commitments[i]: the position ("txid:index"), one-time
    key and sealed amount of each ring member.
    The signer owns member `index`:  ring_keys[index] = x*G  and
    ring_commitments[index] - pseudo = z*G   (same amount, blindings differ by z)."""
    n = len(ring_keys)
    bases = [key_image_base(ref, p.hex()) for ref, p in zip(ring_refs, ring_keys)]
    image = bases[index] * x                 # I: the spent marker
    aux = bases[index] * z                   # D: the same trick for the amount key
    base, mu_key, mu_amount = _context(message, ring_refs, ring_keys, ring_commitments, pseudo, image, aux)
    w = (mu_key * x + mu_amount * z) % L     # one combined secret for both statements
    w_image = image * mu_key + aux * mu_amount

    # Start the ring at our own position with a random commitment, walk all the way round
    # faking every other member's response, then close the loop with the one real response.
    alpha = random_scalar()
    c = [0] * n
    s = [0] * n
    i = (index + 1) % n
    c[i] = hash_to_scalar("vesper/clsag/c", base, G * alpha, bases[index] * alpha)
    while i != index:
        s[i] = random_scalar()
        left = G * s[i] + ring_keys[i] * (c[i] * mu_key) + (ring_commitments[i] - pseudo) * (c[i] * mu_amount)
        right = bases[i] * s[i] + w_image * c[i]
        nxt = (i + 1) % n
        c[nxt] = hash_to_scalar("vesper/clsag/c", base, left, right)
        i = nxt
    s[index] = (alpha - c[index] * w) % L
    return {"c": scalar_to_hex(c[0]), "s": [scalar_to_hex(v) for v in s], "D": aux.hex()}


def verify(message: bytes, ring_refs: list, ring_keys: list, ring_commitments: list, pseudo, image, signature: dict) -> bool:
    """True if the signer owns one ring member, `image` is that member's key image, and
    `pseudo` holds the same amount as that member.  Learns nothing about which member."""
    try:
        n = len(ring_keys)
        if not isinstance(signature, dict) or set(signature) != SIGNATURE_KEYS:
            return False
        if not isinstance(signature["s"], list) or len(signature["s"]) != n or len(ring_commitments) != n or len(ring_refs) != n:
            return False
        c0 = scalar_from_hex(signature["c"])
        s = [scalar_from_hex(v) for v in signature["s"]]
        aux = Point.from_hex(signature["D"])                 # strict: prime-order group only
        bases = [key_image_base(ref, p.hex()) for ref, p in zip(ring_refs, ring_keys)]
        base, mu_key, mu_amount = _context(message, ring_refs, ring_keys, ring_commitments, pseudo, image, aux)
        w_image = image * mu_key + aux * mu_amount
        c = c0
        for i in range(n):
            left = G * s[i] + ring_keys[i] * (c * mu_key) + (ring_commitments[i] - pseudo) * (c * mu_amount)
            right = bases[i] * s[i] + w_image * c
            c = hash_to_scalar("vesper/clsag/c", base, left, right)
        return c == c0                                        # the loop closes only for a real owner
    except Exception:
        return False


# How people actually spend: the natural log of a coin's age in seconds, when it is spent,
# follows a gamma distribution with shape 19.28 and rate 1.61 (Moser et al., 2018, fitted to real
# Monero spends; Monero's own wallets have drawn decoys this way since).  Half of all spends are
# of coins younger than about a day and a half.
SPEND_SHAPE, SPEND_RATE = 19.28, 1.61


def decoy_age(rng, lock_seconds: float = 0.0) -> float:
    """One decoy age in seconds, drawn the way real coins get spent (never younger than the lock)."""
    while True:
        age = math.exp(rng.gammavariate(SPEND_SHAPE, 1.0 / SPEND_RATE))
        if age >= lock_seconds:
            return age


def draw_positions(eligible: int, taken, need: int, outputs_per_block: float = 1.0,
                   lock_blocks: int = 0, block_seconds: float = 30.0, rng=None) -> list:
    """`need` different places in the line of outputs 0 .. eligible-1 (0 is the oldest; the
    newest `eligible` outputs are those just old enough to use), none of them in `taken`.  Fewer
    if there are not that many left.

    Decoys have to look like real spends, or the real member of a ring stands out.  So each draw
    is an AGE, taken from how people actually spend (decoy_age), turned into a place in line with
    the chain's recent pace (`outputs_per_block`).  An age older than the chain becomes any place
    at all.  Vesper first drew decoys by rank in the line (rank = n x u^3): fine on a young chain,
    but as the chain grows its decoys spread over all of history while real spends stay days old,
    and an attacker who knows both could name the real coin a quarter of the time on a busy chain
    a year old, four times the fair 1 in 16 (leaktest.py measures both)."""
    taken = {p for p in taken if type(p) is int and 0 <= p < eligible}
    free = eligible - len(taken)
    if need <= 0 or free <= 0:
        return []
    if free <= need:
        return [p for p in range(eligible) if p not in taken]      # only ever a short line: take all of it
    rng = rng or secrets.SystemRandom()
    per_second = max(outputs_per_block, 1e-6) / block_seconds
    lock_seconds = lock_blocks * block_seconds
    chosen: set = set()
    while len(chosen) < need:
        rank = int((decoy_age(rng, lock_seconds) - lock_seconds) * per_second)      # 0 = newest usable
        position = eligible - 1 - rank if rank < eligible else rng.randrange(eligible)
        if position not in taken:
            chosen.add(position)
    return sorted(chosen)


def pick_ring(candidates: list, real: str, ring_size: int) -> list:
    """Choose the decoys.  candidates: every eligible output reference in chain order (oldest
    first).  Returns `ring_size` references, sorted, with `real` among them.

    Decoys lean toward recent outputs, because real spending does: most coins move soon after
    they arrive.  If decoys were picked evenly from all of history, the newest ring member
    would usually be the real one.  This is the soft spot of every ring design."""
    pool = [ref for ref in candidates if ref != real]
    need = ring_size - 1
    if len(pool) < need:
        raise ValueError("the chain is too young to hide a payment: a ring needs %d other outputs and only %d exist yet"
                         % (need, len(pool)))
    if len(pool) == need:
        return sorted(pool + [real])
    rng = secrets.SystemRandom()
    chosen = set()
    n = len(pool)
    while len(chosen) < need:
        age_rank = min(n - 1, int(n * rng.random() ** 3))     # 0 = newest; cubing leans recent
        chosen.add(pool[n - 1 - age_rank])
    return sorted(chosen | {real})
