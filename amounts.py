"""
amounts.py - hidden amounts (phase 2).

The problem: phase 1 hid WHO received a payment, but every amount was printed on the chain.
Follow the numbers and you can follow the money.

The fix is a Pedersen commitment.  Instead of writing the amount, write

        C = amount * H  +  blinding * G

where H is a second generator nobody knows the private key of, and `blinding` is a big random
number.  C is a sealed envelope:

  - hiding:   C looks like a random point.  Without the blinding you cannot tell 5 from 5,000.
  - binding:  whoever made C cannot later open it as a different amount.
  - additive: envelopes add up without being opened.
              commit(a1, b1) + commit(a2, b2) = commit(a1 + a2, b1 + b2)

That last property is the whole trick.  A node checks a payment with

        sum(input envelopes) - sum(output envelopes) - fee * H  =  "excess"

If the amounts balance, every H cancels and the excess is just (some number) * G - a public
key.  The sender proves it by signing with that key.  If the amounts did NOT balance there
would be H left over, and nobody can sign for a point with H in it.  So nodes verify that no
coins were created, without ever seeing one number.

One hole remains: an "amount" of minus five would also balance.  rangeproof.py closes it by
proving every envelope holds a number between 0 and 2^64 without revealing it.

The receiver learns the amount from `enc_amount`, the amount XOR-ed with a mask only the two
parties can compute from their shared secret.  The view key can compute it too, so an auditor
with the view key sees amounts; nobody else does.
"""

from __future__ import annotations

import hashlib
from functools import lru_cache

from curve import G, hash_to_point

AMOUNT_BITS = 64
MAX_AMOUNT = (1 << AMOUNT_BITS) - 1


@lru_cache(maxsize=None)
def value_generator():
    """H: the generator amounts are multiplied by.  Derived by hashing, so nobody knows log_G(H)."""
    return hash_to_point("vesper/generator/value")


def commit(amount: int, blinding: int):
    """The sealed envelope: amount*H + blinding*G."""
    return value_generator() * amount + G * blinding


def _mask(shared_point, index: int) -> int:
    digest = hashlib.sha512(b"vesper/amount-mask" + shared_point.encode() + int(index).to_bytes(4, "little")).digest()
    return int.from_bytes(digest[:8], "little")


def encrypt_amount(amount: int, shared_point, index: int) -> str:
    if not 0 <= amount <= MAX_AMOUNT:
        raise ValueError("amount out of range")
    return (amount ^ _mask(shared_point, index)).to_bytes(8, "little").hex()


def decrypt_amount(enc_hex: str, shared_point, index: int) -> int:
    raw = bytes.fromhex(enc_hex)
    if len(raw) != 8:
        raise ValueError("encrypted amount must be 8 bytes")
    return int.from_bytes(raw, "little") ^ _mask(shared_point, index)
