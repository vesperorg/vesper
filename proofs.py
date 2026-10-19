"""
proofs.py - prove a payment to one person, without telling anyone else anything.

A shop says "your payment never arrived".  On a transparent chain you would point at it.  On
Vesper nobody can see who was paid or how much - which is the point - so the payer needs a way
to show ONE person, on purpose, that ONE output paid THIS address THAT amount.

    python coin.py proof pay <txid>          the payer makes the proof (from its own records)
    python coin.py proof receive <txid>      the receiver makes one (from its view key)
    python coin.py proof check <file>        anyone checks it against their own node

How.  Every output carries R and is paid through the point S that only payer and receiver
can compute: the payer as r*C (it chose r), the receiver as a*R (a is its view key).  With S in
hand, anyone can redo the receiver's work: S gives the one-time key, which must match the
output, and S opens the sealed amount, which must match the commitment.  So a proof is S plus a
promise that S was made honestly - a Chaum-Pedersen proof that the same secret links

    payer:     R = r*D   and   S = r*C        (the address is (C, D); r is the payer's)
    receiver:  C = a*D   and   S = a*R        (a is the receiver's view key)

without revealing r or a.  Without that promise anyone could invent an S for some other
address; with it, S can only be the real one.

What a proof gives away: to whoever holds the file, that this one output paid this address and
how much - nothing about the payer's or the receiver's other payments.  Hand it only to the
person who needs it.
"""

from __future__ import annotations

from amounts import commit, decrypt_amount
from curve import G, L, Point, hash_to_scalar, random_scalar, scalar_from_hex, scalar_to_hex
from privacy import decode_address

KINDS = ("payment", "receipt")


def _challenge(kind, txid, index, points) -> int:
    return hash_to_scalar("vesper/payment-proof", kind, txid, int(index), *points)


def _dleq(secret: int, g1, g2, kind: str, txid: str, index: int) -> dict:
    """Prove h1 = secret*g1 and h2 = secret*g2 for the same secret (Chaum-Pedersen)."""
    k = random_scalar()
    a1, a2 = g1 * k, g2 * k
    e = _challenge(kind, txid, index, (g1, g1 * secret, g2, g2 * secret, a1, a2))
    return {"e": scalar_to_hex(e), "z": scalar_to_hex((k + e * secret) % L)}


def _dleq_ok(g1, h1, g2, h2, proof: dict, kind: str, txid: str, index: int) -> bool:
    e, z = scalar_from_hex(proof["e"]), scalar_from_hex(proof["z"])
    a1, a2 = g1 * z - h1 * e, g2 * z - h2 * e
    return e == _challenge(kind, txid, index, (g1, h1, g2, h2, a1, a2))


def payment_proof(txid: str, index: int, address: str, r: int, prefix: str) -> dict:
    """The payer's proof that output `index` of `txid` paid `address` (r: what the payer used)."""
    view_pub, spend_pub = decode_address(address, prefix)
    shared = view_pub * r
    return {"kind": "payment", "txid": txid, "index": int(index), "address": address, "shared": shared.hex(),
            "dleq": _dleq(r, spend_pub, view_pub, "payment", txid, index)}


def receipt_proof(txid: str, index: int, address: str, ephemeral_pub_hex: str, view_priv: int, prefix: str) -> dict:
    """The receiver's proof that output `index` of `txid` paid its `address`."""
    view_pub, spend_pub = decode_address(address, prefix)
    shared = Point.from_hex(ephemeral_pub_hex) * view_priv
    return {"kind": "receipt", "txid": txid, "index": int(index), "address": address, "shared": shared.hex(),
            "dleq": _dleq(view_priv, spend_pub, Point.from_hex(ephemeral_pub_hex), "receipt", txid, index)}


def check_proof(proof: dict, output: dict, prefix: str) -> int:
    """The amount `output` (as the chain holds it) paid to the proof's address.  Raises
    ValueError, saying why, if the proof does not show that."""
    if not isinstance(proof, dict) or proof.get("kind") not in KINDS:
        raise ValueError("this is not a Vesper payment proof")
    try:
        txid, index = str(proof["txid"]), int(proof["index"])
        view_pub, spend_pub = decode_address(proof["address"], prefix)
        shared = Point.from_hex(proof["shared"])
        R = Point.from_hex(output["ephemeral_pub"])
        dleq = proof["dleq"]
    except (KeyError, TypeError, ValueError) as exc:
        raise ValueError("the proof is malformed: %s" % exc)
    if int(output.get("index", -1)) != index:
        raise ValueError("the proof is about another output")
    if proof["kind"] == "payment":
        ok = _dleq_ok(spend_pub, R, view_pub, shared, dleq, "payment", txid, index)
    else:
        ok = _dleq_ok(spend_pub, view_pub, R, shared, dleq, "receipt", txid, index)
    if not ok:
        raise ValueError("the proof's maths does not hold: it was not made by the payer or the receiver of this output")
    if (G * hash_to_scalar("stealth", shared, index) + spend_pub).hex() != output["one_time_pub"]:
        raise ValueError("this output was not paid to %s" % proof["address"])
    if "amount" in output:
        return int(output["amount"])
    amount = decrypt_amount(output["enc_amount"], shared, index)
    if commit(amount, hash_to_scalar("blinding", shared, index)).hex() != output["commitment"]:
        raise ValueError("the output pays that address, but its sealed amount does not open: the payer sealed it wrongly")
    return amount
