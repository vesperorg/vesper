"""
rangeproof.py - proof that hidden amounts are between 0 and 2^64 (Bulletproofs).

Why this exists: with hidden amounts, a cheat could pay someone 100 and "pay" themselves
minus 95 out of a 5-coin input.  The envelopes would balance, and 95 coins would appear from
nowhere.  (Scalars wrap around, so "minus 95" is really a gigantic number.)  A range proof
shows every envelope holds an ordinary, small, non-negative number - without opening it.

How, in one paragraph: write the amount in binary, 64 bits.  Commit to the bits.  Prove three
things at once with a single random-looking equation - (1) every bit is 0 or 1, (2) the bits
add up to the amount inside the envelope, (3) nothing else is hiding in there.  The clever
part (Bunz et al., 2017) is the "inner product argument": instead of sending 64 numbers, the
prover folds the vectors in half six times, sending two points per fold.

One proof covers ALL the sealed outputs of a payment ("aggregated", section 4.3 of the paper,
as Monero has done since 2018).  The bits of every amount are laid end to end, and each extra
doubling of outputs costs one more fold - two points, 64 bytes - instead of a whole second
proof.  An ordinary payment (two outputs) carries 736 bytes of proof instead of 2 x 672.
A count of outputs that is not a power of two is padded with zero amounts that are never
written down.

Two things here go further than a straight port: every proof in a block is checked together
in ONE combined equation (`verify_batch`), so the shared generator terms are paid for once per
block instead of once per payment; and all points are checked to be in the prime-order group
on arrival.

Not audited.  Learning code.  The maths is the published protocol, the mistakes are mine.
"""

from __future__ import annotations

import hashlib
import secrets
import threading

from amounts import AMOUNT_BITS, commit, value_generator
from curve import G, L, Point, hash_to_point, multiexp, random_scalar, scalar_from_hex, scalar_inverse, scalar_to_hex

N = AMOUNT_BITS                 # bits proven per amount
LOG_N = N.bit_length() - 1      # folds for one amount (6)
MAX_AMOUNTS = 16                # most amounts one proof may cover (a payment has at most 16 outputs)
PROOF_KEYS = frozenset({"A", "S", "T1", "T2", "taux", "mu", "t", "L", "R", "a", "b"})

_GI: list = []
_HI: list = []
_GEN_LOCK = threading.Lock()


def generators(count: int = N):
    """`count` G and H generators plus one extra, all derived by hashing so nobody knows how
    they relate.  Made on first use and kept: a proof for m amounts needs 64 x m of each."""
    with _GEN_LOCK:
        while len(_GI) < count:
            i = len(_GI)
            _GI.append(hash_to_point("vesper/generator/bp-g", i))
            _HI.append(hash_to_point("vesper/generator/bp-h", i))
        return _GI[:count], _HI[:count], _u()


_U: list = []


def _u():
    if not _U:
        _U.append(hash_to_point("vesper/generator/bp-u"))
    return _U[0]


def padded_count(m: int) -> int:
    """The proof always covers a power of two of amounts: 1, 2, 4, 8 or 16."""
    size = 1
    while size < m:
        size *= 2
    return size


def folds(m: int) -> int:
    """How many L and R points a proof for m amounts has: 6 for one, 7 for two, ... 10 for 16."""
    return LOG_N + padded_count(m).bit_length() - 1


class _Transcript:
    """Fiat-Shamir: the 'random challenges' are hashes of everything said so far, so the
    prover cannot choose them and no back-and-forth with a verifier is needed.  The
    commitments themselves - how many and which, in order - are absorbed first; leaving them
    out is a classic real-world bug."""

    def __init__(self, commitments):
        self.h = hashlib.sha512(b"vesper/bulletproof/v2")
        self.absorb(len(commitments), *commitments)

    def absorb(self, *items) -> None:
        for item in items:
            self.h.update((item % L).to_bytes(32, "little") if isinstance(item, int) else item.encode())

    def challenge(self) -> int:
        digest = self.h.digest()
        self.h.update(digest)                       # ratchet, so the next challenge differs
        return int.from_bytes(digest, "little") % L or 1


def _inner(a, b) -> int:
    return sum(x * y for x, y in zip(a, b)) % L


def _powers(base: int, count: int) -> list:
    out = [1]
    for _ in range(count - 1):
        out.append(out[-1] * base % L)
    return out


# ----------------------------------------------------------------------------- prover
def prove_many(amounts, blindings) -> dict:
    """One proof that commit(amounts[j], blindings[j]) holds a number in [0, 2^64), for every j.
    Needs the secrets.  The verifier gets the commitments in the same order."""
    amounts, blindings = list(amounts), list(blindings)
    m = len(amounts)
    if not 1 <= m <= MAX_AMOUNTS or len(blindings) != m:
        raise ValueError("a range proof covers 1 to %d amounts, each with its blinding" % MAX_AMOUNTS)
    for amount in amounts:
        if type(amount) is not int or not 0 <= amount < (1 << N):
            raise ValueError("amount is outside 0 .. 2^%d - a range proof cannot be made for it" % N)
    size = padded_count(m)
    mn = size * N
    Gi, Hi, U = generators(mn)
    Hv = value_generator()
    commitments = [commit(a, b) for a, b in zip(amounts, blindings)]
    values = amounts + [0] * (size - m)            # padding: amount 0, blinding 0, never written down
    gammas = blindings + [0] * (size - m)

    # all the amounts in binary, end to end, and the same bits minus one (aL * aR = 0, aL - aR = 1)
    aL = [(values[i // N] >> (i % N)) & 1 for i in range(mn)]
    aR = [(bit - 1) % L for bit in aL]
    alpha = random_scalar()
    A = G * alpha + multiexp([(1, Gi[i]) if aL[i] else (L - 1, Hi[i]) for i in range(mn)])

    # blinding vectors, so the opened values leak nothing about the bits
    sL = [random_scalar() for _ in range(mn)]
    sR = [random_scalar() for _ in range(mn)]
    rho = random_scalar()
    S = G * rho + multiexp(list(zip(sL, Gi)) + list(zip(sR, Hi)))

    tr = _Transcript(commitments)
    tr.absorb(A, S)
    y, z = tr.challenge(), tr.challenge()
    yn = _powers(y, mn)
    zp = _powers(z, size + 2)                      # zp[k] = z^k; amount j is tied in with z^(2+j)

    # l(x) = l0 + l1*x and r(x) = r0 + r1*x ; t(x) = <l(x), r(x)> = t0 + t1*x + t2*x^2
    l0 = [(aL[i] - z) % L for i in range(mn)]
    l1 = sL
    r0 = [(yn[i] * (aR[i] + z) + zp[2 + i // N] * (1 << (i % N))) % L for i in range(mn)]
    r1 = [yn[i] * sR[i] % L for i in range(mn)]
    t1 = (_inner(l0, r1) + _inner(l1, r0)) % L
    t2 = _inner(l1, r1)
    tau1, tau2 = random_scalar(), random_scalar()
    T1 = Hv * t1 + G * tau1
    T2 = Hv * t2 + G * tau2

    tr.absorb(T1, T2)
    x = tr.challenge()
    l = [(l0[i] + l1[i] * x) % L for i in range(mn)]
    r = [(r0[i] + r1[i] * x) % L for i in range(mn)]
    t_hat = _inner(l, r)
    taux = (tau2 * x * x + tau1 * x + sum(zp[2 + j] * gammas[j] for j in range(size))) % L
    mu = (alpha + rho * x) % L

    tr.absorb(taux, mu, t_hat)
    w = tr.challenge()
    Uw = U * w
    y_inv = _powers(scalar_inverse(y), mn)
    Hp = [Hi[i] * y_inv[i] for i in range(mn)]

    # inner product argument: prove <l, r> = t_hat by folding both vectors in half, again and again
    a, b, Gs, Hs = l, r, list(Gi), Hp
    Ls, Rs = [], []
    while len(a) > 1:
        h = len(a) // 2
        a_lo, a_hi, b_lo, b_hi = a[:h], a[h:], b[:h], b[h:]
        G_lo, G_hi, H_lo, H_hi = Gs[:h], Gs[h:], Hs[:h], Hs[h:]
        Lp = multiexp(list(zip(a_lo, G_hi)) + list(zip(b_hi, H_lo)) + [(_inner(a_lo, b_hi), Uw)])
        Rp = multiexp(list(zip(a_hi, G_lo)) + list(zip(b_lo, H_hi)) + [(_inner(a_hi, b_lo), Uw)])
        tr.absorb(Lp, Rp)
        e = tr.challenge()
        ei = scalar_inverse(e)
        if h > 1:
            Gs = [G_lo[i] * ei + G_hi[i] * e for i in range(h)]
            Hs = [H_lo[i] * e + H_hi[i] * ei for i in range(h)]
        a = [(a_lo[i] * e + a_hi[i] * ei) % L for i in range(h)]
        b = [(b_lo[i] * ei + b_hi[i] * e) % L for i in range(h)]
        Ls.append(Lp)
        Rs.append(Rp)

    return {
        "A": A.hex(), "S": S.hex(), "T1": T1.hex(), "T2": T2.hex(),
        "taux": scalar_to_hex(taux), "mu": scalar_to_hex(mu), "t": scalar_to_hex(t_hat),
        "L": [p.hex() for p in Ls], "R": [p.hex() for p in Rs],
        "a": scalar_to_hex(a[0]), "b": scalar_to_hex(b[0]),
    }


def prove(amount: int, blinding: int) -> dict:
    """Proof for a single amount."""
    return prove_many([amount], [blinding])


# ----------------------------------------------------------------------------- verifier
def _parse(proof, m: int):
    if not isinstance(proof, dict) or set(proof) != PROOF_KEYS:
        raise ValueError("range proof has the wrong fields")
    want = folds(m)
    if not isinstance(proof["L"], list) or not isinstance(proof["R"], list) or len(proof["L"]) != want or len(proof["R"]) != want:
        raise ValueError("range proof has the wrong number of folds for %d amount(s)" % m)
    points = [Point.from_hex(proof[k]) for k in ("A", "S", "T1", "T2")]
    Ls = [Point.from_hex(p) for p in proof["L"]]
    Rs = [Point.from_hex(p) for p in proof["R"]]
    scalars = [scalar_from_hex(proof[k]) for k in ("taux", "mu", "t", "a", "b")]
    return points, Ls, Rs, scalars


def verify_batch(items) -> bool:
    """items: [(commitments, proof), ...], where commitments is the list of points one proof
    covers, in order (a single point is taken as a list of one).  True only if EVERY proof is
    valid.

    Each proof boils down to two equations of the form "this sum of points is zero".  Multiply
    each by a fresh random number and add them all together: if any single equation were
    false, the total would be zero only with probability 2^-128.  The win is that all proofs
    share the same generators, so their terms are added as plain numbers first and the
    expensive point multiplications are done once."""
    items = [([V] if isinstance(V, Point) else list(V), proof) for V, proof in items]
    if not items:
        return True
    try:
        if any(not 1 <= len(Vs) <= MAX_AMOUNTS for Vs, _ in items):
            return False
        widest = max(padded_count(len(Vs)) for Vs, _ in items) * N
        Gi, Hi, U = generators(widest)
        Hv = value_generator()
        g_co, h_co = [0] * widest, [0] * widest
        base_co = value_co = u_co = 0
        terms = []
        sum_two = (1 << N) - 1
        for position, (Vs, proof) in enumerate(items):
            (A, S, T1, T2), Ls, Rs, (taux, mu, t_hat, a, b) = _parse(proof, len(Vs))
            size = padded_count(len(Vs))
            mn = size * N
            rounds = len(Ls)
            tr = _Transcript(Vs)
            tr.absorb(A, S)
            y, z = tr.challenge(), tr.challenge()
            tr.absorb(T1, T2)
            x = tr.challenge()
            tr.absorb(taux, mu, t_hat)
            w = tr.challenge()
            es = []
            for Lp, Rp in zip(Ls, Rs):
                tr.absorb(Lp, Rp)
                es.append(tr.challenge())
            es_inv = [scalar_inverse(e) for e in es]

            weight = 1 if position == 0 else secrets.randbits(128) + 1   # separates the proofs
            c = secrets.randbits(128) + 1                                # separates this proof's two equations
            zp = _powers(z, size + 3)
            yn = _powers(y, mn)
            y_inv = _powers(scalar_inverse(y), mn)
            delta = ((z - zp[2]) * sum(yn) - sum_two * sum(zp[3:3 + size])) % L

            # s[i]: how much of generator i survives the folds
            s = [0] * mn
            first = 1
            for ei in es_inv:
                first = first * ei % L
            s[0] = first
            for i in range(1, mn):
                k = i.bit_length() - 1
                e = es[rounds - 1 - k]
                s[i] = s[i - (1 << k)] * e * e % L

            for i in range(mn):
                g_co[i] += weight * (-z - a * s[i])
                h_co[i] += weight * (z + (zp[2 + i // N] * (1 << (i % N)) - b * s[mn - 1 - i]) * y_inv[i])
            base_co += weight * (-mu - c * taux)
            value_co += weight * c * (delta - t_hat)
            u_co += weight * w * (t_hat - a * b)
            for j, V in enumerate(Vs):                  # padding commitments are zero: nothing to add
                terms.append((weight * c * zp[2 + j], V))
            terms.append((weight, A))
            terms.append((weight * x, S))
            terms.append((weight * c * x, T1))
            terms.append((weight * c * x * x, T2))
            for e, ei, Lp, Rp in zip(es, es_inv, Ls, Rs):
                terms.append((weight * e * e, Lp))
                terms.append((weight * ei * ei, Rp))
        terms.extend(zip(g_co, Gi))
        terms.extend(zip(h_co, Hi))
        terms.extend([(base_co, G), (value_co, Hv), (u_co, U)])
        return multiexp(terms).is_identity()
    except (ValueError, KeyError, TypeError, AttributeError):
        return False


def verify(commitments, proof: dict) -> bool:
    """One proof on its own.  `commitments`: a point, or the list of points it covers."""
    return verify_batch([(commitments, proof)])


def proof_size_bytes(proof: dict) -> int:
    """Size on the wire in binary form (the JSON hex form on disk is about twice this)."""
    return 32 * (4 + len(proof["L"]) + len(proof["R"]) + 5)
