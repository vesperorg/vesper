"""
curve.py - the elliptic curve every privacy trick stands on (Ed25519).

A point on the curve is like a public key; a scalar (a big whole number) is like a private key.
The one-way street is:  private scalar  x  -->  public point  x*G   (easy)
                        public point     x*G -->  private scalar x  (nobody can)

Stealth addresses, hidden amounts and range proofs are all built from three operations:
add two points, multiply a point by a scalar, and hash things into a scalar.

There are two implementations of the SAME group in this file:

  PyPoint      plain Python, written to be read.  About 1.5 ms per multiplication.
  NativePoint  the same maths done by libsodium (the PyNaCl package).  About 0.1 ms.

`Point` is whichever one is available.  Both produce exactly the same 32-byte encodings and
both reject exactly the same bad ones, so two nodes on different backends always agree.
The self-test cross-checks them against each other.

A valid point here means: canonical encoding, on the curve, in the prime-order group, and not
the identity.  That last part matters for a privacy coin - "small subgroup" points are how
several real coins leaked or lost money - so anything arriving from the network is checked.
"""

from __future__ import annotations

import hashlib
import os
import secrets

# ----------------------------------------------------------------------------- the curve
P = 2 ** 255 - 19                                            # the field: numbers mod P
L = 2 ** 252 + 27742317777372353535851937790883648493        # the group order: scalars mod L
D = (-121665 * pow(121666, P - 2, P)) % P                    # curve constant d
I = pow(2, (P - 1) // 4, P)                                  # sqrt(-1), used when decoding
_GX = 15112221349535400772501151409588531511454012693041857206046113283949847762202
_GY = (4 * pow(5, P - 2, P)) % P                             # the standard base point (RFC 8032)
_ID_BYTES = b"\x01" + b"\x00" * 31


# ----------------------------------------------------------------------------- pure Python
class PyPoint:
    """A curve point in extended coordinates (X, Y, Z, T): x = X/Z, y = Y/Z, T = X*Y/Z."""

    __slots__ = ("X", "Y", "Z", "T")

    def __init__(self, X: int, Y: int, Z: int = 1, T: int | None = None):
        self.X, self.Y, self.Z = X % P, Y % P, Z % P
        self.T = (X * Y * pow(Z, P - 2, P)) % P if T is None else T % P

    def __add__(self, other: "PyPoint") -> "PyPoint":
        A = ((self.Y - self.X) * (other.Y - other.X)) % P
        B = ((self.Y + self.X) * (other.Y + other.X)) % P
        C = (2 * self.T * other.T * D) % P
        Dd = (2 * self.Z * other.Z) % P
        E, F, G_, H = B - A, Dd - C, Dd + C, B + A
        return PyPoint(E * F, G_ * H, F * G_, E * H)

    def double(self) -> "PyPoint":
        return self + self

    def __neg__(self) -> "PyPoint":
        return PyPoint(-self.X, self.Y, self.Z, -self.T)

    def __sub__(self, other: "PyPoint") -> "PyPoint":
        return self + (-other)

    def _mul_raw(self, k: int) -> "PyPoint":
        """k*P by repeated doubling, with k used exactly as given (not reduced mod L)."""
        result, addend = _PY_IDENTITY, self
        while k:
            if k & 1:
                result = result + addend
            addend = addend + addend
            k >>= 1
        return result

    def __mul__(self, k: int) -> "PyPoint":
        return self._mul_raw(k % L)

    __rmul__ = __mul__

    def __eq__(self, other) -> bool:
        if not isinstance(other, PyPoint):
            return NotImplemented
        return (self.X * other.Z - other.X * self.Z) % P == 0 and (self.Y * other.Z - other.Y * self.Z) % P == 0

    def __hash__(self) -> int:
        return hash(self.encode())

    def is_identity(self) -> bool:
        return self.X == 0 and (self.Y - self.Z) % P == 0

    def encode(self) -> bytes:
        """32 bytes: y, with the lowest bit of x stored in the top bit."""
        zi = pow(self.Z, P - 2, P)
        x, y = (self.X * zi) % P, (self.Y * zi) % P
        return (y | ((x & 1) << 255)).to_bytes(32, "little")

    def hex(self) -> str:
        return self.encode().hex()

    @staticmethod
    def _decompress(data: bytes) -> "PyPoint":
        """Any point on the curve.  May be outside the prime-order group - see decode()."""
        if not isinstance(data, (bytes, bytearray)) or len(data) != 32:
            raise ValueError("point must be 32 bytes")
        y = int.from_bytes(data, "little")
        sign = y >> 255
        y &= (1 << 255) - 1
        if y >= P:
            raise ValueError("not a canonical point encoding")
        u, v = (y * y - 1) % P, (D * y * y + 1) % P          # x^2 = u / v
        x = pow(u * pow(v, P - 2, P), (P + 3) // 8, P)
        if (v * x * x - u) % P != 0:
            x = (x * I) % P
        if (v * x * x - u) % P != 0:
            raise ValueError("not a point on the curve")
        if x & 1 != sign:
            x = P - x
        return PyPoint(x, y)

    @staticmethod
    def decode(data: bytes) -> "PyPoint":
        """Strict: on the curve, in the prime-order group, not the identity."""
        point = PyPoint._decompress(data)
        if point.is_identity() or not point._mul_raw(L).is_identity():
            raise ValueError("point is not in the prime-order group")
        return point

    @staticmethod
    def from_hex(text: str) -> "PyPoint":
        return PyPoint.decode(bytes.fromhex(text))

    @staticmethod
    def from_hex_unchecked(text: str) -> "PyPoint":
        """For data the chain has ALREADY validated (skips the expensive group check)."""
        return PyPoint._decompress(bytes.fromhex(text))


_PY_IDENTITY = PyPoint(0, 1)
_PY_G = PyPoint(_GX, _GY)


def _py_multiexp(pairs) -> PyPoint:
    """sum(k_i * P_i) with shared doublings (Straus, 4-bit windows): ~2.5x faster than one by one."""
    tables, scalars = [], []
    for k, point in pairs:
        k %= L
        if k == 0:
            continue
        row = [_PY_IDENTITY, point]
        for _ in range(14):
            row.append(row[-1] + point)
        tables.append(row)
        scalars.append(k)
    acc = _PY_IDENTITY
    for shift in range(252, -1, -4):
        if shift != 252:
            for _ in range(4):
                acc = acc + acc
        for row, k in zip(tables, scalars):
            digit = (k >> shift) & 15
            if digit:
                acc = acc + row[digit]
    return acc


def _py_lift_times_8(digest: bytes):
    """Read 32 bytes as a point (if they are one) and multiply by 8, which lands it in the
    prime-order group.  None if the bytes are not a point, or the result is the identity."""
    try:
        candidate = PyPoint._decompress(digest)
    except ValueError:
        return None
    point = candidate._mul_raw(8)
    return None if point.is_identity() else point


# ----------------------------------------------------------------------------- libsodium
_na = None
if os.environ.get("VESPER_PURE_PYTHON") != "1":
    try:
        from nacl import bindings as _na
        for _name in ("crypto_core_ed25519_add", "crypto_core_ed25519_sub", "crypto_core_ed25519_is_valid_point",
                      "crypto_scalarmult_ed25519_noclamp", "crypto_scalarmult_ed25519_base_noclamp"):
            getattr(_na, _name)
    except (ImportError, AttributeError):
        _na = None

if _na is not None:
    _G_BYTES = _PY_G.encode()

    class NativePoint:
        """The same group, held as its 32-byte encoding and computed by libsodium."""

        __slots__ = ("b",)

        def __init__(self, b: bytes):
            self.b = b

        def __add__(self, other: "NativePoint") -> "NativePoint":
            return NativePoint(_na.crypto_core_ed25519_add(self.b, other.b))

        def __sub__(self, other: "NativePoint") -> "NativePoint":
            return NativePoint(_na.crypto_core_ed25519_sub(self.b, other.b))

        def __neg__(self) -> "NativePoint":
            if self.b == _ID_BYTES:
                return self
            return NativePoint(self.b[:31] + bytes([self.b[31] ^ 0x80]))   # flip the sign of x

        def double(self) -> "NativePoint":
            return self + self

        def __mul__(self, k: int) -> "NativePoint":
            k %= L
            if k == 0 or self.b == _ID_BYTES:
                return IDENTITY
            kb = k.to_bytes(32, "little")
            if self.b == _G_BYTES:
                return NativePoint(_na.crypto_scalarmult_ed25519_base_noclamp(kb))
            return NativePoint(_na.crypto_scalarmult_ed25519_noclamp(kb, self.b))

        __rmul__ = __mul__

        def __eq__(self, other) -> bool:
            if not isinstance(other, NativePoint):
                return NotImplemented
            return self.b == other.b

        def __hash__(self) -> int:
            return hash(self.b)

        def is_identity(self) -> bool:
            return self.b == _ID_BYTES

        def encode(self) -> bytes:
            return self.b

        def hex(self) -> str:
            return self.b.hex()

        @staticmethod
        def decode(data: bytes) -> "NativePoint":
            data = bytes(data)
            if len(data) != 32 or not _na.crypto_core_ed25519_is_valid_point(data):
                raise ValueError("not a valid point in the prime-order group")
            return NativePoint(data)

        @staticmethod
        def from_hex(text: str) -> "NativePoint":
            return NativePoint.decode(bytes.fromhex(text))

        @staticmethod
        def from_hex_unchecked(text: str) -> "NativePoint":
            data = bytes.fromhex(text)
            if len(data) != 32:
                raise ValueError("point must be 32 bytes")
            return NativePoint(data)

    Point = NativePoint
    BACKEND = "libsodium"
    IDENTITY = NativePoint(_ID_BYTES)
    G = NativePoint(_G_BYTES)

    def _to_backend(point: PyPoint) -> "NativePoint":
        return NativePoint.decode(point.encode())

    def _lift_times_8(digest: bytes):
        """Same result as the pure-Python version below, done by libsodium."""
        if (int.from_bytes(digest, "little") & ((1 << 255) - 1)) >= P:
            return None                                   # not a canonical encoding
        try:
            b = _na.crypto_core_ed25519_add(digest, _ID_BYTES)   # fails unless the bytes are a point on the curve
            for _ in range(3):
                b = _na.crypto_core_ed25519_add(b, b)
        except Exception:
            return None
        return None if b == _ID_BYTES else NativePoint(b)

    def multiexp(pairs) -> "NativePoint":
        """sum(k_i * P_i)."""
        acc = IDENTITY
        for k, point in pairs:
            k %= L
            if k:
                acc = acc + point * k
        return acc
else:
    Point = PyPoint
    BACKEND = "pure-python"
    IDENTITY = _PY_IDENTITY
    G = _PY_G
    multiexp = _py_multiexp

    def _to_backend(point: PyPoint) -> PyPoint:
        return point

    def _lift_times_8(digest: bytes):
        return _py_lift_times_8(digest)


# ----------------------------------------------------------------------------- hashing
def _encode_part(part) -> bytes:
    if isinstance(part, str):
        return part.encode("utf-8")
    if isinstance(part, int):
        return (part % (1 << 256)).to_bytes(32, "little")
    if isinstance(part, (bytes, bytearray)):
        return bytes(part)
    return part.encode()          # a point


def _hash(*parts) -> bytes:
    h = hashlib.sha512()
    for part in parts:
        data = _encode_part(part)
        h.update(len(data).to_bytes(4, "little"))
        h.update(data)
    return h.digest()


hash_bytes = _hash        # public name: 64 bytes binding everything passed in


def hash_to_scalar(*parts) -> int:
    """Hash anything (bytes, points, ints, strings) into a scalar mod L."""
    return int.from_bytes(_hash(*parts), "little") % L


def hash_to_point(*parts):
    """A point nobody knows the private key of ("nothing up my sleeve").

    Hash, try to read the result as a point, multiply by 8 to land in the prime-order group,
    repeat with a counter until it works.  Used for the extra generators that hidden amounts
    need: if anyone knew how these relate to G, they could forge commitments."""
    counter = 0
    while True:
        point = _lift_times_8(_hash("vesper/hash-to-point", counter, *parts)[:32])
        counter += 1
        if point is not None:
            return point


# ----------------------------------------------------------------------------- scalars
def random_scalar() -> int:
    return secrets.randbelow(L - 1) + 1


def scalar_to_hex(k: int) -> str:
    return (k % L).to_bytes(32, "little").hex()


def scalar_from_hex(text: str) -> int:
    """Strict: exactly 32 bytes and already reduced mod L (no second spelling of the same number)."""
    data = bytes.fromhex(text)
    if len(data) != 32:
        raise ValueError("scalar must be 32 bytes")
    k = int.from_bytes(data, "little")
    if k >= L:
        raise ValueError("scalar is not reduced")
    return k


def scalar_inverse(k: int) -> int:
    return pow(k % L, -1, L)


# ----------------------------------------------------------------------------- Schnorr signatures
def sign(private: int, message: bytes) -> dict:
    """Schnorr signature with a deterministic nonce.  Works for ANY scalar, including the
    one-time keys that stealth addresses derive and the "excess" keys of hidden amounts."""
    public = G * private
    r = hash_to_scalar("nonce", private, message)
    R = G * r
    c = hash_to_scalar("sig", R, public, message)
    s = (r + c * private) % L
    return {"R": R.hex(), "s": scalar_to_hex(s)}


def verify(public, message: bytes, signature: dict) -> bool:
    try:
        R = Point.from_hex(signature["R"])
        s = scalar_from_hex(signature["s"])
    except (ValueError, KeyError, TypeError):
        return False
    c = hash_to_scalar("sig", R, public, message)
    return G * s == R + public * c
