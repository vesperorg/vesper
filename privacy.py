"""
privacy.py - stealth addresses, view keys, and sealed amounts for outputs.

PHASE 1 - who received.  A wallet has two secrets, a view scalar a and a spend scalar b, and
can hand out as many ADDRESSES as it likes.  Address number i is two public keys

        D_i = B + m_i*G        (B = b*G; m_i = H(a, i), and m_0 = 0, so D_0 = B)
        C_i = a*D_i

Nobody can tell that two of them belong to the same wallet: they are unrelated-looking pairs
of points, and the first one ("the main address") has exactly the same shape as the rest.
Give every person who pays you their own address and they cannot compare notes.

To pay address i, the payer picks a random 16-byte "anchor", turns it into a secret
r = H(anchor, C_i, D_i), and puts R = r*D_i into the output.  Both sides then share the point

        r*C_i = r*a*D_i = a*R

which only the payer and the holder of a can compute.  The coins go to a ONE-TIME key

        P = H(a*R)*G + D_i

which looks like a random key to everyone else.  The wallet finds it by computing a*R, then
P - H(a*R)*G, and looking the result up in its list of D_i - one multiplication per output,
however many addresses it has given out.  Spending needs x = H(a*R) + m_i + b, so the spend
key b.

Two refinements, both from Monero's newer designs:
- a VIEW TAG: one byte of H(a*R) is written next to the output.  A wallet that sees the wrong
  byte knows at once the output is not its own and skips the rest of the work, which is most
  of the work.  The byte means nothing to anyone who cannot compute a*R.
- the ANCHOR is written into the output too, sealed with a*R.  The wallet re-derives r from it
  and checks R = r*D_i.  Without that check someone holding two of your addresses could build
  an output from one address's keys that lands on the other (the "Janus" attack), and learn
  that both are yours if you ever say "yes, that arrived".  Now such an output is not
  recognised at all.

PHASE 2 - how much.  The same shared point a*R also gives both sides
  - the blinding factor of the output's Pedersen commitment (see amounts.py), and
  - a mask that encrypts the amount.
So the receiver (and anyone holding the view key) can open the envelope; nobody else can.

Give someone only `a` and B - the "view key" - and they can see incoming payments to every
address of the wallet AND their amounts, forever, and can never spend a coin.
"""

from __future__ import annotations

import hashlib
import secrets

from amounts import commit, decrypt_amount, encrypt_amount
from curve import G, L, Point, hash_bytes, hash_to_scalar, scalar_from_hex, scalar_to_hex, sign, verify

B58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
DEFAULT_PREFIX = "vesp"
ADDRESS_VERSION = 2              # 1 was (a*G, B) with R = r*G, before every address became the same shape
LOOKAHEAD = 100                  # addresses past the last one handed out that a wallet still recognises
ANCHOR_BYTES = 16


def b58encode(data: bytes) -> str:
    n = int.from_bytes(data, "big")
    out = ""
    while n:
        n, rem = divmod(n, 58)
        out = B58_ALPHABET[rem] + out
    return "1" * (len(data) - len(data.lstrip(b"\x00"))) + out


def b58decode(text: str) -> bytes:
    n = 0
    for ch in text:
        idx = B58_ALPHABET.find(ch)
        if idx < 0:
            raise ValueError("invalid base58 character %r" % ch)
        n = n * 58 + idx
    body = n.to_bytes((n.bit_length() + 7) // 8, "big") if n else b""
    return b"\x00" * (len(text) - len(text.lstrip("1"))) + body


def _checksum(prefix: str, payload: bytes) -> bytes:
    return hashlib.sha256(hashlib.sha256(prefix.encode() + payload).digest()).digest()[:4]


# ----------------------------------------------------------------------------- addresses
def encode_address(view_pub, spend_pub, prefix: str = DEFAULT_PREFIX) -> str:
    """view_pub = C, spend_pub = D of one address."""
    payload = bytes([ADDRESS_VERSION]) + view_pub.encode() + spend_pub.encode()
    return prefix + b58encode(payload + _checksum(prefix, payload))


def decode_address(address: str, prefix: str = DEFAULT_PREFIX):
    """(C, D) of an address, both checked to be proper points."""
    if not isinstance(address, str) or not address.startswith(prefix):
        raise ValueError("address does not start with %r" % prefix)
    raw = b58decode(address[len(prefix):])
    if len(raw) == 68 and raw[64:] == _checksum(prefix, raw[:64]):
        raise ValueError("that is an address from before Vesper 0.6, which no wallet watches any more: ask for a new one")
    if len(raw) != 69 or raw[0] != ADDRESS_VERSION or raw[65:] != _checksum(prefix, raw[:65]):
        raise ValueError("bad address checksum")
    return Point.decode(raw[1:33]), Point.decode(raw[33:65])


def convert_address(address: str, old_prefix: str, new_prefix: str) -> str:
    """The same two public keys, spelled with a different prefix.  The prefix never reaches the
    chain (only one-time keys do), so renaming the coin's ticker does not strand any wallet."""
    view_pub, spend_pub = decode_address(address, old_prefix)
    return encode_address(view_pub, spend_pub, new_prefix)


def is_valid_address(address, prefix: str = DEFAULT_PREFIX) -> bool:
    try:
        decode_address(address, prefix)
        return True
    except (ValueError, TypeError):
        return False


# ----------------------------------------------------------------------------- what the sender and receiver share
def _ephemeral(anchor: bytes, view_pub, spend_pub) -> int:
    """The payer's secret r for one output, made from the anchor and the address it pays."""
    return hash_to_scalar("vesper/ephemeral", anchor, view_pub, spend_pub) or 1


def _view_tag(shared_point, index: int) -> str:
    return hash_bytes("vesper/view-tag", shared_point, index)[:1].hex()


def _anchor_mask(shared_point, index: int) -> bytes:
    return hash_bytes("vesper/anchor", shared_point, index)[:ANCHOR_BYTES]


def _xor(a: bytes, b: bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(a, b))


def _one_output(view_pub, spend_pub, index: int, anchor: bytes):
    """r, R, the shared point and the one-time key of one output to the address (C, D)."""
    r = _ephemeral(anchor, view_pub, spend_pub)
    shared_point = view_pub * r
    shared = hash_to_scalar("stealth", shared_point, index)
    out = {"index": index, "one_time_pub": (G * shared + spend_pub).hex(), "ephemeral_pub": (spend_pub * r).hex(),
           "view_tag": _view_tag(shared_point, index),
           "enc_anchor": _xor(anchor, _anchor_mask(shared_point, index)).hex()}
    return r, shared_point, out


# ----------------------------------------------------------------------------- keys
class ViewKey:
    """The view-only half: private view scalar + public spend key, and how many extra
    addresses the wallet has handed out (`count`)."""

    def __init__(self, view_priv: int, spend_pub, prefix: str = DEFAULT_PREFIX, count: int = 0):
        self.view_priv = view_priv % L
        self.spend_pub = spend_pub
        self.prefix = prefix
        self.count = max(0, int(count))
        self._table: dict = {}           # D_i -> i, for i = 0 .. count + LOOKAHEAD
        self._offsets: list = []         # m_i

    def offset(self, i: int) -> int:
        """m_i: how address i's spend key differs from the main one (0 for the main address)."""
        return 0 if i == 0 else hash_to_scalar("vesper/subaddress", self.view_priv, i)

    def keys_at(self, i: int):
        spend = self.spend_pub + G * self.offset(i) if i else self.spend_pub
        return spend * self.view_priv, spend

    def address_at(self, i: int) -> str:
        return encode_address(*self.keys_at(i), self.prefix)

    @property
    def address(self) -> str:
        return self.address_at(0)

    def watch(self, count: int) -> None:
        """Recognise payments to addresses 1 .. count (and LOOKAHEAD more)."""
        self.count = max(self.count, int(count))

    def prepare(self) -> None:
        """Work out the list of addresses to recognise now (otherwise done on first use)."""
        self._lookup(self.spend_pub)

    def _lookup(self, spend_pub):
        want = self.count + LOOKAHEAD
        while len(self._offsets) <= want:
            i = len(self._offsets)
            m = self.offset(i)
            self._offsets.append(m)
            self._table[self.spend_pub + G * m if i else self.spend_pub] = i
        return self._table.get(spend_pub)

    def to_dict(self) -> dict:
        return {"view_priv": scalar_to_hex(self.view_priv), "spend_pub": self.spend_pub.hex(), "count": self.count}

    @classmethod
    def from_dict(cls, data: dict, prefix: str = DEFAULT_PREFIX) -> "ViewKey":
        return cls(scalar_from_hex(data["view_priv"]), Point.from_hex(data["spend_pub"]), prefix, int(data.get("count", 0)))

    def shared_point(self, ephemeral_pub_hex: str):
        """a * R: the secret this wallet shares with whoever made the output."""
        return Point.from_hex_unchecked(ephemeral_pub_hex) * self.view_priv

    def open(self, output: dict, shared_point=None):
        """None if this output is not ours.  Otherwise what was sealed inside:
        {"amount", "blinding", "shared", "address"} - `shared` is what to add to the private
        spend key to get the one-time private key; `address` is which of the wallet's
        addresses was paid (0 = the main one).

        Outputs handed to this method come from the chain, which already validated every point,
        so the cheaper unchecked decoding is used; a malformed one simply fails to match."""
        try:
            index = int(output["index"])
            if shared_point is None:
                shared_point = self.shared_point(output["ephemeral_pub"])
            found = self._open_at(output, shared_point, index)
            if found is None and index != 0 and "amount" in output:
                found = self._open_at(output, shared_point, 0)     # a pool payout: made at index 0, before its place was known
            return found
        except Exception:
            return None

    def _open_at(self, output: dict, shared_point, index: int):
        """`open` for the output as if it was made at `index`."""
        if output["view_tag"] != _view_tag(shared_point, index):
            return None                                  # 255 times in 256, the work stops here
        shared = hash_to_scalar("stealth", shared_point, index)
        spend = Point.from_hex_unchecked(output["one_time_pub"]) - G * shared
        i = self._lookup(spend)
        if i is None:
            return None
        anchor = _xor(bytes.fromhex(output["enc_anchor"]), _anchor_mask(shared_point, index))
        if len(anchor) != ANCHOR_BYTES or (spend * _ephemeral(anchor, spend * self.view_priv, spend)).hex() != output["ephemeral_pub"]:
            return None                                  # not made for this address: a Janus probe, or junk
        if "amount" in output:                           # a mining reward: public amount, no blinding
            amount, blinding = int(output["amount"]), 0
        else:
            amount = decrypt_amount(output["enc_amount"], shared_point, index)
            blinding = hash_to_scalar("blinding", shared_point, index)
        if commit(amount, blinding) != Point.from_hex_unchecked(output["commitment"]):
            return None                                  # the sender lied about the amount: unspendable, ignore
        return {"amount": amount, "blinding": blinding, "shared": (shared + self._offsets[i]) % L, "address": i}

    def is_mine(self, output: dict) -> bool:
        return self.open(output) is not None


SEED_BYTES = 32


def keys_from_seed(seed: bytes) -> tuple[int, int]:
    """(view scalar, spend scalar) of the wallet that grows from `seed`: 32 random bytes are the
    whole wallet, so they can be written on paper (see wallet.recovery_code)."""
    if not isinstance(seed, bytes) or len(seed) != SEED_BYTES:
        raise ValueError("a wallet seed is %d bytes" % SEED_BYTES)
    return (hash_to_scalar("vesper/seed/view", seed) or 1), (hash_to_scalar("vesper/seed/spend", seed) or 1)


class StealthKeys:
    """A wallet's secret: a private view scalar and a private spend scalar - and, for wallets
    made since recovery codes exist, the 32-byte seed both grow from."""

    def __init__(self, view_priv: int, spend_priv: int, prefix: str = DEFAULT_PREFIX, count: int = 0, seed: bytes | None = None):
        self.view_priv = view_priv % L
        self.spend_priv = spend_priv % L
        self.prefix = prefix
        self.seed = seed
        self.spend_pub = G * self.spend_priv
        self._view = ViewKey(self.view_priv, self.spend_pub, prefix, count)

    @classmethod
    def from_seed(cls, seed: bytes, prefix: str = DEFAULT_PREFIX) -> "StealthKeys":
        view_priv, spend_priv = keys_from_seed(seed)
        return cls(view_priv, spend_priv, prefix, seed=seed)

    @classmethod
    def generate(cls, prefix: str = DEFAULT_PREFIX) -> "StealthKeys":
        return cls.from_seed(secrets.token_bytes(SEED_BYTES), prefix)

    @property
    def count(self) -> int:
        return self._view.count

    def watch(self, count: int) -> None:
        self._view.watch(count)

    @property
    def address(self) -> str:
        self._view.prefix = self.prefix
        return self._view.address

    def address_at(self, i: int) -> str:
        self._view.prefix = self.prefix
        return self._view.address_at(i)

    def view_key(self) -> ViewKey:
        self._view.prefix = self.prefix
        return self._view

    def to_dict(self) -> dict:
        data = {"view_priv": scalar_to_hex(self.view_priv), "spend_priv": scalar_to_hex(self.spend_priv)}
        if self.seed is not None:
            data["seed"] = self.seed.hex()
        return data

    @classmethod
    def from_dict(cls, data: dict, prefix: str = DEFAULT_PREFIX) -> "StealthKeys":
        keys = cls(scalar_from_hex(data["view_priv"]), scalar_from_hex(data["spend_priv"]), prefix)
        if data.get("seed"):
            seed = bytes.fromhex(data["seed"])
            if keys_from_seed(seed) != (keys.view_priv, keys.spend_priv):
                raise ValueError("the wallet's seed does not give its keys: the file is damaged")
            keys.seed = seed
        return keys

    def owns(self, output: dict):
        """If `output` was paid to this wallet, return its one-time private key; else None."""
        opened = self.view_key().open(output)
        return None if opened is None else (opened["shared"] + self.spend_priv) % L

    def sign_input(self, output: dict, message: bytes) -> dict:
        x = self.owns(output)
        if x is None:
            raise ValueError("this wallet does not own that output")
        return sign(x, message)


def scan_outputs(view: ViewKey, utxos: list) -> list:
    """utxos: [{"txid","index","output"}] from a node.  Returns the ones this view key owns,
    each with its opened amount and blinding and which address was paid.  This scan is the
    price of privacy: nobody can look your balance up, so your own wallet has to go and find
    it.  It costs one multiplication per output; the view tag saves the rest."""
    found = []
    for u in utxos:
        opened = view.open(u["output"])
        if opened is not None:
            found.append({"txid": u["txid"], "index": u["index"], "output": u["output"], "address": opened["address"],
                          "amount": opened["amount"], "blinding": opened["blinding"], "shared": opened["shared"]})
    return found


# ----------------------------------------------------------------------------- paying
def make_outputs(payments: list, prefix: str = DEFAULT_PREFIX, hidden: bool = True, secrets_out: list | None = None) -> tuple:
    """payments = [(address, amount), ...]  ->  (outputs, openings).

    openings[i] = (amount, blinding) for the sender's own use (range proofs, balancing); they
    never go on the chain.  Every output gets its own anchor, so its own secret r and its own
    R: outputs to different addresses cannot share one, and doing it for all of them keeps
    every payment the same shape.

    hidden=False is for mining rewards only: the amount is public by nature (everyone must be
    able to check the reward), so it is written in clear and committed with blinding 0.

    secrets_out: if a list is given, each output's secret r is appended to it - what the payer
    keeps to prove a payment later (proofs.py)."""
    outputs, openings = [], []
    for index, (address, amount) in enumerate(payments):
        amount = int(amount)
        view_pub, spend_pub = decode_address(address, prefix)
        r, shared_point, out = _one_output(view_pub, spend_pub, index, secrets.token_bytes(ANCHOR_BYTES))
        if secrets_out is not None:
            secrets_out.append(r)
        if hidden:
            blinding = hash_to_scalar("blinding", shared_point, index)
            out["commitment"] = commit(amount, blinding).hex()
            out["enc_amount"] = encrypt_amount(amount, shared_point, index)
        else:
            blinding = 0
            out["commitment"] = commit(amount, 0).hex()
            out["amount"] = amount
        outputs.append(out)
        openings.append((amount, blinding))
    return outputs, openings


def verify_input_signature(output: dict, message: bytes, signature: dict) -> bool:
    """Anyone can check that the signer knows the one-time private key of `output`."""
    try:
        return verify(Point.from_hex_unchecked(output["one_time_pub"]), message, signature)
    except Exception:
        return False


# ----------------------------------------------------------------------------- auditable outputs
def make_auditable_output(address: str, amount: int, index: int, prefix: str = DEFAULT_PREFIX) -> dict:
    """An output whose RECIPIENT anyone can verify.  Used for the development fund's share of
    each block, which must be publicly checkable in a coin where nothing else is.

    It is an ordinary stealth output with one extra field: the payer's secret r.  With r,
    anyone can redo the payer's maths and confirm the one-time key really belongs to the
    published address.  Revealing r never lets anyone SPEND the output - that still needs the
    private spend key.  Each output has its own r, so nothing else in the transaction is exposed."""
    amount = int(amount)
    view_pub, spend_pub = decode_address(address, prefix)
    r, _, out = _one_output(view_pub, spend_pub, index, secrets.token_bytes(ANCHOR_BYTES))
    out.update({"commitment": commit(amount, 0).hex(), "amount": amount, "ephemeral_secret": scalar_to_hex(r)})
    return out


def verify_auditable_output(output: dict, address: str, prefix: str = DEFAULT_PREFIX) -> bool:
    """True if `output` provably pays `address`."""
    try:
        r = scalar_from_hex(output["ephemeral_secret"])
        view_pub, spend_pub = decode_address(address, prefix)
        if r == 0 or (spend_pub * r).hex() != output["ephemeral_pub"]:
            return False
        shared = hash_to_scalar("stealth", view_pub * r, int(output["index"]))
        return (G * shared + spend_pub).hex() == output["one_time_pub"]
    except Exception:
        return False
