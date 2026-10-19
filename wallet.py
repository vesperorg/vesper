"""
wallet.py - a Vesper wallet file: two secret scalars (view + spend), encrypted.

Amounts on the chain are sealed, so "what is my balance" has only one answer: look at every
output with the view key, open the ones that are yours, and add them up.  A wallet does that
once; after that it keeps a private notebook of what it found and only looks at new blocks
(sync_outputs).

The file stores the main ADDRESS in the clear (so the node can pay mining rewards to it
without ever opening the wallet) and the two private scalars encrypted with your password
(scrypt + Fernet/AES), together with the labels of any extra addresses handed out (they say
who pays you, so they are encrypted too).  `export_view_key` writes a second file that can
FIND your payments but never spend them - give that one to an accountant, never this one.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import secrets

from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

import ringsig
from curve import L

from privacy import (DEFAULT_PREFIX, StealthKeys, ViewKey, convert_address, is_valid_address,  # noqa: F401
                     scan_outputs)

MAX_ADDRESSES = 100_000    # extra addresses one wallet may hand out

# ----------------------------------------------------------------------------- recovery codes
# A wallet made since recovery codes exist grows from 32 random bytes.  Written down as 55
# characters (11 groups of 5) with two check bytes, they ARE the wallet: anyone who has them can
# spend, and with them a lost or broken computer costs nothing.  The alphabet is Crockford's
# base32: no I, L, O or U, and reading an O as 0 or an I or L as 1 does no harm.
_CODE_ALPHABET = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"
_CODE_LENGTH = 55


def _check_bytes(seed: bytes) -> bytes:
    return hashlib.sha256(b"vesper/recovery-code" + seed).digest()[:2]


def recovery_code(seed: bytes) -> str:
    n = int.from_bytes(seed + _check_bytes(seed), "big")
    text = "".join(_CODE_ALPHABET[(n >> (5 * i)) & 31] for i in reversed(range(_CODE_LENGTH)))
    return "-".join(text[i:i + 5] for i in range(0, _CODE_LENGTH, 5))


def seed_from_code(code: str) -> bytes:
    """The seed in a recovery code.  Spaces, dashes and case do not matter; a mistake is caught."""
    text = "".join(ch for ch in str(code).upper() if ch not in " -\t\r\n").translate(str.maketrans("OIL", "011"))
    if len(text) != _CODE_LENGTH or any(ch not in _CODE_ALPHABET for ch in text):
        raise WalletError("a recovery code is %d letters and digits (11 groups of 5); this one is not" % _CODE_LENGTH)
    n = 0
    for ch in text:
        n = n * 32 + _CODE_ALPHABET.index(ch)
    if n >> 272:
        raise WalletError("that recovery code has a mistake in it")
    data = n.to_bytes(34, "big")
    if _check_bytes(data[:32]) != data[32:]:
        raise WalletError("that recovery code has a mistake in it (its check letters do not match): look at it again")
    return data[:32]


REORG_MARGIN = 20          # blocks behind the tip that a wallet treats as settled for good


class WalletError(Exception):
    pass


class WalletLocked(WalletError):
    pass


def _fernet_key(password: str, salt: bytes, n: int, r: int, p: int) -> bytes:
    return base64.urlsafe_b64encode(Scrypt(salt=salt, length=32, n=n, r=r, p=p).derive(password.encode("utf-8")))


def _ref(u: dict) -> str:
    return "%s:%d" % (u["txid"], u["index"])


def _notebook_ok(nb) -> bool:
    return (isinstance(nb, dict) and nb.get("version") == 1 and type(nb.get("height")) is int and nb["height"] >= 0
            and isinstance(nb.get("owned"), list) and all(isinstance(u, dict) and "output" in u for u in nb["owned"]))


def sync_outputs(view: ViewKey, spend_priv: int | None, notebook: dict | None, fetch_page, block_hash_at,
                 margin: int = REORG_MARGIN, markers: dict | None = None):
    """Find a wallet's outputs without reading the whole chain every time.

    notebook       what the last sync left behind, or None for a first look.
    fetch_page(n)  the node's answer for blocks n, n+1, ...: each block's outputs and spent
                   markers (chain.scan_page).  Whole blocks are asked for, never particular
                   outputs, so whoever answers learns nothing about which ones are ours.
    block_hash_at(h)  the ID of block h on the node's chain (None if it has no such block).
    spend_priv     the private spend scalar, or None for a view-only look.  Only the spend
                   key can compute an output's key image, so only the owner can tell which of
                   their outputs are spent.
    markers        {reference: key image} for a view-only look that was handed some.

    Returns (owned, notebook, tip).  owned: every output of this wallet, opened, each
    {"txid","index","output","amount","blinding","key_image","spent"} (spent is None when it
    cannot be told).  notebook: what to save for next time.  tip: what the node said about
    the chain (height, how many outputs are old enough to use, what is waiting to be mined).

    The newest `margin` blocks are read again on every sync and never written to the
    notebook: they can still be reorganised away.  If the chain was reorganised even deeper
    than that, the block the notebook stopped at is gone, and everything is read afresh."""
    nb = notebook if _notebook_ok(notebook) else None
    if nb is not None and nb["height"] > 0 and block_hash_at(nb["height"]) != nb.get("hash"):
        nb = None
    if nb is None:
        nb = {"version": 1, "height": 0, "hash": None, "owned": []}
    markers = markers or {}
    settled = {_ref(u): dict(u) for u in nb["owned"]}
    recent: dict[str, dict] = {}
    recent_spent: set[str] = set()
    by_image = {u["key_image"]: ref for ref, u in settled.items() if u.get("key_image")}
    height, block_hash = nb["height"], nb.get("hash")
    start, scanned, tip, final_through = height + 1, 0, {}, None
    while True:
        page = fetch_page(start)
        if final_through is None:                      # fixed once: the tip may move while we read
            final_through = page["height"] - margin
        tip = {k: v for k, v in page.items() if k != "blocks"}
        for block in page["blocks"]:
            final = block["height"] <= final_through
            scanned += len(block["outputs"])
            for u in scan_outputs(view, block["outputs"]):
                ref, shared = _ref(u), u.pop("shared")
                if spend_priv is not None:
                    u["key_image"] = ringsig.key_image((shared + spend_priv) % L, ref, u["output"]["one_time_pub"]).hex()
                    u["spent"] = False
                else:
                    u["key_image"] = markers.get(ref)
                    u["spent"] = False if (u["key_image"] or "ephemeral_secret" in u["output"]) else None
                (settled if final else recent)[ref] = u
                if u["key_image"]:
                    by_image[u["key_image"]] = ref
            gone = [by_image[i] for i in block["key_images"] if i in by_image]
            gone += [r for r in block["fund_spent"] if r in settled or r in recent]
            for ref in gone:
                if final and ref in settled:
                    settled[ref]["spent"] = True
                else:
                    recent_spent.add(ref)
            if final:
                height, block_hash = block["height"], block["hash"]
        if not page["blocks"] or page["next"] > page["height"] or page["next"] <= start:
            break                                      # done (or the node is not making progress: stop asking)
        start = page["next"]
    owned = []
    for ref, u in list(settled.items()) + list(recent.items()):
        u = dict(u)
        if ref in recent_spent:
            u["spent"] = True
        owned.append(u)
    tip["scanned"] = scanned
    return owned, {"version": 1, "height": height, "hash": block_hash, "owned": list(settled.values())}, tip


def _old_style(address, prefix: str) -> bool:
    """An address written before Vesper 0.6 changed how addresses are made."""
    try:
        convert_address(address, prefix, prefix)
        return False
    except ValueError as exc:
        return "before Vesper 0.6" in str(exc)
    except TypeError:
        return False


class Wallet:
    def __init__(self, keys: StealthKeys, labels=None):
        self.keys = keys
        self.labels = [str(x) for x in (labels or [])]      # label of address i is labels[i - 1]
        keys.watch(len(self.labels))

    @classmethod
    def generate(cls, prefix: str = DEFAULT_PREFIX) -> "Wallet":
        return cls(StealthKeys.generate(prefix))

    @classmethod
    def from_code(cls, code: str, prefix: str = DEFAULT_PREFIX) -> "Wallet":
        """The wallet a recovery code was written from: same keys, same addresses."""
        return cls(StealthKeys.from_seed(seed_from_code(code), prefix))

    def recovery_code(self) -> str | None:
        """None for a wallet made before recovery codes: back up its file instead."""
        return recovery_code(self.keys.seed) if self.keys.seed is not None else None

    @property
    def address(self) -> str:
        return self.keys.address

    @property
    def prefix(self) -> str:
        return self.keys.prefix

    def view_key(self) -> ViewKey:
        return self.keys.view_key()

    # ---- addresses ------------------------------------------------------------------
    # One wallet, as many addresses as you like: give each person who pays you their own and
    # they cannot tell, even together, that the money goes to the same place.  They all land in
    # this wallet, and its view key sees them all.
    def new_address(self, label: str = "") -> tuple[int, str]:
        if len(self.labels) >= MAX_ADDRESSES:
            raise WalletError("this wallet already has %d extra addresses" % MAX_ADDRESSES)
        self.labels.append(str(label))
        self.keys.watch(len(self.labels))
        return len(self.labels), self.keys.address_at(len(self.labels))

    def addresses(self) -> list[tuple[int, str, str]]:
        """[(number, address, label)], the main address first as number 0."""
        return [(0, self.address, "main")] + [(i, self.keys.address_at(i), label) for i, label in enumerate(self.labels, 1)]

    # ---- scanning the chain -------------------------------------------------------
    def scan(self, outputs: list[dict], key_images=(), fund_spent=()) -> list[dict]:
        """outputs: every output on the chain ([{"txid","index","output"}]).  Returns the ones
        this wallet owns, opened, each with its key image and whether that marker is already
        on the chain: {"txid","index","output","amount","blinding","key_image","spent"}.

        Nobody else can do the second half: only the spend key can compute an output's key
        image, so only the owner can tell which of their outputs are spent."""
        key_images, fund_spent = set(key_images), set(fund_spent)
        found = scan_outputs(self.keys.view_key(), outputs)
        for u in found:
            x = (u.pop("shared") + self.keys.spend_priv) % L
            ref = "%s:%d" % (u["txid"], u["index"])
            u["key_image"] = ringsig.key_image(x, ref, u["output"]["one_time_pub"]).hex()
            if "ephemeral_secret" in u["output"]:                       # fund outputs are spent by name
                u["spent"] = ref in fund_spent
            else:
                u["spent"] = u["key_image"] in key_images
        return found

    def unspent(self, outputs: list[dict], key_images=(), fund_spent=()) -> list[dict]:
        return [u for u in self.scan(outputs, key_images, fund_spent) if not u["spent"]]

    def balance(self, outputs: list[dict], key_images=(), fund_spent=()) -> int:
        return sum(u["amount"] for u in self.unspent(outputs, key_images, fund_spent))

    # ---- ring memory ------------------------------------------------------------------
    # If a payment is retried with freshly chosen decoys, the two rings have exactly one output
    # in common: the real one.  So the wallet remembers the ring it first used for each of its
    # outputs and uses the same one again.  The file is encrypted with a key made from the
    # wallet's own secrets: without the wallet it is noise, and it needs no second password.
    def _memory_key(self, label: bytes = b"vesper/ring-memory") -> bytes:
        seed = hashlib.sha256(label + self.keys.view_priv.to_bytes(32, "little")
                              + self.keys.spend_priv.to_bytes(32, "little")).digest()
        return base64.urlsafe_b64encode(seed)

    # ---- the notebook -----------------------------------------------------------------
    # What the wallet has already found on the chain, so the next look only reads new blocks.
    # It lists this wallet's outputs and their amounts, so it is encrypted the same way as
    # the ring memory.  Deleting it costs nothing but time: the next sync reads from the start.
    def sync(self, notebook: dict | None, fetch_page, block_hash_at, margin: int = REORG_MARGIN):
        return sync_outputs(self.keys.view_key(), self.keys.spend_priv, notebook, fetch_page, block_hash_at, margin)

    def load_notebook(self, path: str) -> dict | None:
        try:
            with open(path, "rb") as fh:
                data = json.loads(Fernet(self._memory_key(b"vesper/scan-notebook")).decrypt(fh.read()).decode("utf-8"))
            return data if _notebook_ok(data) else None
        except (OSError, InvalidToken, ValueError):
            return None

    def save_notebook(self, path: str, notebook: dict) -> None:
        os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
        tmp = path + ".tmp"
        with open(tmp, "wb") as fh:
            fh.write(Fernet(self._memory_key(b"vesper/scan-notebook")).encrypt(json.dumps(notebook).encode("utf-8")))
        os.replace(tmp, path)

    # ---- the payments it made ------------------------------------------------------------
    # For each payment: which output paid whom, how much, and the secret r it was made with.
    # With r, the payer can prove that payment to one person (proofs.py).  Encrypted like the
    # ring memory: it says whom you paid.
    def load_sent(self, path: str) -> dict:
        try:
            with open(path, "rb") as fh:
                data = json.loads(Fernet(self._memory_key(b"vesper/sent-log")).decrypt(fh.read()).decode("utf-8"))
            return data if isinstance(data, dict) else {}
        except (OSError, InvalidToken, ValueError):
            return {}

    def save_sent(self, path: str, log: dict) -> None:
        os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
        tmp = path + ".tmp"
        with open(tmp, "wb") as fh:
            fh.write(Fernet(self._memory_key(b"vesper/sent-log")).encrypt(json.dumps(log).encode("utf-8")))
        os.replace(tmp, path)

    def load_rings(self, path: str) -> dict:
        try:
            with open(path, "rb") as fh:
                data = json.loads(Fernet(self._memory_key()).decrypt(fh.read()).decode("utf-8"))
            return data if isinstance(data, dict) else {}
        except (OSError, InvalidToken, ValueError):
            return {}

    def save_rings(self, path: str, rings: dict) -> None:
        os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
        tmp = path + ".tmp"
        with open(tmp, "wb") as fh:
            fh.write(Fernet(self._memory_key()).encrypt(json.dumps(rings).encode("utf-8")))
        os.replace(tmp, path)

    # ---- files ----------------------------------------------------------------------
    def save(self, path: str, password: str | None = None) -> None:
        data = {"version": 2, "kind": "vesper-wallet", "address_prefix": self.prefix, "address": self.address}
        secret = json.dumps(dict(self.keys.to_dict(), labels=self.labels)).encode("utf-8")
        if password:
            salt = secrets.token_bytes(16)
            n, r, p = 2 ** 17, 8, 1          # 128 MiB and about a quarter second per password guess
            token = Fernet(_fernet_key(password, salt, n, r, p)).encrypt(secret)
            data.update({"encrypted": True, "kdf": {"name": "scrypt", "salt": salt.hex(), "n": n, "r": r, "p": p},
                         "cipher": "fernet", "keys_encrypted": token.decode("ascii")})
        else:
            data.update({"encrypted": False, "keys": dict(self.keys.to_dict(), labels=self.labels),
                         "warning": "UNENCRYPTED - anyone who can read this file can spend these coins"})
        os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
        tmp = path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as fh:
            json.dump(data, fh, indent=2)
        os.replace(tmp, path)

    def export_view_key(self, path: str, owned: list | None = None) -> None:
        """A file that can see incoming payments but cannot spend.  Meant to be handed over.

        A view key alone cannot tell which outputs were later spent (that needs the spend key).
        Pass `owned` (this wallet's scan) to include the key images of the outputs it holds
        today, so the file's holder can also see when those are spent.  Outputs received after
        the export stay "spent status unknown" until a fresh file is made."""
        markers = {"%s:%d" % (u["txid"], u["index"]): u["key_image"] for u in (owned or []) if "key_image" in u}
        data = {"version": 3, "kind": "view-key", "address_prefix": self.prefix, "address": self.address,
                "view_key": self.keys.view_key().to_dict(), "key_images": markers,
                "note": "This key can FIND payments to the address above and to the wallet's %d other address(es), "
                        "and open their amounts. It can never spend them." % len(self.labels)}
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(data, fh, indent=2)

    @staticmethod
    def public_info(path: str, prefix: str | None = None) -> dict:
        """Address and status without the password.  `prefix`: spell the address with the coin's
        current prefix even if the file was written under an older one."""
        with open(path, "r", encoding="utf-8") as fh:
            data = json.load(fh)
        stored = data.get("address_prefix", DEFAULT_PREFIX)
        address = data["address"]
        if prefix and prefix != stored:
            address = convert_address(address, stored, prefix)
        return {"address": address, "encrypted": bool(data.get("encrypted")),
                "address_prefix": prefix or stored, "kind": data.get("kind", "vesper-wallet")}

    @classmethod
    def load(cls, path: str, password: str | None = None, prefix: str | None = None) -> "Wallet":
        if not os.path.exists(path):
            raise WalletError("no wallet file at %s" % path)
        with open(path, "r", encoding="utf-8") as fh:
            data = json.load(fh)
        stored_prefix = data.get("address_prefix", DEFAULT_PREFIX)
        if data.get("kind") == "view-key":
            raise WalletError("that is a view-key file: it can watch, not spend")
        if data.get("encrypted"):
            if not password:
                raise WalletLocked("this wallet is encrypted - a password is required")
            kdf = data["kdf"]
            key = _fernet_key(password, bytes.fromhex(kdf["salt"]), kdf["n"], kdf["r"], kdf["p"])
            try:
                secret = json.loads(Fernet(key).decrypt(data["keys_encrypted"].encode("ascii")).decode("utf-8"))
            except InvalidToken:
                raise WalletLocked("wrong password")
        else:
            secret = data["keys"]
        wallet = cls(StealthKeys.from_dict(secret, stored_prefix), secret.get("labels"))
        if wallet.address != data.get("address"):
            if not _old_style(data.get("address"), stored_prefix):
                raise WalletError("wallet file is corrupt: the stored address does not match the keys")
            data["address"] = wallet.address      # same keys; the address is now spelled the 0.6 way
            tmp = path + ".tmp"
            with open(tmp, "w", encoding="utf-8") as fh:
                json.dump(data, fh, indent=2)
            os.replace(tmp, path)
        if prefix and prefix != wallet.keys.prefix:
            wallet.keys.prefix = prefix          # same keys, current spelling
        return wallet

    @staticmethod
    def load_view_markers(path: str) -> dict:
        """{output reference: key image} for the outputs the wallet held when the file was made."""
        with open(path, "r", encoding="utf-8") as fh:
            data = json.load(fh)
        markers = data.get("key_images") or {}
        return markers if isinstance(markers, dict) else {}

    @staticmethod
    def load_view_key(path: str, prefix: str | None = None) -> ViewKey:
        with open(path, "r", encoding="utf-8") as fh:
            data = json.load(fh)
        if data.get("kind") != "view-key":
            raise WalletError("not a view-key file")
        return ViewKey.from_dict(data["view_key"], prefix or data.get("address_prefix", DEFAULT_PREFIX))
