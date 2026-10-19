"""
powcore.py - the proof-of-work function and nothing else.

It lives on its own so that mining worker processes (powpool.py) import only this - not the
ledger, the wallets or the cryptography - and start in a fraction of a second.  chain.py uses
the same function, so a worker and a node can never disagree about what a valid block is.
"""

from __future__ import annotations

import hashlib
import sys

try:
    from nacl import pwhash as _pwhash
except ImportError:                                  # the coin still runs; memory-hard mining does not
    _pwhash = None

POW_ALGORITHMS = ("argon2id", "sha256d")


class PowError(ValueError):
    pass


def pow_digest(header_bytes: bytes, algorithm: str, memory_kib: int = 0, passes: int = 1) -> bytes:
    """The number a miner has to get below the target.

    sha256d is Bitcoin's function.  It is here for tests and for comparison only: machines
    built for Bitcoin compute it about a hundred million times faster than a laptop, so a small
    coin using it can be overrun by anyone who rents a sliver of that hardware.

    argon2id is memory-hard: every single try has to fill and walk `memory_kib` of RAM.  That
    cannot be done by a Bitcoin machine at all, and on purpose it is slow everywhere - a laptop
    core manages about a hundred tries a second at 32 MiB - so ordinary computers are back in
    the game.  The price is that checking a block costs one of those tries (about 10 ms).
    Graphics cards still have an edge over CPUs here; a production coin would likely use
    RandomX, which is built to close that gap too."""
    if algorithm == "sha256d":
        return hashlib.sha256(hashlib.sha256(header_bytes).digest()).digest()
    if algorithm == "argon2id":
        if _pwhash is None:
            raise PowError("this chain's proof of work (argon2id) needs the pynacl package:  pip install pynacl")
        salt = hashlib.sha256(b"vesper/pow" + header_bytes).digest()[:16]
        return _pwhash.argon2id.kdf(32, header_bytes, salt, opslimit=passes, memlimit=memory_kib * 1024)
    raise PowError("unknown proof-of-work algorithm %r" % algorithm)


def disable_windows_power_throttling() -> bool:
    """Windows 11 moves long-running background processes onto efficiency cores at their lowest
    clock; on this laptop that cut mining, proving and the self-test's timings six- to eightfold.
    A process may opt out.  Anything that computes for more than a second should call this first."""
    if sys.platform != "win32":
        return False
    try:
        import ctypes
        import ctypes.wintypes as wt

        class PowerThrottlingState(ctypes.Structure):
            _fields_ = [("Version", wt.ULONG), ("ControlMask", wt.ULONG), ("StateMask", wt.ULONG)]

        kernel32 = ctypes.windll.kernel32
        kernel32.GetCurrentProcess.restype = ctypes.c_void_p
        kernel32.SetProcessInformation.argtypes = [ctypes.c_void_p, ctypes.c_int, ctypes.c_void_p, wt.DWORD]
        kernel32.SetProcessInformation.restype = wt.BOOL
        state = PowerThrottlingState(1, 0x1, 0)
        return bool(kernel32.SetProcessInformation(kernel32.GetCurrentProcess(), 4, ctypes.byref(state), ctypes.sizeof(state)))
    except Exception:
        return False
