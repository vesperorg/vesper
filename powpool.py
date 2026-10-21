"""
powpool.py - proof-of-work tries on several CPU cores at once.

Python threads cannot run Argon2id tries side by side (measured: twelve threads managed what
one did), so mining on more than one core needs separate processes.  The miner hands every
worker process the same block header and a share of the nonces (worker k tries start + k,
start + k + N, ...); the first worker to find a nonce that meets the target reports it, and the
miner checks it once more itself before believing it.

A worker is a plain loop with nothing in it but the hash: it never sees a wallet, a key or the
chain, so a crash in one costs nothing but its share of the tries.
"""

from __future__ import annotations

import multiprocessing as mp
import os
import queue
import secrets
import time

REPORT_EVERY = 8          # tries between progress reports (and between looks for new work)


def default_processes() -> int:
    """Half the cores, at most eight: fast, and the computer stays usable."""
    return max(1, min(8, (os.cpu_count() or 2) // 2))


def _worker(index: int, tasks, results) -> None:
    from powcore import disable_windows_power_throttling, pow_digest   # light on purpose: see powcore.py
    disable_windows_power_throttling()
    if hasattr(os, "nice"):
        os.nice(10)                              # mining yields to the node itself: on a one-core server the
                                                 # node must still answer peers while it mines
    results.cancel_join_thread()                 # never hang on exit over an unread progress report
    parent = mp.parent_process()
    job = None
    nonce = 0
    while True:
        if parent is not None and not parent.is_alive():
            return                               # the node is gone: never keep burning the CPU on our own
        while True:                              # take the newest work waiting; wait only when idle
            try:
                msg = tasks.get() if job is None else tasks.get_nowait()
            except queue.Empty:
                break
            if msg is None:
                return
            job = msg
            nonce = job["start"] + index
        tries = 0
        target = job["target"]
        for _ in range(REPORT_EVERY):
            header = job["head"] + str(nonce).encode() + job["tail"]
            if int.from_bytes(pow_digest(header, job["algorithm"], job["memory_kib"], job["passes"]), "big") < target:
                results.put(("found", job["id"], nonce))
                job = None                       # wait for the next block's work
                break
            nonce += job["stride"]
            tries += 1
        results.put(("tries", None, tries + (1 if job is None else 0)))


class PowPool:
    def __init__(self, processes: int, algorithm: str, memory_kib: int, passes: int):
        self.processes = max(1, int(processes))
        self.algorithm, self.memory_kib, self.passes = algorithm, memory_kib, passes
        ctx = mp.get_context("spawn")
        self.results = ctx.Queue()
        self.tasks = [ctx.Queue() for _ in range(self.processes)]
        self.workers = [ctx.Process(target=_worker, args=(i, self.tasks[i], self.results), daemon=True, name="vesper-pow-%d" % i)
                        for i in range(self.processes)]
        for w in self.workers:
            w.start()
        self.job_id = 0
        self.job_key = None
        self.tries = 0

    def step(self, head: bytes, tail: bytes, target: int, wait: float = 0.5) -> int | None:
        """Make sure every worker is on this header, then wait up to `wait` seconds for a find.
        Returns a nonce that a worker says meets the target, or None."""
        key = (head, tail, target)
        if key != self.job_key:
            self.job_key = key
            self.job_id += 1
            job = {"id": self.job_id, "head": head, "tail": tail, "target": target, "start": secrets.randbelow(1 << 40),
                   "stride": self.processes, "algorithm": self.algorithm, "memory_kib": self.memory_kib, "passes": self.passes}
            for q in self.tasks:
                q.put(job)
        try:
            kind, job_id, value = self.results.get(timeout=wait)
        except queue.Empty:
            if not any(w.is_alive() for w in self.workers):
                raise RuntimeError("the mining worker processes have stopped")
            return None
        while True:
            if kind == "tries":
                self.tries += value
            elif job_id == self.job_id:
                self.job_key = None              # this header is done: the next call posts new work
                return value
            try:
                kind, job_id, value = self.results.get_nowait()
            except queue.Empty:
                return None

    def take_tries(self) -> int:
        n, self.tries = self.tries, 0
        return n

    def close(self) -> None:
        for q in self.tasks:
            try:
                q.put(None)
            except Exception:
                pass
        deadline = time.time() + 5
        while time.time() < deadline and any(w.is_alive() for w in self.workers):
            try:                                 # keep reading, or a worker can block on a full pipe
                self.results.get(timeout=0.1)
            except queue.Empty:
                pass
        for w in self.workers:
            if w.is_alive():
                w.terminate()
            w.join(timeout=2)
