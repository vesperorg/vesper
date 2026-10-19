"""
testdrive.py - the test drive from the web page, run for you, start to finish.

    python testdrive.py            (a few minutes; leaves nothing behind)
    python testdrive.py --more     (then also: one address per payer, the recovery code, a payment proof)

It starts two throwaway nodes on this computer, Alice's (which mines) and Bob's, makes a wallet
for each, waits until the chain is old enough to hide a payment, and then runs every step of the
test drive with the real commands, printing their real output: a private payment, Bob finding it,
his accountant's view key, a search of the raw chain file for the address and the amount, what
the payment really contains, Bob paying back, and a full re-check.  Then it tries to break things
and shows each attempt being refused.

Nothing touches your own wallets or chain: everything lives in two folders named data_drive_*
that are deleted at the end (also if you press Ctrl+C).
"""

from __future__ import annotations

import json
import os
import shutil
import socket
import subprocess
import sys
import time
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
PY = sys.executable
sys.path.insert(0, HERE)
from chain import load_config  # noqa: E402

_CFG = load_config()
T = _CFG["coin"]["ticker"]                       # VESP, or tVESP on a test network
PFX = _CFG["coin"]["address_prefix"]
RING = int(_CFG["consensus"]["ring_size"])
ALICE_PW, BOB_PW = "drive-alice", "drive-bob"


def free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def get(url: str, timeout: float = 30):
    with urllib.request.urlopen(url, timeout=timeout) as r:
        return json.loads(r.read())


def post(url: str, payload) -> dict:
    req = urllib.request.Request(url, data=json.dumps(payload).encode(), method="POST",
                                 headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            return json.loads(r.read())
    except urllib.error.HTTPError as exc:
        return json.loads(exc.read())


class Drive:
    def __init__(self):
        tag = "%d" % os.getpid()
        self.dir_a = os.path.join(HERE, "data_drive_%s_alice" % tag)
        self.dir_b = os.path.join(HERE, "data_drive_%s_bob" % tag)
        self.port_a, self.port_b = free_port(), free_port()
        self.url_a, self.url_b = "http://127.0.0.1:%d" % self.port_a, "http://127.0.0.1:%d" % self.port_b
        self.procs: list = []
        self.logs: list = []
        self.checks: list = []

    # ---- plumbing ---------------------------------------------------------------
    def write_config(self) -> None:
        """The drive's own network: this coin's rules, but its own genesis block, an easy start
        and no peers, so the throwaway nodes never meet the real network and it never meets them."""
        config = {k: v for k, v in _CFG.items() if not k.startswith("_")}
        config["consensus"] = dict(config["consensus"], network="test-drive", initial_difficulty=1024,
                                   genesis_message="Vesper test drive - two throwaway nodes on one computer")
        config["network"] = dict(config["network"], peers=[])
        self.config_path = os.path.join(self.dir_a, "drive_config.json")
        with open(self.config_path, "w", encoding="utf-8") as fh:
            json.dump(config, fh, indent=2)

    def coin(self, *args, node: str, data: str, show: str | None = None) -> str:
        """Run a coin.py command, print it as a reader would type it, and its output."""
        cmd = [PY, os.path.join(HERE, "coin.py"), "--config", self.config_path, "--node", node, "--data-dir", data] + list(args)
        out = subprocess.run(cmd, cwd=HERE, capture_output=True, text=True, timeout=300)
        text = (out.stdout + out.stderr).rstrip()
        print("  > python coin.py %s" % (show or " ".join(args)))
        for line in text.splitlines():
            print("    " + line)
        return text

    def check(self, ok: bool, what: str) -> None:
        self.checks.append((ok, what))
        print("  [%s] %s" % ("ok" if ok else "FAILED", what))

    def start_node(self, port: int, folder: str, *extra) -> subprocess.Popen:
        log = open(os.path.join(folder, "drive_console.log"), "a", encoding="utf-8")
        self.logs.append(log)
        proc = subprocess.Popen([PY, os.path.join(HERE, "node.py"), "--config", self.config_path, "--port", str(port), "--data-dir", folder] + list(extra),
                                cwd=HERE, stdout=log, stderr=subprocess.STDOUT)
        self.procs.append(proc)
        url = "http://127.0.0.1:%d" % port
        for _ in range(120):
            try:
                get(url + "/api/info", timeout=2)
                return proc
            except Exception:
                time.sleep(0.5)
        raise RuntimeError("node on port %d did not start; see %s" % (port, log.name))

    def wait(self, what: str, test, seconds: int = 900) -> None:
        """Until test() is true.  A node busy mining on every core can be slow to answer; that
        is not an answer, so the question is simply asked again."""
        start = time.time()
        while True:
            try:
                if test():
                    return
            except OSError:
                pass
            if time.time() - start > seconds:
                raise RuntimeError("gave up waiting: " + what)
            time.sleep(2)

    def info(self, url: str) -> dict:
        for attempt in range(5):
            try:
                return get(url + "/api/info")
            except OSError:
                if attempt == 4:
                    raise
                time.sleep(3)

    def address(self, folder: str) -> str:
        with open(os.path.join(folder, "wallets", "default.json"), encoding="utf-8") as fh:
            return json.load(fh)["address"]

    def mined(self, url: str, txid: str) -> bool:
        try:
            return get(url + "/api/tx/" + txid).get("block") is not None
        except Exception:
            return False

    # ---- the drive ---------------------------------------------------------------
    def run(self, more: bool = False) -> int:
        from wallet import Wallet
        os.makedirs(self.dir_a), os.makedirs(self.dir_b)
        self.write_config()
        Wallet.generate(PFX).save(os.path.join(self.dir_a, "wallets", "default.json"), ALICE_PW)
        Wallet.generate(PFX).save(os.path.join(self.dir_b, "wallets", "default.json"), BOB_PW)
        alice, bob = self.address(self.dir_a), self.address(self.dir_b)
        A = dict(node=self.url_a, data=self.dir_a)
        B = dict(node=self.url_b, data=self.dir_b)

        print("Vesper test drive: two nodes on this computer, Alice's mines, Bob's listens.")
        print("  Alice's node %s, Bob's node %s, both in throwaway folders.\n" % (self.url_a, self.url_b))
        self.start_node(self.port_a, self.dir_a, "--mine")
        self.start_node(self.port_b, self.dir_b, "--peer", self.url_a)
        print("Mining until %d coins are 10 blocks old - a ring needs that many to hide in." % RING)
        started = time.time()
        self.wait("%d old-enough coins" % RING, lambda: self.info(self.url_a)["spendable_outputs"] >= RING, 3600)
        print("  ready after %.0f seconds, at block %d\n" % (time.time() - started, self.info(self.url_a)["height"]))

        print("STEP 1  Alice has coins")
        self.coin("info", **A)
        print("\nSTEP 2  Alice pays Bob 12.5 %s" % T)
        out = self.coin("send", bob, "12.5", "--password", ALICE_PW, show="send vespBOB... 12.5", **A)
        txid = next((l.split()[1] for l in out.splitlines() if l.startswith("txid ")), "")
        self.check(bool(txid), "the payment was accepted")
        self.wait("the payment to be mined", lambda: self.mined(self.url_b, txid))
        print("\nSTEP 3  Bob finds it, on his own node")
        out = self.coin("wallet", "show", "--password", BOB_PW, **B)
        self.check("Balance : 12.5 %s" % T in out, "Bob's wallet found exactly 12.5 %s" % T)
        print("\nSTEP 4  Bob's accountant, with a view key only")
        self.coin("wallet", "export-view", "--password", BOB_PW, **B)
        out = self.coin("watch", os.path.join(self.dir_b, "wallets", "default.viewkey.json"), show="watch <Bob's view-key file>", **B)
        self.check("12.5 %s" % T in out, "the view key sees the payment and its amount")
        print("\nSTEP 5  A stranger searches Bob's raw chain file for both addresses and the amount")
        with open(os.path.join(self.dir_b, "chain.jsonl"), encoding="utf-8") as fh:
            raw = fh.read()
        for needle, label in ((alice[4:34], "30 characters of Alice's address"), (bob[4:34], "30 characters of Bob's address"),
                              ("1250000000", "12.5 %s in base units" % T), ("12.5", "12.5")):
            print("    %-36s found %d time(s)" % (label, raw.count(needle)))
        self.check(all(raw.count(n) == 0 for n in (alice[4:34], bob[4:34], "1250000000", "12.5")), "none of them is anywhere in the chain")
        print("\nSTEP 6  What the payment really contains")
        out = self.coin("tx", txid, show="tx " + txid[:16] + "...", **A)
        self.check("ring of %d" % RING in out and "sealed amount" in out, "%d candidate inputs, sealed amounts, no address" % RING)
        print("\nSTEP 7  Bob pays 3 back - once his coin is 10 blocks old")
        height = get(self.url_b + "/api/tx/" + txid)["block"]
        self.wait("Bob's coin to be 10 blocks old", lambda: self.info(self.url_b)["height"] >= height + 9)
        out = self.coin("send", alice, "3", "--password", BOB_PW, show="send vespALICE... 3", **B)
        txid2 = next((l.split()[1] for l in out.splitlines() if l.startswith("txid ")), "")
        self.check("passed it quietly to ONE peer" in out, "Bob's node passed it quietly to one peer instead of broadcasting it")
        self.wait("Bob's payment to be mined", lambda: self.mined(self.url_a, txid2))
        print("\nSTEP 8  Balances afterwards")
        out = self.coin("wallet", "show", "--password", BOB_PW, **B)
        self.check("Balance : 9.49999 %s" % T in out, "Bob holds 9.49999 %s: 12.5 - 3 - the fee" % T)
        print("\nSTEP 9  Bob's node re-checks everything from its own disk")
        out = self.coin("validate", **B)
        self.check("Chain OK" in out, "every block, signature, proof and sum re-verified")

        print("\nNOW TRY TO BREAK IT")
        out = self.coin("send", alice, "50", "--password", BOB_PW, show="send vespALICE... 50   (Bob holds 9.49999)", **B)
        self.check("insufficient funds" in out, "spending more than you have is refused")
        tx = get(self.url_a + "/api/tx/" + txid)["tx"]
        answer = post(self.url_a + "/api/tx", tx)
        print("  > post the confirmed payment again\n    %s" % answer)
        self.check("already in the chain" in str(answer.get("error")), "replaying a payment is refused")
        bad = alice[:40] + ("X" if alice[40] != "X" else "Y") + alice[41:]
        out = self.coin("send", bad, "1", "--password", BOB_PW, show="send vesp...(one character changed)... 1", **B)
        self.check("not a valid %s address" % T in out, "a mistyped address is caught by its checksum")
        spare = os.path.join(self.dir_b, "wallets", "spare.json")
        shutil.copy(os.path.join(self.dir_b, "wallets", "default.viewkey.json"), spare)
        out = self.coin("send", alice, "1", "--name", "spare", show="send ... --name spare   (a view-key file)", **B)
        self.check("can watch, not spend" in out, "a view-key file cannot spend")

        print("\nREWRITE HISTORY: stop Bob's node, change one character of a signature in his chain file")
        proc_b = self.procs[1]
        proc_b.terminate()
        proc_b.wait(timeout=30)
        path = os.path.join(self.dir_b, "chain.jsonl")
        with open(path, "rb") as fh:
            lines = fh.read().split(b"\n")
        for i, line in enumerate(lines):
            if line.strip() and len(json.loads(line)["transactions"]) > 1:
                block = json.loads(line)
                s = block["transactions"][1]["inputs"][0]["signature"]["s"]
                s[3] = s[3][:10] + ("0" if s[3][10] != "0" else "1") + s[3][11:]
                lines[i] = json.dumps(block, separators=(",", ":")).encode()
                damaged_height = block["index"]
                break
        with open(path, "wb") as fh:
            fh.write(b"\n".join(lines))
        out = self.coin("validate", **B)
        self.check("block %d" % damaged_height in out and "INVALID" in out, "the re-check names the damaged block")
        self.start_node(self.port_b, self.dir_b, "--peer", self.url_a)
        self.wait("Bob's node to catch up again", lambda: self.info(self.url_b)["height"] >= self.info(self.url_a)["height"] - 1, 120)
        with open(os.path.join(self.dir_b, "node.log"), encoding="utf-8") as fh:
            log = fh.read()
        self.check("was damaged" in log and any(n.startswith("chain.jsonl.damaged-") for n in os.listdir(self.dir_b)),
                   "his node kept the good blocks, set the damaged file aside and fetched the rest from Alice's")

        good = sum(1 for ok, _ in self.checks if ok)
        print("\n%d of %d checks behaved as the test drive page says." % (good, len(self.checks)))
        core_ok = good == len(self.checks)
        if more:
            core_ok = self.more() and core_ok
        return 0 if core_ok else 1

    def more(self) -> bool:
        """--more: what came after the page was written - one address per payer, the recovery
        code, and proving a payment to one person."""
        A = dict(node=self.url_a, data=self.dir_a)
        B = dict(node=self.url_b, data=self.dir_b)
        first = len(self.checks)
        print("\nMORE 1  Bob gives Carol an address of her own; Alice pays it")
        out = self.coin("wallet", "new-address", "--label", "carol", "--password", BOB_PW, **B)
        for_carol = next(line.strip() for line in out.splitlines() if line.strip().startswith(PFX))
        out = self.coin("send", for_carol, "2", "--password", ALICE_PW, show="send vespCAROL... 2", **A)
        txid = next((l.split()[1] for l in out.splitlines() if l.startswith("txid ")), "")
        self.wait("the payment to Carol's address to be mined", lambda: self.mined(self.url_b, txid))
        out = self.coin("wallet", "show", "--password", BOB_PW, **B)
        self.check("to address #1" in out and "Balance : 11.49999 %s" % T in out,
                   "it lands in Bob's wallet, marked as address #1; nothing on the chain ties #1 to his first address")
        print("\nMORE 2  Bob's recovery code rebuilds his wallet")
        out = self.coin("wallet", "recovery-code", "--password", BOB_PW, **B)
        code = out.splitlines()[-1].strip()
        self.coin("wallet", "restore", "--name", "copy", "--code", code, "--password", "copy-pw",
                  show="wallet restore --name copy --code <the code>", **B)
        out = self.coin("wallet", "show", "--name", "copy", "--password", "copy-pw", **B)
        self.check("Balance : 11.49999 %s" % T in out, "the copy holds the same coins, address #1 included, from the code alone")
        print("\nMORE 3  Alice proves her payment to Carol's address, to Bob only")
        proof_file = os.path.join(self.dir_a, "proof.json")
        self.coin("proof", "pay", txid, "--password", ALICE_PW, "--out", proof_file, show="proof pay %s..." % txid[:16], **A)
        out = self.coin("proof", "check", proof_file, show="proof check proof.json", **B)
        self.check("The proof holds" in out and "2 %s" % T in out and for_carol in out,
                   "Bob's node confirms that output paid Carol's address 2 %s; nobody else learns anything" % T)
        extra = self.checks[first:]
        good = sum(1 for ok, _ in extra if ok)
        print("\n%d of %d extra checks passed.  (Not shown: --proxy through Tor, which needs Tor running.)" % (good, len(extra)))
        return good == len(extra)

    def cleanup(self) -> None:
        for proc in self.procs:
            if proc.poll() is None:
                proc.terminate()
                try:
                    proc.wait(timeout=20)
                except subprocess.TimeoutExpired:
                    proc.kill()
        for log in self.logs:
            log.close()
        time.sleep(1)
        for folder in (self.dir_a, self.dir_b):
            shutil.rmtree(folder, ignore_errors=True)


def main() -> int:
    drive = Drive()
    try:
        return drive.run(more="--more" in sys.argv[1:])
    except KeyboardInterrupt:
        print("\nstopped")
        return 1
    finally:
        drive.cleanup()
        print("Throwaway nodes stopped and their folders deleted.")


if __name__ == "__main__":
    sys.exit(main())
