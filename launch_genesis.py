"""
launch_genesis.py - give a new network its genesis block, the moment it is launched.

    python launch_genesis.py testnet-1        (writes config.json; run once, just before launch)

A genesis block anyone could have made a week earlier would let its maker mine in secret and
start the public network with a head start.  So the genesis message names the newest Bitcoin
block at launch time: nobody can know that block's ID before it exists, so nobody can have
mined on this chain before it.  The genesis timestamp is the launch moment itself.

The Bitcoin block is fetched from two independent explorers, and they must agree.  Every
consensus setting - the network's name, the ring size, the rules - is hashed into the genesis
block too, so changing any of them later is a different coin, never a quiet change.

Nothing else is touched: wallets are not, and a chain saved under the old genesis is simply no
longer this network's (start fresh with `python coin.py reset-chain`).
"""

from __future__ import annotations

import json
import os
import re
import sys
import time
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
SOURCES = [
    ("mempool.space", "https://mempool.space/api/blocks/tip/height", "https://mempool.space/api/block-height/%d"),
    ("blockstream.info", "https://blockstream.info/api/blocks/tip/height", "https://blockstream.info/api/block-height/%d"),
]


def fetch(url: str) -> str:
    req = urllib.request.Request(url, headers={"User-Agent": "vesper-launch"})
    with urllib.request.urlopen(req, timeout=20) as resp:
        return resp.read(200).decode("ascii").strip()


def newest_bitcoin_block() -> tuple[int, str]:
    """(height, block ID) of a recent Bitcoin block both explorers agree on: one below the
    newest both have seen (minutes old, so the proof holds, and every explorer has indexed it)."""
    for attempt in range(5):
        try:
            tips = [int(fetch(tip)) for _, tip, _ in SOURCES]
            height = min(tips) - 1
            ids = [fetch(by_height % height) for _, _, by_height in SOURCES]
        except OSError:
            time.sleep(10)
            continue
        if all(re.fullmatch(r"[0-9a-f]{64}", i) for i in ids) and len(set(ids)) == 1:
            return height, ids[0]
        time.sleep(10)
    raise SystemExit("the explorers did not agree on a recent Bitcoin block; try again in a few minutes")


def main() -> int:
    if len(sys.argv) != 2 or not re.fullmatch(r"[a-z0-9-]{3,30}", sys.argv[1]):
        print(__doc__)
        return 2
    network = sys.argv[1]
    path = os.path.join(HERE, "config.json")
    with open(path, "r", encoding="utf-8") as fh:
        config = json.load(fh)
    sys.path.insert(0, HERE)
    from chain import Blockchain, deep_merge, load_config
    old_genesis = Blockchain(load_config(path)).blocks[0]["hash"]
    old = re.search(r"Bitcoin block (\d+) ([0-9a-f]{64})", str(config["consensus"].get("genesis_message", "")))
    height, block_id = newest_bitcoin_block()
    now = int(time.time())
    overlay = os.path.join(HERE, "deploy", network + ".json")     # what this network changes, kept until launch day
    if os.path.exists(overlay):
        with open(overlay, "r", encoding="utf-8") as fh:
            config = deep_merge(config, json.load(fh))
    rules = config["consensus"]
    rules["network"] = network
    rules["genesis_timestamp"] = now
    rules["genesis_message"] = ("Vesper %s - %s - begun after Bitcoin block %d %s"
                                % (network, "test coins, no value" if "test" in network else "private by default",
                                   height, block_id))
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8", newline="\n") as fh:
        json.dump(config, fh, indent=2)
        fh.write("\n")
    os.replace(tmp, path)
    genesis = Blockchain(load_config(path)).blocks[0]
    readme = os.path.join(HERE, "README.md")
    with open(readme, "r", encoding="utf-8") as fh:
        text = fh.read()
    before = text
    if old:
        text = text.replace(old.group(2), block_id).replace("{:,}".format(int(old.group(1))), "{:,}".format(height))
    text = text.replace(old_genesis, genesis["hash"])
    # also by its label, in case other consensus settings changed first (then old_genesis is not
    # the one README shows)
    text = re.sub(r"(first block's own ID is\s+`)[0-9a-f]{64}(`)", lambda m: m.group(1) + genesis["hash"] + m.group(2), text)
    if text != before:
        try:
            with open(readme, "w", encoding="utf-8", newline="\n") as fh:
                fh.write(text)
            print("README.md      : updated to the new Bitcoin block and genesis block ID")
        except PermissionError:
            print("README.md      : LOCKED by another program (close it): update its block number, hash and genesis ID by hand")
    else:
        print("README.md      : did not mention the old genesis; check its test-network paragraph by hand")
    print("Network        : %s" % network)
    print("Bitcoin block  : %d  %s  (both explorers agree)" % (height, block_id))
    print("Genesis time   : %s UTC" % time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime(now)))
    print("Genesis message: %s" % rules["genesis_message"])
    print("Genesis block  : %s" % genesis["hash"])
    print("Written to config.json. Publish this genesis block ID with the launch, so anyone can check it,")
    print("and note the re-made genesis in DECISIONS.md (its launch line records the first one).")
    return 0


if __name__ == "__main__":
    sys.exit(main())
