"""
selftest.py - proves Vesper's rules AND its privacy claims hold.  No real network: the phase 4
checks connect nodes to each other inside this one program.

    python selftest.py

Every check either tries to cheat and expects to be refused, or looks at what is written on the
chain and expects NOT to find something (an address, an amount, a spent output, a time).
"""

from __future__ import annotations

import copy
import hashlib
import json
import logging
import os
import shutil
import sys
import tempfile
import time
import traceback

import chain as chain_module
import curve
import privacy
import rangeproof
import ringsig
from amounts import commit, decrypt_amount, encrypt_amount, value_generator
from chain import (RING_INPUT_KEYS, BlockStore, Blockchain, ChainError, LocalRings, StateView, build_transfer, compute_block_hash,
                   compute_txid, deep_merge, difficulty_target, disable_windows_power_throttling, fee_weight, format_units, input_order_key, load_config,
                   make_coinbase_tx, merkle_root, pow_digest, step_difficulty, to_units, tx_signing_bytes)
from curve import G, L, Point, PyPoint, hash_bytes, hash_to_scalar, random_scalar, scalar_from_hex, scalar_to_hex, sign
from privacy import StealthKeys, decode_address, is_valid_address, make_outputs, scan_outputs, verify_auditable_output
from wallet import Wallet, WalletError, WalletLocked, sync_outputs

RING = 4          # small rings keep the tests quick; the speed report uses the real size
CONFIG = deep_merge(load_config(), {"consensus": {
    "initial_difficulty": 64, "min_difficulty": 1, "difficulty_halflife_seconds": 0,     # fixed, tiny difficulty
    "output_lock_blocks": 0,                                                          # most tests spend at once
    "ring_size": RING, "pow": {"memory_kib": 8}, "dev_fund": {"address": ""},
    "emission": None},                                                                # the tests' own 50 a block, halving
    "pool": {"enabled": False},                                                       # pool checks turn it on themselves
    "network": {"peers": []}})                                                        # never the real seed nodes
REAL = load_config()["consensus"]
PREFIX = CONFIG["coin"]["address_prefix"]
DECIMALS = int(CONFIG["coin"]["decimals"])


def coins(text) -> int:
    return to_units(text, DECIMALS)


def new_chain(data_dir=None, config=None) -> Blockchain:
    return Blockchain(config or CONFIG, data_dir)


def mine(chain: Blockchain, wallet: Wallet, count: int = 1):
    last = None
    for _ in range(count):
        last = None
        while last is None:
            last = chain.mine_block(wallet.address)
    return last


def ref_of(u: dict) -> str:
    return "%s:%d" % (u["txid"], u["index"])


def owned(chain: Blockchain, wallet: Wallet) -> list:
    """The wallet's unspent outputs, found the way a real wallet finds them."""
    return wallet.unspent(chain.all_outputs(), chain.state.key_images, chain.state.fund_spent)


def balance(chain: Blockchain, wallet: Wallet) -> int:
    return sum(u["amount"] for u in owned(chain, wallet))


def spendable(chain: Blockchain, wallet: Wallet) -> list:
    """... of those, the ones old enough to go into the next block."""
    return [u for u in owned(chain, wallet) if u["output"]["height"] + chain.output_lock <= chain.height + 1]


def rings_of(chain: Blockchain) -> LocalRings:
    return LocalRings(chain.all_outputs(), chain.height + 1, chain.output_lock)


def transfer(chain: Blockchain, sender: Wallet, payments: list, fee: int | None = None, inputs: list | None = None,
             known_rings: dict | None = None) -> dict:
    return build_transfer(sender.keys, spendable(chain, sender) if inputs is None else inputs, payments, fee, PREFIX,
                          rings_of(chain), chain.ring_size, min_fee=chain.min_fee_units, known_rings=known_rings)


def pay(chain: Blockchain, sender: Wallet, to: str, amount: int, fee: int | None = None) -> dict:
    tx = transfer(chain, sender, [(to, amount)], fee)
    chain.add_to_mempool(tx)
    return tx


def expect_error(fn, *words):
    try:
        fn()
    except (ChainError, ValueError) as exc:
        text = str(exc).lower()
        for word in words:
            assert word.lower() in text, "error was %r, expected it to mention %r" % (str(exc), word)
        return exc
    raise AssertionError("expected an error but nothing was raised")


def solve(chain: Blockchain, block: dict) -> dict:
    """Do the proof of work for a hand-built block, under that chain's rules."""
    block["nonce"] = 0
    while not chain.proof_of_work_ok(block):
        block["nonce"] += 1
    block["hash"] = compute_block_hash(block)
    return block


def block_with(chain: Blockchain, miner: Wallet, txs: list, coinbase: dict | None = None) -> dict:
    """A correctly mined block containing exactly `txs` (which never went through the mempool)."""
    height = len(chain.blocks)
    ts = max(int(time.time()), chain.median_time_past(chain.blocks, height) + 1)
    if coinbase is None:
        coinbase = make_coinbase_tx(miner.address, chain.reward_at(height) + sum(t["fee"] for t in txs), height,
                                    PREFIX, chain.dev_fund_address, chain.dev_fund_at(height))
    all_txs = [coinbase] + txs
    return solve(chain, {"index": height, "timestamp": ts, "previous_hash": chain.tip["hash"],
                         "merkle_root": merkle_root([t["txid"] for t in all_txs]),
                         "difficulty": chain.expected_difficulty(height, chain.blocks), "nonce": 0,
                         "transactions": all_txs, "hash": ""})


def retxid(tx: dict) -> dict:
    tx["txid"] = compute_txid(tx)
    return tx


def forge(chain: Blockchain, wallet: Wallet, inputs: list, payments: list, fee: int, tweak=None,
          pseudo_bonus: int = 0, secret_key=None, image_hex=None) -> dict:
    """What a cheating wallet would send: built like a real payment, but nothing checks the
    totals, and the caller can bend individual pieces."""
    outputs, openings = make_outputs(payments, PREFIX, hidden=True)
    if tweak:
        tweak(outputs, openings)
    proof = rangeproof.prove_many([amount for amount, _ in openings], [blinding for _, blinding in openings])
    by_ref = {ref_of(u): u["output"] for u in chain.all_outputs()}
    crowd = [ref for ref, out in by_ref.items() if "ephemeral_secret" not in out]
    tx_inputs, plans, blinding_in = [], [], 0
    for u in inputs:
        ref = ref_of(u)
        x = secret_key if secret_key is not None else wallet.keys.owns(u["output"])
        ring = ringsig.pick_ring(crowd, ref, chain.ring_size)
        pseudo_blinding = random_scalar()
        tx_inputs.append({"ring": ring, "key_image": image_hex or ringsig.key_image(x, ref, u["output"]["one_time_pub"]).hex(),
                          "pseudo_commitment": commit(u["amount"] + pseudo_bonus, pseudo_blinding).hex(), "signature": None})
        plans.append((x, ring.index(ref), (u["blinding"] - pseudo_blinding) % L))
        blinding_in += pseudo_blinding
    order = sorted(range(len(tx_inputs)), key=lambda i: input_order_key(tx_inputs[i]))
    tx_inputs, plans = [tx_inputs[i] for i in order], [plans[i] for i in order]
    tx = {"type": "transfer", "inputs": tx_inputs, "outputs": outputs, "fee": fee, "height": 0, "excess_sig": None,
          "range_proof": proof}
    message = tx_signing_bytes(tx)
    tx["excess_sig"] = sign((blinding_in - sum(b for _, b in openings)) % L, message)
    for inp, (x, position, z) in zip(tx["inputs"], plans):
        members = [by_ref[r] for r in inp["ring"]]
        inp["signature"] = ringsig.sign(message, inp["ring"], [Point.from_hex_unchecked(m["one_time_pub"]) for m in members],
                                        [Point.from_hex_unchecked(m["commitment"]) for m in members],
                                        Point.from_hex(inp["pseudo_commitment"]), position, x, z)
    return retxid(tx)


def tampered(tx: dict, change, fix_txid: bool = True) -> dict:
    copy_ = copy.deepcopy(tx)
    change(copy_)
    return retxid(copy_) if fix_txid else copy_


# ----------------------------------------------------------------------------- the maths
def test_both_curve_backends_agree_and_bad_points_are_refused():
    py_g = PyPoint(curve._GX, curve._GY)
    assert py_g.encode().hex() == "58" + "66" * 31, "base point must match the Ed25519 standard"
    assert py_g._mul_raw(L).is_identity() and not py_g._mul_raw(L - 1).is_identity(), "group order"
    k1, k2 = random_scalar(), random_scalar()
    py_h = PyPoint._decompress(value_generator().encode())
    assert (py_g * k1).encode() == (G * k1).encode()
    assert (py_h * k1).encode() == (value_generator() * k1).encode()
    assert ((py_g * k1) + (py_h * k2)).encode() == (G * k1 + value_generator() * k2).encode()
    assert ((py_g * k1) - (py_h * k2)).encode() == (G * k1 - value_generator() * k2).encode()
    assert curve._py_multiexp([(k1, py_g), (k2, py_h)]).encode() == curve.multiexp([(k1, G), (k2, value_generator())]).encode()
    for i in range(120):                              # the fast hash-to-point must equal the readable one
        digest = hash_bytes("probe", i)[:32]
        slow, fast = curve._py_lift_times_8(digest), curve._lift_times_8(digest)
        assert (slow is None) == (fast is None) and (slow is None or slow.encode() == fast.encode()), i
    bad = ["01" + "00" * 31,                    # the identity
           "ec" + "ff" * 30 + "7f",             # order 2
           "00" * 32,                           # order 4
           "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05",  # order 8
           "ed" + "ff" * 30 + "7f",             # non-canonical
           "02" + "00" * 31]                    # not on the curve
    torsion = PyPoint._decompress(bytes.fromhex(bad[3]))
    bad.append(((py_g * 7) + torsion).hex())    # looks fine, but hides a small-order component
    for text in bad:
        for cls in (PyPoint, Point):
            try:
                cls.from_hex(text)
                raise AssertionError("%s accepted bad point %s" % (cls.__name__, text[:16]))
            except ValueError:
                pass


def test_commitments_hide_bind_and_add_up():
    b1, b2 = random_scalar(), random_scalar()
    assert commit(5, b1) != commit(5, b2), "same amount must look different every time"
    assert commit(5, b1) != commit(6, b1)
    assert commit(5, b1) + commit(7, b2) == commit(12, b1 + b2), "envelopes must add up unopened"
    assert (commit(50, b1) - commit(20, b2) - commit(30, 0)) == G * (b1 - b2), "balanced amounts leave only a public key"
    shared = G * random_scalar()
    sealed = encrypt_amount(123456789, shared, 3)
    assert decrypt_amount(sealed, shared, 3) == 123456789
    assert decrypt_amount(sealed, shared, 4) != 123456789 and decrypt_amount(sealed, G * random_scalar(), 3) != 123456789


def test_range_proofs_accept_honest_and_refuse_forged():
    proofs = []
    for amount in (0, 1, 2 ** 64 - 1, coins("12.5")):
        blinding = random_scalar()
        proofs.append((commit(amount, blinding), rangeproof.prove(amount, blinding)))
        assert rangeproof.verify(*proofs[-1])
    assert rangeproof.verify_batch(proofs)
    assert rangeproof.proof_size_bytes(proofs[0][1]) == 672
    V, proof = proofs[3]
    for key in ("A", "S", "T1", "T2"):
        bad = dict(proof); bad[key] = (Point.from_hex(proof[key]) + G).hex()
        assert not rangeproof.verify(V, bad), key
    for key in ("taux", "mu", "t", "a", "b"):
        bad = dict(proof); bad[key] = scalar_to_hex(int.from_bytes(bytes.fromhex(proof[key]), "little") + 1)
        assert not rangeproof.verify(V, bad), key
    for key in ("L", "R"):
        bad = copy.deepcopy(proof); bad[key][2] = (Point.from_hex(proof[key][2]) + G).hex()
        assert not rangeproof.verify(V, bad), key
    assert not rangeproof.verify(V + value_generator(), proof), "proof reused for amount + 1"
    assert not rangeproof.verify(proofs[0][0], proofs[1][1]), "proof reused for another envelope"
    bad = dict(proof); bad["a"] = "ff" * 32
    assert not rangeproof.verify(V, bad), "non-reduced number accepted"
    assert not rangeproof.verify(V, {}) and not rangeproof.verify(V, None)
    for amount in (-1, 2 ** 64, L - 5, 1.5):
        try:
            rangeproof.prove(amount, 1)
            raise AssertionError("made a range proof for %r" % (amount,))
        except ValueError:
            pass
    negative = commit(L - 5, random_scalar())          # an envelope holding "minus five"
    assert not rangeproof.verify(negative, proof)
    assert not rangeproof.verify_batch(proofs[:2] + [(negative, proof)] + proofs[2:]), "one bad proof hid inside a batch"

    # one proof for several amounts: each doubling of the count costs one fold, 64 bytes
    amounts = [coins("12.5"), 0, 2 ** 64 - 1, 7, 1, coins("3")]
    blinds = [random_scalar() for _ in amounts]
    Vs = [commit(a, b) for a, b in zip(amounts, blinds)]
    for m, size in ((2, 736), (3, 800), (6, 864)):
        joint = rangeproof.prove_many(amounts[:m], blinds[:m])
        assert rangeproof.verify(Vs[:m], joint) and rangeproof.proof_size_bytes(joint) == size, m
    joint = rangeproof.prove_many(amounts[:3], blinds[:3])
    pair = rangeproof.prove_many(amounts[:2], blinds[:2])
    assert rangeproof.verify_batch([(Vs[:2], pair), (Vs[:3], joint), proofs[0]]), "proofs of different widths in one batch"
    assert not rangeproof.verify_batch([(Vs[:2], pair), (Vs[:3], pair)]), "a proof used for the wrong count"
    assert not rangeproof.verify([Vs[1], Vs[0], Vs[2]], joint), "the commitments must come in the order proven"
    assert not rangeproof.verify(Vs[:2], joint), "a commitment left out"
    assert not rangeproof.verify(Vs[:3] + [commit(0, 0)], joint), "a zero commitment added"
    assert not rangeproof.verify([Vs[0], negative, Vs[2]], joint), "one envelope swapped for minus five"
    for key in ("A", "T2"):
        bad = dict(joint); bad[key] = (Point.from_hex(joint[key]) + G).hex()
        assert not rangeproof.verify(Vs[:3], bad), key
    for key in ("taux", "t", "b"):
        bad = dict(joint); bad[key] = scalar_to_hex(int.from_bytes(bytes.fromhex(joint[key]), "little") + 1)
        assert not rangeproof.verify(Vs[:3], bad), key
    bad = copy.deepcopy(joint); bad["L"].pop(); bad["R"].pop()
    assert not rangeproof.verify(Vs[:3], bad), "one fold short"
    for wrong in ([], [Vs[0]] * 17):
        assert not rangeproof.verify(wrong, joint), len(wrong)
    try:
        rangeproof.prove_many([1, -1], [1, 2])
        raise AssertionError("made a joint proof with a negative amount in it")
    except ValueError:
        pass


def test_ring_signatures_accept_owners_and_refuse_everyone_else():
    n = 8
    refs = ["%064x:%d" % (1000 + i, i % 2) for i in range(n)]
    xs = [random_scalar() for _ in range(n)]
    keys = [G * x for x in xs]
    amounts = [1000 + i for i in range(n)]
    blinds = [random_scalar() for _ in range(n)]
    commits = [commit(a, b) for a, b in zip(amounts, blinds)]
    msg = b"pay bob"
    for real in (0, 3, n - 1):                         # the signer can stand anywhere in the ring
        pb = random_scalar()
        pseudo = commit(amounts[real], pb)
        sig = ringsig.sign(msg, refs, keys, commits, pseudo, real, xs[real], (blinds[real] - pb) % L)
        image = ringsig.key_image(xs[real], refs[real], keys[real].hex())
        assert ringsig.verify(msg, refs, keys, commits, pseudo, image, sig), real
    assert image == ringsig.key_image(xs[real], refs[real], keys[real].hex()), "an output must always give the same key image"
    assert image != ringsig.key_image(xs[0], refs[0], keys[0].hex()) and image.hex() not in [k.hex() for k in keys]
    assert image != ringsig.key_image(xs[real], refs[0], keys[real].hex()), "the same key somewhere else is a different output"
    assert not ringsig.verify(b"pay eve", refs, keys, commits, pseudo, image, sig), "message swapped"
    assert not ringsig.verify(msg, refs, keys, commits, pseudo, ringsig.key_image(xs[0], refs[0], keys[0].hex()), sig), "another output's key image"
    assert not ringsig.verify(msg, refs, keys, commits, commit(amounts[real] + 1, pb), image, sig), "pseudo output worth one more"
    assert not ringsig.verify(msg, refs[::-1], keys[::-1], commits[::-1], pseudo, image, sig), "ring reordered"
    assert not ringsig.verify(msg, refs[1:] + refs[:1], keys, commits, pseudo, image, sig), "positions shuffled under the keys"
    swapped = list(keys); swapped[2] = G * random_scalar()
    assert not ringsig.verify(msg, refs, swapped, commits, pseudo, image, sig), "a decoy swapped"
    for field, j in (("s", 0), ("s", real), ("c", None)):
        bad = copy.deepcopy(sig)
        if j is None:
            bad["c"] = scalar_to_hex(int.from_bytes(bytes.fromhex(sig["c"]), "little") + 1)
        else:
            bad["s"][j] = scalar_to_hex(int.from_bytes(bytes.fromhex(sig["s"][j]), "little") + 1)
        assert not ringsig.verify(msg, refs, keys, commits, pseudo, image, bad), (field, j)
    bad = dict(sig); bad["D"] = "01" + "00" * 31
    assert not ringsig.verify(msg, refs, keys, commits, pseudo, image, bad), "identity accepted"
    assert not ringsig.verify(msg, refs, keys, commits, pseudo, image, {}) and not ringsig.verify(msg, refs, keys, commits, pseudo, image, None)
    outsider = random_scalar()                        # owns no ring member at all
    fake = ringsig.sign(msg, refs, keys, commits, pseudo, real, outsider, (blinds[real] - pb) % L)
    assert not ringsig.verify(msg, refs, keys, commits, pseudo, ringsig.key_image(outsider, refs[real], keys[real].hex()), fake), "an outsider signed"
    greedy = commit(amounts[real] + 500, pb)           # the real owner, claiming the input is worth more
    fake = ringsig.sign(msg, refs, keys, commits, greedy, real, xs[real], (blinds[real] - pb) % L)
    assert not ringsig.verify(msg, refs, keys, commits, greedy, image, fake), "the owner inflated the amount"
    pool = ["%064x:0" % i for i in range(60)]
    ring = ringsig.pick_ring(pool, pool[50], 16)
    assert len(set(ring)) == 16 and ring == sorted(ring) and pool[50] in ring
    expect_error(lambda: ringsig.pick_ring(pool[:15], pool[3], 16), "too young")


# ----------------------------------------------------------------------------- wallets
def test_wallet_keys_addresses_and_files():
    w = Wallet.generate(PREFIX)
    assert w.address.startswith(PREFIX) and len(w.address) > 80
    assert is_valid_address(w.address, PREFIX)
    assert not is_valid_address(w.address[:-1] + ("1" if w.address[-1] != "1" else "2"), PREFIX)
    tmp = tempfile.mkdtemp(prefix="vesper-test-")
    try:
        path = os.path.join(tmp, "w.json")
        w.save(path, "correct horse")
        assert Wallet.public_info(path)["address"] == w.address
        assert Wallet.load(path, "correct horse").address == w.address
        # the prefix is spelling, not consensus: a renamed coin opens the same wallet with the same keys
        renamed = Wallet.load(path, "correct horse", prefix="zz")
        assert renamed.address.startswith("zz") and is_valid_address(renamed.address, "zz") and not is_valid_address(renamed.address, PREFIX)
        assert renamed.keys.spend_priv == w.keys.spend_priv and renamed.keys.view_priv == w.keys.view_priv
        assert Wallet.public_info(path, "zz")["address"] == renamed.address, "the address must convert without the password"
        number, extra = w.new_address("rent from tom")
        w.save(path, "correct horse")
        again = Wallet.load(path, "correct horse")
        assert number == 1 and extra != w.address and again.addresses() == w.addresses() == [(0, w.address, "main"), (1, extra, "rent from tom")]
        with open(path, encoding="utf-8") as fh:
            assert "rent from tom" not in fh.read(), "labels say who pays you: they are encrypted with the keys"
        for bad in (None, "wrong"):
            try:
                Wallet.load(path, bad)
                raise AssertionError("loaded with a bad password")
            except WalletLocked:
                pass
        with open(path, encoding="utf-8") as fh:
            text = fh.read()
        assert w.keys.to_dict()["spend_priv"] not in text and w.keys.to_dict()["view_priv"] not in text
        assert w.keys.seed.hex() not in text, "the seed is encrypted with the keys"
        # the recovery code: 55 characters that ARE the wallet, typos caught
        code = w.recovery_code()
        assert len(code.replace("-", "")) == 55
        back = Wallet.from_code(code.lower().replace("-", " "), PREFIX)
        assert back.address == w.address and back.keys.to_dict()["spend_priv"] == w.keys.to_dict()["spend_priv"]
        assert back.keys.address_at(1) == extra, "and the same extra addresses"
        assert Wallet.from_code(code.replace("0", "O").replace("1", "I"), PREFIX).address == w.address, "O and I are read as 0 and 1"
        for slip in (code[:3] + ("2" if code[3] != "2" else "3") + code[4:], code[:-2], code + "Q"):
            try:
                Wallet.from_code(slip, PREFIX)
                raise AssertionError("a recovery code with a mistake was accepted: %s" % slip)
            except WalletError:
                pass
        old_style = Wallet(StealthKeys(random_scalar(), random_scalar(), PREFIX))
        assert old_style.recovery_code() is None, "a wallet made before recovery codes has none (and says so)"
        damaged = dict(w.keys.to_dict(), seed="00" * 32)
        try:
            StealthKeys.from_dict(damaged, PREFIX)
            raise AssertionError("a seed that does not fit the keys was accepted")
        except ValueError:
            pass
        vpath = os.path.join(tmp, "view.json")
        w.export_view_key(vpath)
        assert Wallet.load_view_key(vpath).address == w.address and Wallet.load_view_markers(vpath) == {}
        try:
            Wallet.load(vpath)
            raise AssertionError("a view-key file loaded as a spending wallet")
        except WalletError:
            pass
        # the ring memory is readable by this wallet only
        rpath = os.path.join(tmp, "w.rings")
        w.save_rings(rpath, {"ab" * 32: ["x:0", "y:1"]})
        assert w.load_rings(rpath) == {"ab" * 32: ["x:0", "y:1"]}
        assert Wallet.generate(PREFIX).load_rings(rpath) == {} and w.load_rings(os.path.join(tmp, "missing")) == {}
        with open(rpath, "rb") as fh:
            assert b"x:0" not in fh.read(), "the ring memory must not be readable on disk"
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


# ----------------------------------------------------------------------------- the ledger
def test_mining_pays_the_miner_and_nobody_can_tell_who():
    c = new_chain()
    alice, eve = Wallet.generate(PREFIX), Wallet.generate(PREFIX)
    mine(c, alice, 3)
    assert balance(c, alice) == 3 * coins("50") and balance(c, eve) == 0
    assert c.circulating_supply() == 3 * coins("50") and c.supply_at(c.halving_interval) == (c.halving_interval - 1) * coins("50") + coins("25")
    text = json.dumps(c.blocks[:])
    assert alice.address not in text and alice.address[5:30] not in text, "the miner's address leaked onto the chain"
    keys = [tx["outputs"][0]["one_time_pub"] for b in c.blocks[1:] for tx in b["transactions"]]
    assert len(set(keys)) == len(keys), "two rewards to one wallet reused a key"


def test_payment_hides_receiver_amount_and_sender():
    c = new_chain()
    alice, bob, eve = (Wallet.generate(PREFIX) for _ in range(3))
    mine(c, alice, RING + 2)
    before = owned(c, alice)
    fee = c.min_fee_units * 10
    tx = pay(c, alice, bob.address, coins("20"), fee)
    assert len(tx["inputs"]) == 1 and len(tx["outputs"]) == 2
    assert c.add_to_mempool(tx) is False, "the same transaction twice should be ignored"
    block = mine(c, bob)
    assert len(block["transactions"]) == 2 and c.mempool == {}
    assert balance(c, alice) == (RING + 2) * coins("50") - coins("20") - fee
    assert balance(c, bob) == coins("20") + coins("50") + fee, "the miner must receive the fee"
    text = json.dumps(tx)
    assert alice.address[len(PREFIX):] not in text and bob.address[len(PREFIX):] not in text, "an address is on the chain"
    assert all("amount" not in out for out in tx["outputs"]), "an amount field is on the chain"
    assert str(coins("20")) not in text and str(coins("50") - coins("20") - fee) not in text, "an amount is readable on the chain"
    assert "timestamp" not in tx and "timestamp" not in text, "a payment must not say when it was made"
    # WHO PAID: the input names a ring, never one output
    inp = tx["inputs"][0]
    assert set(inp) == RING_INPUT_KEYS and "txid" not in inp and "index" not in inp
    spent = [u for u in before if u["key_image"] == inp["key_image"]]
    assert len(spent) == 1 and ref_of(spent[0]) in inp["ring"], "the real output must be somewhere in the ring"
    assert len(inp["ring"]) == RING == len(set(inp["ring"])) and inp["ring"] == sorted(inp["ring"])
    assert inp["key_image"] not in text.replace('"key_image": "%s"' % inp["key_image"], ""), "the key image must appear nowhere else"
    assert inp["key_image"] not in {o["one_time_pub"] for o in c.state.outputs.values()}, "a key image must not look like any output"
    # nothing was removed from the ledger, so nobody can see WHAT was spent - except the owner
    assert ref_of(spent[0]) in c.state.outputs and len(c.state.key_images) == 1
    assert [u["spent"] for u in alice.scan(c.all_outputs(), c.state.key_images) if ref_of(u) == ref_of(spent[0])] == [True]
    assert all(not u["spent"] for u in eve.scan(c.all_outputs(), c.state.key_images)) and balance(c, eve) == 0
    # spending an output completely still makes two outputs, so "no change" is not visible either
    exact = [u for u in owned(c, bob) if u["amount"] == coins("20")]
    tx2 = transfer(c, bob, [(alice.address, coins("20") - c.min_fee_units)], inputs=exact)
    assert len(tx2["outputs"]) == 2 and tx2["fee"] == c.min_fee_units and c.add_to_mempool(tx2)
    mine(c, alice)
    assert balance(c, bob) == coins("50") + fee


def test_double_spend_rejected():
    c = new_chain()
    alice, bob, carol = (Wallet.generate(PREFIX) for _ in range(3))
    mine(c, alice, RING + 4)
    one = owned(c, alice)[:1]                          # the same coin, three times
    tx1 = transfer(c, alice, [(bob.address, coins("30"))], inputs=one)
    tx2 = transfer(c, alice, [(carol.address, coins("30"))], inputs=one)
    assert tx1["inputs"][0]["key_image"] == tx2["inputs"][0]["key_image"], "one output, one key image, whatever the ring"
    twice = copy.deepcopy(tx1)
    twice["inputs"].append(copy.deepcopy(twice["inputs"][0]))
    twice["fee"] = c.required_fee(2, 2)
    expect_error(lambda: c.add_to_mempool(retxid(twice)), "twice")
    outputs_before, images_before = len(c.state.outputs), len(c.state.key_images)
    c.add_to_mempool(tx1)
    expect_error(lambda: c.add_to_mempool(tx2), "key image already used")
    expect_error(lambda: transfer(c, alice, [(carol.address, coins("60"))], inputs=one), "insufficient")
    assert (len(c.state.outputs), len(c.state.key_images)) == (outputs_before, images_before), "a waiting payment must not touch the ledger"
    mine(c, alice)
    expect_error(lambda: c.add_to_mempool(tx2), "key image already used")
    height, outputs_before = c.height, len(c.state.outputs)
    expect_error(lambda: c.add_block(block_with(c, alice, [tx2])), "key image already used")
    assert (c.height, len(c.state.outputs), len(c.state.key_images)) == (height, outputs_before, 1), "a refused block must leave no trace"
    assert balance(c, bob) == coins("30") and balance(c, carol) == 0


def test_coins_cannot_be_created_out_of_nothing():
    c = new_chain()
    alice, bob = Wallet.generate(PREFIX), Wallet.generate(PREFIX)
    mine(c, alice, RING + 1)
    my = owned(c, alice)[:1]                           # one 50-coin output
    fee = c.min_fee_units
    # 1. outputs worth more than the input.  The leftover has coins in it, so no key can sign it.
    greedy = forge(c, alice, my, [(bob.address, coins("30")), (alice.address, coins("30"))], fee)
    expect_error(lambda: c.add_to_mempool(greedy), "do not balance")

    # 2. the classic: pay bob 100 from a 50 input, and give yourself an output of MINUS 50.
    #    The envelopes balance perfectly.  Only the range proof stands in the way.
    def make_negative(outputs, openings):
        outputs[1]["commitment"] = commit((coins("50") - coins("100") - fee) % L, openings[1][1]).hex()

    negative = forge(c, alice, my, [(bob.address, coins("100")), (alice.address, 0)], fee, tweak=make_negative)
    expect_error(lambda: c.add_to_mempool(negative), "range proof")
    expect_error(lambda: c.add_block(block_with(c, alice, [negative])), "range proof")      # proofs are batched per block

    # 3. claim the hidden input is worth more than it is
    inflated = forge(c, alice, my, [(bob.address, coins("100")), (alice.address, coins("450") - fee)], fee, pseudo_bonus=coins("500"))
    expect_error(lambda: c.add_to_mempool(inflated), "ring signature")

    # 4. a fee the transaction does not really pay
    honest = forge(c, alice, my, [(bob.address, coins("10")), (alice.address, coins("40") - fee)], fee)
    expect_error(lambda: c.add_to_mempool(tampered(honest, lambda t: t.update(fee=fee * 1000))), "do not balance")
    assert c.height == RING + 1 and balance(c, bob) == 0 and len(c.state.key_images) == 0
    c.add_block(block_with(c, alice, [honest]))
    assert balance(c, bob) == coins("10")


def test_forged_transactions_rejected():
    c = new_chain()
    alice, bob, eve = (Wallet.generate(PREFIX) for _ in range(3))
    mine(c, alice, RING + 1)
    my = owned(c, alice)[:1]
    fee = c.min_fee_units
    expect_error(lambda: eve.keys.sign_input(my[0]["output"], b"x"), "does not own")
    good = transfer(c, alice, [(bob.address, coins("1"))], inputs=my)

    def bump(text):
        return scalar_to_hex(int.from_bytes(bytes.fromhex(text), "little") + 1)

    cases = [
        (lambda t: t.update(txid="00" * 32), False, "txid"),
        (lambda t: t.update(bonus=1), False, "fields"),
        (lambda t: t.update(timestamp=int(time.time())), False, "fields"),
        (lambda t: t.update(fee=fee - 1), True, "fee"),
        (lambda t: t["outputs"][0].update(one_time_pub="ff" * 32), True, "malformed key"),
        (lambda t: t["outputs"][0].update(one_time_pub=t["outputs"][0]["one_time_pub"].upper()), True, "malformed key"),
        (lambda t: t["outputs"][0].update(commitment="01" + "00" * 31), True, "sealed amount"),
        (lambda t: t["outputs"].pop(), True, "2 to"),
        (lambda t: t["outputs"][0].update(amount=5), True, "wrong fields"),
        (lambda t: t.pop("range_proof"), True, "fields"),
        (lambda t: t["outputs"][0].update(view_tag="0g"), True, "view tag"),
        (lambda t: t["outputs"][0].update(enc_anchor="00" * 15), True, "view tag"),
        (lambda t: t.update(range_proof=None), True, "no range proof"),
        (lambda t: t["outputs"][0].update(range_proof=t["range_proof"]), True, "wrong fields"),
        (lambda t: t["range_proof"].update(t=bump(t["range_proof"]["t"])), True, "do not balance"),   # the proof is signed too
        # eve re-points bob's payment to herself: everything signed breaks
        (lambda t: t["outputs"][0].update(one_time_pub=make_outputs([(eve.address, 1)], PREFIX)[0][0]["one_time_pub"]), True, "do not balance"),
        (lambda t: t.update(excess_sig=sign(12345, tx_signing_bytes(t))), True, "do not balance"),
        (lambda t: t["inputs"][0]["signature"]["s"].__setitem__(0, bump(t["inputs"][0]["signature"]["s"][0])), True, "ring signature"),
        (lambda t: t["inputs"][0]["signature"].update(c=bump(t["inputs"][0]["signature"]["c"])), True, "ring signature"),
        (lambda t: t["inputs"][0]["signature"].update(D="01" + "00" * 31), True, "ring signature"),
    ]
    for change, fix, word in cases:
        expect_error(lambda: c.add_to_mempool(tampered(good, change, fix)), word)
    # inputs come in key-image order, so their order says nothing about which coin is bigger
    two = transfer(c, alice, [(bob.address, coins("60"))], inputs=owned(c, alice)[1:3])
    assert len(two["inputs"]) == 2 and two["inputs"][0]["key_image"] < two["inputs"][1]["key_image"]
    expect_error(lambda: c.add_to_mempool(tampered(two, lambda t: t["inputs"].reverse())), "order")
    # someone who owns nothing in the ring, signing anyway
    expect_error(lambda: c.add_to_mempool(forge(c, alice, my, [(bob.address, coins("1")), (alice.address, coins("49") - fee)], fee, secret_key=12345)), "ring signature")
    # the real owner attaching a DIFFERENT output's key image (to dodge the double-spend check)
    other_image = owned(c, alice)[1]["key_image"]
    expect_error(lambda: c.add_to_mempool(forge(c, alice, my, [(bob.address, coins("1")), (alice.address, coins("49") - fee)], fee, image_hex=other_image)), "ring signature")
    assert c.add_to_mempool(good) is True


def test_ring_rules_are_enforced():
    c = new_chain()
    alice, bob = Wallet.generate(PREFIX), Wallet.generate(PREFIX)
    mine(c, alice, RING + 3)
    my = owned(c, alice)
    good = transfer(c, alice, [(bob.address, coins("1"))], inputs=my[:1])
    ring = good["inputs"][0]["ring"]
    outsider = next(ref for ref in c.state.outputs if ref not in ring)
    expect_error(lambda: c.add_to_mempool(tampered(good, lambda t: t["inputs"][0].update(ring=ring[:-1]))), "exactly %d" % RING)
    expect_error(lambda: c.add_to_mempool(tampered(good, lambda t: t["inputs"][0].update(ring=ring + [outsider]))), "exactly %d" % RING)
    expect_error(lambda: c.add_to_mempool(tampered(good, lambda t: t["inputs"][0].update(ring=ring[::-1]))), "sorted")
    expect_error(lambda: c.add_to_mempool(tampered(good, lambda t: t["inputs"][0].update(ring=[ring[0]] + ring[:-1]))), "different")
    expect_error(lambda: c.add_to_mempool(tampered(good, lambda t: t["inputs"][0].update(ring=sorted(ring[:-1] + ["ab" * 32 + ":0"])))), "not an output")
    # swapping a ring member after signing: the ring is part of what every signature covers
    expect_error(lambda: c.add_to_mempool(tampered(good, lambda t: t["inputs"][0].update(ring=sorted(ring[:-1] + [outsider])))), "do not balance")
    expect_error(lambda: c.add_to_mempool(tampered(good, lambda t: t["inputs"][0].update(key_image=t["inputs"][0]["key_image"].upper()))), "malformed key image")
    expect_error(lambda: c.add_to_mempool(tampered(good, lambda t: t["inputs"][0].update(key_image="01" + "00" * 31))), "malformed")
    # the phase-2 way of spending (just name the output) is gone for everyone but the fund
    named = {"txid": my[0]["txid"], "index": my[0]["index"], "signature": sign(alice.keys.owns(my[0]["output"]), b"x")}
    expect_error(lambda: c.add_to_mempool(tampered(good, lambda t: t["inputs"].__setitem__(0, named))), "only development fund outputs")
    expect_error(lambda: c.add_to_mempool(tampered(good, lambda t: t.update(inputs=[]))), "1 to")
    young = new_chain()
    mine(young, alice, RING - 1)
    expect_error(lambda: transfer(young, alice, [(bob.address, coins("1"))]), "too young")
    assert c.add_to_mempool(good) is True


def test_the_same_key_twice_is_two_coins_not_one():
    """Monero's "burning bug" and Zcash's "Faerie Gold": pay someone twice to the SAME one-time
    key and, in those designs, only one of the two can ever be spent.  Here the spent marker is
    tied to the output's position, so both are spendable - and no rule against repeated keys is
    needed, a rule that would let a stranger cancel a waiting payment by copying its key."""
    c = new_chain()
    alice, bob = Wallet.generate(PREFIX), Wallet.generate(PREFIX)
    mine(c, alice, RING + 2)
    fee = c.min_fee_units
    kept = {}

    def remember(outputs, openings):
        kept["output"], kept["opening"] = copy.deepcopy(outputs[0]), openings[0]

    def replay(outputs, openings):
        outputs[0], openings[0] = copy.deepcopy(kept["output"]), kept["opening"]

    first = forge(c, alice, owned(c, alice)[:1], [(bob.address, coins("10")), (alice.address, coins("40") - fee)], fee, tweak=remember)
    c.add_to_mempool(first)
    mine(c, alice)
    second = forge(c, alice, owned(c, alice)[:1], [(bob.address, coins("10")), (alice.address, coins("40") - fee)], fee, tweak=replay)
    assert second["outputs"][0]["one_time_pub"] == first["outputs"][0]["one_time_pub"], "the test must reuse the key"
    c.add_to_mempool(second)                           # accepted: a repeated key is not an offence
    mine(c, alice)
    twins = owned(c, bob)
    assert len(twins) == 2 and twins[0]["output"]["one_time_pub"] == twins[1]["output"]["one_time_pub"]
    assert twins[0]["key_image"] != twins[1]["key_image"], "two outputs, two spent markers"
    assert balance(c, bob) == coins("20")
    for twin in twins:                                 # bob spends BOTH
        c.add_to_mempool(transfer(c, bob, [(alice.address, coins("9"))], inputs=[twin]))
        mine(c, alice)
    assert len(owned(c, bob)) == 2 and balance(c, bob) == 2 * (coins("1") - fee), "both coins were spendable"


def test_retrying_a_payment_reuses_the_same_ring():
    """If a payment is rebuilt with fresh decoys, the two rings share exactly one output: the
    real one.  The wallet's ring memory makes every attempt use the same ring."""
    c = new_chain()
    alice, bob = Wallet.generate(PREFIX), Wallet.generate(PREFIX)
    mine(c, alice, RING * 4)
    one = owned(c, alice)[:1]
    careless = [transfer(c, alice, [(bob.address, coins("1"))], inputs=one)["inputs"][0]["ring"] for _ in range(4)]
    assert len({tuple(r) for r in careless}) > 1, "without a memory the decoys change (this is the leak)"
    assert ref_of(one[0]) in set.intersection(*map(set, careless)) and len(set.intersection(*map(set, careless))) < RING, \
        "the real output is in every ring, the decoys are not: comparing rings narrows it down"
    memory: dict = {}
    first = transfer(c, alice, [(bob.address, coins("1"))], inputs=one, known_rings=memory)
    assert list(memory) == [first["inputs"][0]["key_image"]]
    mine(c, alice, 3)                                  # the chain grows; new decoys would be available
    for amount in ("1", "2", "3"):
        again = transfer(c, alice, [(bob.address, coins(amount))], inputs=one, known_rings=memory)
        assert again["inputs"][0]["ring"] == first["inputs"][0]["ring"], "a retry must show the same ring"
    c.add_to_mempool(again)
    # if a remembered ring can no longer be used, a new one is chosen rather than failing
    memory[first["inputs"][0]["key_image"]] = ["gone:0"] * RING
    fresh = transfer(c, alice, [(bob.address, coins("1"))], inputs=one, known_rings=memory)
    assert ref_of(one[0]) in fresh["inputs"][0]["ring"] and "gone:0" not in fresh["inputs"][0]["ring"]
    # ... but a ring that lost ONE member (a reorganisation took that output away) keeps all the
    # others.  Swapping the whole ring would leave the real output as the only thing in common.
    image, ring = first["inputs"][0]["key_image"], first["inputs"][0]["ring"]
    lost = next(r for r in ring if r != ref_of(one[0]))
    for _ in range(5):
        memory[image] = sorted([r for r in ring if r != lost] + ["00" * 32 + ":0"])
        repaired = transfer(c, alice, [(bob.address, coins("1"))], inputs=one, known_rings=memory)["inputs"][0]["ring"]
        assert set(ring) - {lost} <= set(repaired) and len(repaired) == RING and "00" * 32 + ":0" not in repaired, \
            "only the missing member may be replaced"


def test_fee_grows_with_size():
    c = new_chain()
    alice, bob, carol = (Wallet.generate(PREFIX) for _ in range(3))
    mine(c, alice, RING + 3)
    unit = c.min_fee_units
    assert (fee_weight(1, 2), fee_weight(2, 2), fee_weight(1, 3), fee_weight(4, 5)) == (1, 2, 2, 7)
    plain = transfer(c, alice, [(bob.address, coins("1"))])
    assert plain["fee"] == unit, "an ordinary payment pays one unit, and every wallet pays exactly that"
    two_out = transfer(c, alice, [(bob.address, coins("1")), (carol.address, coins("1"))])
    assert len(two_out["outputs"]) == 3 and two_out["fee"] == 2 * unit
    big = transfer(c, alice, [(bob.address, coins("120"))])          # needs three 50-coin inputs
    assert len(big["inputs"]) == 3 and big["fee"] == 3 * unit
    for tx in (plain, two_out):
        expect_error(lambda: c.add_to_mempool(tampered(tx, lambda t: t.update(fee=t["fee"] - 1))), "fee below the minimum")
    # paying for one input and two outputs while stuffing in a third output is refused
    expect_error(lambda: transfer(c, alice, [(bob.address, coins("1")), (carol.address, coins("1"))], fee=unit), "fee too low")
    stuffed = forge(c, alice, owned(c, alice)[:1], [(bob.address, coins("1")), (carol.address, coins("1")), (alice.address, coins("48") - unit)], unit)
    expect_error(lambda: c.add_to_mempool(stuffed), "fee below the minimum", "3 output")
    c.add_to_mempool(big)
    mine(c, carol)
    assert balance(c, bob) == coins("120") and balance(c, carol) == coins("50") + 3 * unit


def test_tampering_with_history_is_detected():
    c = new_chain()
    alice, bob = Wallet.generate(PREFIX), Wallet.generate(PREFIX)
    mine(c, alice, RING)
    pay(c, alice, bob.address, coins("5"))
    mine(c, bob, 2)
    tb = RING + 1                                      # the block holding the payment
    good = copy.deepcopy(c.blocks)
    c.validate_chain(good)

    bad = copy.deepcopy(good)
    bad[tb]["transactions"][1]["outputs"][0]["enc_amount"] = "00" * 8
    expect_error(lambda: c.validate_chain(bad), "txid")
    retxid(bad[tb]["transactions"][1])
    expect_error(lambda: c.validate_chain(bad), "merkle")
    bad = copy.deepcopy(good)
    bad[1]["nonce"] += 1
    expect_error(lambda: c.validate_chain(bad), "hash")

    def reseal(block):
        retxid(block["transactions"][0])
        block["merkle_root"] = merkle_root([t["txid"] for t in block["transactions"]])
        solve(c, block)

    bad = copy.deepcopy(good)                         # the miner awards itself one extra unit
    bad[1]["transactions"][0]["outputs"][0]["amount"] += 1
    reseal(bad[1])
    expect_error(lambda: c.validate_chain(bad), "commitment does not match")
    bad[1]["transactions"][0]["outputs"][0]["commitment"] = commit(bad[1]["transactions"][0]["outputs"][0]["amount"], 0).hex()
    reseal(bad[1])
    expect_error(lambda: c.validate_chain(bad), "coinbase pays")
    bad = copy.deepcopy(good)
    bad[0]["timestamp"] += 1
    expect_error(lambda: c.validate_chain(bad), "genesis")
    other = new_chain()
    assert other.replace_chain(good) is True and other.height == c.height, "a fresh node must accept the honest chain"
    assert other.state.key_images == c.state.key_images and len(other.state.key_images) == 1
    assert list(other.state.outputs) == list(c.state.outputs), "both nodes must hold the same outputs in the same order"


def test_longest_chain_wins_and_orphans_return():
    a, b = new_chain(), new_chain()
    ma, mb = Wallet.generate(PREFIX), Wallet.generate(PREFIX)
    mine(a, ma, 2)
    mine(b, mb, 3)
    a_before = copy.deepcopy(a.blocks)
    assert a.replace_chain(b.blocks) is True and a.height == 3
    assert balance(a, ma) == 0 and balance(a, mb) == coins("150")
    assert a.replace_chain(a_before) is False
    assert a.forks == {"reorganisations": 1, "blocks_orphaned": 2, "competing_blocks_lost": 2}, a.forks
    assert a.info()["forks_since_start"]["blocks_orphaned"] == 2
    a2 = new_chain()
    alice, bob, other = (Wallet.generate(PREFIX) for _ in range(3))
    mine(a2, alice, RING)
    b2 = new_chain()
    assert b2.replace_chain(a2.blocks)
    tx = pay(a2, alice, bob.address, coins("7"))
    mine(a2, alice)
    assert len(a2.state.key_images) == 1
    mine(b2, other, 2)
    # switching branches re-does only the part that differs: the shared blocks are not re-verified
    assert a2.common_height(b2.blocks) == RING
    checks = a2.work_checks
    assert a2.replace_chain(b2.blocks) is True and tx["txid"] in a2.mempool, "an orphaned payment must return to the mempool"
    assert a2.work_checks - checks == 2, "only the two new blocks needed their proof of work checked"
    assert len(a2.state.key_images) == 0, "the orphaned spend must be forgotten with its block"
    mine(a2, other)
    assert balance(a2, bob) == coins("7") and len(a2.state.key_images) == 1


def test_difficulty_follows_the_network_speed():
    H = 600
    rules = deep_merge(CONFIG, {"consensus": {"difficulty_halflife_seconds": H, "initial_difficulty": 1000, "min_difficulty": 16}})
    c = new_chain(config=rules)
    g, T = c.blocks[0]["timestamp"], c.target_seconds

    def step(previous, solve_seconds):
        return step_difficulty(previous, solve_seconds, T, H)

    # one step: exact integer maths, so every computer gets the same number
    assert step(1000, T) == 1000, "a block exactly on time changes nothing"
    assert step(1000, T - H) == 2000 and step(1000, T + H) == 500, "one half-life early doubles it, one late halves it"
    assert (step(1000, 0), step(1000, 2 * T), step(1000, 27), step(1000, 33)) == (1035, 966, 1003, 996)
    assert step(1000, -10 ** 9) == 2000 and step(1000, 10 ** 9) == 250, "one block: at most double, at most down to a quarter"
    assert step(16, T - 1) == 17 and step(17, T + 1) == 16 and step(1, 10 ** 6) == 1, "tiny difficulties still move, and never reach zero"
    assert all(abs(step(10 ** 12, s) / 10 ** 12 / 2 ** ((T - s) / H) - 1) < 2e-4 for s in range(-560, 1220)), \
        "the integer stand-in for 2^x must stay within 0.02% of the real thing"

    def fake(seconds_apart, difficulty=1000, count=40):
        return [c.blocks[0]] + [{"index": i, "timestamp": g + i * seconds_apart, "difficulty": difficulty} for i in range(1, count)]

    assert c.expected_difficulty(1, fake(1)) == c.expected_difficulty(2, fake(1)) == 1000, \
        "blocks 1 and 2 start at the initial difficulty: the gap since genesis says nothing about mining speed"
    assert c.expected_difficulty(3, fake(1)) == step(1000, 1) > 1000, "from the third block on, it follows"
    assert c.expected_difficulty(40, fake(T)) == 1000, "blocks on schedule: no change"
    assert c.expected_difficulty(40, fake(T * 100, difficulty=20)) == 16, "never below the floor"
    # A lying clock gains nothing.  Stamp a block two minutes into the past and the next block
    # gets HARDER; when honest time resumes, the difficulty is back where it would have been.
    honest, liar, now = fake(T, count=3), fake(T, count=3), g + 2 * T
    for height in range(3, 30):
        now += T
        for blocks, lie in ((honest, 0), (liar, -120 if height == 10 else 0)):
            blocks.append({"index": height, "timestamp": now + lie, "difficulty": c.expected_difficulty(height, blocks)})
    assert liar[11]["difficulty"] > 1100 and honest[11]["difficulty"] == 1000, "a clock set back makes the next block harder, never easier"
    assert abs(liar[-1]["difficulty"] - honest[-1]["difficulty"]) <= 2, "and afterwards nothing is left of the lie"
    for lie in (120, -120):                            # ... forwards or backwards, it comes out the same
        assert abs(step(step(10 ** 6, T + lie), T - lie) - 10 ** 6) < 200
    # miners eight times faster than the starting difficulty assumes: it must settle near 8000, i.e. 30 s blocks
    speed = 1000 / (T / 8)                             # tries per second
    blocks, now = [c.blocks[0]], g
    for height in range(1, 400):
        d = c.expected_difficulty(height, blocks)
        now += max(1, round(d / speed))
        blocks.append({"index": height, "timestamp": now, "difficulty": d})
    assert 7600 < blocks[-1]["difficulty"] < 8400, blocks[-1]["difficulty"]
    assert T - 2 <= blocks[-1]["timestamp"] - blocks[-2]["timestamp"] <= T + 2, "block time must settle at the target"
    # Nine miners in ten leave at once.  The first block takes ten times as long - nothing can
    # prevent that - and every block after it is quicker than the one before.
    slow, start = speed / 10, len(blocks)
    for height in range(start, start + 61):
        d = c.expected_difficulty(height, blocks)
        now += max(1, round(d / slow))
        blocks.append({"index": height, "timestamp": now, "difficulty": d})
    gaps = [b["timestamp"] - a["timestamp"] for a, b in zip(blocks[start - 1:], blocks[start:])]
    assert gaps[0] > 8 * T and all(a >= b for a, b in zip(gaps, gaps[1:])), gaps
    assert gaps[12] < 3 * T and gaps[30] < 2 * T and gaps[-1] <= T + 5, gaps
    # the whole network is switched off for a day and comes back: no flood of nearly free blocks
    now += 86400
    before = c.expected_difficulty(len(blocks), blocks)
    blocks.append({"index": len(blocks), "timestamp": now, "difficulty": before})
    back, count, lowest = now, 0, 10 ** 9
    while now < back + 1800:
        d = c.expected_difficulty(len(blocks), blocks)
        now += max(1, round(d / slow))
        blocks.append({"index": len(blocks), "timestamp": now, "difficulty": d})
        count, lowest = count + 1, min(lowest, d)
    assert count < 120 and lowest >= before // 4 - 1, \
        "after an outage the difficulty may drop to a quarter at most: %d blocks in the first half hour (60 is normal)" % count
    # and a block that claims the wrong difficulty is refused
    miner = Wallet.generate(PREFIX)
    mine(c, miner, 12)
    assert c.tip["difficulty"] > c.blocks[2]["difficulty"] == 1000, "twelve blocks in under a second: it must have started climbing"
    cand = c.create_candidate_block(miner.address)
    cand["difficulty"] = max(1, cand["difficulty"] // 4)
    expect_error(lambda: c.add_block(solve(c, cand)), "difficulty")


def test_timestamps_halving_amounts_and_genesis():
    c = new_chain()
    miner = Wallet.generate(PREFIX)
    mine(c, miner)
    cand = c.create_candidate_block(miner.address)
    cand["timestamp"] += 10 * 24 * 3600
    expect_error(lambda: c.add_block(solve(c, cand)), "future")
    cand = c.create_candidate_block(miner.address)
    cand["previous_hash"] = "ab" * 32
    expect_error(lambda: c.add_block(solve(c, cand)), "link")
    h = c.halving_interval
    assert c.reward_at(h - 1) == coins("50") and c.reward_at(h) == coins("25") and c.reward_at(40 * h) == 0
    assert coins("199999") < c.max_supply() <= coins("200000")
    assert coins("1.5") == 150_000_000 and format_units(150_000_000, DECIMALS) == "1.5"
    for bad in ("abc", "1.123456789", "-1", ""):
        try:
            coins(bad)
            raise AssertionError("accepted %r" % bad)
        except ValueError:
            pass
    # every consensus setting is hashed into the genesis block: change a rule, get a different coin
    for change in ({"block_reward": "51"}, {"ring_size": RING + 1}, {"min_fee": "0.00002"}, {"difficulty_halflife_seconds": 700}, {"output_lock_blocks": 11}):
        assert new_chain(config=deep_merge(CONFIG, {"consensus": change})).blocks[0]["hash"] != c.blocks[0]["hash"], change
    expect_error(lambda: new_chain(config=deep_merge(CONFIG, {"consensus": {"ring_size": 1}})), "ring_size")


def test_proof_of_work_is_memory_hard_and_checked_once():
    c = new_chain()
    miner = Wallet.generate(PREFIX)
    assert c.pow_algorithm == "argon2id", "the default work function must not be Bitcoin's"
    block = mine(c, miner)
    header = json.dumps({k: block[k] for k in ("index", "timestamp", "previous_hash", "merkle_root", "difficulty", "nonce")},
                        sort_keys=True, separators=(",", ":")).encode()
    assert block["hash"] == hashlib.sha256(hashlib.sha256(header).digest()).hexdigest(), "the block ID is the plain hash of the header"
    assert int.from_bytes(pow_digest(header, "argon2id", c.pow_memory_kib, c.pow_passes), "big") < difficulty_target(block["difficulty"])
    assert pow_digest(header, "argon2id", 8, 1) != pow_digest(header, "argon2id", 16, 1) != pow_digest(header, "sha256d"), "memory size is part of the function"
    # a block with a perfectly good ID but no work behind it
    cand = c.create_candidate_block(miner.address)
    cand["nonce"] = next(n for n in range(10 ** 6) if not c.proof_of_work_ok(dict(cand, nonce=n)))
    cand["hash"] = compute_block_hash(cand)
    expect_error(lambda: c.add_block(cand), "proof-of-work")
    # work done with Bitcoin's function does not count here, and a chain that uses it is a different coin
    sha_chain = new_chain(config=deep_merge(CONFIG, {"consensus": {"pow": {"algorithm": "sha256d"}}}))
    assert sha_chain.blocks[0]["hash"] != c.blocks[0]["hash"]
    mine(sha_chain, miner, 2)
    expect_error(lambda: c.replace_chain(sha_chain.blocks), "genesis")
    foreign = c.create_candidate_block(miner.address)
    foreign["nonce"] = next(n for n in range(10 ** 6) if int(compute_block_hash(dict(foreign, nonce=n)), 16) < difficulty_target(foreign["difficulty"])
                            and not c.proof_of_work_ok(dict(foreign, nonce=n)))
    foreign["hash"] = compute_block_hash(foreign)
    expect_error(lambda: c.add_block(foreign), "proof-of-work")
    expect_error(lambda: new_chain(config=deep_merge(CONFIG, {"consensus": {"pow": {"algorithm": "md5"}}})), "consensus.pow")


def test_a_restart_does_not_redo_the_heavy_work():
    alice, bob = Wallet.generate(PREFIX), Wallet.generate(PREFIX)
    tmp = tempfile.mkdtemp(prefix="vesper-test-")
    real_batch, real_ring = rangeproof.verify_batch, ringsig.verify
    calls = {"proofs": 0, "rings": 0}

    def counting_batch(items):
        calls["proofs"] += 1
        return real_batch(items)

    def counting_ring(*args):
        calls["rings"] += 1
        return real_ring(*args)

    try:
        first = new_chain(tmp)
        mine(first, alice, RING + 1)
        pay(first, alice, bob.address, coins("3"))
        mine(first, alice)
        height = first.height
        rangeproof.verify_batch, ringsig.verify = counting_batch, counting_ring
        again = new_chain(tmp)
        assert again.height == height and balance(again, bob) == coins("3")
        assert again.work_checks == 0 and calls == {"proofs": 0, "rings": 0}, "a restart must not redo work or signatures it already checked"
        full = Blockchain(CONFIG, tmp, recheck_work=True)
        assert full.work_checks == height and calls["proofs"] == 1 and calls["rings"] == 1, "`validate` must redo all of it"
        rangeproof.verify_batch, ringsig.verify = real_batch, real_ring
        mine(again, alice)
        # tampering is still caught without redoing the maths: block IDs chain into each other
        path = os.path.join(tmp, "chain.jsonl")
        with open(path, encoding="utf-8") as fh:
            lines = fh.readlines()
        at = next(i for i, line in enumerate(lines) if len(json.loads(line)["transactions"]) == 2)
        block = json.loads(lines[at])
        honest_line = lines[at]
        responses = block["transactions"][1]["inputs"][0]["signature"]["s"]          # one number in one ring signature
        responses[1] = scalar_to_hex(int.from_bytes(bytes.fromhex(responses[1]), "little") + 1)
        lines[at] = json.dumps(block, separators=(",", ":")) + "\n"
        with open(path, "w", encoding="utf-8") as fh:
            fh.writelines(lines)
        # `coin.py validate` names the damaged block and changes nothing ...
        expect_error(lambda: Blockchain(CONFIG, tmp, recheck_work=True), "block %d" % at, "txid")
        # ... and a node keeps every block before it, sets the damaged file aside and carries on
        mended = new_chain(tmp)
        assert mended.height == at - 1 and mended.repaired[0] == at and os.path.exists(mended.repaired[2])
        assert new_chain(tmp).height == at - 1 and new_chain(tmp).repaired is None, "the file it keeps is whole again"
        os.remove(mended.repaired[2])
        lines[at] = honest_line
        block = json.loads(lines[2])
        block["nonce"] += 1                            # one digit of one header
        lines[2] = json.dumps(block, separators=(",", ":")) + "\n"
        with open(path, "w", encoding="utf-8") as fh:
            fh.writelines(lines)
        expect_error(lambda: Blockchain(CONFIG, tmp, recheck_work=True), "block 2", "hash")
        mended = new_chain(tmp)
        assert mended.height == 1 and mended.repaired[0] == 2
        os.remove(mended.repaired[2])
        # a chain made under other rules is refused outright, not "repaired" to nothing
        expect_error(lambda: Blockchain(deep_merge(CONFIG, {"consensus": {"block_reward": "49"}}), tmp), "does not belong", "reset-chain")
        # a marker that does not match the chain is ignored, and everything is checked again
        lines[2] = json.dumps(dict(block, nonce=block["nonce"] - 1), separators=(",", ":")) + "\n"
        with open(path, "w", encoding="utf-8") as fh:
            fh.writelines(lines)
        with open(os.path.join(tmp, "verified_tip.json"), "w", encoding="utf-8") as fh:
            json.dump({"height": height + 1, "hash": "00" * 32}, fh)
        assert new_chain(tmp).work_checks == height + 1
    finally:
        rangeproof.verify_batch, ringsig.verify = real_batch, real_ring
        shutil.rmtree(tmp, ignore_errors=True)


def test_saving_and_loading_from_disk():
    tmp = tempfile.mkdtemp(prefix="vesper-test-")
    try:
        c = new_chain(tmp)
        alice, bob = Wallet.generate(PREFIX), Wallet.generate(PREFIX)
        mine(c, alice, RING + 1)
        pay(c, alice, bob.address, coins("3"))
        mine(c, bob)
        pay(c, alice, bob.address, coins("1"))
        c.flush()                                      # what a node does when it shuts down
        again = new_chain(tmp)
        assert again.height == c.height and again.tip["hash"] == c.tip["hash"]
        assert again.state.order == c.state.order and again.output_counts == c.output_counts and again.work == c.work
        assert list(again.state.outputs) == list(c.state.outputs) and again.state.key_images == c.state.key_images
        assert set(again.mempool) == set(c.mempool), "the mempool must survive a restart"
        assert balance(again, bob) == balance(c, bob) == coins("3") + coins("50") + c.min_fee_units
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def test_fee_priority_and_block_limit():
    c = new_chain()
    alice, bob = Wallet.generate(PREFIX), Wallet.generate(PREFIX)
    mine(c, alice, 5)
    for n, u in enumerate(owned(c, alice)):
        c.add_to_mempool(transfer(c, alice, [(bob.address, coins("1"))], c.min_fee_units * (n + 1), inputs=[u]))
    assert len(c.mempool) == 5
    c.max_block_txs = 3
    assert [t["fee"] for t in c.select_transactions()] == [c.min_fee_units * 5, c.min_fee_units * 4], "highest fees first"
    block = mine(c, bob)
    assert len(block["transactions"]) == 3 and len(c.mempool) == 3
    assert isinstance(c.pending_state(), StateView) and len(c.pending_state().key_images) == 3
    # and a block has a size limit in bytes, which the miner keeps to and every node checks
    import chain as chain_module
    limit = chain_module.MAX_BLOCK_BYTES
    try:
        one = len(json.dumps(next(iter(c.mempool.values())), separators=(",", ":")))
        chain_module.MAX_BLOCK_BYTES = chain_module.COINBASE_ROOM + one + 100
        c.max_block_txs = 200
        assert len(c.select_transactions()) == 1, "the miner fills a block only up to its size limit"
        big = block_with(c, bob, list(c.mempool.values()))
        chain_module.MAX_BLOCK_BYTES = len(json.dumps(big, separators=(",", ":"))) - 1
        expect_error(lambda: c.add_block(big), "bigger than")
    finally:
        chain_module.MAX_BLOCK_BYTES = limit
    # the mempool has a size limit in bytes too, so the largest payments cannot fill memory
    room = chain_module.MAX_MEMPOOL_BYTES
    try:
        chain_module.MAX_MEMPOOL_BYTES = c.mempool_bytes + 10
        extra = transfer(c, alice, [(bob.address, coins("1"))], inputs=owned(c, alice)[-1:])
        expect_error(lambda: c.add_to_mempool(extra), "full")
    finally:
        chain_module.MAX_MEMPOOL_BYTES = room


def test_view_key_sees_amounts_but_cannot_spend():
    c = new_chain()
    alice, bob = Wallet.generate(PREFIX), Wallet.generate(PREFIX)
    mine(c, alice, RING + 1)
    pay(c, alice, bob.address, coins("7.25"))
    mine(c, alice)
    view = bob.view_key()
    seen = scan_outputs(view, c.all_outputs())
    assert [u["amount"] for u in seen] == [coins("7.25")], "the view key must open the sealed amount"
    assert not hasattr(view, "spend_priv") and "key_image" not in seen[0], "a view key cannot compute key images"
    assert scan_outputs(Wallet.generate(PREFIX).view_key(), c.all_outputs()) == []
    assert StealthKeys(bob.keys.view_priv, 12345, PREFIX).owns(seen[0]["output"]) is None, "the right view key with a wrong spend key owns nothing"
    # the owner can hand over spent markers, so an auditor also sees money LEAVING
    tmp = tempfile.mkdtemp(prefix="vesper-test-")
    try:
        path = os.path.join(tmp, "view.json")
        bob.export_view_key(path, owned(c, bob))
        markers = Wallet.load_view_markers(path)
        assert list(markers) == [ref_of(seen[0])] and markers[ref_of(seen[0])] not in c.state.key_images
        pay(c, bob, alice.address, coins("1"))
        mine(c, alice)
        assert markers[ref_of(seen[0])] in c.state.key_images, "the auditor must see that this output was spent"
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
    # a sender who lies about the amount in the sealed note makes an output the wallet ignores
    outputs, _ = make_outputs([(bob.address, coins("5"))], PREFIX)
    outputs[0]["enc_amount"] = "11" * 8
    assert view.open(outputs[0]) is None


def test_one_wallet_many_addresses_nobody_can_link():
    """A wallet hands out as many addresses as it likes.  Payments to all of them land in it, its
    view key sees them all, and nothing ties the addresses to each other or to the wallet."""
    c = new_chain()
    alice, bob = Wallet.generate(PREFIX), Wallet.generate(PREFIX)
    mine(c, alice, RING + 1)
    _, for_tom = bob.new_address("tom")
    _, for_ann = bob.new_address("ann")
    addresses = (bob.address, for_tom, for_ann)
    assert len(set(addresses)) == 3 and len({len(a) for a in addresses}) == 1, "the main address looks like any other"
    keys = [decode_address(a, PREFIX) for a in addresses]
    assert len({p.hex() for pair in keys for p in pair}) == 6, "no key is shared between two addresses"
    tx = transfer(c, alice, [(for_tom, coins("2")), (for_ann, coins("3")), (bob.address, coins("4"))])
    c.add_to_mempool(tx)
    mine(c, alice)
    assert len({o["ephemeral_pub"] for o in tx["outputs"]}) == len(tx["outputs"]), "every output has its own R"
    assert sorted((u["address"], u["amount"]) for u in owned(c, bob)) == [(0, coins("4")), (1, coins("2")), (2, coins("3"))]
    assert len(scan_outputs(bob.view_key(), c.all_outputs())) == 3, "the view key sees every address"
    restored = Wallet(StealthKeys(bob.keys.view_priv, bob.keys.spend_priv, PREFIX))
    assert len(owned(c, restored)) == 3, "restored from its two keys alone, it still looks ahead and finds them"
    spent = pay(c, bob, alice.address, coins("8.5"))     # coins from every address, spent together
    mine(c, alice)
    assert balance(c, bob) == coins("9") - coins("8.5") - spent["fee"] and len(spent["inputs"]) == 3

    # Coins that came to different addresses are spent together only when no one address holds enough
    tom_coin = transfer(c, alice, [(for_tom, coins("6")), (for_tom, coins("6"))])
    c.add_to_mempool(tom_coin)
    mine(c, alice)
    pay(c, alice, for_ann, coins("10"))
    mine(c, alice)
    picked = transfer(c, bob, [(alice.address, coins("5"))])
    by_image = {u["key_image"]: u["address"] for u in owned(c, bob)}
    assert {by_image[i["key_image"]] for i in picked["inputs"]} == {1}, "one address can pay alone: only its coins are used"
    bigger = transfer(c, bob, [(alice.address, coins("11"))])
    assert {by_image[i["key_image"]] for i in bigger["inputs"]} == {1}, "address 1 holds 12 in two coins: still alone"
    both = transfer(c, bob, [(alice.address, coins("20"))])
    assert {by_image[i["key_image"]] for i in both["inputs"]} == {1, 2}, "only when no one address is enough are they mixed"

    # The Janus probe: someone holding two of bob's addresses builds an output with the keys of
    # one that lands on the other, hoping bob says "yes, that arrived".  It would land on address
    # 2; the anchor check refuses it, so bob's wallet does not see it at all.
    (C1, D1), (C2, D2) = keys[1], keys[2]
    anchor = os.urandom(privacy.ANCHOR_BYTES)
    r = privacy._ephemeral(anchor, C1, D1)
    point = C1 * r
    shared = hash_to_scalar("stealth", point, 0)
    probe = {"index": 0, "one_time_pub": (G * shared + D2).hex(), "ephemeral_pub": (D1 * r).hex(),
             "view_tag": privacy._view_tag(point, 0), "enc_anchor": privacy._xor(anchor, privacy._anchor_mask(point, 0)).hex(),
             "commitment": commit(coins("1"), 0).hex(), "amount": coins("1")}
    view = bob.view_key()
    assert view._lookup(Point.from_hex(probe["one_time_pub"]) - G * shared) == 2, "without the check it would land on address 2"
    assert view.open(probe) is None, "the anchor check refuses it"

    # the view tag: for an output that is not its own, a wallet stops after one byte nearly every time
    stranger = Wallet.generate(PREFIX).view_key()
    outputs = [u["output"] for u in c.all_outputs()]
    matched = sum(privacy._view_tag(stranger.shared_point(o["ephemeral_pub"]), o["index"]) == o["view_tag"] for o in outputs)
    assert matched <= 2, "%d of %d tags matched a stranger's key; about 1 in 256 should" % (matched, len(outputs))

    # an address from before 0.6 is refused with a reason, not paid into the void
    raw = keys[0][0].encode() + keys[0][1].encode()
    legacy = PREFIX + privacy.b58encode(raw + privacy._checksum(PREFIX, raw))
    assert not is_valid_address(legacy, PREFIX)
    expect_error(lambda: decode_address(legacy, PREFIX), "before Vesper 0.6")


def test_a_payment_can_be_proved_to_one_person():
    """The payer (from the secret it kept) and the receiver (from its view key) can each show
    one person that one output paid one address an amount - and nobody can fake such a proof."""
    import proofs
    c = new_chain()
    alice, shop, eve = (Wallet.generate(PREFIX) for _ in range(3))
    mine(c, alice, RING + 1)
    _, till = shop.new_address("till 2")
    kept: list = []
    tx = build_transfer(alice.keys, spendable(c, alice), [(till, coins("7.5"))], None, PREFIX, rings_of(c), c.ring_size,
                        min_fee=c.min_fee_units, sent=kept)
    c.add_to_mempool(tx)
    mine(c, alice)
    assert len(kept) == 1 and kept[0]["address"] == till and kept[0]["amount"] == coins("7.5"), "the change is not logged"
    out = tx["outputs"][kept[0]["index"]]
    paid = proofs.payment_proof(tx["txid"], kept[0]["index"], till, scalar_from_hex(kept[0]["r"]), PREFIX)
    assert proofs.check_proof(paid, out, PREFIX) == coins("7.5"), "the payer proves 7.5 to the shop's till address"
    opened = shop.view_key().open(out)
    got = proofs.receipt_proof(tx["txid"], out["index"], shop.keys.address_at(opened["address"]), out["ephemeral_pub"],
                               shop.keys.view_priv, PREFIX)
    assert proofs.check_proof(got, out, PREFIX) == coins("7.5"), "and the shop can prove the receipt itself"
    other = tx["outputs"][1 - kept[0]["index"]]
    attempts = [
        (dict(paid, address=eve.address), out, "another address"),
        (dict(paid, shared=(Point.from_hex(paid["shared"]) + G).hex()), out, "a made-up shared point"),
        (dict(paid, index=other["index"]), other, "the same proof moved to the change output"),
        (dict(paid, kind="receipt"), out, "a payer's proof passed off as a receipt"),
        (proofs.payment_proof(tx["txid"], kept[0]["index"], till, random_scalar(), PREFIX), out, "a proof without the real secret"),
        (proofs.receipt_proof(tx["txid"], out["index"], eve.address, out["ephemeral_pub"], eve.keys.view_priv, PREFIX), out,
         "a stranger claiming the receipt"),
    ]
    for forged, target, what in attempts:
        try:
            proofs.check_proof(forged, target, PREFIX)
            raise AssertionError("a forged proof passed: %s" % what)
        except ValueError:
            pass


def test_what_the_chain_still_leaks():
    """Honest accounting of the current privacy level.  Update this test when it changes."""
    c = new_chain()
    alice, bob = Wallet.generate(PREFIX), Wallet.generate(PREFIX)
    mine(c, alice, RING + 5)
    tx = pay(c, alice, bob.address, coins("12"))
    assert c.info()["privacy"] == {"receivers_hidden": True, "amounts_hidden": True, "senders_hidden": True}
    assert tx["fee"] == c.min_fee_units, "the fee is public (the miner must be able to claim it); wallets all pay the same one"
    assert len(tx["inputs"][0]["ring"]) == c.ring_size, "the sender hides among ring_size outputs - a small crowd, not the whole chain"
    assert (len(tx["inputs"]), len(tx["outputs"])) == (1, 2), "how many inputs and outputs a payment has is visible"
    assert c.blocks[1]["transactions"][0]["outputs"][0]["amount"] == coins("50"), "mining rewards are public amounts by design"
    assert "timestamp" not in tx, "no longer leaked: when the payment was made"
    two = transfer(c, alice, [(bob.address, coins("70"))], inputs=owned(c, alice)[1:3])
    images = [i["key_image"] for i in two["inputs"]]
    assert images == sorted(images), "no longer leaked: which input the wallet picked first (the biggest)"
    assert len({o["ephemeral_pub"] for o in tx["outputs"]}) == len(tx["outputs"]), "every output its own R: nothing ties outputs together"
    block = mine(c, alice)
    assert isinstance(block["timestamp"], int), "which block a payment landed in, and that block's time, is visible"
    # not on the chain at all, but true: the node a wallet talks to sees its IP address, and a
    # node's peers see the node's.  Phase 4 (relay.py) stops the FIRST BROADCAST from pointing at
    # the sender; --proxy (socksproxy.py) hides a node's address from its peers behind Tor.  Nothing
    # is encrypted without Tor.  leaktest.py measures the rest.


# ----------------------------------------------------------------------------- development fund
def test_development_fund_is_enforced_and_public():
    fund, miner, eve, bob = (Wallet.generate(PREFIX) for _ in range(4))
    rules = deep_merge(CONFIG, {"consensus": {"dev_fund": {"percent": 10, "duration_blocks": 3, "address": fund.address}}})
    c = new_chain(config=rules)
    assert new_chain().dev_fund_info()["enabled"] is False and len(mine(new_chain(), miner)["transactions"][0]["outputs"]) == 1, "off unless configured"
    assert c.blocks[0]["hash"] != new_chain().blocks[0]["hash"], "a coin with a fund is a different coin from block 0"

    block = mine(c, miner)
    outs = block["transactions"][0]["outputs"]
    assert [o["amount"] for o in outs] == [coins("45"), coins("5")], "reward 50 must split 45 / 5"
    assert balance(c, miner) == coins("45") and balance(c, fund) == coins("5")
    assert verify_auditable_output(outs[1], fund.address, PREFIX), "anyone must be able to verify the fund was paid"
    assert not verify_auditable_output(outs[1], eve.address, PREFIX) and not verify_auditable_output(outs[0], fund.address, PREFIX)
    assert "ephemeral_secret" not in outs[0], "the miner's own output stays private"
    assert fund.address not in json.dumps(block)
    expect_error(lambda: eve.keys.sign_input(outs[1], b"x"), "does not own")       # knowing the secret is not owning the coins
    expect_error(lambda: miner.keys.sign_input(outs[1], b"x"), "does not own")

    def coinbase(fund_address, fund_amount):
        height = len(c.blocks)
        return make_coinbase_tx(miner.address, c.reward_at(height), height, PREFIX, fund_address, fund_amount)

    expect_error(lambda: c.add_block(block_with(c, miner, [], coinbase("", 0))), "development fund", "exactly once")
    expect_error(lambda: c.add_block(block_with(c, miner, [], coinbase(fund.address, coins("4")))), "development fund", "exactly")
    expect_error(lambda: c.add_block(block_with(c, miner, [], coinbase(eve.address, coins("5")))), "development fund", "published address")
    stripped = coinbase(fund.address, coins("5"))
    del stripped["outputs"][1]["ephemeral_secret"]
    expect_error(lambda: c.add_block(block_with(c, miner, [], retxid(stripped))), "development fund")
    mine(c, miner, 2)                                  # blocks 2 and 3: the fund's last
    info = c.dev_fund_info()
    assert info["total_received"] == info["unspent"] == info["lifetime_total"] == coins("15") and info["spent"] == 0
    assert info["active"] is False and info["blocks_remaining"] == 0
    expect_error(lambda: c.add_block(block_with(c, miner, [], coinbase(fund.address, coins("5")))), "development fund", "no fund payment")
    block = mine(c, miner, 2)                          # blocks 4 and 5: the fund has ended
    assert [o["amount"] for o in block["transactions"][0]["outputs"]] == [coins("50")]

    # THE GLASS BOX: fund outputs never hide in rings, and are spent by name, in the open
    fund_outputs = owned(c, fund)
    assert len(fund_outputs) == 3 and all("ephemeral_secret" in u["output"] for u in fund_outputs)
    mine_out = owned(c, miner)[0]
    honest = transfer(c, miner, [(bob.address, coins("1"))], inputs=[mine_out])
    ring = honest["inputs"][0]["ring"]
    with_fund = sorted([r for r in ring if r != ref_of(mine_out)][: RING - 2] + [ref_of(mine_out), ref_of(fund_outputs[0])])
    expect_error(lambda: c.add_to_mempool(tampered(honest, lambda t: t["inputs"][0].update(ring=with_fund))), "cannot be ring members")
    spend = transfer(c, fund, [(bob.address, coins("3"))])
    assert set(spend["inputs"][0]) == {"txid", "index", "signature"}, "the fund must spend by naming its output"
    thief = tampered(spend, lambda t: t["inputs"][0].update(signature=sign(12345, tx_signing_bytes(t))))
    expect_error(lambda: c.add_to_mempool(thief), "bad signature on development fund input")
    c.add_to_mempool(spend)
    expect_error(lambda: c.add_to_mempool(tampered(spend, lambda t: t.update(fee=t["fee"] + 1))), "already spent")
    mine(c, miner)
    info = c.dev_fund_info()
    assert balance(c, bob) == coins("3") and balance(c, fund) == coins("12") - c.min_fee_units
    assert info["unspent"] == coins("10") and info["spent"] == coins("5") and info["total_received"] == coins("15")
    # ...and the fund's CHANGE is an ordinary sealed output, which it then spends through a ring like anyone
    change = [u for u in owned(c, fund) if "ephemeral_secret" not in u["output"]]
    assert len(change) == 1 and change[0]["amount"] == coins("2") - c.min_fee_units
    again = transfer(c, fund, [(bob.address, coins("1"))], inputs=change)
    assert set(again["inputs"][0]) == RING_INPUT_KEYS
    c.add_to_mempool(again)
    mine(c, miner)
    assert balance(c, bob) == coins("4") and c.dev_fund_info()["spent"] == coins("5")
    expect_error(lambda: new_chain().replace_chain(c.blocks), "genesis")
    assert new_chain(config=rules).replace_chain(c.blocks) is True, "a fresh node with the same rules accepts the chain"


# ----------------------------------------------------------------------------- speed
def test_two_different_blocks_never_share_an_id():
    """Bitcoin's transaction tree pairs an odd last entry with a copy of itself, so a block and
    a twin that repeats its last transaction hash to the same ID (CVE-2012-2459)."""
    a, b, d = (hashlib.sha256(bytes([i])).hexdigest() for i in range(3))
    assert merkle_root([a, b, d]) != merkle_root([a, b, d, d]), "repeating the last transaction must change the root"
    assert merkle_root([a]) != a and merkle_root([a, a]) != merkle_root([a])
    assert merkle_root([merkle_root([a, b]), d]) != merkle_root([a, b, d]), "an inner node must not pass for a transaction"
    assert len({merkle_root(x) for x in ([a], [a, b], [b, a], [a, b, d], [a, d, b], [a, b, d, a])}) == 6
    c = new_chain()
    alice, bob = Wallet.generate(PREFIX), Wallet.generate(PREFIX)
    mine(c, alice, RING + 2)
    one, two = owned(c, alice)[:2]
    txs = [transfer(c, alice, [(bob.address, coins("1"))], inputs=[u]) for u in (one, two)]
    good = block_with(c, alice, txs)                    # coinbase + 2 payments: an odd number of entries
    twin = copy.deepcopy(good)
    twin["transactions"].append(copy.deepcopy(twin["transactions"][-1]))
    assert merkle_root([t["txid"] for t in twin["transactions"]]) != good["merkle_root"], "the twin cannot keep the block's ID"
    expect_error(lambda: c.add_block(twin), "repeats")
    c.add_block(good)
    assert balance(c, bob) == coins("2")


def test_rubbish_sent_under_a_real_blocks_id_cannot_shut_it_out():
    """A node must not remember a block by the ID its sender claims, or before checking it:
    otherwise anyone who has seen a new block can race rubbish with the same ID to other nodes
    and make them ignore the real one."""
    from node import Node
    tmp = tempfile.mkdtemp(prefix="vesper-test-")
    try:
        n = Node(CONFIG, tmp, "127.0.0.1", 0, [], None)
        c = new_chain()
        miner = Wallet.generate(PREFIX)
        mine(c, miner, 2)
        assert n.receive_block(copy.deepcopy(c.blocks[1])) is True
        real = c.blocks[2]
        same_header = copy.deepcopy(real)               # the real header (so the real ID and real work), other contents
        same_header["transactions"] = same_header["transactions"] * 2
        expect_error(lambda: n.receive_block(same_header), "repeats")
        claimed = copy.deepcopy(real)                   # another header that merely claims the real ID
        claimed["nonce"] += 1
        expect_error(lambda: n.receive_block(claimed), "hash")
        expect_error(lambda: n.receive_block({"hash": real["hash"], "index": 2}), "malformed")
        assert n.chain.height == 1
        assert n.receive_block(copy.deepcopy(real)) is True and n.chain.height == 2, "the real block must still get in"
        assert n.receive_block(copy.deepcopy(real)) is False, "and only once"
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def test_new_coins_must_age_before_they_are_used():
    """Every output a payment touches - its own coin and all the decoys - must be a few blocks
    old.  An output that young can still vanish in a reorganisation, and a ring with a
    vanished member cannot be checked: the payment would die with it."""
    LOCK = 3
    rules = deep_merge(CONFIG, {"consensus": {"output_lock_blocks": LOCK}})
    c = new_chain(config=rules)
    alice, bob, other = (Wallet.generate(PREFIX) for _ in range(3))
    mine(c, alice, RING)
    assert c.spendable_count() == RING - LOCK + 1 and spendable(c, alice) == owned(c, alice)[:RING - LOCK + 1]
    expect_error(lambda: transfer(c, alice, [(bob.address, coins("1"))]), "too young")
    mine(c, alice, LOCK - 1)
    assert c.spendable_count() == RING
    newest = [u for u in owned(c, alice) if u["output"]["height"] == c.height]
    oldest = [u for u in owned(c, alice) if u["output"]["height"] == 1]
    expect_error(lambda: transfer(c, alice, [(bob.address, coins("1"))], inputs=newest), "too new")
    # a wallet that ignores the rule is refused by every node: as the coin being spent ...
    cheat = forge(c, alice, newest, [(bob.address, coins("49")), (alice.address, coins("1") - c.min_fee_units)], c.min_fee_units)
    expect_error(lambda: c.add_to_mempool(cheat), "too new")
    expect_error(lambda: c.add_block(block_with(c, alice, [cheat])), "too new")
    # ... and as a decoy next to an old coin
    honest = transfer(c, alice, [(bob.address, coins("5"))], inputs=oldest)
    decoy = next(r for r in honest["inputs"][0]["ring"] if r != ref_of(oldest[0]))

    def young_decoy(tx):
        ring = tx["inputs"][0]["ring"]
        tx["inputs"][0]["ring"] = sorted([r for r in ring if r != decoy] + [ref_of(newest[0])])
    expect_error(lambda: c.add_to_mempool(tampered(honest, young_decoy)), "too new")
    c.add_to_mempool(honest)
    mine(c, alice)
    assert balance(c, bob) == coins("5") and spendable(c, bob) == [], "received, but not spendable in the same breath"
    expect_error(lambda: transfer(c, bob, [(alice.address, coins("1"))]), "insufficient")
    mine(c, alice, LOCK - 1)
    assert len(spendable(c, bob)) == 1
    back = pay(c, bob, alice.address, coins("1"))
    block = mine(c, alice)
    assert back["txid"] in [t["txid"] for t in block["transactions"]]
    # What the rule buys.  Another branch replaces the last LOCK - 1 blocks, the one with bob's
    # payment among them.  Every output that payment used is older than the split, so it is
    # just as valid on the other branch and goes straight back into the queue.
    split = c.height - (LOCK - 1)
    assert all(c.state.outputs[r]["height"] <= split for r in back["inputs"][0]["ring"])
    rival = new_chain(config=rules)
    assert rival.replace_chain(c.blocks[:split + 1])
    mine(rival, other, LOCK)
    assert c.replace_chain(rival.blocks) is True and back["txid"] in c.mempool, "the payment must survive the reorganisation"
    block = mine(c, other)
    assert back["txid"] in [t["txid"] for t in block["transactions"]]


def test_switching_branches_costs_the_branch_not_the_chain():
    """A reorganisation undoes the losing blocks and checks the winning ones.  It does not
    replay the ledger from the first block, and it does not rewrite the chain file."""
    fund, miner, bob, other = (Wallet.generate(PREFIX) for _ in range(4))
    rules = deep_merge(CONFIG, {"consensus": {"dev_fund": {"percent": 10, "duration_blocks": 1000, "address": fund.address}}})
    tmp = tempfile.mkdtemp(prefix="vesper-test-")
    try:
        a = new_chain(tmp, config=rules)
        mine(a, miner, RING + 2)
        pay(a, miner, bob.address, coins("3"))
        mine(a, miner)
        split = a.height
        gone_1 = pay(a, miner, bob.address, coins("2"))
        gone_2 = pay(a, fund, bob.address, coins("1"))             # the fund spends in the open: that must be undone too
        mine(a, miner)
        mine(a, miner)
        b = new_chain(config=rules)
        assert b.replace_chain(a.blocks[:split + 1])
        mine(b, other, 3)

        def picture(chain):
            s = chain.state
            return (dict(s.outputs), list(s.outputs), list(s.order), set(s.key_images), set(s.fund_spent), s.fund_unspent,
                    dict(chain.known_txids), list(chain.output_counts), chain.work, chain.tip["hash"], sorted(chain.mempool))
        before = picture(a)
        # a branch with a bad block in it changes nothing at all
        bad = copy.deepcopy(b.blocks)
        bad[-1]["transactions"][0]["outputs"][0]["amount"] += 1
        expect_error(lambda: a.replace_chain(bad), "commitment")
        assert picture(a) == before, "a refused branch must leave no trace"
        # neither does a valid branch with no more work than ours
        assert a.replace_chain(b.blocks[:split + 3]) is False and picture(a) == before
        fork = a.begin_fork(split)
        for block in b.blocks[split + 1:]:
            fork.add(copy.deepcopy(block))
        assert picture(a) == before, "checking a branch must not touch the live ledger"
        # the switch: three new blocks checked, two old ones undone, nothing else looked at
        checks, size_kept = a.work_checks, a.blocks.ends[split]
        with open(os.path.join(tmp, "chain.jsonl"), "rb") as fh:
            kept = fh.read(size_kept)
        assert fork.commit() is True and a.work_checks == checks
        assert a.height == split + 3 and a.tip["hash"] == b.tip["hash"]
        assert set(a.mempool) == {gone_1["txid"], gone_2["txid"]}, "orphaned payments go back in the queue"
        # the result is exactly what replaying the winning chain from the first block gives
        state, known, work, counts = a.validate_chain(b.blocks)
        assert a.state.outputs == state.outputs and list(a.state.outputs) == list(state.outputs) and a.state.order == state.order
        assert a.state.key_images == state.key_images and a.state.fund_spent == state.fund_spent == set()
        assert a.state.fund_unspent == state.fund_unspent == a.dev_fund_total_at(a.height)
        assert a.known_txids == known and a.work == work == b.work and a.output_counts == counts
        assert [o["position"] for o in a.state.outputs.values()] == list(range(a.state.count()))
        # on disk: the part before the split was not rewritten, and a restart sees the new chain
        with open(os.path.join(tmp, "chain.jsonl"), "rb") as fh:
            data = fh.read()
        assert data[:size_kept] == kept and [json.loads(line)["hash"] for line in data.splitlines()] == [blk["hash"] for blk in a.blocks]
        again = new_chain(tmp, config=rules)
        assert again.tip["hash"] == b.tip["hash"] and set(again.mempool) == set(a.mempool) and again.work_checks == 0
        mine(again, other)
        assert balance(again, bob) == coins("6") and again.dev_fund_info()["spent"] == coins("5")
        # a branch that was checked while our chain kept growing is not thrown away: the switch
        # is redone against the chain as it is now
        longer = new_chain(config=rules)
        assert longer.replace_chain(again.blocks[:-1])
        mine(longer, miner, 3)
        fork = again.begin_fork(again.height - 1)
        for block in longer.blocks[again.height:]:
            fork.add(copy.deepcopy(block))
        mine(again, other)                                          # our own miner finds a block meanwhile
        expect_error(fork.commit, "moved on")
        assert again.switch_to(fork.common, fork.added, checked=True) is True and again.tip["hash"] == longer.tip["hash"]
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def test_old_blocks_stay_on_disk_not_in_memory():
    """A node holds only its newest blocks whole; an older one is read back from chain.jsonl
    when something asks for it.  Shown with KEEP = 3, so a short chain is enough."""
    tmp = tempfile.mkdtemp(prefix="vesper-test-")
    keep, cached = BlockStore.KEEP, BlockStore.CACHED
    BlockStore.KEEP, BlockStore.CACHED = 3, 2
    try:
        c = new_chain(tmp)
        alice, bob, carol = (Wallet.generate(PREFIX) for _ in range(3))
        mine(c, alice, RING + 1)
        paid = pay(c, alice, bob.address, coins("2"))
        mine(c, alice)
        split = c.height
        mine(c, alice, 6)
        assert len(c.blocks._whole) <= 4, "only the newest blocks (and the genesis block) stay whole in memory"
        with open(os.path.join(tmp, "chain.jsonl"), "rb") as fh:
            saved = [json.loads(line) for line in fh]
        assert [c.blocks[i] for i in range(len(c.blocks))] == saved == c.blocks[:], "old blocks read back exactly"
        assert c.get_block(saved[2]["hash"]) == saved[2] and c.find_tx(paid["txid"])[1] == split
        assert sum(len(b["outputs"]) for b in c.scan_page(1)["blocks"]) == c.state.count(), "a wallet can scan from block 1"
        assert c.blocks_from(1, 4) == saved[1:5]
        # a reorganisation that reaches back past the blocks held in memory
        rival = new_chain()
        assert rival.replace_chain(saved[:split + 1])
        mine(rival, carol, 8)
        assert c.replace_chain(rival.blocks) and c.tip["hash"] == rival.tip["hash"]
        assert paid["txid"] in c.known_txids and paid["txid"] not in c.mempool, "the shared part is untouched"
        assert [c.blocks[i]["hash"] for i in range(len(c.blocks))] == [b["hash"] for b in rival.blocks]
        again = new_chain(tmp)
        assert again.tip["hash"] == c.tip["hash"] and again.state.order == c.state.order and len(again.blocks._whole) <= 4
        # a block changed on disk behind a running node's back is refused, not served
        path = os.path.join(tmp, "chain.jsonl")
        with open(path, "rb") as fh:
            lines = fh.readlines()
        old = json.loads(lines[2])
        lines[2] = lines[2].replace(old["hash"].encode(), ("0" if old["hash"][0] != "0" else "1").encode() + old["hash"][1:].encode())
        with open(path, "wb") as fh:
            fh.writelines(lines)
        again.blocks._cache.clear()
        expect_error(lambda: again.blocks[2], "changed on disk")
    finally:
        BlockStore.KEEP, BlockStore.CACHED = keep, cached
        shutil.rmtree(tmp, ignore_errors=True)


def test_a_power_cut_while_saving_does_not_brick_the_chain():
    tmp = tempfile.mkdtemp(prefix="vesper-test-")
    try:
        c = new_chain(tmp)
        miner = Wallet.generate(PREFIX)
        mine(c, miner, 3)
        path = os.path.join(tmp, "chain.jsonl")
        with open(path, "ab") as fh:
            fh.write(b'{"index":4,"timestamp":17915')            # half a block: the write never finished
        again = new_chain(tmp)
        assert again.height == 3 and again.tip["hash"] == c.tip["hash"], "the torn block is dropped, the rest is kept"
        mine(again, miner)
        assert new_chain(tmp).height == 4, "and the file is whole again"
        # a clock that is now a day behind must not make the node throw away its own newest blocks
        real_time = time.time
        try:
            chain_module.time.time = lambda: real_time() - 86400
            behind = new_chain(tmp)
        finally:
            chain_module.time.time = real_time
        assert behind.height == 4 and behind.repaired is None, "blocks this node saved are not 'from the future'"
        with open(path, "rb") as fh:
            lines = fh.readlines()
        lines[2] = lines[2][:40] + b"\n"                        # damage in the MIDDLE is not forgiven
        with open(path, "wb") as fh:
            fh.writelines(lines)
        expect_error(lambda: new_chain(tmp), "corrupt")
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def test_a_wallet_reads_only_what_is_new():
    """A wallet keeps a notebook of what it has found, reads only the blocks after it, and
    never asks the node about a particular output - so syncing does not get slower as the
    chain grows, and the node learns nothing about which outputs are the wallet's."""
    c = new_chain()
    alice, bob, carol = (Wallet.generate(PREFIX) for _ in range(3))
    asked: list = []
    MARGIN = 2

    def fetch(start):
        asked.append(start)
        return json.loads(json.dumps(c.scan_page(start, max_blocks=3)))      # as it arrives over the network

    def hash_at(height):
        return c.blocks[height]["hash"] if 0 <= height <= c.height else None

    def same(found, wallet):
        def key(u):
            return ref_of(u), u["amount"], u["blinding"], u["key_image"], u["spent"]
        return sorted(map(key, found)) == sorted(map(key, wallet.scan(c.all_outputs(), c.state.key_images, c.state.fund_spent)))

    mine(c, alice, RING + 2)
    pay(c, alice, bob.address, coins("4"))
    mine(c, alice)
    found, book, tip = alice.sync(None, fetch, hash_at, margin=MARGIN)
    assert same(found, alice) and sum(u["spent"] for u in found) == 1
    assert asked == list(range(1, c.height + 1, 3)), "a first look reads every block once, a page at a time"
    assert tip["scanned"] == tip["output_count"] == c.state.count() and tip["height"] == c.height
    assert book["height"] == c.height - MARGIN and book["hash"] == c.blocks[book["height"]]["hash"]
    assert not any(u["spent"] for u in book["owned"]), "what a reorganisation could still undo is not written down"
    del asked[:]
    found, book, tip = alice.sync(book, fetch, hash_at, margin=MARGIN)
    assert same(found, alice) and asked == [book["height"] + 1]
    assert tip["scanned"] == c.state.count() - c.output_counts[book["height"]], "a second look reads only what came after the notebook"
    mine(c, carol, 6)
    found, book, _ = alice.sync(book, fetch, hash_at, margin=MARGIN)
    assert same(found, alice) and sum(u["spent"] for u in book["owned"]) == 1, "once it is deep enough, the spend is written down"
    assert book["height"] == c.height - MARGIN
    # a reorganisation inside the margin: the notebook was never wrong, the new blocks are simply read
    rival = new_chain()
    assert rival.replace_chain(c.blocks[:-1])
    mine(rival, bob, 2)
    assert c.replace_chain(rival.blocks)
    found, book, _ = alice.sync(book, fetch, hash_at, margin=MARGIN)
    assert same(found, alice) and same(bob.sync(None, fetch, hash_at, margin=MARGIN)[0], bob)
    # one deeper than the margin takes away the block the notebook stopped at: everything is read afresh
    deep = new_chain()
    assert deep.replace_chain(c.blocks[:book["height"]])
    mine(deep, carol, c.height - book["height"] + 2)
    assert c.replace_chain(deep.blocks)
    del asked[:]
    found, book, _ = alice.sync(book, fetch, hash_at, margin=MARGIN)
    assert asked[0] == 1 and same(found, alice) and book["hash"] == c.blocks[book["height"]]["hash"]
    # a view key alone finds the same payments but cannot tell what was spent
    seen, _, _ = sync_outputs(bob.view_key(), None, None, fetch, hash_at, margin=MARGIN)
    assert sum(u["amount"] for u in seen) == coins("4") and all(u["spent"] is None and u["key_image"] is None for u in seen)
    # the notebook lists what the wallet owns, so it is encrypted with the wallet's own keys
    tmp = tempfile.mkdtemp(prefix="vesper-test-")
    try:
        path = os.path.join(tmp, "alice.scan")
        alice.save_notebook(path, book)
        with open(path, "rb") as fh:
            raw = fh.read()
        assert alice.load_notebook(path) == book and bob.load_notebook(path) is None
        assert b"amount" not in raw and b"txid" not in raw
    finally:
        shutil.rmtree(tmp, ignore_errors=True)

    # Fetching a ring: the wallet's own coin is always asked for together with the decoys.
    class Spy(LocalRings):
        def __init__(self, *args):
            super().__init__(*args)
            self.positions, self.refs = [], []

        def by_positions(self, positions):
            self.positions.append(list(positions))
            return super().by_positions(positions)

        def by_refs(self, refs):
            self.refs.append(list(refs))
            return super().by_refs(refs)

    spy = Spy(c.all_outputs(), c.height + 1, c.output_lock)
    coin = [u for u in found if not u["spent"]][:1]
    memory: dict = {}
    tx = build_transfer(alice.keys, coin, [(bob.address, coins("1"))], None, PREFIX, spy, RING, min_fee=c.min_fee_units, known_rings=memory)
    assert coin[0]["output"]["position"] in spy.positions[0] and len(spy.positions[0]) >= RING and spy.refs == []
    again = build_transfer(alice.keys, coin, [(bob.address, coins("2"))], None, PREFIX, spy, RING, min_fee=c.min_fee_units, known_rings=memory)
    assert spy.refs == [tx["inputs"][0]["ring"]] and len(spy.positions) == 1, "a retry asks for the same whole ring, by name"
    assert again["inputs"][0]["ring"] == tx["inputs"][0]["ring"]
    c.add_to_mempool(tx)
    # and the node's lookup answers honestly about what does not exist
    answer = c.lookup_outputs([0, c.state.count(), -1, "x"], [ref_of(coin[0]), "nope:0"])
    assert [a is None for a in answer["positions"]] == [False, True, True, True] and [a is None for a in answer["refs"]] == [False, True]


def test_a_payment_that_arrives_mid_search_gets_into_that_block():
    """The miner used to keep searching for the block it had started, so a payment that came in
    one second later sat out that whole block.  Now the block is rebuilt around it."""
    c = new_chain(config=deep_merge(CONFIG, {"consensus": {"initial_difficulty": 3000}}))
    alice, bob = Wallet.generate(PREFIX), Wallet.generate(PREFIX)
    mine(c, alice, RING + 1)
    c.refresh_seconds = 0
    for _ in range(3):                                  # (a block found within the first few tries proves nothing: go again)
        tx = transfer(c, alice, [(bob.address, coins("2"))])
        version = c.mempool_version
        arrived = []

        def payment_arrives(_tries):
            if not arrived:
                arrived.append(c.add_to_mempool(tx))
        block = None
        while block is None:
            block = c.mine_block(alice.address, on_progress=payment_arrives)
        if arrived:
            break
    assert arrived and c.mempool_version > version
    assert tx["txid"] in [t["txid"] for t in block["transactions"]], "the payment must be in the block that was being searched for"
    assert balance(c, bob) == coins("2")


def test_phase4_the_first_broadcast_does_not_come_from_the_sender():
    """Five nodes in a line.  A wallet hands its payment to the first; it travels quietly along a
    stem and is first broadcast by the node that ends stems this epoch.  A stem node that swallows
    payments only delays one: the sender's node broadcasts it itself when its waiting time is up."""
    import relay
    from node import Node
    root = tempfile.mkdtemp(prefix="vesper-test-")
    try:
        base = os.path.join(root, "base")
        c = new_chain(base)
        alice, bob = Wallet.generate(PREFIX), Wallet.generate(PREFIX)
        mine(c, alice, RING + 4)
        coins_ = owned(c, alice)
        names = ["http://10.0.0.%d:8880" % i for i in range(5)]
        nodes = {}
        for i, url in enumerate(names):
            folder = os.path.join(root, "n%d" % i)
            shutil.copytree(base, folder)
            nodes[url] = Node(CONFIG, folder, "127.0.0.1", 0, [], None, public_url=url)
        first_seen: list = []

        def network(sender):
            def post(peer, path, payload, timeout=5):
                target = nodes.get(peer)
                if target is None:
                    return None
                if path == "/api/tx/stem":
                    return target.submit_tx(copy.deepcopy(payload), sender.url)
                if path == "/api/tx/fluff":
                    return {"new": target.receive_tx(copy.deepcopy(payload), sender.url)}
                return {}
            return post

        for i, url in enumerate(names):
            n = nodes[url]
            n.spawn = lambda fn, *args: fn(*args)                    # deliver at once, in order
            n._post = network(n)
            original = n.chain.add_to_mempool

            def watched(tx, n=n, original=original):
                added = original(tx)
                if added:
                    first_seen.append(n.url)
                return added
            n.chain.add_to_mempool = watched
            n.peers = {names[j] for j in (i - 1, i + 1) if 0 <= j < len(names)}
            n.router.epoch_ends = float("inf")
            n.router.diffuser = i == 3                               # node 3 ends stems this epoch
            n.router.relays = [names[i + 1]] if i + 1 < len(names) else [names[i - 1]]

        tx = transfer(c, alice, [(bob.address, coins("3"))], inputs=coins_[:1])
        assert nodes[names[0]].submit_tx(copy.deepcopy(tx), relay.LOCAL) == {"new": True, "relay": "stem"}
        assert first_seen[0] == names[3], "the first broadcast comes from the end of the stem, not the sender: %s" % first_seen
        assert all(tx["txid"] in n.chain.mempool for n in nodes.values()), "and then everyone has it"
        assert all(not n.stempool for n in nodes.values()), "once it is broadcast, every node lets go of its stem copy"

        # a node on the stem that passes nothing on
        nodes[names[1]]._post = lambda peer, path, payload, timeout=5: {}
        del first_seen[:]
        tx2 = transfer(c, alice, [(bob.address, coins("4"))], inputs=coins_[1:2])
        assert nodes[names[0]].submit_tx(copy.deepcopy(tx2), relay.LOCAL)["relay"] == "stem"
        assert first_seen == [] and tx2["txid"] in nodes[names[0]].stempool, "swallowed: nobody has broadcast it"
        sender = nodes[names[0]]
        deadline = sender.stempool[tx2["txid"]]["deadline"]
        assert deadline - time.time() >= relay.EMBARGO_OWN_BASE - 1, "the sender's own timer is the longest"
        assert sender.check_embargoes(now=deadline - 1) == 0, "nothing happens before the waiting time is up"
        assert sender.check_embargoes(now=deadline + 1) == 1 and first_seen[0] == names[0], \
            "then the sender's node broadcasts it itself: delayed, never lost"
        assert tx2["txid"] in sender.chain.mempool and tx2["txid"] in nodes[names[1]].chain.mempool

        # while a payment is on its stem, only this computer's own wallet is told it is waiting
        tx3 = transfer(c, alice, [(bob.address, coins("5"))], inputs=coins_[2:3])
        sender.submit_tx(copy.deepcopy(tx3), relay.LOCAL)
        image = tx3["inputs"][0]["key_image"]
        assert image in sender.pending_markers(local=True)["key_images"], "the wallet must not spend that coin again"
        assert image not in sender.pending_markers(local=False)["key_images"], "a stranger must not learn this node is on a stem"
        # and a second payment of the same coin is refused even while the first is still quiet
        twin = transfer(c, alice, [(bob.address, coins("6"))], inputs=coins_[2:3])
        expect_error(lambda: sender.submit_tx(copy.deepcopy(twin), relay.LOCAL), "same coin")
        # A stem that comes round in a circle (2 -> 3 -> 4 -> 2) is dropped without a word by the
        # node that already holds it.  The first timer to run out broadcasts it, and the sender's
        # timer is the longest, so that is nearly always a node that only passed it on.
        for url in names:
            nodes[url]._post = network(nodes[url])
        ring = [nodes[names[i]] for i in (2, 3, 4)]
        for i, n in enumerate(ring):
            n.peers = {ring[(i + 1) % 3].url, ring[(i - 1) % 3].url}
            n.router.relays = [ring[(i + 1) % 3].url]
            n.router.routes = {}
            n.router.diffuser = False
        del first_seen[:]
        tx5 = transfer(c, alice, [(bob.address, coins("8"))], inputs=coins_[4:5])
        started = time.time()
        assert ring[0].submit_tx(copy.deepcopy(tx5), relay.LOCAL)["relay"] == "stem"
        assert first_seen == [] and all(tx5["txid"] in n.stempool for n in ring), "a circle ends quietly"
        deadlines = {n.url: n.stempool[tx5["txid"]]["deadline"] - started for n in ring}
        assert deadlines[ring[0].url] >= relay.EMBARGO_OWN_BASE - 1 and min(deadlines.values()) >= relay.EMBARGO_BASE - 1
        first = min(ring, key=lambda n: deadlines[n.url])
        assert first.check_embargoes(now=started + deadlines[first.url] + 0.01) == 1 and first_seen[0] == first.url
        assert all(tx5["txid"] in n.chain.mempool and tx5["txid"] not in n.stempool for n in ring), "then everyone has it"

        # Asking a node "do you hold this payment?" gets the same answer either way, at once,
        # before anything is checked; the work comes after, and a payment it holds is dropped.
        probe = nodes[names[1]]
        probe.peers = {names[0], names[2]}
        queued: list = []
        probe.spawn = lambda fn, *args: queued.append((fn, args))
        held = transfer(c, alice, [(bob.address, coins("2"))], inputs=coins_[5:6])
        probe.submit_tx(copy.deepcopy(held), relay.LOCAL)
        fresh = transfer(c, alice, [(bob.address, coins("1"))], inputs=coins_[6:7])
        del queued[:]
        answers = [probe.accept_stem(copy.deepcopy(t), names[0], "10.0.0.0", False) for t in (held, fresh)]
        assert answers[0] == answers[1] == {"new": None, "relay": "stem"}, "the answer must not depend on what the node holds"
        assert len(queued) == 2 and fresh["txid"] not in probe.stempool, "nothing is checked before answering"
        probe.spawn = lambda fn, *args: None
        for fn, args in queued:
            fn(*args)
        assert fresh["txid"] in probe.stempool and probe.bans.points == {}, "afterwards: the new one goes on, the held one is dropped quietly"
        # the same question through the wallet's door, from another computer: the same answer as for a new payment
        assert probe.submit_tx(copy.deepcopy(held), relay.LOCAL, discreet=True) == {"new": True, "relay": "stem"}
        assert probe.submit_tx(copy.deepcopy(held), relay.LOCAL) == {"new": False, "relay": "stem"}, "this computer may know"
        # with nobody to pass it to, the node has to broadcast it, and says so
        loner = nodes[names[4]]
        loner.peers = set()
        tx4 = transfer(c, alice, [(bob.address, coins("7"))], inputs=coins_[3:4])
        assert loner.submit_tx(copy.deepcopy(tx4), relay.LOCAL)["relay"] == "fluff"
    finally:
        shutil.rmtree(root, ignore_errors=True)


def test_phase4_limits_and_bans():
    """No address may ask a node for more than its share, and one that sends blocks or payments
    that break the rules is ignored for an hour.  This computer is never limited."""
    from node import Node, Refused
    from relay import BanList, RateLimiter
    now = [1000.0]
    limits = RateLimiter(clock=lambda: now[0])
    rate, burst = RateLimiter.LIMITS["tx"]
    assert all(limits.allow("203.0.113.5", "tx") for _ in range(burst)) and not limits.allow("203.0.113.5", "tx")
    assert limits.allow("198.51.100.7", "tx"), "every address has its own allowance"
    assert limits.allow("203.0.113.5", "read"), "and every kind of request its own"
    now[0] += 1.0
    assert sum(limits.allow("203.0.113.5", "tx") for _ in range(10)) == int(rate), "then it refills at the steady rate"
    bans = BanList(clock=lambda: now[0])
    assert not bans.penalise("192.0.2.9", 50) and not bans.banned("192.0.2.9"), "one bad block is not yet a ban"
    assert bans.penalise("192.0.2.9", 50) and bans.banned("192.0.2.9")
    now[0] += BanList.BAN_SECONDS
    assert not bans.banned("192.0.2.9"), "an hour later it is forgiven"
    assert not bans.penalise("192.0.2.10", 50)
    now[0] += BanList.HALF_LIFE
    assert not bans.penalise("192.0.2.10", 50) and not bans.banned("192.0.2.10"), "points fade: 25 + 50 is no ban"
    small = RateLimiter(clock=lambda: now[0])
    small.MAX_TRACKED = 100
    for i in range(1000):                          # a crowd of addresses costs memory for the newest 100 only
        small.allow("10.1.%d.%d" % (i // 256, i % 256), "read")
    assert len(small.buckets) == 100 and ("10.1.3.231", "read") in small.buckets

    tmp = tempfile.mkdtemp(prefix="vesper-test-")
    quiet = logging.getLogger("node")
    level = quiet.level
    quiet.setLevel(logging.ERROR)                  # the ban warning is expected here
    try:
        node = Node(CONFIG, tmp, "127.0.0.1", 0, [], None)

        def refused(address, kind, local=False):
            try:
                node.admit(address, kind, local)
                return None
            except Refused as exc:
                return exc.status
        statuses = [refused("203.0.113.5", "block") for _ in range(RateLimiter.LIMITS["block"][1] + 1)]
        assert statuses[:-1] == [None] * RateLimiter.LIMITS["block"][1] and statuses[-1] == 429
        assert refused("203.0.113.5", "block", local=True) is None, "this computer is never limited"
        node.penalise("192.0.2.66", BanList.BAN_POINTS, False, "test")
        assert refused("192.0.2.66", "read") == 403
        node.penalise("127.0.0.1", 10 ** 6, True, "test")
        assert refused("127.0.0.1", "read", local=True) is None, "and never banned"
    finally:
        quiet.setLevel(level)
        shutil.rmtree(tmp, ignore_errors=True)


def test_a_node_nobody_can_reach_hands_over_its_branch():
    """A node behind a home router or Tor cannot be reached, so a seed that falls behind it
    could never fetch its blocks and the two would stay on different branches for good (it
    happened on testnet-1).  Now the node hands its heavier side over itself, a batch at a
    time, every block checked on arrival.  Also: a node does not mine while it catches up,
    and only one process can use a data folder."""
    import node as node_module
    from urllib.parse import parse_qs, urlparse
    from chain import lock_data_dir
    from node import Node
    tmp_a, tmp_b = tempfile.mkdtemp(prefix="vesper-test-"), tempfile.mkdtemp(prefix="vesper-test-")
    old_batch = node_module.SYNC_BATCH
    try:
        seed = Node(CONFIG, tmp_a, "127.0.0.1", 0, [], None, public_url="http://8.8.4.4:8880")
        home = Node(CONFIG, tmp_b, "127.0.0.1", 0, [], None, public_url="http://8.8.8.8:8880")
        for n in (seed, home):
            n._post = lambda *args, **kwargs: None
        mine(seed.chain, Wallet.generate(PREFIX), 3)
        assert home.chain.replace_chain(seed.chain.blocks[:])
        mine(seed.chain, Wallet.generate(PREFIX), 2)                 # the seed's side: 2 blocks
        mine(home.chain, Wallet.generate(PREFIX), 5)                 # the home node's side: 5, more work

        def seed_answers(peer, path, timeout=5):                     # home can reach the seed ...
            if path == "/api/info":
                return seed.info()
            if path.startswith("/api/hashes"):
                q = parse_qs(urlparse(path).query)
                start, limit = int(q["start"][0]), int(q["limit"][0])
                return {"height": seed.chain.height, "hashes": seed.chain.blocks.hashes[start:start + limit]}
            raise OSError("no such page")
        home._get = seed_answers
        home._request = lambda peer, method, path, payload=None, timeout=5: \
            seed.receive_branch(json.loads(json.dumps(payload))["blocks"], "203.0.113.7")
        node_module.SYNC_BATCH = 2                                   # ... and hands over its side in several batches
        assert home.push_to("http://8.8.4.4:8880") is True
        assert seed.chain.tip["hash"] == home.chain.tip["hash"], "the seed must end up on the heavier side"
        assert seed.chain.forks == {"reorganisations": 1, "blocks_orphaned": 2, "competing_blocks_lost": 0}, seed.chain.forks
        assert home.push_to("http://8.8.4.4:8880") is False, "nothing to hand over once both agree"
        # the other way round, over a slow link: the home node switches as soon as the seed's side
        # is heavier and fetches the rest batch by batch (one timeout no longer loses it all)
        mine(seed.chain, Wallet.generate(PREFIX), 6)
        mine(home.chain, Wallet.generate(PREFIX), 1)

        def seed_serves(peer, path, timeout=5):
            if path.startswith("/api/blocks"):
                q = parse_qs(urlparse(path).query)
                return {"height": seed.chain.height,
                        "blocks": json.loads(json.dumps(seed.chain.blocks_from(int(q["start"][0]), int(q["limit"][0]))))}
            return seed_answers(peer, path, timeout)
        home._get = seed_serves
        assert home.sync_from("http://8.8.4.4:8880") is True
        assert home.chain.tip["hash"] == seed.chain.tip["hash"], "after the early switch the rest must follow"
        expect_error(lambda: seed.receive_branch([dict(seed.chain.tip, index=999, previous_hash="00" * 32)], "203.0.113.8"),
                     "does not start")
        expect_error(lambda: seed.receive_branch([{"index": 1}], "203.0.113.8"), "malformed")
        expect_error(lambda: seed.receive_branch([seed.chain.tip] * 3, "203.0.113.8"), "batches")
        # no mining while catching up, nor before the peers have been asked once
        home.first_sync_done.clear()
        home.miner.started_at = time.time()
        assert not home.miner.may_mine()
        home.first_sync_done.set()
        home.catching_up.set()
        assert not home.miner.may_mine()
        home.catching_up.clear()
        assert home.miner.may_mine()
        # one process per data folder
        held = lock_data_dir(tmp_a)
        expect_error(lambda: lock_data_dir(tmp_a), "already using")
        held.close()
        lock_data_dir(tmp_a).close()
    finally:
        node_module.SYNC_BATCH = old_batch
        shutil.rmtree(tmp_a, ignore_errors=True)
        shutil.rmtree(tmp_b, ignore_errors=True)


def test_the_smooth_curve_and_tail_pay_what_they_promise():
    """consensus.emission (the plan for mainnet, on test networks from testnet-2): a curve with no
    halving day, then a tail that steps down and never ends.  Small numbers, the real rule."""
    rules = {"main_curve": "1000", "curve_shift": 4, "tail_start": "2", "tail_step": "0.5", "tail_step_blocks": 10, "tail_floor": "1"}
    e = new_chain(config=deep_merge(CONFIG, {"consensus": {"emission": rules}}))
    rewards = [e.reward_at(h) for h in range(1, 400)]
    assert rewards[0] == coins("1000") >> 4 and rewards == sorted(rewards, reverse=True), "the reward only ever goes down"
    assert all(a - b < coins("7") for a, b in zip(rewards, rewards[1:])), "no halving day"
    assert rewards[-1] == coins("1") and min(rewards) == coins("1"), "the tail stops at its floor and stays there"
    assert coins("2") in rewards and coins("1.5") in rewards, "the tail steps down"
    assert e.supply_at(399) == sum(rewards) and e.max_supply() is None, "the supply adds up, and there is no cap"
    assert e.reward_at(37) == rewards[36] and e.reward_at(300) == rewards[299], "asking out of order changes nothing"
    wallet = Wallet.generate(PREFIX)
    mine(e, wallet, 3)
    assert balance(e, wallet) == sum(rewards[:3]) and e.circulating_supply() == sum(rewards[:3]), "blocks pay the curve"
    assert e.info()["blocks_until_halving"] is None and e.info()["max_supply"] is None
    assert new_chain(config=deep_merge(CONFIG, {"consensus": {"emission": rules}})).blocks.hash_at(0) != new_chain().blocks.hash_at(0), \
        "the curve is one of the rules hashed into the first block"
    expect_error(lambda: new_chain(config=deep_merge(CONFIG, {"consensus": {"emission": dict(rules, tail_floor="3")}})), "impossible")


def test_a_pool_with_no_operator_pays_every_member():
    """Mining together without a company in the middle (pool.py): members mine shares at an
    easier target, every block pays a draw of the recent shares, weighted by their work, straight
    to one-time keys their own wallets made, and a share that pays anyone the wrong amount, or
    builds on a share nobody has, is refused.  A pool block is an ordinary block: 16 outputs at most."""
    from pool import PoolError, ShareChain, draw, mine_share, split
    config = deep_merge(CONFIG, {"consensus": {"initial_difficulty": 32}})
    c = new_chain(config=config)
    members = {name: Wallet.generate(PREFIX) for name in ("ana", "ben", "cal")}
    shares = ShareChain(c, {"window": 12, "paid_shares": 15, "initial_share_difficulty": 4, "halflife_seconds": 0})
    expected, owners, names, made, found = dict.fromkeys(members, 0), {}, list(members), 0, 0
    while found < 2:
        name = names[made % 3]
        share, block = mine_share(shares, members[name].address)
        owners[share["stub"]["one_time_pub"]] = name
        shares.add(share)
        made += 1
        if block:
            c.add_block(block)                     # the node checks it like any other block
            found += 1
            for out in block["transactions"][0]["outputs"]:
                expected[owners[out["one_time_pub"]]] += out["amount"]
    assert sum(expected.values()) == c.reward_at(1) + c.reward_at(2)
    outputs = c.all_outputs()
    for name, wallet in members.items():
        assert sum(u["amount"] for u in scan_outputs(wallet.view_key(), outputs)) == expected[name], \
            "%s's wallet must find exactly its part of every block" % name
    assert len(owners) == made, "every share has its own payout key"
    mine(c, Wallet.generate(PREFIX), RING)                  # enough older outputs to hide a payment among
    carol = Wallet.generate(PREFIX)
    tx = pay(c, members["ana"], carol.address, coins("5"))  # a pool payout is spendable like any coin
    mine(c, Wallet.generate(PREFIX))
    assert tx["txid"] in c.known_txids and balance(c, carol) == coins("5"), "a pool payout must be spendable"
    share, _ = mine_share(shares, members["ana"].address)
    forged_stub = dict(share["stub"], view_tag="00" if share["stub"]["view_tag"] != "00" else "01")
    for bad, word in ((dict(share, stub=forged_stub), "draw picked"), (dict(share, parent="ab" * 32), "unknown parent")):
        try:
            shares.check(bad)
            raise AssertionError("a bad share was accepted")
        except PoolError as exc:
            assert word in str(exc), str(exc)
    assert split(10, [1, 1, 1]) == [3, 3, 4]
    won = draw([("light", 1), ("heavy", 3)], 4000, b"seed")          # the draw follows the work: 1 to 3, give or take
    assert sum(won) == 4000 and 850 < won[0] < 1150 and draw([("a", 1), ("b", 1)], 8, b"x") == draw([("a", 1), ("b", 1)], 8, b"x")
    # between nodes (node.py --pool): a node that missed the shares a share builds on is handed them
    from node import Node
    pool_config = deep_merge(config, {"pool": {"enabled": True, "window": 12, "paid_shares": 15, "initial_share_difficulty": 4, "halflife_seconds": 0}})
    tmp_a, tmp_b = tempfile.mkdtemp(prefix="vesper-test-"), tempfile.mkdtemp(prefix="vesper-test-")
    try:
        seed = Node(pool_config, tmp_a, "127.0.0.1", 0, [], None, public_url="http://8.8.4.4:8880")
        home = Node(pool_config, tmp_b, "127.0.0.1", 0, [], None, public_url="http://8.8.8.8:8880")
        home.spawn = lambda fn, *args: fn(*args)                       # hand shares over at once, in this thread
        home.peers = {"http://8.8.4.4:8880"}

        def to_seed(peer, method, path, payload=None, timeout=5):
            payload = json.loads(json.dumps(payload))
            if path == "/api/pool/share":
                return {"accepted": seed.receive_share(payload)}
            return seed.receive_shares(payload["shares"])
        home._request = to_seed
        first, _ = mine_share(home.sharechain, members["ben"].address)
        home.sharechain.add(first)                                     # the seed never heard of this one ...
        second, _ = mine_share(home.sharechain, members["ben"].address)
        home.on_share_mined(second, None)                              # ... so this one does not fit, and both are handed over
        assert seed.sharechain.tip == home.sharechain.tip and len(seed.sharechain.shares) == 2
        expect_error(lambda: Node(deep_merge(CONFIG, {"pool": {"enabled": True, "paid_shares": 16}}), tmp_a + "x",
                                  "127.0.0.1", 0, [], None), "config.json, pool")
    finally:
        shutil.rmtree(tmp_a, ignore_errors=True)
        shutil.rmtree(tmp_b, ignore_errors=True)


def test_phase4_one_peer_cannot_fill_the_peer_table():
    """Gossip only suggests addresses.  A node checks a couple per round, keeps its peers spread
    over different networks, sends nothing to home-network addresses it heard about, and passes
    stems only to peers it chose itself - so one attacker cannot take over its view of the
    network or the first hop of its payments."""
    import node as node_module
    from node import Node
    tmp = tempfile.mkdtemp(prefix="vesper-test-")
    try:
        n = Node(CONFIG, tmp, "127.0.0.1", 0, ["http://9.9.9.9:8880"], None, public_url="http://8.8.4.4:8880")
        genesis = n.chain.blocks.hash_at(0)
        answers = {}

        def fake_get(peer, path, timeout=5):
            if path == "/api/info" and peer in answers:
                return answers[peer]
            raise OSError("no such node")
        n._get = fake_get
        n._post = lambda *args, **kwargs: None
        flood = ["http://1.2.%d.%d:8880" % (i // 250, i % 250) for i in range(300)]            # one attacker's /16
        flood += ["http://192.168.0.%d:8880" % i for i in range(1, 20)] + ["http://127.0.0.1:%d" % p for p in range(9000, 9010)]
        budget = [node_module.GOSSIP_PER_PEER]
        for url in flood:
            n.consider(url, budget)
        assert len(n.candidates) == node_module.GOSSIP_PER_PEER, "one peer's list adds only a few candidates a round"
        assert all(node_module.address_kind(c) == "public" for c in n.candidates), "no home-network or local addresses from gossip"
        for url in list(n.candidates):
            answers[url] = {"genesis_hash": genesis}
        taken = sum(n.promote_candidates() for _ in range(5))
        assert taken == node_module.MAX_PER_GROUP and len(n.peers) == 1 + node_module.MAX_PER_GROUP, "two from one network block, no more"
        answers["http://4.4.4.4:8880"] = {"genesis_hash": "00" * 32}                          # another coin's node
        n.consider("http://4.4.4.4:8880", [1])
        assert n.promote_candidates() == 0 and "http://4.4.4.4:8880" not in n.peers, "a node on another chain is not taken"
        n.consider("http://5.5.5.5:8880", [1])
        assert n.promote_candidates() == 0, "nor one that does not answer"
        assert n.add_peer("http://6.6.6.6:8880", announce=False, origin="announced")
        assert "http://6.6.6.6:8880" not in n.relay_peers() and "http://9.9.9.9:8880" in n.relay_peers(), \
            "a peer that only introduced itself is never handed a stem"
        for _ in range(node_module.DROP_AFTER_FAILURES + 1):
            n.peer_failures["http://6.6.6.6:8880"] = n.peer_failures["http://9.9.9.9:8880"] = 10 ** 6
        n.sync_from = lambda peer: False
        n.sync_once()
        assert "http://6.6.6.6:8880" not in n.peers and "http://9.9.9.9:8880" in n.peers, "silent peers go, the ones you named stay"
        reloaded = Node(CONFIG, tmp, "127.0.0.1", 0, [], None, public_url="http://8.8.4.4:8880")
        assert reloaded.peer_origin == n.peer_origin, "who is who survives a restart"
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def test_phase4_peers_can_be_reached_through_tor():
    """With --proxy, every connection to a peer goes through a SOCKS5 proxy such as Tor, and the
    name lookup too; nothing is ever opened directly, and the node keeps its own address to
    itself.  A small SOCKS5 proxy stands in for Tor here."""
    import socketserver
    import threading
    from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
    from node import Node
    seen = {"proxy": [], "target": []}

    class Target(BaseHTTPRequestHandler):
        def do_GET(self):
            seen["target"].append(dict(self.headers))
            body = b'{"ok": true}'
            self.send_response(200)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *args):
            pass

    class Socks(socketserver.BaseRequestHandler):
        def handle(self):
            s = self.request
            s.recv(3)
            s.sendall(b"\x05\x00")
            head = s.recv(4)
            if head[3] == 3:
                host = s.recv(s.recv(1)[0]).decode()
            else:
                host = ".".join(str(b) for b in s.recv(4))
            port = int.from_bytes(s.recv(2), "big")
            seen["proxy"].append((head[3], host, port))
            out = socket.create_connection(("127.0.0.1" if host == "localhost" else host, port))
            s.sendall(b"\x05\x00\x00\x01" + bytes(6))
            def pump(a, b):
                try:
                    while True:
                        data = a.recv(65536)
                        if not data:
                            break
                        b.sendall(data)
                except OSError:
                    pass
                finally:
                    for x in (a, b):
                        try:
                            x.shutdown(socket.SHUT_RDWR)
                        except OSError:
                            pass
            other = threading.Thread(target=pump, args=(out, s), daemon=True)
            other.start()
            pump(s, out)
            other.join(5)

    import socket
    target = ThreadingHTTPServer(("127.0.0.1", 0), Target)
    proxy = socketserver.ThreadingTCPServer(("127.0.0.1", 0), Socks)
    proxy.daemon_threads = True
    for server in (target, proxy):
        threading.Thread(target=server.serve_forever, daemon=True).start()
    tmp = tempfile.mkdtemp(prefix="vesper-test-")
    try:
        rules = deep_merge(CONFIG, {"network": {"proxy": "socks5h://127.0.0.1:%d" % proxy.server_address[1]}})
        n = Node(rules, tmp, "127.0.0.1", 0, [], None)
        assert n.announce_url is None, "behind a proxy the node does not tell peers its address"
        peer = "http://localhost:%d" % target.server_address[1]
        assert n._get(peer, "/api/info") == {"ok": True}
        assert seen["proxy"] == [(3, "localhost", target.server_address[1])], "the proxy, not this computer, looked the name up"
        assert "X-Node-Url" not in seen["target"][0], "and no address of ours went along"
        closed = socket.socket()
        closed.bind(("127.0.0.1", 0))
        dead_port = closed.getsockname()[1]
        closed.close()
        blind = Node(deep_merge(CONFIG, {"network": {"proxy": "socks5h://127.0.0.1:%d" % dead_port}}), tmp, "127.0.0.1", 0, [], None)
        before = len(seen["target"])
        try:
            blind._get(peer, "/api/info")
            raise AssertionError("reached a peer although the proxy is down")
        except OSError:
            pass
        assert len(seen["target"]) == before, "with the proxy down, nothing goes out directly instead"
        assert Node(CONFIG, tmp, "127.0.0.1", 0, [], None).announce_url, "without a proxy the node introduces itself as before"
    finally:
        target.shutdown()
        proxy.shutdown()
        target.server_close()
        proxy.server_close()
        shutil.rmtree(tmp, ignore_errors=True)


def test_phase4_silent_connections_cannot_lock_the_node():
    """A few dozen connections that send nothing used to hold every slot forever ("slowloris").
    Now one address gets a handful of slots, a silent connection is closed after a while, and
    the node's own computer always gets in."""
    import socket
    import threading
    from node import CappedServer, Handler

    class Quick(Handler):
        timeout = 1

    class Strict(CappedServer):
        exempt = ()                                   # so the test, run from this computer, is limited too
        max_per_address = 3
    server = Strict(("127.0.0.1", 0), Quick)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        address = server.server_address
        idle = [socket.create_connection(address, timeout=5) for _ in range(3)]
        time.sleep(0.3)
        extra = socket.create_connection(address, timeout=5)
        assert extra.recv(1) == b"", "a fourth silent connection from the same address is closed at once"
        for sock in idle:
            sock.settimeout(5)
            assert sock.recv(1) == b"", "and silent ones are closed after the timeout"
        time.sleep(0.3)
        assert server._active == {}, "every slot is free again"
        server.exempt = ("127.0.0.1",)
        own = [socket.create_connection(address, timeout=5) for _ in range(6)]
        time.sleep(0.3)
        assert server._active.get("127.0.0.1") == 6, "the node's own computer is never turned away"
        for sock in own + idle + [extra]:
            sock.close()
    finally:
        server.shutdown()
        server.server_close()


def test_phase4_leak_measurement():
    """The network leak, measured with leaktest.py: the same routing code in a simulated network,
    an attacker running a fifth of the nodes and naming the first node that handed it each payment."""
    import leaktest
    plain = leaktest.run("broadcast", nodes=150, spy_share=0.2, payments=800, seed=5)
    stem = leaktest.run("stem", nodes=150, spy_share=0.2, payments=800, seed=5)
    assert stem["right"] < 0.8 * plain["right"], (plain, stem)
    assert stem["right"] < 0.3, "with the stem, the guess is right about as often as the attacker's share of nodes: %s" % stem


def test_decoys_look_like_real_spending():
    """Decoys are drawn as AGES from how people actually spend, then placed in the line of
    outputs with the chain's pace.  Measured with leaktest.py: on a busy chain a year old the old
    rank rule let an attacker name the real coin about a quarter of the time; this rule stays
    close to the fair 1 in 16."""
    import random as _random
    import leaktest
    rng = _random.Random(11)
    eligible, per_block, lock = 1_000_000, 40.0, 10
    positions = []
    for _ in range(250):
        positions += ringsig.draw_positions(eligible, set(), 8, per_block, lock, 30, rng)
    ages = sorted((eligible - 1 - p) / (per_block / 30) + lock * 30 for p in positions)
    model = sorted(ringsig.decoy_age(rng, lock * 30) for _ in range(len(ages)))
    day = 86400
    share = lambda xs: sum(1 for a in xs if a < day) / len(xs)
    assert abs(share(ages) - share(model)) < 0.05, "decoys younger than a day: %.2f, real spending: %.2f" % (share(ages), share(model))
    assert all(0 <= p < eligible for p in positions)
    old = leaktest.ring_leak("rank", 40, 1_051_200, payments=1500, seed=4)
    new = leaktest.ring_leak("time", 40, 1_051_200, payments=1500, seed=4)
    assert old["right"] > 0.15 and new["right"] < 0.10, (old, new)


def test_mining_on_several_cores_finds_valid_blocks():
    """Python threads cannot run proof-of-work tries side by side, so the miner uses worker
    processes (powpool.py).  Whatever they find is checked once more by the chain before use."""
    from powpool import PowPool
    c = new_chain(config=deep_merge(CONFIG, {"consensus": {"initial_difficulty": 200}}))
    miner = Wallet.generate(PREFIX)
    pool = PowPool(2, c.pow_algorithm, c.pow_memory_kib, c.pow_passes)
    try:
        for _ in range(3):
            block = None
            while block is None:
                block = c.mine_block(miner.address, pool=pool)
            assert c.proof_of_work_ok(block) and c.tip["hash"] == block["hash"]
        assert c.height == 3 and balance(c, miner) == coins("150")
        # a worker that lies about a find is not believed: the chain re-checks every nonce
        honest_step = pool.step
        pool.step = lambda head, tail, target, wait=0.5: 12345           # a nonce that does not meet the target
        tries = {"n": 0}

        def stop_soon():
            tries["n"] += 1
            return tries["n"] > 3
        assert c.mine_block(miner.address, pool=pool, should_abort=stop_soon) is None and c.height == 3
        pool.step = honest_step
    finally:
        pool.close()
    assert all(not w.is_alive() for w in pool.workers), "stopping the miner ends its worker processes"
    try:                                     # and a pool whose workers are gone says so (the node then mines on one core)
        pool.step(b"head", b"tail", 1, wait=0.2)
        raise AssertionError("a pool with no live workers must not go quiet")
    except RuntimeError:
        pass


def test_speed_report():
    c = new_chain(config=deep_merge(CONFIG, {"consensus": {"ring_size": REAL["ring_size"]}}))
    alice, bob = Wallet.generate(PREFIX), Wallet.generate(PREFIX)
    mine(c, alice, max(20, c.ring_size + 4))
    my = owned(c, alice)[:20]
    txs = []
    t = time.perf_counter()
    for u in my:
        txs.append(transfer(c, alice, [(bob.address, coins("1"))], inputs=[u]))
    build_ms = (time.perf_counter() - t) * 1000 / len(txs)
    t = time.perf_counter()
    for tx in txs:
        c.add_to_mempool(tx)
    accept_ms = (time.perf_counter() - t) * 1000 / len(txs)
    t = time.perf_counter()
    mine(c, bob)                                       # every proof was already checked on arrival
    own_block_ms = (time.perf_counter() - t) * 1000
    fresh = new_chain(config=c.config)
    assert fresh.replace_chain(c.blocks[:-1])
    t = time.perf_counter()
    fresh.add_block(copy.deepcopy(c.blocks[-1]))       # a node seeing these 20 payments for the first time
    fresh_block_ms = (time.perf_counter() - t) * 1000
    outputs = c.all_outputs()
    stranger = Wallet.generate(PREFIX)
    stranger.view_key().prepare()
    bob.view_key().prepare()
    t = time.perf_counter()
    assert stranger.scan(outputs) == []
    scan_ms = (time.perf_counter() - t) * 1000 / len(outputs)
    t = time.perf_counter()
    found = bob.scan(outputs, c.state.key_images)
    own_scan_ms = ((time.perf_counter() - t) * 1000 - scan_ms * (len(outputs) - len(found))) / len(found)
    assert len(found) == 21 and all(tx["txid"] in c.known_txids for tx in txs) and len(c.state.key_images) == 20
    size = len(json.dumps(txs[0], separators=(",", ":")))
    # the ledger grows forever; a waiting payment or a new block must not cost more because of it
    probe = transfer(c, bob, [(alice.address, coins("0.5"))], inputs=owned(c, bob)[:1])
    c.validate_transfer(probe, c.pending_state(), c.height + 1)      # first look: the full check, remembered by txid
    for i in range(200_000):
        c.state.outputs["%064x:0" % i] = {}
        c.state.key_images.add("%064x" % i)
    t = time.perf_counter()
    for _ in range(50):
        c.validate_transfer(probe, c.pending_state(), c.height + 1)
    big_ledger_ms = (time.perf_counter() - t) * 20

    def fetch(start):
        return c.scan_page(start)

    def hash_at(height):
        return c.blocks[height]["hash"] if 0 <= height <= c.height else None
    _, book, _ = bob.sync(None, fetch, hash_at)
    t = time.perf_counter()
    _, _, tip = bob.sync(book, fetch, hash_at)
    sync_ms = (time.perf_counter() - t) * 1000
    # a one-block reorganisation on that 200,000-output ledger: undo a 20-payment block, take two others
    rival = new_chain(config=c.config)
    assert rival.replace_chain(c.blocks[:-1])
    mine(rival, alice, 2)
    t = time.perf_counter()
    assert c.replace_chain(rival.blocks) and len(c.mempool) == 20
    reorg_ms = (time.perf_counter() - t) * 1000
    t = time.perf_counter()
    for i in range(10):
        pow_digest(b"header %d" % i, REAL["pow"]["algorithm"], REAL["pow"]["memory_kib"], REAL["pow"]["passes"])
    work_ms = (time.perf_counter() - t) * 100
    print("      curve maths: %s, ring size %d" % (curve.BACKEND, c.ring_size))
    print("      one proof-of-work try (%s, %d MiB)        %7.1f ms  = about %d tries a second per core" % (
        REAL["pow"]["algorithm"], REAL["pow"]["memory_kib"] // 1024, work_ms, 1000 / work_ms))
    print("      build a payment (seal, prove, ring-sign)        %7.1f ms" % build_ms)
    print("      node accepts a payment (all checks)             %7.1f ms" % accept_ms)
    print("      fresh node validates a 20-payment block         %7.1f ms  (%.1f ms per payment, range proofs batched)" % (fresh_block_ms, fresh_block_ms / 20))
    print("      mine a block of 20 already-seen payments        %7.1f ms  (nothing is re-checked)" % own_block_ms)
    print("      re-check a known payment, 200,000-output ledger  %7.3f ms  (does not grow with the chain)" % big_ledger_ms)
    print("      switch branches (undo 20 payments), same ledger %7.1f ms  (does not grow with the chain)" % reorg_ms)
    print("      wallet scans one output (someone else's)        %7.2f ms  (one of its own: %.2f ms)" % (scan_ms, own_scan_ms))
    print("      wallet looks again, nothing new                 %7.1f ms  (rereads the newest 20 blocks: %d outputs)" % (sync_ms, tip["scanned"]))
    print("      one payment on disk                             %7d bytes of JSON" % size)
    assert fresh_block_ms < 30000 and big_ledger_ms < 2, "validation cost must not depend on the size of the ledger"
    assert reorg_ms < 500, "a reorganisation must cost the two branches, not the whole chain"


TESTS = [
    test_both_curve_backends_agree_and_bad_points_are_refused,
    test_commitments_hide_bind_and_add_up,
    test_range_proofs_accept_honest_and_refuse_forged,
    test_ring_signatures_accept_owners_and_refuse_everyone_else,
    test_wallet_keys_addresses_and_files,
    test_mining_pays_the_miner_and_nobody_can_tell_who,
    test_payment_hides_receiver_amount_and_sender,
    test_double_spend_rejected,
    test_coins_cannot_be_created_out_of_nothing,
    test_forged_transactions_rejected,
    test_ring_rules_are_enforced,
    test_the_same_key_twice_is_two_coins_not_one,
    test_retrying_a_payment_reuses_the_same_ring,
    test_fee_grows_with_size,
    test_tampering_with_history_is_detected,
    test_longest_chain_wins_and_orphans_return,
    test_difficulty_follows_the_network_speed,
    test_timestamps_halving_amounts_and_genesis,
    test_proof_of_work_is_memory_hard_and_checked_once,
    test_a_restart_does_not_redo_the_heavy_work,
    test_saving_and_loading_from_disk,
    test_fee_priority_and_block_limit,
    test_two_different_blocks_never_share_an_id,
    test_rubbish_sent_under_a_real_blocks_id_cannot_shut_it_out,
    test_new_coins_must_age_before_they_are_used,
    test_switching_branches_costs_the_branch_not_the_chain,
    test_old_blocks_stay_on_disk_not_in_memory,
    test_a_power_cut_while_saving_does_not_brick_the_chain,
    test_a_wallet_reads_only_what_is_new,
    test_a_payment_that_arrives_mid_search_gets_into_that_block,
    test_phase4_the_first_broadcast_does_not_come_from_the_sender,
    test_phase4_limits_and_bans,
    test_phase4_one_peer_cannot_fill_the_peer_table,
    test_a_node_nobody_can_reach_hands_over_its_branch,
    test_a_pool_with_no_operator_pays_every_member,
    test_the_smooth_curve_and_tail_pay_what_they_promise,
    test_phase4_peers_can_be_reached_through_tor,
    test_phase4_silent_connections_cannot_lock_the_node,
    test_phase4_leak_measurement,
    test_decoys_look_like_real_spending,
    test_mining_on_several_cores_finds_valid_blocks,
    test_view_key_sees_amounts_but_cannot_spend,
    test_one_wallet_many_addresses_nobody_can_link,
    test_a_payment_can_be_proved_to_one_person,
    test_what_the_chain_still_leaks,
    test_development_fund_is_enforced_and_public,
    test_speed_report,
]


def main() -> int:
    disable_windows_power_throttling()       # or Windows may slow the whole run, and its timings, sixfold
    print("%s self-test  (%d checks, curve maths: %s)" % (CONFIG["coin"]["name"], len(TESTS), curve.BACKEND))
    print("-" * 60)
    failures = 0
    for test in TESTS:
        name = test.__name__[5:].replace("_", " ")
        try:
            test()
            print("PASS  %s" % name)
        except Exception:
            failures += 1
            print("FAIL  %s" % name)
            traceback.print_exc()
    print("-" * 60)
    if failures:
        print("%d of %d checks FAILED" % (failures, len(TESTS)))
        return 1
    print("All %d checks passed - the rules hold, and receivers, amounts and senders stay hidden." % len(TESTS))
    return 0


if __name__ == "__main__":
    sys.exit(main())
