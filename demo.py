"""demo.py - one private payment, step by step, with timings.     python demo.py"""

import json
import time

import curve
import rangeproof
import ringsig
from amounts import commit, value_generator
from chain import disable_windows_power_throttling, load_config
from curve import G, L, random_scalar
from privacy import StealthKeys, make_outputs, scan_outputs

CONFIG = load_config()                     # the network's own numbers: ring size, ticker, address prefix
COIN = 10 ** int(CONFIG["coin"]["decimals"])
T = CONFIG["coin"]["ticker"]
PFX = CONFIG["coin"]["address_prefix"]
RING = int(CONFIG["consensus"]["ring_size"])


def timed(label, fn, n=20):
    t = time.perf_counter()
    for _ in range(n):
        result = fn()
    print("   %-46s %8.2f ms" % (label, (time.perf_counter() - t) * 1000 / n))
    return result


disable_windows_power_throttling()           # keeps Windows from slowing the timings below
print("Curve maths: %s\n" % curve.BACKEND)

print("1. WHO.  Bob makes a wallet: two secret numbers, one long public address.")
bob = StealthKeys.generate(PFX)
print("   address: %s...%s" % (bob.address[:28], bob.address[-8:]))
alice_pays_1, _ = make_outputs([(bob.address, 5 * COIN)], PFX)
alice_pays_2, _ = make_outputs([(bob.address, 5 * COIN)], PFX)
print("   Alice pays him 5 %s twice. On the chain the two payments land at:" % (T))
print("     one-time key %s..." % alice_pays_1[0]["one_time_pub"][:32])
print("     one-time key %s..." % alice_pays_2[0]["one_time_pub"][:32])
print("   Same person, same amount, nothing in common. Bob's address appears nowhere.")
bob.watch(1)
for_carol = bob.address_at(1)
carol_pays, _ = make_outputs([(for_carol, 2 * COIN)], PFX)
print("   Bob gives Carol an address of her own:  %s...%s" % (for_carol[:28], for_carol[-8:]))
print("   It shares no key with his first one, and her payment still lands in his wallet:  %s" % (
    scan_outputs(bob.view_key(), [{"txid": "demo", "index": 0, "output": carol_pays[0]}])[0]["address"] == 1))

print("\n2. HOW MUCH.  The amount is sealed in a commitment: amount*H + blinding*G.")
print("     sealed 5 %s: %s..." % (T, alice_pays_1[0]["commitment"][:32]))
print("     sealed 5 %s: %s..." % (T, alice_pays_2[0]["commitment"][:32]))
print("   The same amount twice, and the two envelopes look nothing alike.")
print("   What a node stores for the payment (no name, no number):")
print("     " + json.dumps({k: (v[:14] + "...") for k, v in alice_pays_1[0].items() if isinstance(v, str)}))

print("\n3. WHO CAN OPEN IT.")
eve = StealthKeys.generate(PFX)
found = scan_outputs(bob.view_key(), [{"txid": "demo", "index": 0, "output": alice_pays_1[0]}])
print("   Eve, a stranger, scans it with her keys:        %s" % ("hers" if eve.owns(alice_pays_1[0]) else "not hers, cannot open"))
print("   Bob's VIEW key (what an accountant would hold): his, amount = %s %s" % (found[0]["amount"] / COIN, T))
print("   The view key has no spend key in it:            %s" % (not hasattr(bob.view_key(), "spend_priv")))

print("\n4. NO COINS FROM NOWHERE, without reading a single amount.")
b_in, b_out1, b_out2 = random_scalar(), random_scalar(), random_scalar()
leftover = commit(50 * COIN, b_in) - commit(20 * COIN, b_out1) - commit(30 * COIN, b_out2)
print("   50 in, 20 + 30 out:  what is left over is a plain public key:  %s" % (leftover == G * (b_in - b_out1 - b_out2)))
leftover = commit(50 * COIN, b_in) - commit(20 * COIN, b_out1) - commit(31 * COIN, b_out2)
print("   50 in, 20 + 31 out:  what is left over is a plain public key:  %s   <- one coin too many, nobody can sign this" % (leftover == G * (b_in - b_out1 - b_out2)))

print("\n5. THE LOOPHOLE, AND THE PROOF THAT CLOSES IT.")
print("   50 in, 100 + (minus 50) out balances too. So every envelope is covered by a range proof:")
blinding = random_scalar()
proof = rangeproof.prove(5 * COIN, blinding)
print("   honest proof for a sealed 5 %-5s verifies:           %s   (%d bytes)" % (T, rangeproof.verify(commit(5 * COIN, blinding), proof), rangeproof.proof_size_bytes(proof)))
minus_fifty = commit((-50 * COIN) % L, blinding)
print("   same proof on an envelope holding minus 50:          %s" % rangeproof.verify(minus_fifty, proof))
try:
    rangeproof.prove(-50 * COIN, blinding)
except ValueError as exc:
    print("   making a proof for minus 50:                         refused (%s)" % str(exc)[:38])
pair_blind = random_scalar()
pair = rangeproof.prove_many([20 * COIN, 30 * COIN], [blinding, pair_blind])
pair_ok = rangeproof.verify([commit(20 * COIN, blinding), commit(30 * COIN, pair_blind)], pair)
print("   a payment's two envelopes share ONE proof:           %s   (%d bytes, not 2 x %d)" % (pair_ok, rangeproof.proof_size_bytes(pair), rangeproof.proof_size_bytes(proof)))

print("\n6. WHICH COIN WAS SPENT.  A payment points at a ring of %d outputs and proves it owns one." % (RING))
N = RING
ring_secrets = [random_scalar() for _ in range(N)]
ring_keys = [G * x for x in ring_secrets]
ring_refs = ["%064x:0" % (i + 1) for i in range(N)]          # where each output sits on the chain
ring_blinds = [random_scalar() for _ in range(N)]
ring_amounts = [commit(5 * COIN, b) for b in ring_blinds]
real = 11                                              # Bob owns number 12; the other 15 are strangers' outputs
pseudo_blinding = random_scalar()
pseudo = commit(5 * COIN, pseudo_blinding)
ring_sig = ringsig.sign(b"pay carol", ring_refs, ring_keys, ring_amounts, pseudo, real, ring_secrets[real], (ring_blinds[real] - pseudo_blinding) % L)
marker = ringsig.key_image(ring_secrets[real], ring_refs[real], ring_keys[real].hex())
print("   signed by the owner of ONE of the %d:               verifies = %s" % (RING, ringsig.verify(b"pay carol", ring_refs, ring_keys, ring_amounts, pseudo, marker, ring_sig)))
print("   all the chain keeps of the spender: a spent marker  %s..." % marker.hex()[:32])
print("   which of the %d it was:                             nowhere (it was number %d; nothing written says so)" % (RING, real + 1))
print("   spend the same output again, same marker appears:   %s   <- that is how a double spend is caught" % (ringsig.key_image(ring_secrets[real], ring_refs[real], ring_keys[real].hex()) == marker))
print("   the same key paid a second time, elsewhere on the chain:  a different marker = %s   <- so both coins can be spent" % (ringsig.key_image(ring_secrets[real], "ff" * 32 + ":0", ring_keys[real].hex()) != marker))
stranger = random_scalar()
fake = ringsig.sign(b"pay carol", ring_refs, ring_keys, ring_amounts, pseudo, real, stranger, (ring_blinds[real] - pseudo_blinding) % L)
print("   someone who owns none of the %d signs anyway:       verifies = %s" % (RING, ringsig.verify(b"pay carol", ring_refs, ring_keys, ring_amounts, pseudo, ringsig.key_image(stranger, ring_refs[real], ring_keys[real].hex()), fake)))
richer = commit(500 * COIN, pseudo_blinding)
fake = ringsig.sign(b"pay carol", ring_refs, ring_keys, ring_amounts, richer, real, ring_secrets[real], (ring_blinds[real] - pseudo_blinding) % L)
print("   the real owner claims the coin is worth 500:        verifies = %s" % ringsig.verify(b"pay carol", ring_refs, ring_keys, ring_amounts, richer, marker, fake))

print("\n7. SPEED on this PC")
k = random_scalar()
H = value_generator()
timed("one curve multiplication", lambda: H * k, n=200)
timed("seal one amount (commitment)", lambda: commit(5 * COIN, k), n=200)
timed("prove one sealed amount is 0..2^64", lambda: rangeproof.prove(5 * COIN, blinding), n=5)
timed("verify one range proof alone", lambda: rangeproof.verify(commit(5 * COIN, blinding), proof), n=10)
timed("prove a payment's 2 amounts (one joint proof)", lambda: rangeproof.prove_many([20 * COIN, 30 * COIN], [blinding, pair_blind]), n=5)
timed("verify that joint proof alone", lambda: rangeproof.verify([commit(20 * COIN, blinding), commit(30 * COIN, pair_blind)], pair), n=10)
batch = [(commit(5 * COIN, blinding), proof)] * 40
t = time.perf_counter()
rangeproof.verify_batch(batch)
print("   %-46s %8.2f ms" % ("verify one range proof in a batch of 40", (time.perf_counter() - t) * 1000 / 40))
timed("sign as one of a ring of %d" % (RING), lambda: ringsig.sign(b"pay carol", ring_refs, ring_keys, ring_amounts, pseudo, real, ring_secrets[real], (ring_blinds[real] - pseudo_blinding) % L), n=10)
timed("verify a ring of %d" % (RING), lambda: ringsig.verify(b"pay carol", ring_refs, ring_keys, ring_amounts, pseudo, marker, ring_sig), n=10)
timed("wallet scans one output", lambda: bob.view_key().open(alice_pays_1[0]), n=200)
print("\nDone. Who was paid, how much, and which coin was spent are all gone from the chain.")
print("What is left to fix: the crowd is %d, not everyone (the next research step). On the network, a payment" % (RING))
print("now travels quietly from node to node before anyone broadcasts it (phase 4), but nothing between nodes")
print("is encrypted: use Tor or a VPN if who you are matters.")
