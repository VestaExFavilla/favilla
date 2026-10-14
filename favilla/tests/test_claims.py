#!/usr/bin/env python3
"""
Favilla adversarial consensus tests (SPEC §16, v0.5 — D13).

REGTEST ONLY. Spins up a local favillad, feeds it a simulated Bitcoin-regtest
header chain via `submitbitcoinheader`, builds burn transactions and v4 claim
transactions by hand, and checks accept/reject behavior against the spec.

D13 semantics exercised:
- D13a: every block at height >= 1 carries exactly one coinbase OP_RETURN
  commitment (0x6a 0x20 || 32-byte Bitcoin tip hash); zero hash = "no tip".
- D13b: V3 depth judged against the block's COMMITTED tip; unknown committed
  tip => block HELD as not-yet-validated (never cached invalid).
- D13c: Fire era by the burn's Bitcoin height (rate locked at burn time).
- D13d: Vigil spends additionally gated on the spending block's committed
  Bitcoin tip MTP >= burn_mtp + 126_000_000.
- D13e: claim_signature is a 65-byte compact recoverable STANDARD Bitcoin
  Signed Message signature over "FVLA-CLAIM" || magic || burn_txid.
- D13f: burn_tx cap 400_000 bytes.

Usage:
    python3 test_claims.py [--keep] [--node PATH]

  --keep   leave the datadir in /tmp/fvtest-* for inspection
  --node   path to bitcoind binary (default: ~/workspace/favilla/core/build/bin/bitcoind)

Requires: python3 `ecdsa` package.
"""

import argparse
import hashlib
import json
import os
import shutil
import struct
import subprocess
import sys
import tempfile
import time
import urllib.request

from ecdsa import SigningKey, SECP256k1, util
from ecdsa.ellipticcurve import Point

# ---------------------------------------------------------------- primitives

def sha256d(b: bytes) -> bytes:
    return hashlib.sha256(hashlib.sha256(b).digest()).digest()

def sha256(b: bytes) -> bytes:
    return hashlib.sha256(b).digest()

def compact(n: int) -> bytes:
    if n < 0xfd:
        return struct.pack("B", n)
    if n <= 0xffff:
        return b"\xfd" + struct.pack("<H", n)
    if n <= 0xffffffff:
        return b"\xfe" + struct.pack("<I", n)
    return b"\xff" + struct.pack("<Q", n)

def script_num(n: int) -> bytes:
    """Minimal CScriptNum encoding (must match Bitcoin Core byte-for-byte)."""
    if n == 0:
        return b""
    neg = n < 0
    n = abs(n)
    r = bytearray()
    while n:
        r.append(n & 0xFF)
        n >>= 8
    if r[-1] & 0x80:
        r.append(0x80 if neg else 0x00)
    elif neg:
        r[-1] |= 0x80
    return bytes(r)

def push(data: bytes) -> bytes:
    assert len(data) <= 75, "only small pushes needed in tests"
    return struct.pack("B", len(data)) + data

OP_CLTV, OP_DROP, OP_CHECKSIG = 0xB1, 0x75, 0xAC

def vigil_script(unlock: int, pubkey33: bytes) -> bytes:
    return push(script_num(unlock)) + bytes([OP_CLTV, OP_DROP]) + push(pubkey33) + bytes([OP_CHECKSIG])

def target_from_bits(bits: int) -> int:
    exp = bits >> 24
    mant = bits & 0xFFFFFF
    if exp <= 3:
        return mant >> (8 * (3 - exp))
    return mant << (8 * (exp - 3))

FURNACE_HASH160 = bytes.fromhex("e881fbbaf021322e69c396b9da2b554602d4fde9")
FURNACE_SPK = b"\x00\x14" + FURNACE_HASH160  # P2WPKH
NET_MAGIC = bytes([0x66, 0x76, 0x6c, 0x61])  # regtest pchMessageStart "fvla"
BTC_BITS = 0x207FFFFF  # bitcoin-regtest, no retargeting
VIGIL_BTC_SECONDS = 126_000_000  # SPEC §11.1 D13d

# ---------------------------------------------------------------- keys

def gen_key():
    sk = SigningKey.generate(curve=SECP256k1)
    vk = sk.get_verifying_key()
    x = vk.pubkey.point.x().to_bytes(32, "big")
    prefix = b"\x02" if vk.pubkey.point.y() % 2 == 0 else b"\x03"
    return sk, prefix + x

def der_sign(sk: SigningKey, msg32: bytes) -> bytes:
    return sk.sign_digest(msg32, sigencode=util.sigencode_der)

def claim_msg_digest(burn_txid_internal: bytes) -> bytes:
    """SPEC §7 V5 (D13e): standard Bitcoin Signed Message digest over
    P = "FVLA-CLAIM" || network_magic || burn_txid (46 bytes)."""
    payload = b"FVLA-CLAIM" + NET_MAGIC + burn_txid_internal
    assert len(payload) == 46
    envelope = b"\x18Bitcoin Signed Message:\n" + compact(len(payload)) + payload
    return sha256d(envelope)

def _recover_point(r: int, s: int, digest32: bytes, recid: int):
    """SEC 1 v2 §4.1.6 public-key recovery."""
    curve = SECP256k1.curve
    G = SECP256k1.generator
    n = SECP256k1.order
    p = curve.p()
    x = r + (recid // 2) * n
    if x >= p:
        return None
    alpha = (pow(x, 3, p) + curve.a() * x + curve.b()) % p
    beta = pow(alpha, (p + 1) // 4, p)
    y = beta if (beta % 2 == recid % 2) else p - beta
    R = Point(curve, x, y, n)
    e = int.from_bytes(digest32, "big")
    r_inv = pow(r, n - 2, n)
    return ((-e * r_inv) % n) * G + ((s * r_inv) % n) * R

def compact_sign(sk: SigningKey, digest32: bytes) -> bytes:
    """65-byte compact recoverable signature: recid || r || s (D13e)."""
    sig64 = sk.sign_digest_deterministic(digest32, hashfunc=hashlib.sha256,
                                         sigencode=util.sigencode_string)
    r = int.from_bytes(sig64[:32], "big")
    s = int.from_bytes(sig64[32:], "big")
    want = sk.get_verifying_key().pubkey.point
    for recid in range(4):
        if _recover_point(r, s, digest32, recid) == want:
            return bytes([recid]) + sig64
    raise RuntimeError("no recovery id found")

# ---------------------------------------------------------------- bitcoin tx

def ser_burn_tx(vin, vout, witness):
    """vin: list of (prev_hash32, prev_idx, scriptSig, seq); witness: list per input of [items]."""
    s = struct.pack("<i", 2)  # version
    has_wit = any(witness)
    if has_wit:
        s += b"\x00\x01"
    s += compact(len(vin))
    for prev_h, prev_i, ss, seq in vin:
        s += prev_h + struct.pack("<I", prev_i) + compact(len(ss)) + ss + struct.pack("<I", seq)
    s += compact(len(vout))
    for val, spk in vout:
        s += struct.pack("<q", val) + compact(len(spk)) + spk
    if has_wit:
        for items in witness:
            s += compact(len(items))
            for it in items:
                s += compact(len(it)) + it
    s += struct.pack("<I", 0)
    return s

def burn_txid_no_witness(tx_bytes_with_witness: bytes, vin, vout) -> bytes:
    """txid = sha256d of the no-witness serialization."""
    s = struct.pack("<i", 2)
    s += compact(len(vin))
    for prev_h, prev_i, ss, seq in vin:
        s += prev_h + struct.pack("<I", prev_i) + compact(len(ss)) + ss + struct.pack("<I", seq)
    s += compact(len(vout))
    for val, spk in vout:
        s += struct.pack("<q", val) + compact(len(spk)) + spk
    s += struct.pack("<I", 0)
    return sha256d(s)

def merkle_root(txids):
    cur = list(txids)
    if not cur:
        return b"\x00" * 32
    while len(cur) > 1:
        if len(cur) % 2:
            cur.append(cur[-1])
        cur = [sha256d(cur[i] + cur[i + 1]) for i in range(0, len(cur), 2)]
    return cur[0]

def merkle_branch(txids, index):
    branch = []
    cur = list(txids)
    idx = index
    while len(cur) > 1:
        if len(cur) % 2:
            cur.append(cur[-1])
        branch.append(cur[idx ^ 1])
        cur = [sha256d(cur[i] + cur[i + 1]) for i in range(0, len(cur), 2)]
        idx >>= 1
    return branch

def make_btc_header(prev_internal, root_internal, timestamp, bits, nonce):
    return (struct.pack("<i", 1) + prev_internal + root_internal +
            struct.pack("<III", timestamp, bits, nonce))

def grind_btc_header(prev_internal, root_internal, timestamp, bits=BTC_BITS):
    target = target_from_bits(bits)
    nonce = 0
    while True:
        h = make_btc_header(prev_internal, root_internal, timestamp, bits, nonce)
        if int.from_bytes(sha256d(h), "little") <= target:
            return h
        nonce += 1
        if nonce > 5_000_000:
            raise RuntimeError("grind failed")

# ---------------------------------------------------------------- claim tx (v4)

def ser_claim(burn_txid_internal, header80, branch, index, burn_tx_bytes,
              sig65, vout_list):
    assert len(sig65) == 65, "D13e: claim signature must be 65-byte compact"
    s = struct.pack("<i", 4)  # nVersion = 4
    s += compact(1)  # marker input
    s += b"\x00" * 32 + struct.pack("<I", 0xFFFFFFFF) + compact(0) + struct.pack("<I", 0xFFFFFFFF)
    s += burn_txid_internal
    assert len(header80) == 80
    s += header80
    s += compact(len(branch)) + b"".join(branch)
    s += struct.pack("<I", index)
    s += compact(len(burn_tx_bytes)) + burn_tx_bytes
    s += compact(len(sig65)) + sig65
    s += struct.pack("<I", 0)  # nLockTime
    s += compact(len(vout_list))
    for val, spk in vout_list:
        s += struct.pack("<q", val) + compact(len(spk)) + spk
    return s

def cinis_for(burned_sats, burn_btc_height):
    """SPEC §9 (D13c): fire = burn_btc_height // 210_000 (rate locked at burn)."""
    fire = burn_btc_height // 210_000
    heat = 1_000_000 * (2 ** fire)
    return (burned_sats * 100_000_000) // heat

# ---------------------------------------------------------------- vigil spend (legacy sighash)

def legacy_sighash(tx_version, vin_list, vout_list, locktime, input_index, script_code):
    """vin_list: [(prev_hash32, prev_idx, seq)]. Legacy SIGHASH_ALL preimage."""
    s = struct.pack("<i", tx_version)
    s += compact(len(vin_list))
    for i, (prev_h, prev_i, seq) in enumerate(vin_list):
        s += prev_h + struct.pack("<I", prev_i)
        s += compact(len(script_code)) + script_code if i == input_index else compact(0)
        s += struct.pack("<I", seq)
    s += compact(len(vout_list))
    for val, spk in vout_list:
        s += struct.pack("<q", val) + compact(len(spk)) + spk
    s += struct.pack("<I", locktime)
    s += struct.pack("<I", 1)  # SIGHASH_ALL
    return sha256d(s)

def make_vigil_spend(claim_txid_internal, mint_value, unlock, pubkey33, sk, fee=1000):
    """Spend of a Vigil mint output. nLockTime=1 (final) so the tx reaches
    ConnectBlock; the CLTV script then fails on height (expected) — the D13d
    Bitcoin-time gate is what these vectors pin."""
    spk_code = vigil_script(unlock, pubkey33)
    vout = [(mint_value - fee, b"\x51")]  # OP_1 output
    sighash = legacy_sighash(2, [(claim_txid_internal, 0, 0)], vout, 1, 0, spk_code)
    sig = der_sign(sk, sighash) + b"\x01"
    s = struct.pack("<i", 2)
    s += compact(1)
    s += claim_txid_internal + struct.pack("<I", 0)
    s += compact(len(sig)) + sig
    s += struct.pack("<I", 0)  # nSequence = 0 (BIP65: not 0xFFFFFFFF)
    s += compact(len(vout))
    for val, spk in vout:
        s += struct.pack("<q", val) + compact(len(spk)) + spk
    s += struct.pack("<I", 1)  # nLockTime = 1 (final; CLTV fails later by design)
    return s

# ---------------------------------------------------------------- node harness

class Node:
    def __init__(self, bitcoind, datadir, rpcport, p2pport):
        self.bitcoind = bitcoind
        self.datadir = datadir
        self.rpcport = rpcport
        self.p2pport = p2pport
        self.url = f"http://127.0.0.1:{rpcport}"
        self._auth_hdr = None

    def start(self, extra=()):
        os.makedirs(self.datadir, exist_ok=True)
        cmd = [self.bitcoind, "-regtest", f"-datadir={self.datadir}",
               f"-rpcport={self.rpcport}", f"-port={self.p2pport}",
               "-daemon", "-server", "-listen=1", "-dnsseed=0", "-fixedseeds=0",
               "-rpcallowip=127.0.0.1", "-rpcbind=127.0.0.1", *extra]
        subprocess.run(cmd, check=True, capture_output=True)
        cookie_path = os.path.join(self.datadir, "regtest", ".cookie")
        for _ in range(100):
            if os.path.exists(cookie_path):
                break
            time.sleep(0.2)
        else:
            raise RuntimeError(f"node did not create cookie at {cookie_path}")
        with open(cookie_path) as f:
            userpass = f.read().strip()
        import base64
        self._auth_hdr = "Basic " + base64.b64encode(userpass.encode()).decode()
        for _ in range(100):
            try:
                self.rpc("getblockcount")
                return
            except Exception:
                time.sleep(0.2)
        raise RuntimeError("node did not come up")

    def stop(self):
        try:
            self.rpc("stop")
        except Exception:
            pass

    def rpc(self, method, *params):
        body = json.dumps({"jsonrpc": "1.0", "id": "t",
                           "method": method, "params": list(params)}).encode()
        req = urllib.request.Request(self.url, data=body,
                                     headers={"Content-Type": "application/json",
                                              "Authorization": self._auth_hdr})
        try:
            with urllib.request.urlopen(req, timeout=60) as r:
                resp = json.loads(r.read())
        except urllib.error.HTTPError as e:
            resp = json.loads(e.read())
        if resp.get("error"):
            raise NodeError(resp["error"]["code"], resp["error"]["message"])
        return resp["result"]

class NodeError(Exception):
    def __init__(self, code, message):
        super().__init__(f"[{code}] {message}")
        self.code = code
        self.message = message

# ---------------------------------------------------------------- test suite

class Suite:
    def __init__(self, node: Node):
        self.node = node
        self.passed = []
        self.failed = []

    def check(self, name, cond, detail=""):
        if cond:
            self.passed.append(name)
            print(f"  PASS {name}")
        else:
            self.failed.append((name, detail))
            print(f"  FAIL {name} :: {detail}")

    def expect_reject(self, name, raw_hex, needle):
        """sendrawtransaction must fail with `needle` in the message."""
        try:
            txid = self.node.rpc("sendrawtransaction", raw_hex)
            self.check(name, False, f"ACCEPTED unexpectedly as {txid}")
        except NodeError as e:
            self.check(name, needle in e.message, f"got: {e.message}")

    def expect_submit_reject(self, name, block_hex, needle):
        """submitblock must reject (return string or throw) with `needle`."""
        try:
            res = self.node.rpc("submitblock", block_hex)
            ok = isinstance(res, str) and needle in res
            self.check(name, ok, f"submitblock returned {res!r}")
        except NodeError as e:
            self.check(name, needle in e.message, f"threw: {e.message}")

    def summary(self):
        print(f"\n==== {len(self.passed)} passed, {len(self.failed)} failed ====")
        for n, d in self.failed:
            print(f"  FAILED: {n} :: {d}")
        return len(self.failed) == 0

# ---------------------------------------------------------------- scenario

class Scenario:
    """Builds a simulated Bitcoin-regtest header chain + burns + claims."""

    def __init__(self, node: Node):
        self.node = node
        self.btc_headers = []   # list of 80-byte headers (index == btc height)
        self.burns = {}         # name -> dict with tx bytes, txid, header idx, etc.

    def build_btc_chain(self, n=160, burn_specs=()):
        """burn_specs: list of (header_idx, name, kind, sats).
        Multiple burns may share a header_idx (they go in one block).
        kind: 'p2wpkh' | 'p2pkh' | 'taproot' | 'opreturn' | 'wrapped' | 'zerofurnace'"""
        from collections import defaultdict
        burns = defaultdict(list)
        for (hidx, name, kind, sats) in burn_specs:
            burns[hidx].append((name, kind, sats))
        prev = b"\x00" * 32
        t0 = 1_700_000_000
        for i in range(n):
            if i in burns:
                specs = [self.make_burn(name, kind, sats) for (name, kind, sats) in burns[i]]
                coinbase = self.make_coinbase()
                txids = [sha256d(coinbase)] + [s["txid"] for s in specs]
                root = merkle_root(txids)
                for j, spec in enumerate(specs):
                    idx = j + 1  # position in block
                    self.burns[spec["name"]] = {**spec, "header_idx": i,
                        "merkle_branch": merkle_branch(txids, idx), "merkle_index": idx}
            else:
                coinbase = self.make_coinbase()
                root = merkle_root([sha256d(coinbase)])
            hdr = grind_btc_header(prev, root, t0 + i * 600)
            self.btc_headers.append(hdr)
            prev = sha256d(hdr)
        for h in self.btc_headers:
            self.node.rpc("submitbitcoinheader", h.hex())
        info = self.node.rpc("getbitcoinheaderchaininfo")
        assert info["tip_height"] == n - 1, info
        return self

    @staticmethod
    def make_coinbase():
        # minimal fake coinbase (never validated by Favilla; only hashed)
        return (struct.pack("<i", 2) + compact(1) + b"\x00" * 32 +
                struct.pack("<I", 0xFFFFFFFF) + compact(0) +
                struct.pack("<I", 0xFFFFFFFF) + compact(1) +
                struct.pack("<q", 0) + compact(1) + b"\x51" +
                struct.pack("<I", 0))

    def make_burn(self, name, kind, sats):
        sk, pubkey33 = gen_key()
        if kind == "taproot":
            vin = [(os.urandom(32), 0, b"", 0xFFFFFFFF)]
            wit = [[b"\x11" * 64]]
        elif kind == "p2pkh":
            vin = [(os.urandom(32), 0, b"\x47" + b"\x22" * 71 + b"\x21" + pubkey33, 0xFFFFFFFF)]
            wit = [[]]
        else:  # p2wpkh / opreturn / wrapped / zerofurnace
            vin = [(os.urandom(32), 0, b"", 0xFFFFFFFF)]
            wit = [[b"\x44" + b"\x33" * 68, pubkey33]]
        vout = []
        if kind == "wrapped":
            h160 = hashlib.new("ripemd160", hashlib.sha256(FURNACE_SPK).digest()).digest()
            vout.append((sats, b"\xa9\x14" + h160 + b"\x87"))
        elif kind == "zerofurnace":
            vout.append((sats, push(pubkey33)))
        else:
            vout.append((sats, FURNACE_SPK))
        if kind == "opreturn":
            vout.append((0, b"\x6a" + push(b"hello")))
        tx_wit = ser_burn_tx(vin, vout, wit)
        txid = burn_txid_no_witness(tx_wit, vin, vout)
        return {"name": name, "sk": sk, "pubkey33": pubkey33, "tx": tx_wit,
                "txid": txid, "sats": sats, "kind": kind,
                "furnace_sats": sats if kind in ("p2wpkh", "p2pkh", "taproot", "opreturn") else 0}

    def make_claim(self, burn_name, fav_height, sig="good", mutate=None,
                   header_override=None, mint_override_cinis=None,
                   vout_override=None):
        """sig: 'good' | 'wrongkey' | 'wrongmsg' | 'empty' | 'short' | 'der' | 'olddigest'.
        D13c: cinis uses the burn's BITCOIN height (rate locked at burn time)."""
        b = self.burns[burn_name]
        burned = b["furnace_sats"]
        cinis = cinis_for(burned, b["header_idx"])
        if mint_override_cinis is not None:
            cinis = mint_override_cinis
        unlock = fav_height + 210_000
        spk = vigil_script(unlock, b["pubkey33"])
        digest = claim_msg_digest(b["txid"])
        if sig == "good":
            sig65 = compact_sign(b["sk"], digest)
        elif sig == "wrongkey":
            other, _ = gen_key()
            sig65 = compact_sign(other, digest)
        elif sig == "wrongmsg":
            # valid compact sig, but over the wrong digest (wrong network magic)
            wrong = claim_msg_digest(b["txid"]).replace(NET_MAGIC, b"\x66\x76\x6c\x74", 1) \
                if False else sha256d(b"\x18Bitcoin Signed Message:\n" + compact(46) +
                                       b"FVLA-CLAIM" + b"\x66\x76\x6c\x74" + b["txid"])
            sig65 = compact_sign(b["sk"], wrong)
        elif sig == "olddigest":
            # 65-byte compact sig over the PRE-D13e custom digest
            # SHA256("FVLA-CLAIM" || magic || txid): passes M2, fails V5.
            old_digest = sha256(b"FVLA-CLAIM" + NET_MAGIC + b["txid"])
            sig65 = compact_sign(b["sk"], old_digest)
        elif sig == "der":
            sig65 = der_sign(b["sk"], digest)  # ~71 bytes: old pre-D13e shape
        elif sig == "empty":
            sig65 = b""
        elif sig == "short":
            sig65 = b"\x30\x06\x02\x01\x00\x02\x01\x00"[:7]
        else:
            raise ValueError(sig)
        vouts = vout_override if vout_override is not None else [(cinis, spk)]
        # ser_claim asserts len(sig)==65 for well-formed sigs; bypass for
        # malformed-length vectors by inlining the serialization.
        if len(sig65) == 65:
            raw = ser_claim(b["txid"], header_override or self.btc_headers[b["header_idx"]],
                            b["merkle_branch"], b["merkle_index"], b["tx"],
                            sig65, vouts)
        else:
            s = struct.pack("<i", 4) + compact(1)
            s += b"\x00" * 32 + struct.pack("<I", 0xFFFFFFFF) + compact(0) + struct.pack("<I", 0xFFFFFFFF)
            s += b["txid"] + (header_override or self.btc_headers[b["header_idx"]])
            s += compact(len(b["merkle_branch"])) + b"".join(b["merkle_branch"])
            s += struct.pack("<I", b["merkle_index"])
            s += compact(len(b["tx"])) + b["tx"]
            s += compact(len(sig65)) + sig65
            s += struct.pack("<I", 0) + compact(len(vouts))
            for val, spk2 in vouts:
                s += struct.pack("<q", val) + compact(len(spk2)) + spk2
            raw = s
        if mutate:
            raw = mutate(raw)
        return raw.hex(), {"cinis": cinis, "unlock": unlock, "spk": spk,
                           "txid": sha256d(raw)[::-1].hex(), "burn": b}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--keep", action="store_true")
    ap.add_argument("--node", default=os.path.expanduser(
        "~/workspace/favilla/core/build/bin/bitcoind"))
    args = ap.parse_args()

    datadir = tempfile.mkdtemp(prefix="fvtest-")
    node = Node(args.node, datadir, rpcport=28443, p2pport=28444)
    print("starting node...")
    node.start()
    try:
        run_all(node, args)
    finally:
        node.stop()
        time.sleep(1)
        if not args.keep:
            shutil.rmtree(datadir, ignore_errors=True)
        else:
            print("datadir kept at", datadir)


def btc_tip_internal(node):
    """Current Bitcoin header tip hash in internal byte order."""
    h = node.rpc("getbitcoinheaderchaininfo")["tip_hash"]
    return bytes.fromhex(h)[::-1]


def run_all(node: Node, args):
    s = Suite(node)
    print("== setup: mine 101 Favilla blocks ==")
    node.rpc("createwallet", "test")
    addr = node.rpc("getnewaddress")
    node.rpc("generatetoaddress", 101, addr)
    h0 = node.rpc("getblockcount")
    s.check("chain at 101", h0 == 101, f"height={h0}")

    print("== setup: simulated Bitcoin header chain (160 headers, tip 159) ==")
    sc = Scenario(node).build_btc_chain(160, [
        (15, "burnA", "p2wpkh", 1_000_000),      # depth 144 vs tip 159 — happy path
        (15, "burnH", "p2wpkh", 3_000_000),      # shares header 15; block-level vectors
        (16, "burnB", "p2wpkh", 2_000_000),      # depth 143 — too shallow (V3)
        (14, "burnC", "taproot", 1_000_000),     # depth 145; key-path: unrecoverable
        (14, "burnI", "p2wpkh", 1_000_000),      # depth 145; vector 33 (stale tip)
        (13, "burnD", "opreturn", 500_000),      # depth 146; OP_RETURN ignored
        (12, "burnE", "p2pkh", 750_000),         # depth 147; legacy input
        (11, "burnF", "wrapped", 1_000_000),     # depth 148; non-exact spk → 0
        (10, "burnG", "zerofurnace", 1_000_000), # depth 149; no furnace → 0
        (15, "burnV", "p2wpkh", 1_000_000),      # depth 144; vigil-spend vectors
        (15, "burnJ", "p2wpkh", 2_000_000),      # depth 144; vector 36 (fire pin)
        (15, "burnK", "p2wpkh", 1_000_000),      # depth 144; vector 32 (held)
    ])
    s.check("btc tip at 159", node.rpc("getbitcoinheaderchaininfo")["tip_height"] == 159)
    tip159 = btc_tip_internal(node)

    H = node.rpc("getblockcount") + 1  # claim inclusion height

    print("== happy path + vector 38 (D13e compact message sig): valid claim confirms ==")
    raw, info = sc.make_claim("burnA", H)
    txid = node.rpc("sendrawtransaction", raw)
    s.check("claim accepted to mempool (V5 compact sig)", isinstance(txid, str) and len(txid) == 64)
    node.rpc("generatetoaddress", 1, addr)
    s.check("block mined at H", node.rpc("getblockcount") == H)
    from decimal import Decimal
    utxo = node.rpc("gettxout", txid, 0)
    s.check("mint utxo exists", utxo is not None, "gettxout returned null")
    if utxo:
        got_cinis = int(Decimal(str(utxo["value"])) * 100_000_000)
        s.check("mint value == cinis", got_cinis == info["cinis"],
                f"value={utxo['value']} cinis={got_cinis} expected={info['cinis']}")
        s.check("mint script == vigil", utxo["scriptPubKey"]["hex"] == info["spk"].hex())
    # vector 36 pin (D13c): burn at btc height 15 (Fire 0) mints at Fire-0 rate
    # regardless of Favilla height: 1M sats -> 100M cinis.
    s.check("vector 36: fire-0 burn mints fire-0 rate (D13c)",
            info["cinis"] == 100_000_000, f"cinis={info['cinis']}")
    # double-claim after confirmation -> V1 reject
    raw2, _ = sc.make_claim("burnA", H + 1)
    s.expect_reject("double-claim rejected (V1)", raw2, "bad-claim-double-claim")
    # bug (a) regression: getblock verbosity 2 on a claim block must not crash
    blkhash = node.rpc("getbestblockhash")
    try:
        blk2 = node.rpc("getblock", blkhash, 2)
        ntx = len(blk2["tx"])
        s.check("getblock v2 on claim block (bug a)", ntx == 2, f"ntx={ntx}")
    except NodeError as e:
        s.check("getblock v2 on claim block (bug a)", False, f"threw: {e.message}")
    H += 1

    print("== SPEC §16 vectors 1-30 (D13 semantics) ==")
    H = node.rpc("getblockcount") + 1

    # V3: 143 confirmations (burnB at btc height 16, tip 159 -> depth 143)
    rawB, _ = sc.make_claim("burnB", H)
    s.expect_reject("v2: burn at depth<144 rejected (V3)", rawB, "bad-claim-insufficient-depth")

    # V2: flipped bit in merkle branch
    def flip(b):
        b = bytearray(b)
        b[170] ^= 0x01
        return bytes(b)
    rawM, _ = sc.make_claim("burnD", H, mutate=flip)
    s.expect_reject("v3: bad merkle branch rejected (V2)", rawM, "bad-claim-merkle-root")

    # V2: burn_txid mismatch — flip a byte in the burn's vout value
    def fliptx(b):
        b = bytearray(b)
        b[245] ^= 0x02
        return bytes(b)
    rawT, _ = sc.make_claim("burnD", H, mutate=fliptx)
    s.expect_reject("v9: burn_txid mismatch rejected (V2)", rawT, "bad-claim-txid-mismatch")

    # V2: burn_txid field set to the wtxid instead of the txid
    bD = sc.burns["burnD"]
    wtxid = sha256d(bD["tx"])
    rawW, _ = sc.make_claim("burnD", H,
                            mutate=lambda b: b[:46] + wtxid + b[78:])
    s.expect_reject("v9b: wtxid-as-burn_txid rejected (V2)", rawW, "bad-claim-txid-mismatch")

    # V4: taproot key-path input 0
    rawC, _ = sc.make_claim("burnC", H)
    s.expect_reject("v7: taproot key-path rejected (V4)", rawC, "bad-claim-unrecoverable-pubkey")

    # V6: zero furnace sats (wrapped + zerofurnace)
    rawF, _ = sc.make_claim("burnF", H)
    s.expect_reject("v10: non-exact furnace spk -> zero mint (V6)", rawF, "bad-claim-zero-mint")
    rawG, _ = sc.make_claim("burnG", H)
    s.expect_reject("v10: no furnace output -> zero mint (V6)", rawG, "bad-claim-zero-mint")

    # V5/M2 signature vectors (D13e)
    rawD, _ = sc.make_claim("burnD", H, sig="empty")
    s.expect_reject("v10a: missing signature rejected (M2)", rawD, "bad-claim-sig-size")
    rawD, _ = sc.make_claim("burnD", H, sig="short")
    s.expect_reject("v10a: short signature rejected (M2)", rawD, "bad-claim-sig-size")
    rawD, _ = sc.make_claim("burnD", H, sig="der")
    s.expect_reject("v37: old-style DER signature rejected (M2, not V5)",
                    rawD, "bad-claim-sig-size")
    rawD, _ = sc.make_claim("burnD", H, sig="olddigest")
    s.expect_reject("v37b: 65-byte sig over pre-D13e custom digest rejected (V5)",
                    rawD, "bad-claim-sig-verify")
    rawD, _ = sc.make_claim("burnD", H, sig="wrongkey")
    s.expect_reject("v10b: wrong-key signature rejected (V5)", rawD, "bad-claim-sig-verify")
    rawD, _ = sc.make_claim("burnD", H, sig="wrongmsg")
    s.expect_reject("v39: signature over wrong network magic rejected (V5)", rawD,
                    "bad-claim-sig-verify")

    # V3: burn_header from a stale fork (not in the committed tip's ancestry).
    # Fork 5 headers off btc header 10; fork header #2 reuses burnB's block
    # root so V2 passes and V3 is what fails.
    bB = sc.burns["burnB"]
    burnB_root = merkle_root([sha256d(Scenario.make_coinbase()), bB["txid"]])
    fprev = sha256d(sc.btc_headers[10])
    fhs = []
    for i in range(5):
        r = burnB_root if i == 2 else merkle_root([sha256d(Scenario.make_coinbase())])
        h = grind_btc_header(fprev, r, 1_700_000_000 + 9000 + i)
        node.rpc("submitbitcoinheader", h.hex())
        fhs.append(h)
        fprev = sha256d(h)
    s.check("fork did not overtake tip",
            node.rpc("getbitcoinheaderchaininfo")["tip_height"] == 159)
    rawFork, _ = sc.make_claim("burnB", H, header_override=fhs[2])
    s.expect_reject("v4: fork header not in committed tip ancestry (V3)", rawFork,
                    "bad-claim-header-unknown")

    # V3: burn_header unknown to the node (correct root, unsubmitted header)
    fake = make_btc_header(os.urandom(32), burnB_root, 99999, BTC_BITS, 0)
    rawUnk, _ = sc.make_claim("burnB", H, header_override=fake)
    s.expect_reject("v5: unknown burn header rejected (V3)", rawUnk, "bad-claim-header-unknown")

    # V7: stale-height claim (built for H, mined after tip advances)
    Htip = node.rpc("getblockcount")
    rawStale, _ = sc.make_claim("burnE", Htip + 1)
    node.rpc("generatetoaddress", 1, addr)  # tip advances; claim now stale
    s.expect_reject("v15: stale-height claim rejected (V7)", rawStale,
                    "bad-claim-script-mismatch")
    H = node.rpc("getblockcount") + 1

    # V7: wrong value / wrong script / wrong unlock (burnE, p2pkh)
    bE = sc.burns["burnE"]
    cinisE = cinis_for(bE["furnace_sats"], bE["header_idx"])
    spkE = vigil_script(H + 210_000, bE["pubkey33"])
    sigE = compact_sign(bE["sk"], claim_msg_digest(bE["txid"]))
    def claimE(vout):
        return ser_claim(bE["txid"], sc.btc_headers[bE["header_idx"]],
                         bE["merkle_branch"], bE["merkle_index"], bE["tx"],
                         sigE, vout).hex()
    s.expect_reject("v13: wrong mint value rejected (V7)",
                    claimE([(cinisE + 1, spkE)]), "bad-claim-value-mismatch")
    s.expect_reject("v8: wrong mint script rejected (V7)",
                    claimE([(cinisE, vigil_script(H + 210_000, os.urandom(33)))]),
                    "bad-claim-script-mismatch")
    s.expect_reject("v14: wrong unlock height rejected (V7)",
                    claimE([(cinisE, vigil_script(H + 210_001, bE["pubkey33"]))]),
                    "bad-claim-script-mismatch")

    # v40 (D13f): burn_tx of 400_001 bytes -> MALFORMED (M2)
    big_burn = sc.burns["burnD"]["tx"] + b"\x00" * (400_001 - len(sc.burns["burnD"]["tx"]))
    rawBig, _ = sc.make_claim("burnD", H, mutate=lambda b: b)  # placeholder
    # rebuild with the oversized burn tx: patch the CompactSize length + bytes
    bDd = sc.burns["burnD"]
    sigDd = compact_sign(bDd["sk"], claim_msg_digest(bDd["txid"]))
    s_big = struct.pack("<i", 4) + compact(1)
    s_big += b"\x00" * 32 + struct.pack("<I", 0xFFFFFFFF) + compact(0) + struct.pack("<I", 0xFFFFFFFF)
    s_big += bDd["txid"] + sc.btc_headers[bDd["header_idx"]]
    s_big += compact(len(bDd["merkle_branch"])) + b"".join(bDd["merkle_branch"])
    s_big += struct.pack("<I", bDd["merkle_index"])
    s_big += compact(len(big_burn)) + big_burn
    s_big += compact(len(sigDd)) + sigDd + struct.pack("<I", 0)
    cinisDd = cinis_for(bDd["furnace_sats"], bDd["header_idx"])
    s_big += compact(1) + struct.pack("<q", cinisDd) + compact(len(vigil_script(H + 210_000, bDd["pubkey33"]))) + vigil_script(H + 210_000, bDd["pubkey33"])
    s.expect_reject("v40: 400001-byte burn_tx rejected (M2)", s_big.hex(),
                    "bad-claim-burntx-size")

    # OP_RETURN in burn is ignored -> valid claim accepted (burnD, v6)
    rawD, infoD = sc.make_claim("burnD", H)
    txidD = node.rpc("sendrawtransaction", rawD)
    s.check("v6: burn with OP_RETURN accepted (D1)", len(txidD) == 64)
    node.rpc("generatetoaddress", 1, addr)
    H = node.rpc("getblockcount") + 1

    # mempool dedup: two claims for same burn. The second must be a DIFFERENT
    # tx (same txid re-submits are idempotent); flip a sig byte so the txid
    # differs — HasClaimForBurn fires before the (now-broken) V5 check.
    rawE1, _ = sc.make_claim("burnE", H)
    node.rpc("sendrawtransaction", rawE1)
    rawE2, _ = sc.make_claim("burnE", H)
    b2 = bytearray(bytes.fromhex(rawE2))
    b2[-80] ^= 0x01  # inside the 65-byte compact signature
    s.expect_reject("v10d: second mempool claim for burn rejected", bytes(b2).hex(),
                    "claim-burn-already-in-mempool")

    print("== block-level vectors via submitblock (D13a commitments) ==")
    ok = block_level_vectors(node, sc, s, addr, H, tip159)

    print("== vectors 34/35 (D13d Bitcoin-time Vigil) ==")
    ok = vigil_vectors(node, sc, s, addr) and ok

    print("== vector 32 (D13b held block) ==")
    ok = held_vector(node, sc, s, addr) and ok

    print("== two-node smoke test ==")
    ok = two_node_smoke(node, s, args, sc) and ok

    if not s.summary():
        sys.exit(1)
    if not ok:
        sys.exit(1)
    print("ALL GREEN")

# ---------------------------------------------------------------- block-level vectors

def grind_fv_header(prev_internal, root_internal, timestamp, bits=0x207FFFFF):
    target = target_from_bits(bits)
    nonce = 0
    ver = 0x20000000
    while True:
        h = (struct.pack("<i", ver) + prev_internal + root_internal +
             struct.pack("<III", timestamp, bits, nonce))
        if int.from_bytes(sha256d(h), "little") <= target:
            return h
        nonce += 1

def make_coinbase_fv(height, commit_tip_internal, extra_commitments=0):
    """Favilla coinbase with the D13a commitment output:
    value-0, scriptPubKey 0x6a 0x20 || commit_tip (34 bytes)."""
    if 1 <= height <= 16:
        push_h = bytes([0x50 + height])
    else:
        hb = height.to_bytes((height.bit_length() + 7) // 8, "little")
        if hb[-1] & 0x80:
            hb += b"\x00"
        push_h = bytes([len(hb)]) + hb
    if len(push_h) < 2:
        push_h = push_h + b"\x00" * (2 - len(push_h))
    s = struct.pack("<i", 2)
    s += compact(1)
    s += b"\x00" * 32 + struct.pack("<I", 0xFFFFFFFF) + compact(len(push_h)) + push_h + struct.pack("<I", 0xFFFFFFFF)
    outs = [(0, compact(1) + b"\x51")]  # dummy OP_1 output (fees are 0)
    for _ in range(1 + extra_commitments):
        outs.append((0, b"\x6a\x20" + commit_tip_internal))  # D13a commitment
    s += compact(len(outs))
    for val, spk in outs:
        s += struct.pack("<q", val) + compact(len(spk)) + spk
    s += struct.pack("<I", 0)
    return s

def submit_block(node, txs_raw, commit_tip_internal, expect_ok=True, name=""):
    tip = bytes.fromhex(node.rpc("getbestblockhash"))[::-1]
    height = node.rpc("getblockcount") + 1
    tip_time = node.rpc("getblockheader", node.rpc("getbestblockhash"))["time"]
    txids = [sha256d(t) for t in txs_raw]
    root = merkle_root(txids)
    ts = max(int(time.time()), tip_time + 1)
    hdr = grind_fv_header(tip, root, ts, 0x207FFFFF)
    blk = hdr + compact(len(txs_raw)) + b"".join(txs_raw)
    res = node.rpc("submitblock", blk.hex())
    return res, height

def block_level_vectors(node, sc, s, addr, H, tip159):
    """Block-level consensus vectors using submitblock."""
    H = node.rpc("getblockcount") + 1
    cb = make_coinbase_fv(H, tip159)

    def claimH(height, burn="burnH"):
        raw_hex, _ = sc.make_claim(burn, height)
        return bytes.fromhex(raw_hex)

    # vector 11: two claims for the same burn in one block -> INVALID
    raw1 = claimH(H)
    raw2 = claimH(H)
    res, _ = submit_block(node, [cb, raw1, raw2], tip159)
    s.check("v11: double-claim in one block -> INVALID", isinstance(res, str) and res != "duplicate",
            f"submitblock returned {res!r}")

    # vector 12a: one claim in a block -> ACCEPT
    res, h = submit_block(node, [cb, raw1], tip159)
    s.check("v12a: single claim block accepted", res is None, f"submitblock returned {res!r}")
    s.check("tip advanced", node.rpc("getblockcount") == h)

    # vector 12b: same burn claimed again on top -> INVALID (V1 nullifier)
    H2 = node.rpc("getblockcount") + 1
    cb2 = make_coinbase_fv(H2, tip159)
    raw3 = claimH(H2)
    res, _ = submit_block(node, [cb2, raw3], tip159)
    s.check("v12b: re-claim next block -> INVALID (V1)", isinstance(res, str) and res != "duplicate",
            f"submitblock returned {res!r}")

    # vector: claim with tampered mint value in a block -> INVALID
    rawE_hex, _ = sc.make_claim("burnE", H2, mint_override_cinis=1)
    res, _ = submit_block(node, [cb2, bytes.fromhex(rawE_hex)], tip159)
    s.check("v13b: wrong mint value in block -> INVALID", isinstance(res, str) and res != "duplicate",
            f"submitblock returned {res!r}")

    # vector 29 (Favilla reorg): invalidate the claim block, nullifier must clear
    tiphash = node.rpc("getbestblockhash")
    node.rpc("invalidateblock", tiphash)
    s.check("v29: tip dropped after invalidate", node.rpc("getblockcount") == h - 1)
    H3 = node.rpc("getblockcount") + 1
    cb3 = make_coinbase_fv(H3, tip159)
    raw4 = claimH(H3)
    try:
        node.rpc("sendrawtransaction", raw4.hex())
        s.check("v29: re-claim after reorg accepted", True)
        node.rpc("generatetoaddress", 1, addr)
    except NodeError as e:
        s.check("v29: re-claim after reorg accepted", False, e.message)

    # vector 31 (D13a): commitment shapes
    H4 = node.rpc("getblockcount") + 1
    # 31a: coinbase WITHOUT the commitment -> INVALID
    cb_nocommit = make_coinbase_fv(H4, tip159)
    # strip the commitment output: rebuild with only the dummy output
    s_nc = struct.pack("<i", 2) + compact(1)
    if 1 <= H4 <= 16:
        push_h = bytes([0x50 + H4])
    else:
        hb = H4.to_bytes((H4.bit_length() + 7) // 8, "little")
        if hb[-1] & 0x80:
            hb += b"\x00"
        push_h = bytes([len(hb)]) + hb
    if len(push_h) < 2:
        push_h = push_h + b"\x00" * (2 - len(push_h))
    s_nc += b"\x00" * 32 + struct.pack("<I", 0xFFFFFFFF) + compact(len(push_h)) + push_h + struct.pack("<I", 0xFFFFFFFF)
    s_nc += compact(1) + struct.pack("<q", 0) + compact(1) + b"\x51" + struct.pack("<I", 0)
    res, _ = submit_block(node, [s_nc], tip159)
    s.check("v31a: coinbase without commitment -> INVALID",
            isinstance(res, str) and "bad-cb-commitment-count" in res,
            f"submitblock returned {res!r}")
    # 31b: coinbase with TWO commitments -> INVALID
    cb_two = make_coinbase_fv(H4, tip159, extra_commitments=1)
    res, _ = submit_block(node, [cb_two], tip159)
    s.check("v31b: coinbase with two commitments -> INVALID",
            isinstance(res, str) and "bad-cb-commitment-count" in res,
            f"submitblock returned {res!r}")
    # 31c: zero-hash commitment, NO claims -> ACCEPT
    cb_zero = make_coinbase_fv(H4, b"\x00" * 32)
    res, hz = submit_block(node, [cb_zero], b"\x00" * 32)
    s.check("v31c: zero-hash commitment without claims -> ACCEPT", res is None,
            f"submitblock returned {res!r}")
    # 31d: zero-hash commitment WITH a claim -> INVALID
    H5 = node.rpc("getblockcount") + 1
    cb_zero2 = make_coinbase_fv(H5, b"\x00" * 32)
    rawI, _ = sc.make_claim("burnI", H5)
    res, _ = submit_block(node, [cb_zero2, bytes.fromhex(rawI)], b"\x00" * 32)
    s.check("v31d: zero-hash commitment with claim -> INVALID",
            isinstance(res, str) and "bad-cb-commitment-zero-with-claims" in res,
            f"submitblock returned {res!r}")

    # vector 33 (D13b): stale-but-valid committed tip — burnI sits at btc
    # height 14, so committing to header 158 gives depth exactly 144, while
    # the node's live tip is 159. The depth rule follows the COMMITTED tip.
    H6 = node.rpc("getblockcount") + 1
    stale_tip = sha256d(sc.btc_headers[158])  # internal
    cb_stale = make_coinbase_fv(H6, stale_tip)
    rawI2, _ = sc.make_claim("burnI", H6)
    res, _ = submit_block(node, [cb_stale, bytes.fromhex(rawI2)], stale_tip)
    s.check("v33: claim at 144 below stale committed tip -> ACCEPT (D13b)",
            res is None, f"submitblock returned {res!r}")

    # confirm burnV (needed for the vigil-spend vectors 34/35)
    H7 = node.rpc("getblockcount") + 1
    cb7 = make_coinbase_fv(H7, tip159)
    rawV, infoV = sc.make_claim("burnV", H7)
    res, _ = submit_block(node, [cb7, bytes.fromhex(rawV)], tip159)
    s.check("burnV claim confirmed (vigil setup)", res is None,
            f"submitblock returned {res!r}")
    sc.burns["burnV"]["claim_info"] = infoV
    sc.burns["burnV"]["claim_raw"] = rawV
    return True

# ---------------------------------------------------------------- vigil vectors (D13d)

def vigil_vectors(node, sc, s, addr):
    """Vectors 34/35: Vigil spends gated on the spending block's committed
    Bitcoin tip MTP >= burn_mtp + 126_000_000 (D13d)."""
    bV = sc.burns["burnV"]
    infoV = bV["claim_info"]
    claim_txid_internal = sha256d(bytes.fromhex(bV["claim_raw"]))
    mint_value = infoV["cinis"]
    unlock = infoV["unlock"]

    # burnV at btc height 15: burn_mtp = MTP(15) = nTime[10] = 1_700_006_000.
    # Committed tip 159: MTP(159) = nTime[154] = 1_700_092_400
    #   < 1_700_006_000 + 126_000_000 = 1_826_006_000  -> INVALID (v34).
    H = node.rpc("getblockcount") + 1
    tip159 = btc_tip_internal(node)
    spend = make_vigil_spend(claim_txid_internal, mint_value, unlock,
                             bV["pubkey33"], bV["sk"])
    cb = make_coinbase_fv(H, tip159)
    res, _ = submit_block(node, [cb, spend], tip159)
    s.check("v34: vigil spend with tip MTP < burn_mtp+126M -> INVALID (D13d)",
            isinstance(res, str) and "bad-vigil-bitcoin-time" in res,
            f"submitblock returned {res!r}")

    # v35: submit 11 headers with far-future nTime (they overtake the tip:
    # 170 > 159). Committed tip 170 has MTP ~= 1_900_003_000 >= 1_826_006_000,
    # so the D13d gate PASSES; the spend still fails the CLTV height lock
    # (script failure, NOT bad-vigil-bitcoin-time). A full ACCEPT would need
    # 210_000 Favilla blocks — infeasible in-test; the D13d gate is what's pinned.
    prev = sha256d(sc.btc_headers[159])
    for i in range(11):
        root = merkle_root([sha256d(Scenario.make_coinbase())])
        h = grind_btc_header(prev, root, 1_900_000_000 + i * 600)
        node.rpc("submitbitcoinheader", h.hex())
        prev = sha256d(h)
        sc.btc_headers.append(h)
    info = node.rpc("getbitcoinheaderchaininfo")
    s.check("fork tip at 170", info["tip_height"] == 170, f"tip={info['tip_height']}")
    tip170 = btc_tip_internal(node)
    H2 = node.rpc("getblockcount") + 1
    spend2 = make_vigil_spend(claim_txid_internal, mint_value, unlock,
                              bV["pubkey33"], bV["sk"])
    cb2 = make_coinbase_fv(H2, tip170)
    res, _ = submit_block(node, [cb2, spend2], tip170)
    ok = isinstance(res, str) and "bad-vigil-bitcoin-time" not in res
    s.check("v35: D13d gate passes with tip MTP >= burn_mtp+126M "
            "(reject is the CLTV height lock, not D13d)", ok,
            f"submitblock returned {res!r}")
    return True

# ---------------------------------------------------------------- held vector (D13b)

def held_vector(node, sc, s, addr):
    """Vector 32: a claim block whose committed Bitcoin tip is unknown to the
    node is HELD as not-yet-validated — not cached as invalid, no peer
    penalty — and validates once the header arrives."""
    # Grind one header on the current tip but do NOT submit it yet.
    tip_hash = node.rpc("getbitcoinheaderchaininfo")["tip_hash"]
    tip_height = node.rpc("getbitcoinheaderchaininfo")["tip_height"]
    prev = bytes.fromhex(tip_hash)[::-1]
    prev_time = struct.unpack("<I", sc.btc_headers[-1][68:72])[0]
    hdr = grind_btc_header(prev, merkle_root([sha256d(Scenario.make_coinbase())]),
                          prev_time + 600)
    commit = sha256d(hdr)  # internal; UNKNOWN to the node for now

    H = node.rpc("getblockcount") + 1
    cb = make_coinbase_fv(H, commit)
    rawK, _ = sc.make_claim("burnK", H)
    before = node.rpc("getblockcount")
    invalid_before = sum(1 for t in node.rpc("getchaintips") if t["status"] == "invalid")
    try:
        res = node.rpc("submitblock", _build_block(node, [cb, bytes.fromhex(rawK)]))
        s.check("v32: unknown-tip claim block HELD (not accepted, not invalid)",
                False, f"submitblock unexpectedly returned {res!r}")
        return False
    except NodeError as e:
        s.check("v32: unknown-tip claim block HELD (not accepted, not invalid)",
                "tip-unknown" in e.message, f"threw: {e.message}")
    s.check("v32: tip unchanged while held", node.rpc("getblockcount") == before)
    # The held block must NOT be cached as invalid: the invalid-tip count
    # must not grow (earlier INVALID vectors legitimately left some).
    invalid_after = sum(1 for t in node.rpc("getchaintips") if t["status"] == "invalid")
    s.check("v32: held block not marked invalid",
            invalid_after == invalid_before,
            f"invalid tips {invalid_before} -> {invalid_after}")

    # Now submit the missing header: the held block must validate.
    node.rpc("submitbitcoinheader", hdr.hex())
    sc.btc_headers.append(hdr)
    after = node.rpc("getblockcount")
    s.check("v32: held block connects once the tip header arrives", after == before + 1,
            f"before={before} after={after}")
    return True

def _build_block(node, txs_raw):
    tip = bytes.fromhex(node.rpc("getbestblockhash"))[::-1]
    tip_time = node.rpc("getblockheader", node.rpc("getbestblockhash"))["time"]
    txids = [sha256d(t) for t in txs_raw]
    root = merkle_root(txids)
    ts = max(int(time.time()), tip_time + 1)
    hdr = grind_fv_header(tip, root, ts, 0x207FFFFF)
    return (hdr + compact(len(txs_raw)) + b"".join(txs_raw)).hex()

# ---------------------------------------------------------------- two-node smoke

def two_node_smoke(nodeA, s, args, sc):
    datadirB = tempfile.mkdtemp(prefix="fvtest-b-")
    # Ports: node A holds 28443 (RPC), 28444 (P2P), 28445 (onion = -port+1).
    # Node B must avoid all three: RPC 28448, P2P 28449 (onion 28450).
    nodeB = Node(args.node, datadirB, rpcport=28448, p2pport=28449)
    try:
        print("  starting node B...")
        # -listen=0: node B only makes an outbound connection to A; this
        # avoids the default onion bind (127.0.0.1:chainDefaultPort+1) which
        # node A already holds.
        nodeB.start(extra=("-listen=0",))
        # Node B must learn the same Bitcoin headers, or D13b correctly
        # holds the claim blocks as not-yet-validated (it has no tip).
        for h in sc.btc_headers:
            nodeB.rpc("submitbitcoinheader", h.hex())
        nodeB.rpc("addnode", "127.0.0.1:28444", "add")
        ha = hb = -1
        for _ in range(60):
            ha = nodeA.rpc("getblockcount")
            hb = nodeB.rpc("getblockcount")
            if ha == hb and ha > 0:
                break
            time.sleep(1)
        s.check("node B synced to A", ha == hb and ha > 0, f"A={ha} B={hb}")
        if ha == hb and ha > 0:
            ba = nodeA.rpc("getbestblockhash")
            bb = nodeB.rpc("getbestblockhash")
            s.check("tips match", ba == bb, f"A={ba} B={bb}")
        return True
    finally:
        nodeB.stop()
        time.sleep(1)
        shutil.rmtree(datadirB, ignore_errors=True)

if __name__ == "__main__":
    main()
