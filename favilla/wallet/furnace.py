#!/usr/bin/env python3
"""
furnace.py — Favilla wallet / CLI (regtest + public testnet).

Makes the core ritual real end-to-end:
    burn BTC to the furnace -> wait 144 Bitcoin confirmations ->
    file a claim -> FVLA mints to the burn key's address, Vigil-locked.

Default chain is regtest; pass --testnet for the public testnet.
TESTNET burns are REAL Bitcoin testnet4 transactions — the simulated
Bitcoin chain below is regtest-only and is never used on testnet.

Design notes (see SPEC.md — normative):
- REGTEST: there is no live Bitcoin P2P network. The wallet maintains a
  *simulated* Bitcoin-regtest chain: it grinds block headers (trivial PoW at
  nBits 0x207fffff, same as the consensus test suite) and submits them to the
  Favilla node via `submitbitcoinheader`. The Favilla node validates every
  header's PoW and tracks the most-work chain itself (SPEC §6).
- TESTNET: burns come from the user's own testnet4 wallet. The claim path
  fetches the burn tx, its Merkle proof (from the full confirmed block) and
  depth from an upstream testnet4 node (--btc-datadir/--btc-rpc-port), and
  checks the Favilla node's header chain (fed by the operator's header feed)
  before building the claim. `mine-btc` and `demo` are regtest-only.
- Burns are fully-formed, properly-signed P2WPKH Bitcoin transactions.
  Per SPEC D11 the Favilla node never validates burn inputs — inclusion at
  depth >= 144 in the header chain IS the validity argument.
- Key custody model (prototype): a single WIF keypair in the wallet file.
  Mainnet would use hardware-wallet signing (out of scope).

Chain parameters come from the CHAINS table (--testnet selects "fvlt":
magic 66766c74, RPC 34443, HRP "fvlt"); nothing chain-specific is hardcoded
elsewhere (audit F1).

Commands:
    newkey                  generate a burner keypair (prints WIF once)
    burn --amount <btc> [--key WIF]
                            regtest: create + sign a burn, mine 1 block.
                            testnet: print furnace address + instructions.
    mine-btc [N]             grind N Bitcoin headers (regtest only)
    claim <burn_txid> [--key WIF] [--mine]
                            file the v4 claim (loud failure without the key)
    status <burn_txid>       confirmations, eligibility, expected mint
    balance                 FVLA mints: locked (Vigil) vs spendable
    demo                    full happy-path end-to-end (regtest only)

Requires: python3 `ecdsa` package. A running favillad (regtest or testnet).
"""

import argparse
import base64
import hashlib
import json
import os
import struct
import sys
import time
import urllib.request
import urllib.error

from ecdsa import SigningKey, SECP256k1, util
from ecdsa.ellipticcurve import Point  # SEC 1 public-key recovery (D13e)

# ---------------------------------------------------------------- constants

FURNACE_HASH160 = bytes.fromhex("e881fbbaf021322e69c396b9da2b554602d4fde9")
FURNACE_SPK = b"\x00\x14" + FURNACE_HASH160          # P2WPKH, SPEC §3
# ---------------------------------------------------------------- chain selection
# Set by --testnet in main(). Every chain-specific value (signature magic,
# RPC port/cookie, address HRP, furnace address) MUST come from here —
# nothing chain-specific may be hardcoded elsewhere (audit F1).

CHAINS = {
    "regtest": {
        "magic": bytes([0x66, 0x76, 0x6c, 0x61]),  # "fvla", SPEC §2.1
        "rpc_port": 28443,
        "cookie_subdir": "regtest",
        "hrp": "fvla",                            # node code-truth (SPEC §2.1)
        "furnace_addr": "fvla1qazqlhwhsyyezu6wrj6ua5264gcpdfl0ffnewuz",  # SPEC §3
        "simulated_btc": True,   # wallet grinds its own fake Bitcoin chain
    },
    "testnet": {
        "magic": bytes([0x66, 0x76, 0x6c, 0x74]),  # "fvlt", SPEC §2.2
        "rpc_port": 34443,
        "cookie_subdir": "testnet",
        "hrp": "fvlt",
        "furnace_addr": "fvlt1qazqlhwhsyyezu6wrj6ua5264gcpdfl0fqtwx7p",  # SPEC §3
        "simulated_btc": False,  # REAL Bitcoin testnet4 burns only
    },
}
CHAIN = CHAINS["regtest"]

BTC_BITS = 0x207FFFFF                                # bitcoin-regtest, no retarget
BURN_CONFIRMATIONS = 144                             # SPEC §7 V3
VIGIL_BLOCKS = 210_000                               # SPEC §11
FIRE_BLOCKS = 210_000                                # SPEC §9
CINIS_PER_FVLA = 100_000_000

OP_CLTV, OP_DROP, OP_CHECKSIG = 0xB1, 0x75, 0xAC

# ---------------------------------------------------------------- primitives

def sha256d(b: bytes) -> bytes:
    return hashlib.sha256(hashlib.sha256(b).digest()).digest()

def sha256(b: bytes) -> bytes:
    return hashlib.sha256(b).digest()

def hash160(b: bytes) -> bytes:
    return hashlib.new("ripemd160", hashlib.sha256(b).digest()).digest()

def compact(n: int) -> bytes:
    if n < 0xfd:
        return struct.pack("B", n)
    if n <= 0xffff:
        return b"\xfd" + struct.pack("<H", n)
    if n <= 0xffffffff:
        return b"\xfe" + struct.pack("<I", n)
    return b"\xff" + struct.pack("<Q", n)

def script_num(n: int) -> bytes:
    """Minimal CScriptNum encoding (matches Bitcoin Core byte-for-byte)."""
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
    assert len(data) <= 75
    return struct.pack("B", len(data)) + data

def vigil_script(unlock: int, pubkey33: bytes) -> bytes:
    """SPEC §11 VIGIL_SCRIPT."""
    return (push(script_num(unlock)) + bytes([OP_CLTV, OP_DROP]) +
            push(pubkey33) + bytes([OP_CHECKSIG]))

def target_from_bits(bits: int) -> int:
    exp = bits >> 24
    mant = bits & 0xFFFFFF
    if exp <= 3:
        return mant >> (8 * (3 - exp))
    return mant << (8 * (exp - 3))

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

# ---------------------------------------------------------------- base58 / WIF

_B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

def b58encode(b: bytes) -> str:
    n = int.from_bytes(b, "big")
    s = ""
    while n:
        n, r = divmod(n, 58)
        s = _B58[r] + s
    pad = len(b) - len(b.lstrip(b"\x00"))
    return "1" * pad + s

def b58decode(s: str) -> bytes:
    n = 0
    for ch in s:
        n = n * 58 + _B58.index(ch)
    b = n.to_bytes((n.bit_length() + 7) // 8, "big") if n else b""
    pad = len(s) - len(s.lstrip("1"))
    return b"\x00" * pad + b

def wif_from_privkey(priv32: bytes) -> str:
    payload = b"\x80" + priv32 + b"\x01"  # compressed
    return b58encode(payload + sha256d(payload)[:4])

def privkey_from_wif(wif: str) -> bytes:
    raw = b58decode(wif.strip())
    # Testnet-aware (audit 5c): 0x80 = mainnet/regtest-style, 0xEF = testnet.
    # (The 5c burn key was a 0xEF WIF and was rejected before this fix.)
    if len(raw) != 38 or raw[0] not in (0x80, 0xEF) or raw[-5] != 0x01:
        raise WalletError("WIF malformed: expected 38 bytes, 0x80/0xEF prefix, compressed flag")
    if sha256d(raw[:-4])[:4] != raw[-4:]:
        raise WalletError("WIF checksum mismatch")
    return raw[1:33]

# ---------------------------------------------------------------- keys

class WalletError(Exception):
    """User-facing errors: printed plainly, no stack trace."""

def gen_keypair():
    sk = SigningKey.generate(curve=SECP256k1)
    priv = sk.to_string()  # 32 bytes big-endian
    return priv, pubkey33_from_priv(priv)

def pubkey33_from_priv(priv32: bytes) -> bytes:
    sk = SigningKey.from_string(priv32, curve=SECP256k1)
    vk = sk.get_verifying_key()
    x = vk.pubkey.point.x().to_bytes(32, "big")
    prefix = b"\x02" if vk.pubkey.point.y() % 2 == 0 else b"\x03"
    return prefix + x

def der_sign(priv32: bytes, msg32: bytes) -> bytes:
    sk = SigningKey.from_string(priv32, curve=SECP256k1)
    return sk.sign_digest(msg32, sigencode=util.sigencode_der)

def claim_msg_digest(burn_txid_internal: bytes) -> bytes:
    """SPEC §7 V5 message digest (D13e): the STANDARD Bitcoin Signed Message
    digest over the payload P = "FVLA-CLAIM" || network_magic || burn_txid
    (46 bytes, burn_txid in internal byte order).
      digest = SHA256D("\\x18Bitcoin Signed Message:\\n" || CompactSize(45) || P)
    The chain magic is consensus-critical: regtest claims sign b"fvla",
    testnet claims sign b"fvlt" (domain separation across Favilla networks).
    This is the format hardware wallets sign — the wallet never needs to
    export the key for a custom digest."""
    payload = b"FVLA-CLAIM" + CHAIN["magic"] + burn_txid_internal
    # 10 ("FVLA-CLAIM") + 4 (network magic) + 32 (burn txid) = 46 bytes.
    # (SPEC §7 V5's parenthetical "45-byte" is an arithmetic slip; the
    # normative rule is CompactSize(len(P)), which this implements.)
    assert len(payload) == 46, f"claim payload must be 46 bytes, got {len(payload)}"
    envelope = b"\x18Bitcoin Signed Message:\n" + compact(len(payload)) + payload
    return sha256d(envelope)

def _recover_point(r: int, s: int, digest32: bytes, recid: int):
    """SEC 1 v2 §4.1.6 public-key recovery: candidate point for (r, s, recid).
    Returns None if the x-coordinate is out of range."""
    curve = SECP256k1.curve
    G = SECP256k1.generator
    n = SECP256k1.order
    p = curve.p()
    x = r + (recid // 2) * n
    if x >= p:
        return None
    # y^2 = x^3 + a*x + b (mod p); p % 4 == 3 for secp256k1 so sqrt is direct.
    alpha = (pow(x, 3, p) + curve.a() * x + curve.b()) % p
    beta = pow(alpha, (p + 1) // 4, p)
    y = beta if (beta % 2 == recid % 2) else p - beta
    R = Point(curve, x, y, n)
    e = int.from_bytes(digest32, "big")
    r_inv = pow(r, n - 2, n)
    Q = ((-e * r_inv) % n) * G + ((s * r_inv) % n) * R
    return Q

def compact_sign(priv32: bytes, digest32: bytes) -> bytes:
    """Sign a 32-byte message digest, returning the 65-byte compact
    recoverable signature (SPEC §7 V5, D13e): recid (1 byte, 0-3) ||
    r (32 bytes BE) || s (32 bytes BE). Deterministic nonce (RFC 6979)."""
    sk = SigningKey.from_string(priv32, curve=SECP256k1)
    sig64 = sk.sign_digest_deterministic(digest32, hashfunc=hashlib.sha256,
                                         sigencode=util.sigencode_string)
    r = int.from_bytes(sig64[:32], "big")
    s = int.from_bytes(sig64[32:], "big")
    want = sk.get_verifying_key().pubkey.point
    for recid in range(4):
        if _recover_point(r, s, digest32, recid) == want:
            return bytes([recid]) + sig64
    raise WalletError("compact_sign: no recovery id reproduces the public key "
                      "(unreachable — investigate)")

def cinis_for(burned_sats: int, burn_btc_height: int) -> int:
    """SPEC §9 (D13c): the Fire era — and hence the mint rate — is locked at
    BURN time: fire = burn_btc_height // FIRE_BLOCKS. The claim's Favilla
    height plays no role in issuance (only in the Vigil unlock)."""
    fire = burn_btc_height // FIRE_BLOCKS
    heat = 1_000_000 * (2 ** fire)
    return (burned_sats * CINIS_PER_FVLA) // heat

# ---------------------------------------------------------------- bech32 (BIP173)

_BECH32_CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"

def _bech32_polymod(values):
    GEN = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3]
    chk = 1
    for v in values:
        b = chk >> 25
        chk = ((chk & 0x1ffffff) << 5) ^ v
        for i in range(5):
            chk ^= GEN[i] if ((b >> i) & 1) else 0
    return chk

def _bech32_hrp_expand(hrp):
    return [ord(x) >> 5 for x in hrp] + [0] + [ord(x) & 31 for x in hrp]

def _convertbits(data, frombits, tobits, pad=True):
    acc = bits = 0
    ret = bytearray()
    maxv = (1 << tobits) - 1
    for b in data:
        acc = (acc << frombits) | b
        bits += frombits
        while bits >= tobits:
            bits -= tobits
            ret.append((acc >> bits) & maxv)
    if pad and bits:
        ret.append((acc << (tobits - bits)) & maxv)
    return bytes(ret)

def bech32_encode(hrp, witver, program):
    """Encode a segwit address."""
    data = [witver] + list(_convertbits(program, 8, 5))
    pm = _bech32_polymod(_bech32_hrp_expand(hrp) + data + [0] * 6) ^ 1
    checksum = [(pm >> 5 * (5 - i)) & 31 for i in range(6)]
    return hrp + "1" + "".join(_BECH32_CHARSET[d] for d in data + checksum)

def bech32_decode(addr):
    """Returns (hrp, witver, program_bytes). Raises WalletError on failure."""
    addr = addr.strip()
    if addr.lower() != addr and addr.upper() != addr:
        raise WalletError(f"bad address {addr!r}: mixed case")
    addr = addr.lower()
    pos = addr.rfind("1")
    if pos < 1 or pos + 7 > len(addr):
        raise WalletError(f"bad address {addr!r}")
    hrp, data = addr[:pos], addr[pos + 1:]
    try:
        vals = [_BECH32_CHARSET.index(c) for c in data]
    except ValueError:
        raise WalletError(f"bad address {addr!r}: bad charset")
    if _bech32_polymod(_bech32_hrp_expand(hrp) + vals) != 1:
        raise WalletError(f"bad address {addr!r}: checksum failed")
    witver = vals[0]
    prog = _convertbits(vals[1:-6], 5, 8, pad=False)
    if not (2 <= witver <= 16 or witver == 0):
        raise WalletError(f"bad address {addr!r}: bad witness version")
    # round-trip: re-encode and compare (catches padding/length issues)
    if bech32_encode(hrp, witver, prog) != addr:
        raise WalletError(f"bad address {addr!r}: re-encode mismatch")
    return hrp, witver, prog

def p2wpkh_address(pubkey33: bytes, hrp: str = None) -> str:
    return bech32_encode(hrp or CHAIN["hrp"], 0, hash160(pubkey33))

# ---------------------------------------------------------------- RPC client

class NodeError(Exception):
    def __init__(self, code, message):
        super().__init__(f"[{code}] {message}")
        self.code = code
        self.message = message

class FavillaRPC:
    def __init__(self, datadir, rpc_port, subdir=None, name="favillad"):
        self.url = f"http://127.0.0.1:{rpc_port}"
        self.name = name
        subdir = subdir if subdir is not None else CHAIN["cookie_subdir"]
        cookie = os.path.join(datadir, subdir, ".cookie")
        if not os.path.exists(cookie):
            raise WalletError(
                f"no RPC cookie at {cookie} — is {name} running with "
                f"-datadir={datadir} ({subdir})?")
        with open(cookie) as f:
            userpass = f.read().strip()
        self._auth = "Basic " + base64.b64encode(userpass.encode()).decode()

    def __call__(self, method, *params, _wallet=None):
        url = self.url + (f"/wallet/{_wallet}" if _wallet else "")
        body = json.dumps({"jsonrpc": "1.0", "id": "furnace",
                           "method": method, "params": list(params)}).encode()
        req = urllib.request.Request(
            url, data=body,
            headers={"Content-Type": "application/json",
                     "Authorization": self._auth})
        try:
            with urllib.request.urlopen(req, timeout=120) as r:
                resp = json.loads(r.read())
        except urllib.error.HTTPError as e:
            resp = json.loads(e.read())
        except (urllib.error.URLError, ConnectionRefusedError):
            raise WalletError(
                f"cannot reach {self.name} at {self.url} — is it running?")
        if resp.get("error"):
            raise NodeError(resp["error"]["code"], resp["error"]["message"])
        return resp["result"]


def bitcoin_rpc(datadir, rpc_port):
    """Upstream Bitcoin (testnet4) node RPC — testnet mode only."""
    return FavillaRPC(os.path.expanduser(datadir), rpc_port,
                      subdir="testnet4", name="bitcoind (testnet4)")


class MempoolSpaceBtc:
    """mempool.space testnet4 API as a drop-in `btc(...)` callable.

    Our upstream Bitcoin node is headers-only (no txindex, no blocks), so
    the wallet cannot fetch burn txs / full blocks from it. This client
    sources the same fields from mempool.space instead. It is DATA FETCH
    only: the Favilla node independently re-validates everything the claim
    carries (header membership, Merkle branch, depth, amount, signature),
    so a wrong API answer fails loudly at claim time rather than passing
    silently. Testnet only.
    """
    BASE = "https://mempool.space/testnet4/api"

    def __init__(self):
        self.name = "mempool.space (testnet4)"

    @staticmethod
    def _curl(path, timeout=60):
        """mempool.space GET via curl subprocess.

        This sandbox's egress proxy answers urllib's credential-less CONNECT
        with 403/407 instead of challenging properly, so urllib's proxy auth
        never completes; curl sends Proxy-Authorization preemptively and works.
        Returns (http_code:int, body:bytes)."""
        import subprocess
        out = subprocess.run(
            ["curl", "-sS", "--max-time", str(timeout),
             "-o", "-", "-w", "\n%{http_code}",
             MempoolSpaceBtc.BASE + path,
             "-H", "User-Agent: favilla-furnace/1.0"],
            capture_output=True, timeout=timeout + 10)
        if out.returncode != 0:
            raise NodeError(-1, f"mempool.space unreachable for {path}: "
                                f"{out.stderr.decode(errors='replace').strip()[:160]}")
        body, _, code = out.stdout.rpartition(b"\n")
        try:
            http_code = int(code.strip())
        except ValueError:
            raise NodeError(-1, f"mempool.space bad response for {path}")
        return http_code, body

    def _get(self, path, expect_json=True):
        http_code, body = self._curl(path, timeout=60)
        if http_code == 404:
            raise NodeError(-5, f"mempool.space: {path} not found (404)")
        if http_code != 200:
            raise NodeError(-1, f"mempool.space HTTP {http_code} for {path}")
        return json.loads(body) if expect_json else body.decode().strip()

    def _get_raw(self, path):
        """GET a binary endpoint; returns raw bytes (no decode)."""
        http_code, body = self._curl(path, timeout=120)
        if http_code == 404:
            raise NodeError(-5, f"mempool.space: {path} not found (404)")
        if http_code != 200:
            raise NodeError(-1, f"mempool.space HTTP {http_code} for {path}")
        return body

    def __call__(self, method, *params):
        if method == "getrawtransaction":
            txid = params[0]
            info = self._get(f"/tx/{txid}")
            raw = self._get(f"/tx/{txid}/hex", expect_json=False)
            out = {"hex": raw}
            st = info.get("status") or {}
            bh = st.get("block_hash") if st.get("confirmed") else None
            if bh:
                # only advertise a blockhash the block endpoint can serve —
                # the tx index can briefly lead the block index (reorg race)
                try:
                    self._get(f"/block/{bh}")
                except NodeError:
                    bh = None
            if bh:
                out["blockhash"] = bh
            return out
        if method == "getblockheader":
            h, verbose = params[0], params[1]
            if verbose:
                return {"height": self._get(f"/block/{h}")["height"]}
            hdr = self._get(f"/block/{h}/header", expect_json=False)
            assert len(hdr) == 160, "bad header hex length"
            return hdr
        if method == "getblock":
            h = params[0]
            # /block/<h>/raw returns BINARY block data; the caller does
            # bytes.fromhex() on the result, so return hex here (2026-10-10:
            # the old .decode() path raised UnicodeDecodeError on real blocks).
            return self._get_raw(f"/block/{h}/raw").hex()
        if method == "getblockcount":
            return int(self._get("/blocks/tip/height", expect_json=False))
        raise NodeError(-1, f"mempool.space adapter: unsupported method {method!r}")

# ---------------------------------------------------------------- wallet state

class Wallet:
    """~/.favilla-wallet/: key.wif, btcchain.json, claims.json."""

    def __init__(self, wdir):
        self.wdir = os.path.expanduser(wdir)
        os.makedirs(self.wdir, exist_ok=True)
        self.key_path = os.path.join(self.wdir, "key.wif")
        self.chain_path = os.path.join(self.wdir, "btcchain.json")
        self.claims_path = os.path.join(self.wdir, "claims.json")

    # -- key --
    def has_key(self):
        return os.path.exists(self.key_path)

    def load_key(self, wif_override=None) -> bytes:
        """Returns 32-byte privkey. Loud failure if none available."""
        if wif_override:
            try:
                return privkey_from_wif(wif_override)
            except WalletError as e:
                raise WalletError(f"bad --key: {e}")
        if self.has_key():
            with open(self.key_path) as f:
                try:
                    return privkey_from_wif(f.read())
                except WalletError as e:
                    raise WalletError(f"wallet key file corrupt: {e}\n"
                                      f"Delete {self.key_path} and run `newkey`.")
        raise WalletError(
            "no burner key available.\n\n"
            "A burn MUST come from a key you control. The claim requires a\n"
            "signature from the burn's key (SPEC §7 V5) — this is what makes\n"
            "burns from exchanges or custodians fail LOUDLY (unclaimable)\n"
            "instead of silently minting FVLA to the custodian's key.\n\n"
            "Run `furnace.py newkey` to generate one, or pass --key <WIF>.")

    def save_key(self, priv32: bytes):
        with open(self.key_path, "w") as f:
            f.write(wif_from_privkey(priv32))
        os.chmod(self.key_path, 0o600)

    # -- simulated bitcoin chain --
    def load_chain(self):
        if os.path.exists(self.chain_path):
            with open(self.chain_path) as f:
                return json.load(f)
        return {"headers": [], "blocks": [], "burns": {}, "submitted": 0}

    def save_chain(self, ch):
        tmp = self.chain_path + ".tmp"
        with open(tmp, "w") as f:
            json.dump(ch, f)
        os.replace(tmp, self.chain_path)

    # -- claims --
    def load_claims(self):
        if os.path.exists(self.claims_path):
            with open(self.claims_path) as f:
                return json.load(f)
        return {}

    def save_claims(self, c):
        tmp = self.claims_path + ".tmp"
        with open(tmp, "w") as f:
            json.dump(c, f)
        os.replace(tmp, self.claims_path)

# ---------------------------------------------------------------- simulated Bitcoin chain

def make_btc_header(prev_internal: bytes, root_internal: bytes, timestamp: int,
                    bits: int = BTC_BITS, nonce: int = 0) -> bytes:
    return (struct.pack("<i", 1) + prev_internal + root_internal +
            struct.pack("<III", timestamp, bits, nonce))

def grind_btc_header(prev_internal: bytes, root_internal: bytes, timestamp: int,
                     bits: int = BTC_BITS) -> bytes:
    target = target_from_bits(bits)
    nonce = 0
    while True:
        h = make_btc_header(prev_internal, root_internal, timestamp, bits, nonce)
        if int.from_bytes(sha256d(h), "little") <= target:
            return h
        nonce += 1
        if nonce > 10_000_000:
            raise WalletError("header grind failed (should be impossible on regtest)")

def fake_coinbase() -> bytes:
    """Minimal coinbase; never validated by Favilla, only hashed into the tree."""
    return (struct.pack("<i", 2) + compact(1) + b"\x00" * 32 +
            struct.pack("<I", 0xFFFFFFFF) + compact(0) +
            struct.pack("<I", 0xFFFFFFFF) + compact(1) +
            struct.pack("<q", 0) + compact(1) + b"\x51" +
            struct.pack("<I", 0))

def bip143_sighash(priv32: bytes, prev_txid: bytes, prev_vout: int,
                   prev_value: int, pubkey33: bytes, tx_ins, tx_outs,
                   locktime: int = 0) -> bytes:
    """BIP143 SIGHASH_ALL preimage hash for a P2WPKH input."""
    h160 = hash160(pubkey33)
    script_code = b"\x76\xa9\x14" + h160 + b"\x88\xac"  # P2PKH script of the key
    hash_prevouts = sha256d(b"".join(t + struct.pack("<I", i) for t, i, _, _ in tx_ins))
    hash_sequence = sha256d(b"".join(struct.pack("<I", s) for _, _, _, s in tx_ins))
    outs = b""
    for val, spk in tx_outs:
        outs += struct.pack("<q", val) + compact(len(spk)) + spk
    hash_outputs = sha256d(outs)
    preimage = (struct.pack("<i", 2) + hash_prevouts + hash_sequence +
                prev_txid + struct.pack("<I", prev_vout) +
                compact(len(script_code)) + script_code +
                struct.pack("<q", prev_value) + struct.pack("<I", 0xFFFFFFFF) +
                hash_outputs + struct.pack("<I", locktime) +
                struct.pack("<I", 1))  # SIGHASH_ALL
    return sha256d(preimage)

def build_burn_tx(priv32: bytes, amount_sats: int):
    """Build a fully-formed P2WPKH burn: 1 input spending a simulated
    confirmed UTXO of the burner's key, 1 output paying FURNACE_SPK.
    Returns (tx_with_witness_bytes, txid_internal, pubkey33).

    The prevout is simulated (the prototype has no live Bitcoin network);
    the signature is REAL — valid relative to its own fictional prevout —
    exactly as a hardware wallet would produce for a real one. Per SPEC D11
    the Favilla node never validates burn inputs, so consensus treats this
    identically to a mainnet burn."""
    pubkey33 = pubkey33_from_priv(priv32)
    # Simulated confirmed funding UTXO paying to our P2WPKH.
    fund_txid = sha256d(b"favilla-faucet" + pubkey33 + struct.pack("<q", amount_sats))
    fund_spk = b"\x00\x14" + hash160(pubkey33)
    # Real BIP143 signature over the fictional prevout.
    sighash = bip143_sighash(priv32, fund_txid, 0, amount_sats, pubkey33,
                             [(fund_txid, 0, b"", 0xFFFFFFFF)],
                             [(amount_sats, FURNACE_SPK)])
    sig_der = der_sign(priv32, sighash)
    # -- serialize with witness: <sig+SIGHASH_ALL> <pubkey> --
    wit_items = [sig_der + b"\x01", pubkey33]
    s = struct.pack("<i", 2) + b"\x00\x01" + compact(1)
    s += fund_txid + struct.pack("<I", 0) + compact(0) + struct.pack("<I", 0xFFFFFFFF)
    s += compact(1) + struct.pack("<q", amount_sats) + compact(len(FURNACE_SPK)) + FURNACE_SPK
    s += compact(len(wit_items))
    for it in wit_items:
        s += compact(len(it)) + it
    s += struct.pack("<I", 0)
    # txid = sha256d of the witness-stripped serialization (SPEC §7 V2)
    t = struct.pack("<i", 2) + compact(1)
    t += fund_txid + struct.pack("<I", 0) + compact(0) + struct.pack("<I", 0xFFFFFFFF)
    t += compact(1) + struct.pack("<q", amount_sats) + compact(len(FURNACE_SPK)) + FURNACE_SPK
    t += struct.pack("<I", 0)
    return s, sha256d(t), pubkey33

def _chain_base(wallet: Wallet, node) -> tuple:
    """Return (base_height, base_prev_hash_hex) that new local headers build on.

    The wallet's header i (0-indexed) lives at node height base_height + 1 + i.
    Aligned once against the node's header chain, then stored."""
    ch = wallet.load_chain()
    if "base_height" not in ch:
        info = node("getbitcoinheaderchaininfo")
        tip_h = info["tip_height"]
        if tip_h is None or tip_h < 0:
            ch["base_height"] = -1
            ch["base_prev"] = "00" * 32
        else:
            ch["base_height"] = tip_h
            # tip_hash is display order (reversed); headers need internal order
            ch["base_prev"] = bytes.fromhex(info["tip_hash"])[::-1].hex()
        wallet.save_chain(ch)
    return ch["base_height"], ch["base_prev"]

def _check_chain_consistent(wallet: Wallet, node):
    """Fail clearly if the node's header chain was reset under this wallet."""
    ch = wallet.load_chain()
    if not ch["headers"]:
        return
    expect_tip = ch["base_height"] + len(ch["headers"])
    try:
        tip = node("getbitcoinheaderchaininfo")["tip_height"]
    except (NodeError, WalletError):
        return  # node unreachable; caller handles
    if tip is not None and tip >= 0 and tip < expect_tip:
        raise WalletError(
            "the Favilla node's Bitcoin header chain looks RESET (its tip is "
            f"below this wallet's headers: node={tip}, wallet expects>={expect_tip}).\n"
            "Wallet state is stale — use a fresh --wallet-dir, or restart the "
            "node AND the wallet together.")

def mine_btc_block(wallet: Wallet, txs, node=None, quiet=False):
    """Grind one header over [coinbase] + txs, append to chain state,
    submit the header to the Favilla node if given.
    txs: list of (raw_bytes, txid_internal) — txid MUST be the witness-stripped
    SHA256D (the wtxid is NOT the txid).
    Returns (node_height, header_hex)."""
    base_h, base_prev = _chain_base(wallet, node) if node else (-1, "00" * 32)
    # note: when node is None we cannot align; require node for real use
    ch = wallet.load_chain()
    if node is None and not ch["headers"] and "base_height" not in ch:
        raise WalletError("mine-btc needs the Favilla node up (to align header heights)")
    prev = bytes.fromhex(ch["headers"][-1]["hash"]) if ch["headers"] else bytes.fromhex(base_prev)
    node_height = base_h + len(ch["headers"]) + 1
    cb = fake_coinbase()
    txids = [sha256d(cb)] + [txid for _, txid in txs]
    root = merkle_root(txids)
    hdr = grind_btc_header(prev, root, 1_700_000_000 + node_height * 600)
    hh = sha256d(hdr)
    ch["headers"].append({"hash": hh.hex(), "header": hdr.hex(), "height": node_height})
    ch["blocks"].append({"txids": [t.hex() for t in txids],
                         "txs": {txid.hex(): raw.hex() for raw, txid in txs}})
    if node is not None:
        try:
            r = node("submitbitcoinheader", hdr.hex())
            if r.get("height", node_height) != node_height:
                print(f"warning: node reports header at height {r.get('height')}, "
                      f"wallet expected {node_height}")
        except (NodeError, WalletError) as e:
            if not quiet:
                print(f"warning: header {node_height} not submitted ({e}); "
                      f"run with the node up to sync")
    wallet.save_chain(ch)
    return node_height, hdr.hex()

def _local_idx(ch, node_height: int) -> int:
    """Node height -> index into the wallet's local headers/blocks lists."""
    return node_height - ch["base_height"] - 1

def sync_headers(wallet: Wallet, node) -> int:
    """Submit all locally-mined headers the node hasn't seen. Returns count."""
    ch = wallet.load_chain()
    n = 0
    for h in ch["headers"][ch.get("submitted", 0):]:
        node("submitbitcoinheader", h["header"])
        n += 1
    ch["submitted"] = len(ch["headers"])
    wallet.save_chain(ch)
    return n

def btc_tip_height(wallet: Wallet) -> int:
    """Node height of the wallet's last local header (-1 if none)."""
    ch = wallet.load_chain()
    if not ch["headers"]:
        return ch.get("base_height", -1)
    return ch["base_height"] + len(ch["headers"])

# ---------------------------------------------------------------- claim construction (SPEC §5)

def ser_claim(burn_txid_internal: bytes, header80: bytes, branch, index: int,
              burn_tx_bytes: bytes, sig_der: bytes, vout_list) -> bytes:
    s = struct.pack("<i", 4)  # nVersion = 4
    s += compact(1)  # marker input
    s += b"\x00" * 32 + struct.pack("<I", 0xFFFFFFFF) + compact(0) + struct.pack("<I", 0xFFFFFFFF)
    assert len(header80) == 80
    s += burn_txid_internal + header80
    s += compact(len(branch)) + b"".join(branch)
    s += struct.pack("<I", index)
    s += compact(len(burn_tx_bytes)) + burn_tx_bytes
    s += compact(len(sig_der)) + sig_der
    s += struct.pack("<I", 0)  # nLockTime
    s += compact(len(vout_list))
    for val, spk in vout_list:
        s += struct.pack("<q", val) + compact(len(spk)) + spk
    return s

def _read_compact(b: bytes, o: int):
    first = b[o]
    if first < 0xfd:
        return first, o + 1
    if first == 0xfd:
        return struct.unpack("<H", b[o+1:o+3])[0], o + 3
    if first == 0xfe:
        return struct.unpack("<I", b[o+1:o+5])[0], o + 5
    return struct.unpack("<Q", b[o+1:o+9])[0], o + 9

def _witness_pubkey(burn_tx: bytes) -> bytes:
    o = 4 + 2
    nvin, o = _read_compact(burn_tx, o)
    # skip inputs
    in0_wit_off = None
    for i in range(nvin):
        o += 32 + 4
        sl, o = _read_compact(burn_tx, o); o += sl
        o += 4
    nout, o = _read_compact(burn_tx, o)
    for _ in range(nout):
        o += 8
        sl, o = _read_compact(burn_tx, o); o += sl
    # witness stacks
    for i in range(nvin):
        nitems, o = _read_compact(burn_tx, o)
        items = []
        for _ in range(nitems):
            il, o = _read_compact(burn_tx, o)
            items.append(burn_tx[o:o+il]); o += il
        if i == 0:
            for it in items:
                if len(it) == 33 and it[0] in (0x02, 0x03):
                    return it
    raise WalletError("burn input 0 reveals no compressed pubkey "
                      "(Taproot key-path burns are unclaimable in the prototype)")


def _parse_tx_txid(b: bytes, o: int):
    """Parse one Bitcoin tx at offset o; return (txid_internal, next_offset).
    txid is the witness-stripped SHA256D (SPEC §7 V2)."""
    start = o
    o += 4  # nVersion
    has_wit = b[o] == 0 and b[o + 1] == 1
    if has_wit:
        o += 2
    in_start = o
    nvin, o = _read_compact(b, o)
    for _ in range(nvin):
        o += 36
        sl, o = _read_compact(b, o)
        o += sl
        o += 4
    out_start = o
    nout, o = _read_compact(b, o)
    for _ in range(nout):
        o += 8
        sl, o = _read_compact(b, o)
        o += sl
    out_end = o
    if has_wit:
        for _ in range(nvin):
            nitems, o = _read_compact(b, o)
            for _ in range(nitems):
                il, o = _read_compact(b, o)
                o += il
    locktime = b[o:o + 4]
    o += 4
    stripped = b[start:start + 4] + b[in_start:out_end] + locktime
    return sha256d(stripped), o


def parse_block_txids(block_bytes: bytes):
    """Parse a raw Bitcoin block; return [txid_internal] in block order."""
    if len(block_bytes) < 80:
        raise WalletError("block too short for an 80-byte header")
    o = 80
    ntx, o = _read_compact(block_bytes, o)
    if ntx == 0 or ntx > 10_000_000:
        raise WalletError(f"absurd tx count {ntx} in block")
    txids = []
    for _ in range(ntx):
        txid, o = _parse_tx_txid(block_bytes, o)
        txids.append(txid)
    return txids


def _tx_outputs(burn_tx: bytes):
    """Yield (value_sats, scriptPubKey) for each output of a raw tx."""
    o = 4
    has_wit = burn_tx[o] == 0 and burn_tx[o + 1] == 1
    if has_wit:
        o += 2
    nvin, o = _read_compact(burn_tx, o)
    for _ in range(nvin):
        o += 36
        sl, o = _read_compact(burn_tx, o)
        o += sl
        o += 4
    nout, o = _read_compact(burn_tx, o)
    for _ in range(nout):
        val = struct.unpack("<q", burn_tx[o:o + 8])[0]
        o += 8
        sl, o = _read_compact(burn_tx, o)
        yield val, burn_tx[o:o + sl]
        o += sl

def build_claim(wallet: Wallet, burn_txid_hex: str, priv32: bytes, node) -> dict:
    """Assemble, sign and return (not submit) a v4 claim. Raises WalletError
    with plain-language messages on any problem."""
    ch = wallet.load_chain()
    _check_chain_consistent(wallet, node)
    sync_headers(wallet, node)
    burn = ch["burns"].get(burn_txid_hex.lower())
    if not burn:
        raise WalletError(
            f"unknown burn {burn_txid_hex[:16]}… — no record in this wallet.\n"
            f"Claims need the burn's block (header + Merkle branch). If the burn\n"
            f"was made with this wallet, check the txid; otherwise the wallet\n"
            f"never saw the burn's Bitcoin block.")
    # depth check against the node's own header chain (SPEC §7 V3)
    info = node("getbitcoinheaderchaininfo")
    tip = info["tip_height"]
    depth = tip - burn["btc_height"]
    if depth < BURN_CONFIRMATIONS:
        need = BURN_CONFIRMATIONS - depth
        raise WalletError(
            f"burn has {depth} Bitcoin confirmations; {BURN_CONFIRMATIONS} required.\n"
            f"Mine {need} more Bitcoin blocks:  furnace.py mine-btc {need}")
    # key must match the burn's input-0 key — LOUD failure otherwise
    burn_tx = bytes.fromhex(burn["tx_hex"])
    try:
        input0_pubkey = _witness_pubkey(burn_tx)
    except WalletError as e:
        raise WalletError(f"cannot claim this burn: {e}")
    mine_pubkey = pubkey33_from_priv(priv32)
    if mine_pubkey != input0_pubkey:
        raise WalletError(
            "YOU DON'T CONTROL THE BURN KEY — this burn can never be claimed\n"
            "with the key you provided.\n\n"
            "The claim must carry a signature from the private key behind the\n"
            "burn's first input (SPEC §7 V5). The key you gave corresponds to a\n"
            "different public key than the one that funded this burn.\n\n"
            "If this burn was made from an exchange or custodial wallet, there\n"
            "is no key to provide: the burn is unclaimable BY DESIGN, so the\n"
            "FVLA cannot silently mint to the custodian's key. The sats are\n"
            "burned; nothing will ever mint from them. Burn only from\n"
            "self-custody (ideally a fresh single-use address per offering).")
    # assemble the claim for the next Favilla height
    H = node("getblockcount") + 1
    # D13c: the mint rate is locked at burn time (fire by burn's btc height).
    cinis = cinis_for(burn["sats"], burn["btc_height"])
    if cinis <= 0:
        raise WalletError(f"burn of {burn['sats']} sats mints 0 cinis in fire "
                          f"{burn['btc_height'] // FIRE_BLOCKS} (burn's era) — dust.")
    unlock = H + VIGIL_BLOCKS
    spk = vigil_script(unlock, input0_pubkey)
    li = _local_idx(ch, burn["btc_height"])
    block = ch["blocks"][li]
    txids = [bytes.fromhex(t) for t in block["txids"]]
    branch = merkle_branch(txids, burn["merkle_index"])
    # burn_txid_hex is display order (user-facing); consensus uses internal
    burn_txid_internal = bytes.fromhex(burn_txid_hex)[::-1]
    # D13e: standard Bitcoin Signed Message signature (65-byte compact).
    sig65 = compact_sign(priv32, claim_msg_digest(burn_txid_internal))
    raw = ser_claim(burn_txid_internal,
                    bytes.fromhex(ch["headers"][li]["header"]),
                    branch, burn["merkle_index"], burn_tx, sig65,
                    [(cinis, spk)])
    claim_txid = sha256d(raw)[::-1].hex()  # display order
    return {"raw_hex": raw.hex(), "claim_txid": claim_txid, "cinis": cinis,
            "fvla": cinis / CINIS_PER_FVLA, "height": H, "unlock": unlock,
            "spk_hex": spk.hex(), "pubkey": input0_pubkey.hex(),
            "sats": burn["sats"]}


def build_claim_testnet(burn_txid_hex: str, priv32: bytes, node, btc) -> dict:
    """Assemble, sign and return (not submit) a v4 claim for a REAL Bitcoin
    testnet4 burn. All burn data comes live from the upstream testnet4 node;
    the wallet keeps no simulated chain on testnet."""
    txid_hex = burn_txid_hex.strip().lower()
    if len(txid_hex) != 64 or any(c not in "0123456789abcdef" for c in txid_hex):
        raise WalletError(f"bad txid {burn_txid_hex!r}: expected 64 hex chars")

    # 1. fetch the burn tx (verbose) from the testnet4 node
    try:
        tx = btc("getrawtransaction", txid_hex, True)
    except NodeError as e:
        raise WalletError(
            f"burn {txid_hex[:16]}… not found on your Bitcoin testnet4 node.\n"
            f"  node said: {e.message}\n"
            "Is the txid right, and is your testnet4 node synced?")
    blockhash = tx.get("blockhash")
    if not blockhash:
        raise WalletError(
            f"burn {txid_hex[:16]}… is still in the testnet4 mempool "
            "(0 confirmations).\nWait for it to confirm, then claim.")
    burn_tx = bytes.fromhex(tx["hex"])

    # 2. confirmations on the real testnet4 chain
    hdr = btc("getblockheader", blockhash, True)
    btc_height = hdr["height"]
    tip = btc("getblockcount")
    depth = tip - btc_height + 1
    if depth < BURN_CONFIRMATIONS:
        raise WalletError(
            f"burn has {depth} testnet4 confirmations; "
            f"{BURN_CONFIRMATIONS} required.\n"
            f"Wait for {BURN_CONFIRMATIONS - depth} more testnet4 blocks "
            f"(roughly {(BURN_CONFIRMATIONS - depth) * 10} minutes), then claim.")

    # 3. the burn must actually pay the furnace — sum its furnace outputs
    sats = sum(v for v, spk in _tx_outputs(burn_tx) if spk == FURNACE_SPK)
    if sats <= 0:
        raise WalletError(
            f"burn {txid_hex[:16]}… has NO output paying the furnace script.\n"
            f"Only outputs to {CHAIN['furnace_addr']} count as burns. "
            "This transaction can never mint FVLA.")

    # 4. Merkle branch from the full confirmed block
    block_raw = bytes.fromhex(btc("getblock", blockhash, 0))
    txids = parse_block_txids(block_raw)
    target = bytes.fromhex(txid_hex)[::-1]  # display -> internal
    try:
        index = txids.index(target)
    except ValueError:
        raise WalletError("burn txid not found in its own confirmed block "
                          "(node data inconsistent — investigate before claiming)")
    branch = merkle_branch(txids, index)
    header80 = bytes.fromhex(btc("getblockheader", blockhash, False))
    assert len(header80) == 80

    # 5. key must match the burn's input-0 key — LOUD failure otherwise
    try:
        input0_pubkey = _witness_pubkey(burn_tx)
    except WalletError as e:
        raise WalletError(f"cannot claim this burn: {e}")
    mine_pubkey = pubkey33_from_priv(priv32)
    if mine_pubkey != input0_pubkey:
        raise WalletError(
            "YOU DON'T CONTROL THE BURN KEY — this burn can never be claimed\n"
            "with the key you provided.\n\n"
            "The claim must carry a signature from the private key behind the\n"
            "burn's first input (SPEC §7 V5). The key you gave corresponds to a\n"
            "different public key than the one that funded this burn.\n\n"
            "If this burn was made from an exchange or custodial wallet, there\n"
            "is no key to provide: the burn is unclaimable BY DESIGN, so the\n"
            "FVLA cannot silently mint to the custodian's key. The sats are\n"
            "burned; nothing will ever mint from them. Burn only from\n"
            "self-custody (ideally a fresh single-use address per offering).")

    # 6. the Favilla node must know this header (submit is idempotent; the
    #    header feed normally keeps it synced — this is a belt-and-suspenders
    #    check that fails clearly if the feed is down)
    try:
        r = node("submitbitcoinheader", header80.hex())
    except NodeError as e:
        raise WalletError(
            f"your Favilla node rejected the burn's Bitcoin header:\n  {e.message}\n\n"
            "Its Bitcoin header chain is probably behind — make sure the header\n"
            "feed is running against your testnet4 node, then try again.")
    h = r.get("height", -1)
    if h is None or h < 0:
        raise WalletError(
            "your Favilla node's Bitcoin header chain does not include this\n"
            "burn's block (not on its active header chain).\n"
            "Make sure the header feed is running against your testnet4 node.")
    ntip = node("getbitcoinheaderchaininfo")["tip_height"]
    if ntip - h < BURN_CONFIRMATIONS - 1:
        raise WalletError(
            f"your Favilla node knows the burn's block (header height {h}) but\n"
            f"its header tip is only {ntip} — it needs "
            f"{BURN_CONFIRMATIONS - 1 - (ntip - h)} more headers fed before "
            "this claim is eligible.")

    # 7. assemble exactly like the regtest path from here on
    H = node("getblockcount") + 1
    # D13c: the mint rate is locked at burn time (fire by burn's btc height).
    cinis = cinis_for(sats, btc_height)
    if cinis <= 0:
        raise WalletError(f"burn of {sats} sats mints 0 cinis in fire "
                          f"{btc_height // FIRE_BLOCKS} (burn's era) — dust.")
    unlock = H + VIGIL_BLOCKS
    spk = vigil_script(unlock, input0_pubkey)
    burn_txid_internal = bytes.fromhex(txid_hex)[::-1]
    # D13e: standard Bitcoin Signed Message signature (65-byte compact).
    sig65 = compact_sign(priv32, claim_msg_digest(burn_txid_internal))
    raw = ser_claim(burn_txid_internal, header80, branch, index,
                    burn_tx, sig65, [(cinis, spk)])
    claim_txid = sha256d(raw)[::-1].hex()  # display order
    return {"raw_hex": raw.hex(), "claim_txid": claim_txid, "cinis": cinis,
            "fvla": cinis / CINIS_PER_FVLA, "height": H, "unlock": unlock,
            "spk_hex": spk.hex(), "pubkey": input0_pubkey.hex(),
            "sats": sats, "btc_height": btc_height, "depth": depth}

# ---------------------------------------------------------------- commands

def parse_btc_amount(s: str) -> int:
    """Decimal BTC string -> exact sats. No floats."""
    s = s.strip()
    if "." in s:
        whole, frac = s.split(".", 1)
        if len(frac) > 8 or not frac.isdigit():
            raise WalletError(f"bad amount {s!r}: at most 8 decimals")
        frac = frac.ljust(8, "0")
    else:
        whole, frac = s, "00000000"
    if not whole.isdigit():
        raise WalletError(f"bad amount {s!r}")
    sats = int(whole) * CINIS_PER_FVLA + int(frac)
    if sats <= 0:
        raise WalletError("amount must be positive")
    if sats > 21_000_000 * CINIS_PER_FVLA:
        raise WalletError("amount exceeds total Bitcoin supply (sanity check)")
    return sats

def fmt_fvla(cinis: int) -> str:
    return f"{cinis / CINIS_PER_FVLA:.8f}".rstrip("0").rstrip(".")

def cmd_newkey(wallet: Wallet, args):
    priv, pub = gen_keypair()
    if wallet.has_key():
        print("wallet already has a key. Overwrite? [y/N] ", end="")
        if input().strip().lower() != "y":
            print("kept existing key.")
            return
    wallet.save_key(priv)
    print("new burner key generated and saved to", wallet.key_path)
    print()
    print("  WIF (private — back this up, never share it):")
    print(f"    {wif_from_privkey(priv)}")
    print()
    print(f"  pubkey: {pub.hex()}")
    print(f"  HASH160: {hash160(pub).hex()}")
    print(f"  favilla P2WPKH address: {p2wpkh_address(pub)}")
    print()
    print("Burns from this key will mint FVLA to the P2WPKH above (deterministic")
    print("recipient). On mainnet this key would be created and held by a")
    print("hardware wallet; the prototype keeps a hot WIF for convenience.")

def cmd_burn(wallet: Wallet, args, node):
    if not CHAIN["simulated_btc"]:
        # TESTNET: burns are REAL testnet4 transactions. The wallet cannot
        # fabricate them — the user broadcasts from their own testnet4 wallet.
        print("testnet burn: send REAL testnet4 BTC to the furnace.")
        print()
        print(f"  furnace (testnet4): {CHAIN['furnace_addr']}")
        print()
        print("Use any testnet4 wallet (Sparrow, bitcoin-cli, …). The burn MUST")
        print("come from a key you control — burns from exchanges/custodians")
        print("are unclaimable by design (SPEC §7 V5).")
        if getattr(args, "amount", None):
            print(f"You asked about {args.amount} tBTC — send exactly that "
                  "amount; the fee is separate.")
        print()
        print("After it confirms, file the claim:")
        print("  furnace.py --testnet claim <burn_txid> [--key <WIF>]")
        print()
        print("Then wait for 144 testnet4 confirmations before claiming.")
        return
    sats = parse_btc_amount(args.amount)
    priv = wallet.load_key(args.key)  # loud refusal without a key
    _check_chain_consistent(wallet, node)
    pub = pubkey33_from_priv(priv)

    burn_tx, txid, _ = build_burn_tx(priv, sats)
    txid_hex = txid[::-1].hex()  # display order

    # mine it into a Bitcoin block (1 confirmation) and submit the header
    height, _ = mine_btc_block(wallet, [(burn_tx, txid)], node)
    # find the burn's index in its block: [coinbase, burn] -> index 1
    ch = wallet.load_chain()
    ch["burns"][txid_hex] = {
        "tx_hex": burn_tx.hex(),
        "btc_height": height,
        "merkle_index": 1,
        "sats": sats,
        "pubkey": pub.hex(),
    }
    wallet.save_chain(ch)
    sync_headers(wallet, node)

    print("burn created.")
    print(f"  burn txid : {txid_hex}")
    print(f"  amount    : {sats} sats -> furnace {CHAIN['furnace_addr'][:20]}…")
    print(f"  bitcoin block height: {height} (1 confirmation)")
    print()
    print("NEXT STEPS")
    print(f"  1. mine {BURN_CONFIRMATIONS - 1} more Bitcoin blocks:")
    print(f"       furnace.py mine-btc {BURN_CONFIRMATIONS - 1}")
    print(f"  2. file the claim:")
    print(f"       furnace.py claim {txid_hex}")
    print()
    print("The burn key is already in your wallet file, so the claim will")
    print("find it automatically. Keep this txid.")

def cmd_mine_btc(wallet: Wallet, args, node):
    if not CHAIN["simulated_btc"]:
        raise WalletError(
            "mine-btc is regtest-only: it mines the wallet's SIMULATED "
            "Bitcoin chain.\nOn testnet, burns need REAL testnet4 confirmations "
            f"({BURN_CONFIRMATIONS} blocks, ~24h). There is no shortcut — "
            "that wait is the security.")
    n = args.n
    for _ in range(n):
        mine_btc_block(wallet, [], node, quiet=True)
    try:
        submitted = sync_headers(wallet, node)
    except (NodeError, WalletError) as e:
        print(f"warning: could not sync headers to node: {e}")
        submitted = 0
    tip = btc_tip_height(wallet)
    print(f"mined {n} bitcoin blocks; local tip height {tip} "
          f"({submitted} headers submitted this run)")

def _favilla_miner_addr(node):
    try:
        node("createwallet", "furnace-miner")
    except NodeError as e:
        if "already exists" not in e.message.lower() and "duplicate" not in e.message.lower():
            raise
    return node("getnewaddress", _wallet="furnace-miner")

def _btc_node(args):
    """Upstream Bitcoin testnet4 RPC client (testnet mode only)."""
    if getattr(args, "btc_api", False):
        if CHAIN["simulated_btc"]:
            raise WalletError("--btc-api is testnet-only")
        return MempoolSpaceBtc()
    return bitcoin_rpc(args.btc_datadir, args.btc_rpc_port)


def cmd_claim(wallet: Wallet, args, node):
    priv = wallet.load_key(args.key)  # loud refusal without a key
    if CHAIN["simulated_btc"]:
        built = build_claim(wallet, args.burn_txid, priv, node)  # loud on key mismatch/depth
    else:
        btc = _btc_node(args)
        built = build_claim_testnet(args.burn_txid, priv, node, btc)
    try:
        node("sendrawtransaction", built["raw_hex"])
    except NodeError as e:
        raise WalletError(
            f"the Favilla node REJECTED the claim:\n  {e.message}\n\n"
            f"(This is consensus speaking, not a wallet bug. Common causes:\n"
            f" double-claim of the same burn, or the Favilla tip advanced after\n"
            f" the claim was built — rebuild it with `claim` and try again.)")
    claims = wallet.load_claims()
    claims[args.burn_txid.lower()] = {
        "claim_txid": built["claim_txid"],
        "cinis": built["cinis"],
        "unlock": built["unlock"],
        "height": built["height"],
        "sats": built["sats"],
        "pubkey": built["pubkey"],
    }
    wallet.save_claims(claims)
    print("claim accepted by the Favilla node.")
    print(f"  claim txid : {built['claim_txid']}")
    print(f"  mints      : {built['cinis']} cinis = {fmt_fvla(built['cinis'])} FVLA")
    print(f"  for Favilla height {built['height']} "
          f"(Vigil unlocks at {built['unlock']})")
    print(f"  recipient  : P2WPKH of burn key {built['pubkey'][:20]}… (deterministic)")
    if args.mine:
        addr = _favilla_miner_addr(node)
        node("generatetoaddress", 1, addr)
        print(f"  mined 1 Favilla block — mint confirmed at height {built['height']}.")
    else:
        print("  next: mine a Favilla block to confirm it "
              "(or re-run with --mine).")

def cmd_status(wallet: Wallet, args, node):
    txid_hex = args.burn_txid.lower()
    if not CHAIN["simulated_btc"]:
        _cmd_status_testnet(args, node, txid_hex)
        return
    ch = wallet.load_chain()
    burn = ch["burns"].get(txid_hex)
    if not burn:
        raise WalletError(f"unknown burn {args.burn_txid[:16]}… — not in this wallet.")
    _check_chain_consistent(wallet, node)
    sync_headers(wallet, node)
    info = node("getbitcoinheaderchaininfo")
    tip = info["tip_height"]
    depth = tip - burn["btc_height"]
    eligible = depth >= BURN_CONFIRMATIONS
    H = node("getblockcount") + 1
    cinis = cinis_for(burn["sats"], burn["btc_height"])
    claimed = txid_hex in wallet.load_claims()
    print(f"burn      : {txid_hex}")
    print(f"  amount  : {burn['sats']} sats")
    print(f"  bitcoin : block {burn['btc_height']}, tip {tip} "
          f"-> {depth}/{BURN_CONFIRMATIONS} confirmations")
    if eligible:
        print("  status  : ELIGIBLE — you can file the claim now")
    else:
        print(f"  status  : waiting — mine {BURN_CONFIRMATIONS - depth} more "
              f"Bitcoin blocks (furnace.py mine-btc {BURN_CONFIRMATIONS - depth})")
    print(f"  if claimed at Favilla height {H} "
          f"(fire {burn["btc_height"] // FIRE_BLOCKS} — rate locked at burn time): "
          f"{cinis} cinis = {fmt_fvla(cinis)} FVLA")
    print(f"  Vigil unlock would be: {H + VIGIL_BLOCKS}")
    print(f"  claimed already: {'yes' if claimed else 'no'}")


def _cmd_status_testnet(args, node, txid_hex):
    """Burn status for a REAL testnet4 burn — all data live from the
    upstream testnet4 node."""
    btc = _btc_node(args)
    try:
        tx = btc("getrawtransaction", txid_hex, True)
    except NodeError as e:
        raise WalletError(f"burn {txid_hex[:16]}… not found on your Bitcoin "
                          f"testnet4 node: {e.message}")
    blockhash = tx.get("blockhash")
    if not blockhash:
        print(f"burn      : {txid_hex}")
        print("  status  : in testnet4 mempool (0 confirmations) — not yet a burn")
        return
    burn_tx = bytes.fromhex(tx["hex"])
    sats = sum(v for v, spk in _tx_outputs(burn_tx) if spk == FURNACE_SPK)
    hdr = btc("getblockheader", blockhash, True)
    btc_height = hdr["height"]
    tip = btc("getblockcount")
    depth = tip - btc_height + 1
    H = node("getblockcount") + 1
    cinis = cinis_for(sats, btc_height) if sats > 0 else 0
    print(f"burn      : {txid_hex}")
    print(f"  furnace output: {sats} sats "
          f"({'VALID burn' if sats > 0 else 'NO furnace output — can never mint!'})")
    print(f"  testnet4: block {btc_height}, tip {tip} "
          f"-> {depth}/{BURN_CONFIRMATIONS} confirmations")
    if depth >= BURN_CONFIRMATIONS:
        print("  status  : ELIGIBLE — you can file the claim now")
    else:
        print(f"  status  : waiting — {BURN_CONFIRMATIONS - depth} more "
              f"testnet4 blocks needed")
    if sats > 0:
        print(f"  if claimed at Favilla height {H} "
              f"(fire {btc_height // FIRE_BLOCKS} — rate locked at burn time): "
              f"{cinis} cinis = {fmt_fvla(cinis)} FVLA")
        print(f"  Vigil unlock would be: {H + VIGIL_BLOCKS}")

def cmd_balance(wallet: Wallet, args, node):
    claims = wallet.load_claims()
    if not claims:
        print("no mints tracked by this wallet yet. File a claim first.")
        return
    filt = None
    if args.address:
        hrp, witver, prog = bech32_decode(args.address)
        if hrp != CHAIN["hrp"] or witver != 0 or len(prog) != 20:
            raise WalletError(f"only {CHAIN['hrp']} P2WPKH addresses (burn-key "
                              "addresses) are supported by balance --address")
        filt = prog
        print(f"filtering to burner address {args.address}\n")
    height = node("getblockcount")
    locked = spendable = 0
    print(f"Favilla height {height}\n")
    for burn_txid, c in claims.items():
        if filt is not None and hash160(bytes.fromhex(c["pubkey"])) != filt:
            continue
        utxo = node("gettxout", c["claim_txid"], 0)
        state = "missing?!"
        if utxo is None:
            state = "SPENT or not yet mined"
        elif height < c["unlock"]:
            state = f"LOCKED until {c['unlock']} ({c['unlock'] - height} blocks left)"
            locked += c["cinis"]
        else:
            state = "SPENDABLE (Vigil complete)"
            spendable += c["cinis"]
        print(f"  {c['claim_txid'][:16]}…  {fmt_fvla(c['cinis']):>18} FVLA  {state}")
    print()
    print(f"  locked (Vigil) : {fmt_fvla(locked)} FVLA")
    print(f"  spendable      : {fmt_fvla(spendable)} FVLA")

def cmd_demo(wallet: Wallet, args, node):
    """Full happy path: key -> burn -> 150 btc blocks -> claim -> mine -> verify."""
    if not CHAIN["simulated_btc"]:
        raise WalletError("demo is regtest-only (it mines a simulated "
                          "Bitcoin chain).")
    print("== demo: full Favilla ritual on regtest ==")
    # fresh key
    priv, pub = gen_keypair()
    wallet.save_key(priv)
    print(f"[1/6] burner key generated ({pub.hex()[:20]}…)")

    # burn 1,000,000 sats
    sats = 1_000_000
    burn_tx, txid, _ = build_burn_tx(priv, sats)
    txid_hex = txid[::-1].hex()
    height, _ = mine_btc_block(wallet, [(burn_tx, txid)], node)
    ch = wallet.load_chain()
    ch["burns"][txid_hex] = {"tx_hex": burn_tx.hex(), "btc_height": height,
                             "merkle_index": 1, "sats": sats, "pubkey": pub.hex()}
    wallet.save_chain(ch)
    print(f"[2/6] burned {sats} sats -> txid {txid_hex[:16]}… (btc height {height})")

    # mine to maturity
    for _ in range(150):
        mine_btc_block(wallet, [], node, quiet=True)
    sync_headers(wallet, node)
    depth = node("getbitcoinheaderchaininfo")["tip_height"] - height
    print(f"[3/6] mined 150 bitcoin blocks (depth now {depth})")

    # claim
    built = build_claim(wallet, txid_hex, priv, node)
    node("sendrawtransaction", built["raw_hex"])
    claims = wallet.load_claims()
    claims[txid_hex] = {"claim_txid": built["claim_txid"], "cinis": built["cinis"],
                        "unlock": built["unlock"], "height": built["height"],
                        "sats": sats, "pubkey": pub.hex()}
    wallet.save_claims(claims)
    print(f"[4/6] claim submitted: {built['claim_txid'][:16]}… "
          f"({built['cinis']} cinis)")

    # mine a Favilla block, verify the mint
    addr = _favilla_miner_addr(node)
    node("generatetoaddress", 1, addr)
    H = built["height"]
    assert node("getblockcount") == H, "tip did not advance as expected"
    utxo = node("gettxout", built["claim_txid"], 0)
    assert utxo is not None, "mint UTXO missing after confirmation!"
    from decimal import Decimal
    got = int(Decimal(str(utxo["value"])) * CINIS_PER_FVLA)
    assert got == built["cinis"], f"value {got} != {built['cinis']}"
    assert utxo["scriptPubKey"]["hex"] == built["spk_hex"], "script mismatch!"
    print(f"[5/6] Favilla block {H} mined; mint UTXO verified:")
    print(f"       value  = {got} cinis == expected {built['cinis']}")
    print(f"       script = Vigil(unlock={built['unlock']}, burn key) ✓")
    print("[6/6] DEMO COMPLETE — the ritual works end to end.")
    return {"burn_txid": txid_hex, "claim_txid": built["claim_txid"],
            "cinis": built["cinis"], "height": H, "unlock": built["unlock"]}

# ---------------------------------------------------------------- main

def main(argv=None):
    ap = argparse.ArgumentParser(
        prog="furnace.py",
        description="Favilla wallet/CLI — burn BTC to the furnace, wait 144 "
                    "confirmations, claim Vigil-locked FVLA. Default chain is "
                    "regtest; pass --testnet for the public testnet (REAL "
                    "testnet4 burns — the simulated Bitcoin chain is "
                    "regtest-only).")
    ap.add_argument("--testnet", action="store_true",
                    help="use the Favilla public testnet (chain magic "
                         "\"fvlt\", RPC 34443). Burns are real testnet4 "
                         "transactions.")
    ap.add_argument("--wallet-dir", default="~/.favilla-wallet")
    ap.add_argument("--favilla-datadir", default="~/.favilla")
    ap.add_argument("--rpc-port", type=int, default=None,
                    help="Favilla node RPC port (default: 28443 regtest, "
                         "34443 testnet)")
    ap.add_argument("--btc-datadir", default="~/.bitcoin",
                    help="upstream Bitcoin node datadir (testnet mode only)")
    ap.add_argument("--btc-rpc-port", type=int, default=48332,
                    help="upstream Bitcoin testnet4 RPC port (default 48332)")
    ap.add_argument("--btc-api", action="store_true",
                    help="fetch burn data from the mempool.space testnet4 API "
                         "instead of an upstream Bitcoin node (needed when the "
                         "upstream node is headers-only with no txindex)")
    sub = ap.add_subparsers(dest="cmd", required=True)

    sub.add_parser("newkey", help="generate a burner keypair")

    p = sub.add_parser("burn", help="burn BTC to the furnace")
    p.add_argument("--amount",
                   help="BTC to burn, e.g. 0.01 (exact decimal). Regtest: "
                        "required (builds the burn). Testnet: optional, shown "
                        "in the instructions.")
    p.add_argument("--key", default=None, help="WIF of the burner key")

    p = sub.add_parser("mine-btc", help="mine N simulated Bitcoin blocks "
                                       "(regtest only)")
    p.add_argument("n", nargs="?", type=int, default=10)

    p = sub.add_parser("claim", help="file a v4 claim for a matured burn")
    p.add_argument("burn_txid", help="burn txid (display order hex)")
    p.add_argument("--key", default=None, help="WIF of the burn key")
    p.add_argument("--mine", action="store_true",
                   help="mine one Favilla block after submitting")

    p = sub.add_parser("status", help="burn confirmations / claim eligibility")
    p.add_argument("burn_txid")

    p = sub.add_parser("balance", help="FVLA mints: Vigil-locked vs spendable")
    p.add_argument("--address", default=None,
                   help="filter to one burner P2WPKH address")
    sub.add_parser("demo", help="full happy-path end-to-end (regtest only)")

    args = ap.parse_args(argv)

    global CHAIN
    CHAIN = CHAINS["testnet"] if args.testnet else CHAINS["regtest"]
    rpc_port = args.rpc_port or CHAIN["rpc_port"]

    wallet = Wallet(args.wallet_dir)
    needs_node = args.cmd in ("burn", "mine-btc", "claim", "status",
                              "balance", "demo")
    if args.testnet and args.cmd == "burn":
        # informational only on testnet — no node needed
        needs_node = False
    node = None
    if needs_node:
        node = FavillaRPC(os.path.expanduser(args.favilla_datadir), rpc_port)

    try:
        if args.cmd == "newkey":
            cmd_newkey(wallet, args)
        else:
            {"burn": cmd_burn,
             "mine-btc": cmd_mine_btc,
             "claim": cmd_claim,
             "status": cmd_status,
             "balance": cmd_balance,
             "demo": cmd_demo}[args.cmd](wallet, args, node)
    except WalletError as e:
        print(f"\nERROR: {e}\n", file=sys.stderr)
        sys.exit(2)
    except NodeError as e:
        print(f"\nFavilla node error: {e}\n", file=sys.stderr)
        sys.exit(3)

if __name__ == "__main__":
    main()
