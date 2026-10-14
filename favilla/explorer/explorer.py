#!/usr/bin/env python3
"""Furnace Watch — a simple block explorer for Favilla (regtest + testnet).

Reads ONLY from the Favilla node's RPC. Every number shown is derived from
Favilla-chain data (claims carry their burn proofs; mint outputs carry value
+ Vigil lock). No dependency on the wallet's simulated Bitcoin chain.

Default chain is regtest; pass --testnet for the public testnet.

Usage:
    python3 explorer.py [--datadir /tmp/fv-node] [--rpc-port 28443]
                        [--port 8080] [--no-browser] [--testnet]

Then open http://127.0.0.1:8080/
"""

import base64
import hashlib
import html
import http.server
import json
import os
import struct
import sys
import urllib.request
import urllib.error
import urllib.parse
import webbrowser
from datetime import datetime, timezone

# ---------------------------------------------------------------- constants
# From SPEC.md §2/§3. Chain identity comes from the CHAINS table (--testnet
# selects the public testnet); nothing chain-specific is hardcoded elsewhere
# (audit F1). FURNACE_SPK is identical on all chains (SPEC §3) — only the
# human-readable address encoding changes.
CHAINS = {
    "regtest": {
        "rpc_port": 28443,
        "cookie_subdir": "regtest",
        "hrp": "fvla",   # node code-truth (SPEC §2.1)
        "furnace_addr": "fvla1qazqlhwhsyyezu6wrj6ua5264gcpdfl0ffnewuz",  # SPEC §3
        "label": "regtest",
    },
    "testnet": {
        "rpc_port": 34443,
        "cookie_subdir": "testnet",
        "hrp": "fvlt",   # SPEC §2.2
        "furnace_addr": "fvlt1qazqlhwhsyyezu6wrj6ua5264gcpdfl0fqtwx7p",  # SPEC §3
        "label": "testnet",
    },
}
CHAIN = CHAINS["regtest"]

FURNACE_SPK = bytes.fromhex("0014e881fbbaf021322e69c396b9da2b554602d4fde9")
CINIS_PER_FVLA = 100_000_000
FIRE_BLOCKS = 210_000
VIGIL_BLOCKS = 210_000
BURN_CONFIRMATIONS = 144


def sha256d(b: bytes) -> bytes:
    return hashlib.sha256(hashlib.sha256(b).digest()).digest()


def rev_hex(b: bytes) -> str:
    """Internal byte order -> display hex (Bitcoin convention)."""
    return b[::-1].hex()


# ---------------------------------------------------------------- RPC client
class NodeError(Exception):
    pass


class FavillaRPC:
    def __init__(self, datadir, rpc_port):
        self.url = f"http://127.0.0.1:{rpc_port}"
        cookie = os.path.join(os.path.expanduser(datadir),
                              CHAIN["cookie_subdir"], ".cookie")
        if not os.path.exists(cookie):
            raise NodeError(f"no RPC cookie at {cookie} — is favillad running?")
        with open(cookie) as f:
            userpass = f.read().strip()
        self._auth = "Basic " + base64.b64encode(userpass.encode()).decode()

    def __call__(self, method, *params):
        body = json.dumps({"jsonrpc": "1.0", "id": "furnace-watch",
                           "method": method, "params": list(params)}).encode()
        req = urllib.request.Request(
            self.url, data=body,
            headers={"Content-Type": "application/json",
                     "Authorization": self._auth})
        try:
            with urllib.request.urlopen(req, timeout=120) as r:
                resp = json.loads(r.read())
        except urllib.error.HTTPError as e:
            resp = json.loads(e.read())
        except (urllib.error.URLError, ConnectionRefusedError):
            raise NodeError(f"cannot reach favillad at {self.url}")
        if resp.get("error"):
            raise NodeError(resp["error"].get("message", str(resp["error"])))
        return resp["result"]


# ---------------------------------------------------------------- parsing
class ParseError(Exception):
    pass


class Reader:
    def __init__(self, data: bytes):
        self.d = data
        self.o = 0

    def read(self, n: int) -> bytes:
        if self.o + n > len(self.d):
            raise ParseError("truncated")
        b = self.d[self.o:self.o + n]
        self.o += n
        return b

    def u32(self) -> int:
        return struct.unpack("<I", self.read(4))[0]

    def i32(self) -> int:
        return struct.unpack("<i", self.read(4))[0]

    def i64(self) -> int:
        return struct.unpack("<q", self.read(8))[0]

    def compactsize(self) -> int:
        b0 = self.read(1)[0]
        if b0 < 0xfd:
            return b0
        if b0 == 0xfd:
            return struct.unpack("<H", self.read(2))[0]
        if b0 == 0xfe:
            return struct.unpack("<I", self.read(4))[0]
        return struct.unpack("<Q", self.read(8))[0]

    def bytes_prefixed(self) -> bytes:
        return self.read(self.compactsize())


def parse_btc_tx(data: bytes):
    """Parse a Bitcoin transaction (segwit-aware). Returns dict with
    version, vins (list of dicts with scriptsig/witness bytes), vouts
    (value, spk), locktime, txid (internal bytes), raw length."""
    r = Reader(data)
    start = 0
    version = r.i32()
    segwit = False
    if len(data) >= r.o + 2 and data[r.o] == 0x00 and data[r.o + 1] == 0x01:
        segwit = True
        r.o += 2
    vins = []
    for _ in range(r.compactsize()):
        prev = r.read(36)
        script = r.bytes_prefixed()
        seq = r.read(4)
        vins.append({"prev": prev, "scriptsig": script, "seq": seq})
    vouts = []
    for _ in range(r.compactsize()):
        value = r.i64()
        spk = r.bytes_prefixed()
        vouts.append({"value": value, "spk": spk})
    if segwit:
        for vin in vins:
            stack = []
            for _ in range(r.compactsize()):
                stack.append(r.bytes_prefixed())
            vin["witness"] = stack
    locktime = r.u32()
    raw = data[start:r.o]
    return {"version": version, "vins": vins, "vouts": vouts,
            "locktime": locktime, "txid": sha256d(raw), "rawlen": r.o}


def extract_input0_pubkey(burn_tx: dict):
    """Return 33-byte compressed pubkey revealed by burn input 0, or None."""
    vin0 = burn_tx["vins"][0]
    cands = []
    for item in vin0.get("witness", []):
        cands.append(item)
    # parse scriptSig pushes
    try:
        sr = Reader(vin0["scriptsig"])
        while sr.o < len(vin0["scriptsig"]):
            op = sr.read(1)[0]
            if op <= 0x4b:
                cands.append(sr.read(op))
            elif op == 0x4c:
                cands.append(sr.read(sr.read(1)[0]))
            elif op == 0x4d:
                cands.append(sr.read(struct.unpack("<H", sr.read(2))[0]))
            else:
                break
    except ParseError:
        pass
    for c in cands:
        if len(c) == 33 and c[0] in (0x02, 0x03):
            return c
    return None


def parse_claim_tx(data: bytes):
    """Parse a version-4 claim transaction per SPEC §5."""
    r = Reader(data)
    if r.i32() != 4:
        raise ParseError("not a v4 claim")
    if r.compactsize() != 1:
        raise ParseError("claim vin count != 1")
    if r.read(32) != b"\x00" * 32 or r.u32() != 0xFFFFFFFF:
        raise ParseError("bad marker prevout")
    if r.compactsize() != 0:
        raise ParseError("marker scriptsig not empty")
    if r.u32() != 0xFFFFFFFF:
        raise ParseError("bad marker sequence")
    burn_txid = r.read(32)
    burn_header = r.read(80)
    n = r.compactsize()
    if n > 32:
        raise ParseError("merkle branch too long")
    branch = [r.read(32) for _ in range(n)]
    merkle_index = r.u32()
    burn_tx_raw = r.bytes_prefixed()
    if not (1 <= len(burn_tx_raw) <= 1_000_000):
        raise ParseError("bad burn_tx size")
    sig = r.bytes_prefixed()
    if not (8 <= len(sig) <= 73):
        raise ParseError("bad claim_signature size")
    if r.u32() != 0:
        raise ParseError("claim nLockTime != 0")
    if r.compactsize() != 1:
        raise ParseError("claim vout count != 1")
    value = r.i64()
    spk = r.bytes_prefixed()
    raw = data[:r.o]
    return {
        "txid": sha256d(raw),
        "burn_txid": burn_txid,
        "burn_header": burn_header,
        "merkle_branch": branch,
        "merkle_index": merkle_index,
        "burn_tx": parse_btc_tx(burn_tx_raw),
        "claim_signature": sig,
        "mint_value": value,
        "mint_spk": spk,
        "rawlen": r.o,
    }


def parse_vigil_spk(spk: bytes):
    """Parse VIGIL_SCRIPT -> (unlock_height, pubkey). SPEC §11."""
    # <pushlen><unlock bytes> 0xb1 0x75 0x21 <33B pubkey> 0xac
    if len(spk) < 1 + 1 + 1 + 1 + 1 + 33 + 1:
        raise ParseError("vigil spk too short")
    ln = spk[0]
    if not (1 <= ln <= 5) or len(spk) != 1 + ln + 1 + 1 + 1 + 33 + 1:
        raise ParseError("vigil spk bad shape")
    unlock = int.from_bytes(spk[1:1 + ln], "little")
    rest = spk[1 + ln:]
    if rest[0] != 0xb1 or rest[1] != 0x75 or rest[2] != 0x21 or rest[-1] != 0xac:
        raise ParseError("vigil spk bad template")
    return unlock, rest[3:3 + 33]


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
    acc = 0
    bits = 0
    ret = []
    maxv = (1 << tobits) - 1
    for value in data:
        acc = (acc << frombits) | value
        bits += frombits
        while bits >= tobits:
            bits -= tobits
            ret.append((acc >> bits) & maxv)
    if pad:
        if bits:
            ret.append((acc << (tobits - bits)) & maxv)
    elif bits >= frombits or ((acc << (tobits - bits)) & maxv):
        raise ValueError("bad bech32 padding")
    return ret


def bech32_encode(hrp, witver, witprog: bytes) -> str:
    data = [witver] + _convertbits(witprog, 8, 5)
    pm = _bech32_polymod(_bech32_hrp_expand(hrp) + data + [0] * 6) ^ 1
    return hrp + "1" + "".join(_BECH32_CHARSET[d] for d in data) + \
        "".join(_BECH32_CHARSET[(pm >> 5 * (5 - i)) & 31] for i in range(6))


def p2wpkh_address(pubkey: bytes, hrp=None) -> str:
    h160 = hashlib.new("ripemd160", hashlib.sha256(pubkey).digest()).digest()
    return bech32_encode(hrp or CHAIN["hrp"], 0, h160)


# ---------------------------------------------------------------- chain index
class Claim:
    def __init__(self, height, blockhash, parsed):
        self.height = height
        self.blockhash = blockhash  # display hex
        self.txid = parsed["txid"]  # internal bytes
        self.parsed = parsed
        p = parsed
        self.burn_txid = p["burn_txid"]
        self.burned_sats = sum(
            o["value"] for o in p["burn_tx"]["vouts"] if o["spk"] == FURNACE_SPK)
        self.burn_block_hash = sha256d(p["burn_header"])
        self.cinis = p["mint_value"]
        try:
            self.unlock, self.pubkey = parse_vigil_spk(p["mint_spk"])
            self.recipient = p2wpkh_address(self.pubkey)
            self.vigil_ok = True
        except ParseError:
            self.unlock, self.pubkey, self.recipient = None, None, None
            self.vigil_ok = False
        # independent consensus re-check (SPEC §9): does the mint match?
        fire = height // FIRE_BLOCKS
        heat = 1_000_000 * (2 ** fire)
        self.expected_cinis = (self.burned_sats * CINIS_PER_FVLA) // heat
        self.amount_ok = (self.expected_cinis == self.cinis and self.cinis > 0)


class ChainIndex:
    """Scans the Favilla chain via RPC; caches by tip hash."""

    def __init__(self, rpc: FavillaRPC):
        self.rpc = rpc
        self.tip_hash = None
        self.height = -1
        self.blocks = []   # list of dicts: height, hash, time, ntx, nclaims
        self.claims = []   # list of Claim
        self.by_burn_txid = {}  # burn_txid internal bytes -> Claim

    def refresh(self):
        tip = self.rpc("getbestblockhash")
        if tip == self.tip_hash:
            return
        # rescan (chains are tiny on regtest; correctness first)
        self.blocks = []
        self.claims = []
        self.by_burn_txid = {}
        self.height = self.rpc("getblockcount")
        for h in range(self.height + 1):
            bh = self.rpc("getblockhash", h)
            raw = bytes.fromhex(self.rpc("getblock", bh, 0))
            blk = self._parse_block(raw)
            blk["height"] = h
            blk["hash"] = bh
            self.blocks.append(blk)
            for tx in blk["txs"]:
                if tx["version"] == 4:
                    try:
                        c = Claim(h, bh, parse_claim_tx(tx["raw"]))
                    except ParseError:
                        continue
                    self.claims.append(c)
                    self.by_burn_txid[c.burn_txid] = c
        self.tip_hash = tip

    def _parse_block(self, raw: bytes):
        r = Reader(raw)
        header = r.read(80)
        ntime = struct.unpack("<I", header[68:72])[0]
        ntx = r.compactsize()
        txs = []
        for _ in range(ntx):
            start = r.o
            version = struct.unpack("<i", r.read(4))[0]
            r.o = start
            if version == 4:
                end = start + self._skip_claim(r)
                rawtx = raw[start:end]
                txs.append({"version": 4, "raw": rawtx,
                            "txid": sha256d(rawtx)})
            else:
                # minimal parse: need txid + coinbase value
                tx = parse_btc_tx(raw[start:])
                end = start + tx["rawlen"]
                rawtx = raw[start:end]
                r.o = end
                txs.append({"version": version, "raw": rawtx,
                            "txid": tx["txid"], "vouts": tx["vouts"],
                            "is_coinbase": _is_coinbase(tx)})
        return {"time": ntime, "ntx": ntx, "txs": txs}

    def _skip_claim(self, r: Reader) -> int:
        # walk a v4 claim to find its end (mirrors parse_claim_tx)
        r.i32()
        assert r.compactsize() == 1
        r.read(32); r.u32(); r.bytes_prefixed(); r.u32()
        r.read(32); r.read(80)
        n = r.compactsize(); [r.read(32) for _ in range(n)]
        r.u32(); r.bytes_prefixed(); r.bytes_prefixed(); r.u32()
        assert r.compactsize() == 1
        r.i64(); r.bytes_prefixed()
        return r.o

    # -- aggregates -------------------------------------------------
    def totals(self):
        burned = sum(c.burned_sats for c in self.claims)
        minted = sum(c.cinis for c in self.claims)
        return {"burned_sats": burned, "minted_cinis": minted,
                "claims": len(self.claims)}

    def vigil_locked(self):
        """Sum of unspent mint outputs still under lock. Returns
        (locked_cinis, entries)."""
        locked = 0
        entries = []
        for c in self.claims:
            if not c.vigil_ok:
                continue
            try:
                utxo = self.rpc("gettxout", rev_hex(c.txid), 0)
            except NodeError:
                utxo = None
            unspent = utxo is not None
            still_locked = c.unlock > self.height
            if unspent and still_locked:
                locked += c.cinis
            entries.append({"claim": c, "unspent": unspent,
                            "still_locked": still_locked})
        entries.sort(key=lambda e: e["claim"].unlock)
        return locked, entries


def _is_coinbase(tx):
    return (len(tx["vins"]) == 1 and
            tx["vins"][0]["prev"] == b"\x00" * 32 + b"\xff\xff\xff\xff")

# ---------------------------------------------------------------- html
CSS = """
body{background:#0d0b09;color:#e8ded2;font-family:Georgia,serif;max-width:1000px;
margin:0 auto;padding:24px;line-height:1.5}
h1,h2{color:#f0a35e} h1{font-size:1.6em} h2{font-size:1.2em;margin-top:1.6em}
a{color:#f0a35e} a:visited{color:#c77f3e}
table{border-collapse:collapse;width:100%;margin:12px 0}
th,td{border:1px solid #3a2f26;padding:6px 10px;text-align:left;font-size:.92em}
th{background:#1d1712;color:#f0a35e}
tr:nth-child(even){background:#141009}
.mono{font-family:monospace;font-size:.88em;word-break:break-all}
.num{text-align:right;font-variant-numeric:tabular-nums}
.badge{display:inline-block;padding:2px 10px;border-radius:10px;font-size:.8em}
.ok{background:#1e3a24;color:#8fd694}.warn{background:#3a2a1e;color:#f0c35e}
.nav{margin:18px 0;padding:10px 0;border-top:1px solid #3a2f26;border-bottom:1px solid #3a2f26}
.nav a{margin-right:18px;text-decoration:none}
.claim{background:#2a1a10;border-left:3px solid #f0a35e;padding:2px 8px}
.footer{margin-top:30px;color:#8a7a66;font-size:.8em}
.refresh{float:right;font-size:.8em}
"""

PAGE = """<!DOCTYPE html><html><head><meta charset="utf-8">
<meta http-equiv="refresh" content="30">
<title>{title} — Furnace Watch</title><style>{css}</style></head>
<body>
<h1>&#128293; Furnace Watch <span style="font-size:.55em;color:#8a7a66">Favilla {CHAIN_LABEL} explorer</span></h1>
<div class="nav"><a href="/">Overview</a><a href="/blocks">Blocks</a>
<a href="/furnace">Furnace</a><a href="/vigil">Vigil</a>
<span class="refresh"><a href="{path}">&#8635; refresh</a> (auto 30s)</span></div>
{body}
<div class="footer">{CHAIN_LABEL} — all data derived live from the Favilla node's RPC.
Burns are visible only once claimed (unclaimed burns leave no Favilla-chain trace).</div>
</body></html>"""


def esc(s):
    return html.escape(str(s))


def fmt_cinis(c):
    return f"{c:,} cinis ({c / CINIS_PER_FVLA:,.8f} FVLA)".rstrip("0").rstrip(".")


def fmt_sats(s):
    return f"{s:,} sats ({s / 100_000_000:.8f} BTC)"


def era_info(height):
    fire = height // FIRE_BLOCKS
    heat = 1_000_000 * (2 ** fire)
    return fire, heat


class Handler(http.server.BaseHTTPRequestHandler):
    index: ChainIndex = None  # set by main()
    rpc: FavillaRPC = None

    def log_message(self, *a):
        pass

    def _send(self, title, body, path, code=200):
        page = PAGE.format(title=esc(title), css=CSS, body=body,
                           path=esc(path), CHAIN_LABEL=CHAIN["label"])
        data = page.encode()
        self.send_response(code)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def _err(self, msg):
        ex_port = CHAIN["rpc_port"] + 1
        chain_flag = "-chain=testnet" if CHAIN["label"] == "testnet" else "-regtest"
        self._send("Node unreachable",
                   f"<h2>Cannot reach favillad</h2><p>{esc(msg)}</p>"
                   f"<p>Start it, e.g.:<br><span class='mono'>"
                   f"~/workspace/favilla/core/build/bin/bitcoind {chain_flag} "
                   f"-datadir=/tmp/fv-node -rpcport={CHAIN['rpc_port']} "
                   f"-port={ex_port} -daemon"
                   f"</span></p>", self.path, code=503)

    def do_GET(self):
        try:
            self.index.refresh()
        except NodeError as e:
            return self._err(str(e))
        except Exception as e:
            return self._err(f"index error: {e}")
        u = urllib.parse.urlparse(self.path)
        path = u.path
        try:
            if path == "/":
                return self._send("Overview", self.p_overview(), path)
            if path == "/blocks":
                return self._send("Blocks", self.p_blocks(u), path)
            if path.startswith("/block/"):
                return self._send("Block", self.p_block(path[7:]), path)
            if path.startswith("/claim/"):
                return self._send("Claim", self.p_claim(path[7:]), path)
            if path == "/furnace":
                return self._send("Furnace", self.p_furnace(), path)
            if path == "/vigil":
                return self._send("Vigil", self.p_vigil(), path)
            return self._send("Not found", "<h2>404</h2>", path, code=404)
        except NodeError as e:
            return self._err(str(e))
        except Exception as e:
            return self._send("Error",
                              f"<h2>Error</h2><p class='mono'>{esc(e)}</p>",
                              path, code=500)

    # -- pages ------------------------------------------------------
    def p_overview(self):
        ix = self.index
        t = ix.totals()
        fire, heat = era_info(ix.height)
        locked, _ = ix.vigil_locked()
        if fire == 0:
            rate = "1,000,000 sats = 1 FVLA"
        else:
            rate = f"{heat:,} sats = 1 FVLA"
        rows = [
            ("Favilla height", f"{ix.height}"),
            ("Tip hash", f"<span class='mono'>{ix.tip_hash[:16]}…</span>"),
            ("Era (Fire)", f"{fire} &mdash; burn rate: <b>{rate}</b>"),
            ("Burn claims", f"{t['claims']}"),
            ("Total sats burned", fmt_sats(t["burned_sats"])),
            ("Total FVLA minted", fmt_cinis(t["minted_cinis"])),
            ("Vigil-locked", fmt_cinis(locked)),
        ]
        try:
            btc = self.rpc("getbitcoinheaderchaininfo")
            rows.append(("Bitcoin headers known",
                         f"{btc['headers']} (tip height {btc['tip_height']})"))
        except NodeError:
            rows.append(("Bitcoin headers known", "n/a"))
        body = "<h2>Overview</h2><table>" + "".join(
            f"<tr><th>{k}</th><td>{v}</td></tr>" for k, v in rows) + "</table>"
        if ix.claims:
            body += "<h2>Latest claims</h2>" + self._claim_table(ix.claims[-5:][::-1])
        else:
            body += ("<p><i>No claims yet. The fire is cold — "
                     "burn something with the wallet CLI.</i></p>")
        return body

    def _claim_table(self, claims):
        rows = []
        for c in claims:
            link = f"/claim/{rev_hex(c.burn_txid)}"
            badge = ('<span class="badge ok">consensus OK</span>'
                     if (c.amount_ok and c.vigil_ok)
                     else '<span class="badge warn">CHECK FAILED</span>')
            rows.append(
                f"<tr><td class='num'>{c.height}</td>"
                f"<td class='mono'><a href='{link}'>{rev_hex(c.burn_txid)[:16]}…</a></td>"
                f"<td class='num'>{c.burned_sats:,}</td>"
                f"<td class='num'>{c.cinis / CINIS_PER_FVLA:,.8f}</td>"
                f"<td>{badge}</td></tr>")
        return ("<table><tr><th>Favilla height</th><th>Burn txid</th>"
                "<th class='num'>Burned sats</th><th class='num'>Minted FVLA</th>"
                "<th>Check</th></tr>" + "".join(rows) + "</table>")

    def p_blocks(self, u):
        ix = self.index
        n = int(urllib.parse.parse_qs(u.query).get("n", ["25"])[0])
        n = max(1, min(n, 200))
        blks = ix.blocks[-n:][::-1]
        rows = []
        for b in blks:
            nclaims = sum(1 for t in b["txs"] if t["version"] == 4)
            dt = datetime.fromtimestamp(b["time"], tz=timezone.utc)
            rows.append(
                f"<tr><td class='num'><a href='/block/{b['height']}'>{b['height']}</a></td>"
                f"<td class='mono'>{b['hash'][:20]}…</td>"
                f"<td class='num'>{b['ntx']}</td>"
                f"<td class='num'>{nclaims}</td>"
                f"<td>{dt.strftime('%Y-%m-%d %H:%M:%S')} UTC</td></tr>")
        return (f"<h2>Recent blocks</h2><table><tr><th>Height</th><th>Hash</th>"
                f"<th class='num'>Txs</th><th class='num'>Claims</th><th>Time</th></tr>"
                + "".join(rows) + "</table>")

    def p_block(self, ident):
        ix = self.index
        try:
            h = int(ident)
            blk = ix.blocks[h]
        except (ValueError, IndexError):
            hits = [b for b in ix.blocks if b["hash"] == ident]
            if not hits:
                return "<h2>Block not found</h2>"
            blk = hits[0]
        dt = datetime.fromtimestamp(blk["time"], tz=timezone.utc)
        rows = []
        for t in blk["txs"]:
            tid = rev_hex(t["txid"])
            if t["version"] == 4:
                c = next((x for x in ix.claims if x.txid == t["txid"]), None)
                burn = rev_hex(c.burn_txid) if c else "?"
                rows.append(
                    f"<tr class='claim'><td class='mono'>{tid[:20]}…</td>"
                    f"<td><b>CLAIM</b> — burn "
                    f"<a href='/claim/{rev_hex(c.burn_txid)}' class='mono'>"
                    f"{burn[:16]}…</a></td>"
                    f"<td class='num'>{c.cinis / CINIS_PER_FVLA:,.8f} FVLA</td></tr>"
                    if c else
                    f"<tr class='claim'><td class='mono'>{tid[:20]}…</td>"
                    f"<td><b>CLAIM</b> (unparsed)</td><td></td></tr>")
            else:
                val = sum(v["value"] for v in t.get("vouts", []))
                kind = "coinbase" if t.get("is_coinbase") else f"v{t['version']}"
                rows.append(
                    f"<tr><td class='mono'>{tid[:20]}…</td><td>{kind}</td>"
                    f"<td class='num'>{val / 100_000_000:.8f} FVLA</td></tr>")
        return (f"<h2>Block {blk['height']}</h2>"
                f"<p class='mono'>hash {blk['hash']}<br>time "
                f"{dt.strftime('%Y-%m-%d %H:%M:%S')} UTC · {blk['ntx']} transactions</p>"
                f"<table><tr><th>Txid</th><th>Type</th><th class='num'>Value</th></tr>"
                + "".join(rows) + "</table>")

    def p_claim(self, burn_hex):
        ix = self.index
        try:
            internal = bytes.fromhex(burn_hex)[::-1]
        except ValueError:
            return "<h2>Bad burn txid</h2>"
        c = ix.by_burn_txid.get(internal)
        if not c:
            return ("<h2>Claim not found</h2><p>No confirmed claim for this "
                    "burn txid. It may be unclaimed, still maturing "
                    "(needs 144 Bitcoin confirmations), or invalid.</p>")
        p = c.parsed
        fire, heat = era_info(c.height)
        badge = ('<span class="badge ok">amount matches §9 formula</span>'
                 if c.amount_ok else '<span class="badge warn">AMOUNT MISMATCH</span>')
        sig_badge = ('<span class="badge ok">signature gate passed (V5)</span>'
                     if len(p["claim_signature"]) >= 8
                     else '<span class="badge warn">no signature</span>')
        rows = [
            ("Burn txid",
             f"<span class='mono'>{rev_hex(c.burn_txid)}</span>"),
            ("Burn amount", fmt_sats(c.burned_sats)),
            ("Bitcoin confirmations at claim",
             f"≥ {BURN_CONFIRMATIONS} (consensus-verified at inclusion)"),
            ("Burn block",
             f"<span class='mono'>{rev_hex(c.burn_block_hash)}</span>"),
            ("Claim txid",
             f"<span class='mono'>{rev_hex(c.txid)}</span>"),
            ("Claimed at Favilla height", f"{c.height} (Fire {fire})"),
            ("Minted", f"{fmt_cinis(c.cinis)} {badge}"),
            ("Recipient",
             f"<span class='mono'>{esc(c.recipient or 'unparseable')}</span>"),
            ("Vigil unlock", f"height {c.unlock:,} "
             f"({c.unlock - ix.height:,} blocks away)" if c.unlock else "n/a"),
            ("Authorization", sig_badge),
            ("Nullifier",
             "recorded — burn txid is spent (claimed at height "
             f"{c.height}; double-claims rejected)"),
        ]
        return "<h2>Burn claim</h2><table>" + "".join(
            f"<tr><th>{k}</th><td>{v}</td></tr>" for k, v in rows) + "</table>"

    def p_furnace(self):
        ix = self.index
        t = ix.totals()
        rows = []
        for c in sorted(ix.claims, key=lambda x: x.height):
            rows.append(
                f"<tr><td class='num'>{c.height}</td>"
                f"<td class='mono'><a href='/claim/{rev_hex(c.burn_txid)}'>"
                f"{rev_hex(c.burn_txid)[:24]}…</a></td>"
                f"<td class='num'>{c.burned_sats:,}</td>"
                f"<td class='num'>{c.cinis / CINIS_PER_FVLA:,.8f}</td></tr>")
        return (f"<h2>&#128293; The Furnace</h2>"
                f"<p>One global, provably unspendable address. "
                f"<span class='mono'>{CHAIN['furnace_addr']}</span></p>"
                f"<p>Total received (via {t['claims']} claimed burns): "
                f"<b>{fmt_sats(t['burned_sats'])}</b></p>"
                f"<table><tr><th class='num'>Claimed at</th><th>Burn txid</th>"
                f"<th class='num'>Sats</th><th class='num'>Minted FVLA</th></tr>"
                + "".join(rows) + "</table>"
                + "<p><i>Only claimed burns are visible — an unclaimed burn "
                "leaves no trace on the Favilla chain.</i></p>")

    def p_vigil(self):
        ix = self.index
        locked, entries = ix.vigil_locked()
        rows = []
        for e in entries:
            c = e["claim"]
            away = c.unlock - ix.height
            state = ('<span class="badge ok">sleeping</span>'
                     if e["still_locked"] and e["unspent"]
                     else '<span class="badge warn">awake/spent</span>')
            rows.append(
                f"<tr><td class='num'>{c.unlock:,}</td>"
                f"<td class='num'>{away:,}</td>"
                f"<td class='num'>{c.cinis / CINIS_PER_FVLA:,.8f}</td>"
                f"<td class='mono'>{esc((c.recipient or '')[:24])}…</td>"
                f"<td class='num'>{c.height}</td><td>{state}</td></tr>")
        return (f"<h2>The Vigil</h2><p>{len(entries)} mint outputs · "
                f"<b>{fmt_cinis(locked)}</b> still locked</p>"
                f"<table><tr><th class='num'>Unlock height</th>"
                f"<th class='num'>Blocks away</th><th class='num'>FVLA</th>"
                f"<th>Recipient</th><th class='num'>Minted at</th><th>State</th></tr>"
                + "".join(rows) + "</table>")


# ---------------------------------------------------------------- main
def main():
    import argparse
    global CHAIN
    ap = argparse.ArgumentParser(description="Furnace Watch — Favilla explorer")
    ap.add_argument("--testnet", action="store_true",
                    help="explore the public testnet (RPC 34443, HRP \"fvlt\")")
    ap.add_argument("--datadir", default="/tmp/fv-explorer-node")
    ap.add_argument("--rpc-port", type=int, default=None,
                    help="favillad RPC port (default: 28443 regtest, 34443 testnet)")
    ap.add_argument("--port", type=int, default=8080)
    ap.add_argument("--no-browser", action="store_true")
    args = ap.parse_args()
    CHAIN = CHAINS["testnet"] if args.testnet else CHAINS["regtest"]
    rpc_port = args.rpc_port or CHAIN["rpc_port"]

    rpc = FavillaRPC(args.datadir, rpc_port)
    try:
        rpc("getblockcount")
    except NodeError as e:
        sys.exit(f"cannot reach favillad: {e}\n(hint: --datadir/--rpc-port)")

    Handler.rpc = rpc
    Handler.index = ChainIndex(rpc)
    srv = http.server.HTTPServer(("127.0.0.1", args.port), Handler)
    url = f"http://127.0.0.1:{args.port}/"
    print(f"Furnace Watch serving {url}  (datadir={args.datadir})", flush=True)
    if not args.no_browser:
        webbrowser.open(url)
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
