#!/usr/bin/env python3
"""
feed.py -- Bitcoin testnet4 header feed for a Favilla node (SPEC section 6).

Polls an upstream (non-Favilla) Bitcoin Core bitcoind on testnet4 for new
block headers and submits them, oldest-first, to favillad's
`submitbitcoinheader` RPC so the Favilla node maintains the validated
Bitcoin header chain that burn-claim depth checks (144 confirmations,
SPEC section 7 V3) are measured against.

Stdlib only. Idempotent: re-submitting an already-known header succeeds on
the Favilla side, and the feed records the last-fed header in a state file
so restarts resume where they left off.

Usage:
    feed.py --upstream http://user:pass@127.0.0.1:48332 \
            --favilla  http://user:pass@127.0.0.1:34443 \
            [--state ~/.favilla/testnet-feed/state.json] \
            [--poll 60] [--once]

Environment fallbacks: FV_FEED_UPSTREAM, FV_FEED_FAVILLA, FV_FEED_STATE.

OPERATOR REQUIREMENT (read README.md): EVERY Favilla node MUST run its own
feed (or equivalent header sync). Header sync is per-node; nothing on the
Favilla P2P network propagates Bitcoin headers.

Exit codes: 0 = caught up (with --once) / clean shutdown (loop, SIGINT);
1 = configuration error; 2 = stalled (a header was REJECTED by favillad --
see README "known prototype limitation").
"""

import argparse
import base64
import http.client
import json
import os
import sys
import time
import urllib.parse
from datetime import datetime, timezone

# Bitcoin testnet4 (BIP94) genesis, cross-checked 2026-10-07 against
# mempool.space/testnet4/api/block-height/0 and Bitcoin Core v31.0 chainparams.
TESTNET4_GENESIS = "00000000da84f2bafbbc53dee25a72ae507ff4914b867c565be350b0da8bf043"

DEFAULT_POLL = 60
DEFAULT_STATE = os.path.expanduser("~/.favilla/testnet-feed/state.json")
# Max headers submitted per poll iteration (bounds one iteration's work).
BATCH_CAP = 20000
# Bound for the reorg fast path: headers walked back from the tip before
# checking for a fork point (deeper than any plausible testnet4 reorg; see
# README). NOT a bound on resuming after an outage — the walk continues past
# this for a deep backlog (Phase 4 fix, 2026-10-07: a restart mid-catch-up
# used to die here with a fatal "deep reorg" error and wedge the service in
# a crash loop).
WALKBACK_CAP = 10000


class RPCError(Exception):
    def __init__(self, err):
        self.code = err.get("code")
        self.message = err.get("message")
        super().__init__(f"RPC error {self.code}: {self.message}")


class RPC:
    """Minimal JSON-RPC client over HTTP with basic auth. Stdlib only."""

    def __init__(self, url, timeout=60):
        p = urllib.parse.urlparse(url)
        if not p.hostname or not p.username:
            raise ValueError(f"RPC URL must include user, host and port: {url}")
        self.host = p.hostname
        self.port = p.port or 80
        creds = f"{p.username}:{p.password or ''}".encode()
        self.headers = {
            "Authorization": "Basic " + base64.b64encode(creds).decode(),
            "Content-Type": "application/json",
        }
        self.timeout = timeout
        self._id = 0

    def __call__(self, method, params=()):
        self._id += 1
        body = json.dumps(
            {"jsonrpc": "1.0", "id": self._id, "method": method, "params": list(params)}
        ).encode()
        conn = http.client.HTTPConnection(self.host, self.port, timeout=self.timeout)
        try:
            conn.request("POST", "/", body, self.headers)
            resp = conn.getresponse()
            data = json.loads(resp.read().decode())
        finally:
            conn.close()
        if data.get("error"):
            raise RPCError(data["error"])
        return data["result"]


def log(msg):
    print(f"[{datetime.now(timezone.utc).strftime('%H:%M:%S')}] {msg}", flush=True)


def load_state(path):
    if os.path.exists(path):
        with open(path) as f:
            return json.load(f)
    return {}


def save_state(path, state):
    tmp = path + ".tmp"
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    with open(tmp, "w") as f:
        json.dump(state, f, indent=2)
    os.replace(tmp, path)


def upstream_tip(up):
    """Most-work header-chain tip of the upstream node.

    NOTE: an upstream node filled via `submitheader` (headers-only, no block
    data -- the normal state for this feed's sandbox workaround, and fine in
    general) NEVER advances its *active* chain past genesis: activating a
    chain requires full blocks. So getbestblockhash/getblockcount are useless
    here; the best *header* chain is what matters, and it is tracked via
    getchaintips (status "headers-only") / m_best_header.
    """
    tips = up("getchaintips")
    best_hash, best_work = None, -1
    for t in tips:
        if t["status"] in ("active", "headers-only", "valid-headers", "valid-fork"):
            work = int(up("getblockheader", [t["hash"], True])["chainwork"], 16)
            if work > best_work:
                best_hash, best_work = t["hash"], work
    if best_hash is None:
        raise RuntimeError("no usable header tip found via getchaintips")
    h = up("getblockheader", [best_hash, True])
    return best_hash, h["height"]


def find_fork_point(up, last_hash, out):
    """Bounded reorg search: walk back from last_hash (up to WALKBACK_CAP
    headers) and look for a hash also present in `out` — the headers already
    walked back from the tip, newest-first. Returns (height, hash) of the
    common ancestor nearest the tip, or None if there is none within reach.

    A hash unknown to the upstream node (wiped/replaced node) ends the
    search instead of raising: the caller's full walk will then produce the
    clear fatal error for that case.

    2026-10-12 fix: the previous version broke out of the walk the moment
    the *parent* hash was found in `out`, without recording that parent —
    so the common ancestor was never in `old_chain` and the trailing scan
    always returned None (reorgs were never detected; the feed fell through
    to the fatal "reached genesis" exit). Check each hash against `out`
    *before* stepping to its parent instead.
    """
    out_heights = {hhash: height for height, hhash in out}
    c2 = last_hash
    for _ in range(WALKBACK_CAP):
        if c2 in out_heights:
            return (out_heights[c2], c2)
        try:
            h2 = up("getblockheader", [c2, True])
        except RPCError:
            break
        c2 = h2.get("previousblockhash")
        if c2 is None:
            break
    return None


def collect_new_headers(up, state):
    """Return [(height, hash)] ascending, from after state['upstream_hash']
    up to the upstream tip. Handles the first run (no state) and reorgs.

    The walk back from the tip is NOT bounded by WALKBACK_CAP: a restart
    after a long outage (or during the initial multi-hour catch-up) must
    resume from a last-fed hash far behind the tip. The bounded fast path
    plus the bounded fork-point search still detect reorgs promptly; only
    when neither finds the last-fed hash do we commit to the full walk,
    which distinguishes a deep backlog (last-fed IS an ancestor of the tip
    and is eventually reached) from a wiped/replaced upstream node or an
    impossibly deep reorg (the walk reaches genesis without finding it ->
    fatal error, no guessing).
    """
    tip_hash, tip_h = upstream_tip(up)
    last_hash = state.get("upstream_hash")

    if not last_hash:
        genesis = up("getblockhash", [0])
        if genesis != TESTNET4_GENESIS:
            raise SystemExit(
                f"REFUSING TO FEED: upstream block 0 is {genesis}, not the "
                f"expected testnet4 genesis {TESTNET4_GENESIS}. Wrong chain?"
            )
        log(f"first run: upstream tip {tip_h} ({tip_hash[:16]}...), syncing from genesis")

    # Walk back from the tip until we reach the last-fed hash (or genesis).
    target = last_hash or TESTNET4_GENESIS
    # First run must walk the whole chain, so its bound is the chain height.
    max_walk = tip_h + 1
    out = []  # newest-first while walking; reversed before return
    cur = tip_hash
    guard = 0
    while cur != target:
        hdr = up("getblockheader", [cur, True])
        out.append((hdr["height"], cur))
        cur = hdr.get("previousblockhash")
        if cur is None:
            # Walked past genesis: the last-fed hash is not on this upstream
            # chain (stale state, or the upstream node was wiped/replaced).
            raise SystemExit(
                "last-fed hash not found on the upstream chain (reached "
                "genesis without finding it); refusing to guess. Check the "
                "state file and the upstream node (see README)."
            )
        guard += 1
        if last_hash and guard == WALKBACK_CAP:
            # Fast path exhausted. Before committing to a long walk, check
            # for a reorg with a common ancestor within reach.
            log("last-fed hash not within walkback cap; checking for reorg fork point")
            fork = find_fork_point(up, last_hash, out)
            if fork is not None:
                log(f"reorg detected; common ancestor at height {fork[0]}")
                out = [(h, hh) for (h, hh) in out if h > fork[0]]
                out.reverse()  # ascending; excludes the fork point itself
                return out, tip_hash, tip_h
            log("no recent fork point; continuing full walk back "
                "(deep backlog after outage/restart, not a reorg)")
        if guard > max_walk:
            raise SystemExit(
                "walkback exceeded upstream chain height; aborting instead "
                "of guessing (see README)"
            )
    out.reverse()  # ascending; excludes the already-fed target itself
    if not last_hash:
        # First run: include the genesis header itself so the Favilla-side
        # chain is anchored at true height 0 (its store numbers the first
        # header it sees as height 0).
        out.insert(0, (0, target))
    return out, tip_hash, tip_h


def run_once(up, fv, state, args):
    new_headers, tip_hash, tip_h = collect_new_headers(up, state)

    if not new_headers:
        log(f"caught up: upstream tip {tip_h}, nothing new")
        return True, False

    # Bound one iteration's work; the rest is picked up next poll.
    batch = new_headers[:BATCH_CAP]
    log(f"submitting {len(batch)} header(s) "
        f"(heights {batch[0][0]}..{batch[-1][0]}); {len(new_headers)-len(batch)} deferred")

    t0 = time.time()
    submitted = 0
    for height, hhash in batch:
        raw = up("getblockheader", [hhash, False])  # 80-byte header hex
        try:
            res = fv("submitbitcoinheader", [raw])
        except RPCError as e:
            log(f"STALL at upstream height {height} ({hhash[:16]}...): {e}")
            state["stall"] = {"upstream_hash": hhash, "upstream_height": height,
                              "error": str(e)}
            save_state(args.state, state)
            return False, False
        # Submit is idempotent on the Favilla side; the state file is the
        # resume point.
        submitted += 1
        state["upstream_hash"] = hhash
        state["upstream_height"] = height
        state["stall"] = None
        state["updated_utc"] = datetime.now(timezone.utc).isoformat()
        if submitted % 500 == 0:
            save_state(args.state, state)
            dt = time.time() - t0
            log(f"  ... {submitted}/{len(batch)} submitted "
                f"({1000*dt/submitted:.1f} ms/header); favilla tip_height={res['tip_height']}")
    save_state(args.state, state)
    dt = time.time() - t0
    info = fv("getbitcoinheaderchaininfo", [])
    log(f"done: {submitted} submitted in {dt:.1f}s "
        f"({1000*dt/max(submitted,1):.1f} ms/header); "
        f"favilla headers={info['headers']} tip_height={info['tip_height']} "
        f"tip_hash={info['tip_hash'][:16]}...")
    # Cross-check favilla tip against the last header we submitted.
    if info["tip_hash"] != state["upstream_hash"]:
        log(f"WARNING: favilla tip {info['tip_hash'][:16]}... != last submitted "
            f"header {state['upstream_hash'][:16]}... -- possible reorg divergence")
    else:
        log(f"tip verified: favilla tip == upstream header {state['upstream_height']} "
            f"({state['upstream_hash'][:16]}...)")
    return True, len(new_headers) > len(batch)


def main():
    global TESTNET4_GENESIS
    ap = argparse.ArgumentParser(description="Bitcoin testnet4 header feed for favillad")
    ap.add_argument("--upstream", default=os.environ.get("FV_FEED_UPSTREAM"),
                    help="upstream bitcoind RPC URL http://user:pass@host:port")
    ap.add_argument("--favilla", default=os.environ.get("FV_FEED_FAVILLA"),
                    help="favillad RPC URL http://user:pass@host:port")
    ap.add_argument("--state", default=os.environ.get("FV_FEED_STATE", DEFAULT_STATE))
    ap.add_argument("--poll", type=int, default=DEFAULT_POLL,
                    help="poll interval in seconds (loop mode)")
    ap.add_argument("--once", action="store_true", help="catch up once, then exit")
    ap.add_argument("--genesis-hash", default=TESTNET4_GENESIS,
                    help="override expected upstream genesis (testing only)")
    args = ap.parse_args()
    TESTNET4_GENESIS = args.genesis_hash

    if not args.upstream or not args.favilla:
        ap.error("--upstream and --favilla (or FV_FEED_UPSTREAM / FV_FEED_FAVILLA) are required")

    up, fv = RPC(args.upstream), RPC(args.favilla)
    # Fail fast on bad credentials / wrong ports.
    up_chain = up("getblockchaininfo")["chain"]
    log(f"upstream chain: {up_chain}")
    if up_chain != "testnet4":
        log(f"WARNING: upstream chain is '{up_chain}', expected 'testnet4' "
            f"(genesis check still applies)")

    state = load_state(args.state)
    if state.get("upstream_hash"):
        log(f"resuming from state: height {state.get('upstream_height')} "
            f"({state['upstream_hash'][:16]}...)")

    if args.once:
        try:
            while True:
                ok, more = run_once(up, fv, state, args)
                if not ok:
                    return 2
                if not more:
                    return 0
                state = load_state(args.state)  # run_once saved progress; continue
        except (RPCError, ConnectionError, OSError) as e:
            log(f"error: {e}")
            return 1

    log(f"loop mode: poll every {args.poll}s, state={args.state}")
    while True:
        try:
            state = load_state(args.state)
            while True:
                ok, more = run_once(up, fv, state, args)
                if not ok:
                    log("stalled (see above); will retry when upstream tip advances")
                    break
                if not more:
                    break
                state = load_state(args.state)
        except (RPCError, ConnectionError, OSError) as e:
            log(f"transient error: {e}; retrying next poll")
        except KeyboardInterrupt:
            log("interrupted; state saved, exiting")
            return 0
        time.sleep(args.poll)


if __name__ == "__main__":
    sys.exit(main())
