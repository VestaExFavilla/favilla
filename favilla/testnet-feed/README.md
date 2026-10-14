# Favilla testnet4 header feed

`feed.py` keeps a Favilla node's Bitcoin header chain (SPEC §6) current by
polling an upstream Bitcoin Core bitcoind on **testnet4** (BIP94) and
submitting new headers, oldest-first, to favillad's `submitbitcoinheader`
RPC. The header chain is what burn-claim depth checks (144 confirmations,
SPEC §7 V3) are measured against.

## Current status (2026-10-07) — READ BEFORE RUNNING

**2026-10-07 Phase 4 (seed standup): the feed is now LIVE as a systemd
service** (`favilla-feed.service`, Restart=always, state at
`~/.favilla/testnet-feed/state.json`), feeding the persistent seed node
(`favilla-seed.service`, datadir `~/.favilla`, P2P 34444 / RPC 34443) from
the persistent upstream node (`btc-upstream.service`, datadir
`~/btc-testnet4`, RPC 48332). The old HOLD below is lifted: the consensus
fixes (H1/H2/M2/M1) are in the build at
`~/workspace/favilla/core/build/bin/` and genuine testnet4 headers
validate, including the 2016 retarget boundary. See STATUS.md "Phase 4"
for the full seed layout, and `upstream-node.txt` for the current
upstream connection details.

**2026-10-07 /tmp wipe:** a runtime event wiped everything under `/tmp`
(all bitcoind processes, `/tmp/btc-testnet4`, `/tmp/fvtestnet-a`,
`/tmp/fvtestnet-b`, the fetch log). Recovered so far:

- Upstream testnet4 bitcoind: **rebuilt** (`-datadir=/tmp/btc-testnet4`,
  fresh `bitcoin.conf` with a new scratch RPC password). Connection details
  in `upstream-node.txt`. It is re-syncing headers from the mempool.space
  API via `fetch_upstream.py` in loop mode (default; `--once` does a single
  pass — there is no `--loop` flag). Progress: log at
  `fetch-upstream-loop.log`, state at
  `~/.favilla/testnet-feed/upstream-fetch-state.json`.
- The two old-binary favillad testnet nodes (`/tmp/fvtestnet-a`,
  `/tmp/fvtestnet-b`) **died in the wipe and were NOT restarted** — the
  fixes worker owns bringing Favilla nodes back up after the rebuild.
- `/tmp` is ephemeral: expect datadirs there to vanish on VM restarts.
  Nothing irreplaceable lives there (upstream headers re-sync from the
  public API; Favilla header state re-feeds from the upstream node).

## Why a feed, and why per node

Header sync is **per-node, not P2P-propagated**: nothing on the Favilla P2P
network relays Bitcoin headers (verified 2026-10-06 on regtest: a header
submitted to node A is invisible to node B). **EVERY Favilla full node MUST
run its own feed** (or equivalent header sync) or its claim depth checks
fail closed (all claims rejected until ≥144 headers are known).

## Components

| File | Purpose |
|---|---|
| `feed.py` | **The deliverable.** Polls upstream bitcoind → `submitbitcoinheader` on favillad. Stdlib only. |
| `fetch_upstream.py` | Sandbox workaround (see below). Fills the upstream bitcoind's header chain from the mempool.space HTTP API via `submitheader`. On a normal host the upstream node syncs via P2P and this script is unnecessary. Loop mode is the default (no `--loop` flag); `--once` does a single pass. |
| `upstream/` | Official Bitcoin Core v31.0 binaries (SHA256-verified, OTS-attested) used as the upstream node. |
| `upstream-node.txt` | Live connection details for the running upstream node (RPC endpoint, credentials, current tip) — written for whoever needs the node next (e.g. the consensus-fixes worker's H1 acceptance proof). |
| `fetch-upstream-loop.log` | Log of the currently-running header-fill loop. |

## Quick start

```bash
# 1. Upstream bitcoind on testnet4 (normal host: P2P sync does this alone)
./upstream/bitcoin-31.0/bin/bitcoind -chain=testnet4 -datadir=/tmp/btc-testnet4 -daemon
# sandbox only: fill it via HTTP because this VM has no Bitcoin P2P egress
python3 fetch_upstream.py --rpc http://USER:PASS@127.0.0.1:48332 --once

# 2. Favilla testnet node (already-built fork binaries)
~/workspace/favilla/core/build/bin/bitcoind -chain=testnet -datadir=~/.favilla/testnet -daemon

# 3. The feed (loop; --once for a single catch-up run)
python3 feed.py --upstream http://USER:PASS@127.0.0.1:48332 \
                --favilla  http://USER:PASS@127.0.0.1:34443
```

State (last-fed header) lives in `~/.favilla/testnet-feed/state.json`
(`FV_FEED_STATE` overrides). The feed is idempotent: re-submitting a known
header succeeds on the Favilla side, and restarts resume from the state file.
If the state file is lost, the feed re-syncs from the testnet4 genesis —
which it **verifies** (`00000000da84f2bafbbc53dee25a72ae507ff4914b867c565be350b0da8bf043`,
cross-checked against mempool.space and Core v31.0 chainparams) and refuses
to feed any other chain. This matters because the fork anchors the first
header it ever sees at height 0 — feeding the wrong chain would silently
misalign every height.

Each poll the feed cross-checks `getbitcoinheaderchaininfo` tip hash against
the last header it submitted and logs a warning on divergence.

## Poll interval

Default 60 s (`--poll`). Testnet4 targets 600 s blocks (often slower in
practice), so 60 s is plenty; the loop also catches up any backlog in
batches of up to 20,000 headers per iteration.

## Reorg behavior

The feed walks back from the upstream **most-work header tip** (via
`getchaintips`, not `getbestblockhash` — see "headers-only" note below) to
the last-fed hash using `previousblockhash` links, so after a reorg it
naturally follows the new best chain and submits the new branch in order.
The fork's header store keeps both branches and tracks the most-work tip;
depth checks use the active (most-work) chain.

**Restarting after an outage (Phase 4 fix, 2026-10-07):** the walk back is
not capped at 10,000 — a restart during the initial multi-hour catch-up (or
after any long outage) resumes from a last-fed hash far behind the tip. The
first 10,000 headers are a fast path: if the last-fed hash isn't there, the
feed checks for a reorg fork point within reach; only when there is none
does it commit to the full walk back, which distinguishes a deep backlog
(the last-fed hash IS an ancestor of the tip, so the walk reaches it) from
a wiped/replaced upstream node (the walk reaches genesis without finding it
and the feed exits with a clear fatal error instead of guessing). Before
this fix, any feed restart more than 10,000 headers behind the tip died
with "deep reorg beyond walkback cap" and wedged the service in a crash
loop until the state file was manually deleted.

**Status: reorg handling is reasoned through but NOT live-tested** — there
is no practical way to trigger a testnet4 reorg on demand from here.

## Known prototype limitation (important)

The fork's Bitcoin header chain (`core/src/favilla/btcheaders.cpp`) is
hardcoded to **Bitcoin-regtest parent-chain semantics**: no retargeting —
any header whose `nBits` differs from its parent is rejected with
`bad-diffbits`. Real testnet4 retargets every 2016 blocks (first change at
height 2016: `0x1d00ffff` → `0x1c3fffc0`), so the feed **stalls at header
2016**: it submits headers 0–2015 (all accepted, verified 2026-10-07), then
stops with the rejection recorded in the state file (`"stall"`), retrying
only when the upstream tip advances. This is by design of the current
prototype, not a feed bug — do not work around it by skipping headers
(skipping breaks the prev-link chain and every later header becomes an
orphan).

What Phase 4 / consensus work must change for a real testnet4 feed:
`BitcoinRegtestParams` → testnet4 params (powLimit 2²²⁴, 2016-block
retarget, BIP94 min-difficulty reset rule), and the `nBits`-equality check →
`CalculateNextWorkRequired`-based validation per SPEC §6 ("every difficulty
retarget follows Bitcoin consensus rules").

## Operational notes

- **Upstream RPC is `getchaintips`-based, not `getbestblockhash`-based.**
  A bitcoind filled via `submitheader` (headers-only, no block data) never
  advances its *active* chain past genesis — activating a chain requires
  full blocks, which is normal Core behavior, not an error. The feed
  therefore tracks the most-work *header* tip. Every submitted header is
  still fully validated by the upstream node (PoW, prev-link, difficulty
  rules); `submitheader` errors on anything invalid.
- **Once a Favilla block is marked invalid it stays invalid** even if the
  header chain later catches up: if a claim-bearing block was rejected
  because the header chain was too short at connect time, use
  `reconsiderblock <favilla-block-hash>` after the feed has caught up.
  (Untested; flagged for Phase 4.)
- Favilla persists its header chain on every submission
  (`<datadir>/testnet/favilla_btcheaders.dat`); node restarts are safe.
- Ports used in testing: upstream testnet4 P2P 48333 / RPC 48332 (Core
  defaults); Favilla testnet P2P 34444 / RPC 34443 (SPEC §2.2). No
  collisions.
- The feed trusts its upstream the way any SPV header source is trusted:
  the FIRST header fed anchors the chain, hence the genesis-hash check.
  Run the upstream node yourself; do not point the feed at someone else's
  RPC.

## Verification (2026-10-07)

Mechanism test (official Core v31.0 on **regtest** as upstream, 311 blocks
mined on demand → feed → fresh favillad testnet node): batch catch-up
(301 headers, **~1.6 ms/header**), idempotent restart ("caught up, nothing
new"), new-header auto-pickup within the 10 s poll interval (5 blocks mined
→ fed 2 s later, tip hashes match), header persistence across favillad
restart. All green.

Real-data test (upstream testnet4 → favillad): headers 0–2015 accepted
(tip_height/tip_hash match upstream; heights align, genesis at 0), stall at
2016 with `bad-diffbits` as documented above. Per-header timing on real
headers: **~2.7 ms/header** (two localhost RPC round-trips + PoW check each;
a full ~155k-header initial sync projects to roughly 7 minutes of submit
time — the bottleneck is RPC round-trips, not validation).
