# Furnace Watch — Favilla block explorer (regtest + testnet)

A simple, server-rendered web app for watching the fire: burns, claims,
mints, and the Vigil unfolding on the Favilla chain.

Default chain is **regtest**; pass `--testnet` for the public testnet
(HRP `fvlt`, RPC 34443, testnet furnace address — audit F1).

## Run it

```bash
# 1. start favillad (regtest), e.g.:
~/workspace/favilla/core/build/bin/bitcoind -regtest \
  -datadir=/tmp/fv-explorer-node -rpcport=28443 -port=28444 \
  -daemon -server -listen=1 -dnsseed=0 -fixedseeds=0

# 2. start the explorer (defaults match the above):
python3 explorer.py --datadir /tmp/fv-explorer-node --rpc-port 28443 --port 8080

# 3. open http://127.0.0.1:8080/
```

For testnet: `python3 explorer.py --testnet --datadir <testnet-datadir>`
(defaults: RPC 34443). Options: `--datadir`, `--rpc-port`, `--port`,
`--no-browser`, `--testnet`.
Python standard library only — no pip dependencies.

## What it shows (and where the data comes from)

Everything is derived live from the Favilla node's RPC — no dependency on
the wallet's simulated Bitcoin chain:

| Page | Source |
|---|---|
| **Overview** — height, era/fire + burn rate, total sats burned, total FVLA minted, claim count, Vigil-locked total | scans blocks 0..tip via `getblock`; parses v4 claims per SPEC §5; sums furnace outputs (byte-identical `FURNACE_SPK`, §3); Vigil-locked via `gettxout` per mint |
| **Blocks** — recent blocks; block detail highlights claims | `getblock` verbosity 0 (raw hex), parsed locally |
| **Claim** (`/claim/<burn_txid>`) — burn amount, minted cinis/FVLA, recipient address (P2WPKH of burn input-0 key, derived locally), Vigil unlock height, signature-gate + §9 amount re-checks, nullifier status | claim fields parsed from chain; recipient pubkey extracted from burn input 0 per §7 V4; address = bech32(`fvlrt`) of its HASH160 |
| **Furnace** — the furnace address, total sats received, per-burn list | `fvlrt1qazqlhwhsyyezu6wrj6ua5264gcpdfl0f9t56ey` (SPEC §3 test vector); burns aggregated from claims |
| **Vigil** — every mint output with unlock height, blocks-away, sleeping/awake | Vigil scripts parsed per SPEC §11 (`<unlock> CLTV DROP <pubkey> CHECKSIG`) |

Each claim row carries an independent re-check badge: the explorer
recomputes the §9 issuance formula and re-parses the Vigil script itself,
so a consensus mismatch would show up as `CHECK FAILED` rather than being
trusted.

### Honest limitations

- **Bitcoin confirmations at claim time** can't be recovered from Favilla RPC
  alone (the node exposes no header-height lookup). The claim page states
  "≥ 144 (consensus-verified at inclusion)" — the guarantee consensus gives,
  not a number we can't prove.
- **Only claimed burns are visible.** An unclaimed burn leaves no trace on
  the Favilla chain; the furnace total counts claimed burns only.
- **Nullifier status** is derived from active-chain inclusion (equivalent to
  the §8 nullifier set by its stated invariant), not from a nullifier RPC —
  none exists.
- Pages auto-refresh every 30s; the chain is re-scanned only when the tip
  hash changes (cheap on regtest).

## Verification (2026-10-07)

Tested against a fresh regtest node with real activity generated via the
wallet CLI (`furnace.py`): two burns (1,000,000 and 2,500,000 sats), 150+
Bitcoin blocks, two claims mined at Favilla heights 1 and 2.

- Overview: height 2, Fire 0, 2 claims, 3,500,000 sats burned,
  350,000,000 cinis (3.5 FVLA) minted, 350,000,000 Vigil-locked — all matched
  against an independent ground-truth script using `bitcoin-cli` directly
  (separate parser, not the explorer's code). ✅
- Claim pages: burn txids, amounts, minted values, unlock heights
  (210001/210002), and recipient address all matched; recipient address
  re-derived independently from the burn key's pubkey — byte-exact. ✅
- Vigil page: both mint outputs listed as sleeping with correct unlocks. ✅
- Unknown burn txid → clean "Claim not found" page. ✅
- No discrepancies found.

## Files

- `explorer.py` — the whole app (RPC client, parsers, bech32, pages, server)
- `README.md` — this file
