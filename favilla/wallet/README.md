# furnace.py — Favilla wallet/CLI (regtest + public testnet)

The ritual, made real: burn BTC to the furnace → wait 144 Bitcoin
confirmations → file a claim → FVLA mints to the burn key's address,
Vigil-locked for 210,000 blocks.

Default chain is **regtest**. Pass `--testnet` for the public testnet —
burns there are REAL Bitcoin testnet4 transactions (nothing simulated).

## Testnet mode

```bash
# point at a Favilla testnet node (defaults: --favilla-datadir ~/.favilla --rpc-port 34443)
python3 furnace.py --testnet --favilla-datadir /tmp/fv-tn newkey

# see the furnace address and instructions (no node needed for this step)
python3 furnace.py --testnet burn --amount 0.01
# -> send REAL testnet4 BTC from your own testnet4 wallet, then:

# check confirmations any time (needs your testnet4 node: --btc-datadir/--btc-rpc-port)
python3 furnace.py --testnet claim <burn_txid>   # same for status/balance
```

Testnet requirements: a Favilla testnet node with its Bitcoin header chain
fed (see `../testnet-feed/` — every node must feed its own headers), and an
upstream Bitcoin testnet4 node for the wallet to fetch the burn tx, Merkle
proof (from the full confirmed block) and depth. `mine-btc` and `demo` are
regtest-only and refuse to run on testnet. Chain parameters (signature
magic `"fvlt"`, RPC 34443, HRP `"fvlt"`) come from the CHAINS table —
nothing chain-specific is hardcoded (audit F1).

## Setup (regtest)

```bash
# 1. start favillad (regtest), e.g.:
~/workspace/favilla/core/build/bin/bitcoind -regtest \
  -datadir=/tmp/fv-wallet-node -rpcport=28443 -port=28444 \
  -daemon -server -listen=1 -dnsseed=0 -fixedseeds=0

# 2. point the wallet at it (defaults: --favilla-datadir ~/.favilla --rpc-port 28443)
python3 furnace.py --favilla-datadir /tmp/fv-wallet-node newkey
```

Requires: python3, the `ecdsa` package.

## The ritual

```bash
# burn 0.01 BTC to the furnace (uses the wallet key; refuses without one)
python3 furnace.py burn --amount 0.01
# -> prints the burn txid and next steps

# wait: mine Bitcoin blocks until 144 confirmations
python3 furnace.py mine-btc 150

# check readiness any time
python3 furnace.py status <burn_txid>

# file the claim (key auto-loaded from the wallet file)
python3 furnace.py claim <burn_txid> --mine   # --mine also confirms it in a Favilla block

# see your mints
python3 furnace.py balance
```

`demo` runs the whole happy path unattended (for testing).

## Key custody

- The wallet holds **one** WIF keypair (`key.wif`, mode 0600). The burn's
  first input spends from this key; the claim signature (SPEC §7 V5) is made
  with it; the FVLA mints to its P2WPKH address.
- `burn` and `claim` **refuse to run without a key you control**, and say why:
  burns from exchanges/custodians are unclaimable *by design* — no valid
  claim signature can ever exist, so nothing silently mints to the
  custodian's key. Burn only from self-custody.
- `claim --key <WIF>` with the *wrong* key fails loudly ("you don't control
  the burn key") instead of submitting a doomed transaction.
- Private keys are never written to logs. `newkey` prints the WIF once, at
  creation, as an explicit user action. Mainnet would use hardware-wallet
  signing (out of scope for the prototype).

## The simulated Bitcoin chain

There is no live Bitcoin network on regtest, so the wallet maintains one:
`mine-btc` grinds block headers (trivial PoW, nBits 0x207fffff — the same
difficulty the consensus tests use) and submits each to the Favilla node via
`submitbitcoinheader`, which validates PoW and tracks the most-work chain
itself (SPEC §6). Chain state lives in `<wallet-dir>/btcchain.json`.

Burns are fully-formed, properly-signed P2WPKH Bitcoin transactions spending
*simulated* confirmed UTXOs of the burner key — byte-for-byte what a real
wallet would produce, including a real BIP143 signature. Per SPEC D11 the
Favilla node never validates burn inputs (inclusion at depth ≥144 *is* the
validity argument), so consensus treats these exactly like mainnet burns.

## What `claim` builds (SPEC §5, §7)

A version-4 transaction: marker input, `burn_txid`, 80-byte burn header,
Merkle branch + index, raw burn tx, DER ECDSA `claim_signature` over
`SHA256("FVLA-CLAIM" || network_magic || burn_txid)` — where network_magic
is `fvla` on regtest and `fvlt` on testnet (chain-specific; a regtest-signed
claim is invalid on testnet and vice versa, audit F1), and exactly one output:
the Vigil script `PUSH(unlock) OP_CLTV OP_DROP PUSH(pubkey) OP_CHECKSIG`
with `unlock = inclusion_height + 210_000` and value `cinis` per SPEC §9.
The recipient is deterministic (burn input-0's key) — the claim names none.
