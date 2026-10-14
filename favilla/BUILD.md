# Favilla — Build & Regtest Guide

**Phase 1 prototype base: pristine Bitcoin Core fork, regtest only.**
Nothing here touches mainnet, real BTC, or any public network. Consensus rules
are intentionally UNCHANGED from upstream; only chain parameters (regtest) and
light branding differ. See "Deviations from upstream Bitcoin Core" at the end.

## 1. Upstream version

- **Bitcoin Core v31.1** — tag `v31.1`, commit `9be056a8a72b624dae9623b2f7bded92c2a21c91`
  (shallow clone: `git clone --depth 1 --branch v31.1 https://github.com/bitcoin/bitcoin core`).
- **Why v31.1:**
  - Newest major release line (31.x) per the GitHub releases API as of 2026-10-06 —
    not a prerelease/RC (the only newer-dated tags, v29.4 and v30.3, are
    maintenance backports on older branches, published 2026-07-10).
  - Published 2026-07-08: ~3 months of real-world soak time, i.e. stable, not bleeding-edge.
  - Builds with the stock Ubuntu 24.04 (noble) toolchain: GCC 13.3, CMake 3.28 —
    no custom compiler or depends-tree needed.
- Note: v31.x uses the **CMake** build system (autotools was removed upstream).
  The `libtool`/`autotools-dev`/`automake` packages are therefore NOT needed;
  `cmake` is required instead. `bsdmainutils` is also not needed for a CMake build.

## 2. Dependencies (Ubuntu 24.04 noble, x86_64)

Already present on the machine: `build-essential` (GCC 13.3.0), `cmake` 3.28.3,
`pkgconf`/`pkg-config`, `python3`.

Installed via apt for this build (2026-10-06):

```
sudo apt-get update
sudo apt-get install -y --no-install-recommends libevent-dev libboost-dev libsqlite3-dev
```

Installed versions: `libevent-dev` 2.1.12-stable-9ubuntu2.2,
`libboost-dev` 1.83.0.1ubuntu2, `libsqlite3-dev` 3.45.1-1ubuntu2.8.

- `libsqlite3-dev` — required for the **wallet** (needed for `generatetoaddress`
  in the regtest smoke test).
- Qt GUI packages deliberately **not** installed (`-DBUILD_GUI=OFF`).
- ZMQ (`libzmq3-dev`) and Cap'n Proto (`libcapnp-dev`) deliberately **not**
  installed (`-DWITH_ZMQ=OFF -DENABLE_IPC=OFF`) — not needed for a regtest prototype.

## 3. Build commands (exact)

From `~/workspace/favilla/core`:

```bash
# Configure (CMake). No GUI, no IPC/multiprocess, no ZMQ, no bench/fuzz binaries.
cmake -B build -DBUILD_GUI=OFF -DENABLE_IPC=OFF -DWITH_ZMQ=OFF \
      -DBUILD_BENCH=OFF -DBUILD_FUZZ_BINARY=OFF

# Build just the daemon and CLI (2 cores on this machine; ~45-60 min).
cmake --build build --target bitcoind bitcoin-cli -j2
```

Resulting binaries:
- `build/src/bitcoind`
- `build/src/bitcoin-cli`

(`bitcoin-wallet`, `bitcoin-tx`, `bitcoin-util`, and `test_bitcoin` targets exist
in the tree but were not built; only the daemon and CLI are needed.)

## 4. Favilla regtest chain parameters

Everything below is a **chainparams-only** change in `CRegTestParams`
(`src/kernel/chainparams.cpp`) plus the regtest RPC port
(`src/chainparamsbase.cpp`). No consensus rule was altered; the regtest genesis
block is byte-identical to upstream Bitcoin regtest (deliberate — it keeps
upstream's regtest functional tests meaningful and the network is already
uniquely identified by magic bytes + ports + address formats).

| Parameter | Upstream regtest | Favilla regtest | Why |
|---|---|---|---|
| Network magic (`pchMessageStart`) | `fa bf b5 da` | `66 76 6c 61` (ASCII "fvla") | Distinct from BTC mainnet (`f9 be b4 d9`), testnet3 (`0b 11 09 07`), BTC regtest, signet (`1c 16 3f 28`); prevents any cross-talk with Bitcoin P2P networks |
| P2P port (`nDefaultPort`) | 18444 | **28444** | Avoids 8333/18333/38333/48333 (BTC nets), 18444 (BTC regtest), 9333/19335/19444 (LTC), 22556 (DOGE), 18445 (BTC regtest Tor) |
| RPC port (`chainparamsbase.cpp`) | 18443 | **28443** | P2P port − 1, following Bitcoin's own convention; avoids 8332/18332/38332/48332/18443 and LTC's 9332/19332 |
| Tor/onion incoming port | 18445 | **28445** | Automatic: `nDefaultPort + 1`, no extra change needed |
| P2PKH version byte | 111 | **35** (`0x23`) | Addresses start with **'F'** (for Favilla); avoids BTC 0/111 and common alts |
| P2SH version byte | 196 | **95** (`0x5f`) | Addresses start with **'f'**; avoids BTC 5/196 |
| WIF version byte | 239 | **96** (`0x60`) | Private keys start with **'F'**; avoids BTC 128/239 |
| xpub version bytes | `04 35 87 cf` ("tpub") | `46 4c 9d 76` | Extended public keys start with **"Fvap..."** ("FVa public"); mathematically solved for a clean prefix, verified stable over 200 random payloads |
| xprv version bytes | `04 35 83 94` ("tprv") | `46 4c a0 a0` | Extended private keys start with **"Fvar..."**; same verification |
| Bech32 HRP | `bcrt` | **`fvla`** | Segwit/taproot addresses look like `fvla1q…` / `fvla1p…`; distinct from `bc`/`tb`/`bcrt` |

## 5. Light branding (non-consensus, `src/common/args.cpp`)

- Default data directory: `~/.bitcoin` → **`~/.favilla`**
  (Windows/macOS equivalents renamed `Bitcoin` → `Favilla` for consistency).
  Rationale: a Favilla regtest node must never share a datadir with a Bitcoin
  Core node by accident.
- Default config file: `bitcoin.conf` → **`favilla.conf`**.
- Deliberately NOT renamed: the `bitcoind`/`bitcoin-cli` binary names and the
  `Satoshi` client name/user-agent. Renaming CMake targets ripples into install
  rules, man pages, and the functional test framework; the chain identity lives
  in the network parameters above, which is sufficient for a prototype.

## 6. Two-node regtest setup

**Status: VERIFIED WORKING — 2026-10-06 (~23:00 UTC).**

Binaries: `build/bin/bitcoind`, `build/bin/bitcoin-cli` (note: v31 CMake puts
runtime binaries in `build/bin/`, not `build/src/`).

Node configs (regtest-only, localhost RPC with trivial credentials — never
expose; regtest coins have no value):

`/tmp/favilla/node1/favilla.conf`:
```ini
regtest=1
server=1
daemon=0
listen=1
rpcuser=favilla
rpcpassword=regtest-only-local
fallbackfee=0.0001
[regtest]
port=28444        # Favilla regtest P2P default
rpcport=28443     # Favilla regtest RPC default
rpcbind=127.0.0.1
```

`/tmp/favilla/node2/favilla.conf`:
```ini
regtest=1
server=1
daemon=0
listen=1
rpcuser=favilla
rpcpassword=regtest-only-local
fallbackfee=0.0001
[regtest]
port=28454       # distinct P2P port so both nodes run on one machine
rpcport=28453    # distinct RPC port
rpcbind=127.0.0.1
connect=127.0.0.1:28444   # peer only with node1
```

Note: in v31, network-specific options (`port`, `rpcport`, `connect`) are
rejected at the top level of the config when a network is selected — they MUST
live in the `[regtest]` section ("Config setting for -port only applied on
regtest network when in [regtest] section").

Launch / operate:
```bash
B=~/workspace/favilla/core/build/bin
C1="$B/bitcoin-cli -datadir=/tmp/favilla/node1 -rpcport=28443 -rpcuser=favilla -rpcpassword=regtest-only-local"
C2="$B/bitcoin-cli -datadir=/tmp/favilla/node2 -rpcport=28453 -rpcuser=favilla -rpcpassword=regtest-only-local"

$B/bitcoind -daemon -datadir=/tmp/favilla/node1 -conf=/tmp/favilla/node1/favilla.conf
$B/bitcoind -daemon -datadir=/tmp/favilla/node2 -conf=/tmp/favilla/node2/favilla.conf

$C1 -named createwallet wallet_name=miner descriptors=true
$C2 -named createwallet wallet_name=miner descriptors=true
$C1 -rpcwallet=miner generatetoaddress 101 "$($C1 -rpcwallet=miner getnewaddress)"

# stop:
$C1 stop; $C2 stop
```

Smoke-test results (2026-10-06):
- Both nodes start on `chain: regtest`, same genesis
  `0f9188f13cb7b2c71f2a335e3a4fc328bf5beb436012afca590b1a11466e2206`
  (upstream regtest genesis — kept deliberately, see §4).
- Peering: node2 `connect=` to node1's P2P port 28444; `getpeerinfo` shows
  1 peer on each side.
- Favilla address formats confirmed live:
  - bech32: `fvla1q54c6zvww8m0wzn0x43j2v474mcwjl36hx4jlpt`
  - legacy P2PKH: `FHTYJyxKWQUTbBNLkrGzZ2JXvM8nE1wNXq` (starts 'F')
  - P2SH-segwit: `fML4kKb2MiwDeJetWwA5CkA4UgzYZfJCsD` (starts 'f')
- Mined 101 blocks on node1 → node2 synced to identical tip (height 101,
  same best hash); node1 wallet balance 50.0 after maturity.
- Cross-node payment: node1 `sendtoaddress` 1.5 → node2's `fvla1q…` address;
  tx appeared in node2's mempool, confirmed in next block; node2 balance 1.5.
  Both nodes at height 102 with matching tips. ✔

## 7. Build log / environment notes

- `sudo apt-get update` took ~20 min (2026-10-06): the configured fallback
  mirror `mirror.cogentco.com` is dead/timing out; all traffic effectively went
  to `http://azure.archive.ubuntu.com/ubuntu` (~200 KB/s). Not a blocker, just slow.
- Machine: 2 cores. Full `bitcoind` + `bitcoin-cli` build took ~21 min with `-j2`.
- No build errors or warnings-as-errors issues; configure summary confirmed
  GUI OFF, IPC OFF, ZMQ OFF, wallet ON.

## 8. Deviations from upstream Bitcoin Core

(Keep this section updated — append a dated entry every time the fork diverges
further from upstream.)

- **2026-10-06 — chainparams (regtest only):** `src/kernel/chainparams.cpp`
  `CRegTestParams`: network magic → `66 76 6c 61` ("fvla"); P2P port 18444 →
  28444; base58 prefixes → P2PKH 35, P2SH 95, WIF 96, xpub `46 4c 9d 76`
  ("Fvap…"), xprv `46 4c a0 a0` ("Fvar…"); bech32 HRP `bcrt` → `fvla`.
  `src/chainparamsbase.cpp`: regtest RPC port 18443 → 28443 (+ Tor-port comment).
  Genesis block UNCHANGED (still upstream regtest genesis).
- **2026-10-06 — light branding:** `src/common/args.cpp`: default datadir
  `.bitcoin` → `.favilla` (Win/macOS `Bitcoin` → `Favilla`); default config
  `bitcoin.conf` → `favilla.conf`. Binary names (`bitcoind`/`bitcoin-cli`) and
  the `Satoshi` user-agent string intentionally left as upstream.
- **Consensus rules: NO CHANGES.** No AuxPoW, no burn-claim logic, no timelock
  changes — those belong to the separate consensus workstream.

### Consensus workstream (2026-10-06, regtest only)

All changes below are gated to regtest (new `Consensus::Params::fZeroSubsidy`,
set only in `CRegTestParams`); mainnet/testnet/signet/testnet4 consensus is
untouched. Every consensus check fails closed.

- **New module `src/favilla/`** (`favilla.h`, `auxpow.h/.cpp`, `claim.h/.cpp`,
  `btcheaders.h/.cpp`): chain ID `0xFA17`; furnace P2WPKH
  `RIPEMD160(SHA256("ex favilla furnace v1"))` =
  `e881fbbaf021322e69c396b9da2b554602d4fde9` (test vector verified);
  Vigil template `<unlock> CLTV DROP <pubkey> CHECKSIG` builder;
  `CalcCinis` (128-bit integer, `cinis = floor(burned_sats×10^8/(10^6·2^(H//210000)))`).
- **AuxPoW merged-mining (`CAuxPow`, `CheckAuxPow`, SPEC §12):** block version
  bit `0x100` signals an AuxPoW payload; wire order = 80-byte header, payload,
  then transactions (diff vs Namecoin recorded in STATUS.md — the fork follows
  the SPEC, not Namecoin). Payload: parent coinbase tx, parent header,
  coinbase merkle branch (≤32), aux merkle branch (≤32), parent header
  (≤1440 bytes). Checks: magic `0xFABE6D6D` followed by chain root in internal
  byte order; parent coinbase cannot carry witness (fail closed); parent PoW
  verified against Favilla `nBits`; parent header must be on the active
  Bitcoin header chain. `CheckBlockHeader` skips direct Favilla PoW for AuxPoW
  blocks (work is proven via the parent). Compact blocks always fall back to
  full-block relay for AuxPoW blocks (`PartiallyDownloadedBlock::FillBlock`
  returns `READ_STATUS_FAILED`), because compact blocks cannot carry the
  payload.
- **Claim transactions (`nVersion=4`, SPEC §5/§7):** fixed serialization
  (33-byte pubkey, no witness, no length prefix); txid = SHA256D of the §5
  bytes. `CTransaction`/`CMutableTransaction` carry the six claim fields;
  `IsClaim()`; `IsCoinBase()` now excludes v4; `GetValueOut()` hardened to
  int64 range (v1/v2 semantics unchanged — `CheckTransaction` still caps their
  outputs). `CheckClaimTransaction` (structural, `consensus/tx_check.cpp`):
  exact §5 grammar, pubkey fully-valid (secp256k1), burn tx parses with
  non-empty/non-negative outputs.
- **Claim contextual validation (`CheckClaimContextual`, V1–V6 normative
  order):** V1 nullifier (burn txid not yet spent); V2 header-txid binding
  (recomputed merkle root, index in range); V3 ≥144 Bitcoin confirmations on
  the active header chain; V4 OP_RETURN binding (burn tx's first OP_RETURN
  data == claim `burn_txid`) and furnace sum ≥ era rate (sum over ALL furnace
  outputs); V5 cinis > 0; V6 mint output byte-equal to the Vigil template.
  Wired into `ConnectBlock` (claims skip `CheckTxInputs`/fee/BIP68/script
  checks; per-block nullifier dedup; sigops counted) and the mempool
  (dedicated `AcceptClaimTransaction`: structural → dedup → V1–V6 at tip+1 →
  feeless staging, bypassing fee/input policy; `removeClaims()` on every tip
  change; disconnected claims dropped, never re-queued per §13.1).
- **Nullifier set (SPEC §8):** txid-keyed, stored in the chainstate LevelDB
  (`DB_NULLIFIER{'N'}`) with `NullifierEntry{height, txindex}`, riding the
  same atomic `BatchWrite` as coins; `CBlockUndo::vNullifierKeys` provides
  per-block undo on reorg; never pruned. Read through the `CCoinsView` chain.
- **Era rate / feeless claims (SPEC §9/§10):** `CalcCinis` integer-only;
  `GetBlockSubsidy` returns 0 when `fZeroSubsidy`; `ConnectBlock` requires
  coinbase == total fees exactly; mempool exempts claims from all fee policy.
- **Vigil (SPEC §11):** mint output must be byte-equal to
  `<H+210000> CLTV DROP <pubkey> CHECKSIG`; enforced in V6 and in
  `CalcVigilScript` (minimal-push encoding).
- **Genesis (SPEC §4):** `CRegTestParams` now builds `CreateFavillaGenesisBlock()`
  — coinbase v1, scriptSig `00 0a "ex favilla"`, value-0 OP_RETURN output (no
  premine), nTime 1791288000, nBits 0x207fffff, nonce 2. Hash
  `7cbe5b666f7c8702523033b0218dff488196c2818006ef3c216179ca0858e735`, asserted
  at startup (matches the SPEC §4 test vector byte-for-byte). **This replaces
  the S2 upstream-identical regtest genesis; all existing regtest datadirs are
  invalidated and must be wiped.**
- **Bitcoin header chain (SPEC §6):** `g_btcHeaderChain` — validated,
  most-work header store with flat-file persistence
  (`<datadir>/favilla_btcheaders.dat`, loaded at startup, dumped after each
  add); fed by the new `submitbitcoinheader` RPC (PoW + connectivity checked
  on submission) and inspected via `getbitcoinheaderchaininfo`. No P2P sync —
  transport is implementation-defined in the prototype.

### Direction change #2 (2026-10-06, decided by Matthew)

**D1 FINAL: deterministic recipient** — supersedes BOTH the OP_RETURN
recipient-binding rule AND the signature-authorization rule.
- Claim format: NO `recipient_pubkey` field, NO `claim_signature` field, NO
  OP_RETURN checks. The claim identifies only the burn (txid + SPV proof).
- Consensus: mint output pays to the P2WPKH of the pubkey revealed in the
  burn's first input (index 0). Fully deterministic; anyone may submit;
  front-running harmless; nullifier prevents double-mint.
- Prototype restriction: input 0 must reveal pubkey (P2PKH, P2WPKH,
  P2SH-P2WPKH, single-key P2WSH); Taproot key-path REJECTED with
  `bad-claim-unrecoverable-pubkey`.
- Code: removed `CTransaction::claim_recipient_pubkey`,
  `claim_signature`; removed `GetOpReturnData`, `ExtractInputPubkeys`,
  `VerifyClaimSignature`; added `ExtractBurnInput0Pubkey`; V4 extracts
  mint pubkey, V6 verifies Vigil against it. `src/primitives/transaction.*`,
  `src/consensus/tx_check.cpp`, `src/favilla/claim.cpp`,
  `src/favilla/favilla.h` updated.
- SPEC.md v0.2: §5 (no recipient/auth fields), §7 V4/V5/V6 rewritten,
  §14 D1 records full history, O4 resolved, §16 vectors updated.
