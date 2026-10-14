# Favilla (FVLA) — public testnet

Favilla is a **proof-of-burn cryptocurrency**: you destroy bitcoin by sending
it to a single provably-unspendable address (the "furnace"), then submit a
claim on the Favilla chain with an SPV proof of the burn. Consensus mints
FVLA to the key that signed the burn. There is no premine, no founder
reward, no ICO, no subsidy — the founder burns like everyone else.

Every mint is locked ~4 years ("the Vigil") behind **two** independent
locks: a Favilla block-height lock *and* a Bitcoin-time lock (the spending
block's committed Bitcoin tip must sit ~4 years past the burn in Bitcoin
median-time — a lone Favilla miner cannot fast-forward Bitcoin's clock).

**This is a testnet prototype.** Burns use Bitcoin **testnet4** (worthless
by design); testnet FVLA is worthless too. **Expected value of everything
here: zero. This is an experiment, not an investment.**

## Where things live

- Normative spec: `favilla/SPEC.md` (v0.5 — the D13 "Bitcoin-anchored
  claims" design is adopted there)
- Join guide + attack surface: `favilla/TESTNET.md`
- Build guide: `favilla/BUILD.md`
- Wallet/CLI: `favilla/wallet/furnace.py`
- Explorer: `favilla/explorer/explorer.py`
- Adversarial test suite (55 claim-validation vectors): `favilla/tests/test_claims.py`
- Bitcoin header feed: `favilla/testnet-feed/` (mandatory for every node — see below)
- Whitepaper: *Ex Favilla* (to be published — will be linked here)

## How to build

Standard Bitcoin Core v31.1 CMake build, from the repo root:

```
cmake -B build && cmake --build build
```

Binaries land in `build/bin/` (`favillad`, `favilla-cli`, ...). Ubuntu
24.04 toolchain (GCC 13.3, CMake 3.28) plus the usual Core deps
(libevent, libsqlite3, Boost) — see `favilla/BUILD.md`.

## How to join the testnet

1. **Build** the fork (above).
2. **Run a testnet node** and connect to the seed:
   ```
   favillad -chain=testnet -addnode=[2a04:4e41:14:5508::e416:5508]:34444 -daemon
   ```
   Chain identity: magic `fvlt`, P2P 34444 / RPC 34443, bech32 HRP `fvlt`,
   genesis at minimum difficulty (CPU-mineable). The seed's public IPv6
   could not be verified reachable from outside our own host — if you can't
   connect, report it; that's useful data, not your failure.
3. **Feed Bitcoin headers to your node. Mandatory, not optional.** Favilla
   validates burns against Bitcoin headers *locally*; headers are not
   propagated over Favilla P2P. A node with no headers cannot validate
   claims and stalls. Run a Bitcoin testnet4 node and feed continuously
   (see `favilla/testnet-feed/`).
4. **Get tBTC** from a faucet (cypherfaucet.com worked for us; testnet4.dev
   is a backup) or patiently CPU-mine testnet4.
5. **Burn** tBTC to the furnace from a key **you control**:
   `fvlt1qazqlhwhsyyezu6wrj6ua5264gcpdfl0fqtwx7p`
   (nothing-up-my-sleeve: HASH160 of `"ex favilla furnace v1"`).
   **Do not burn from an exchange or custodial wallet** — the mint goes to
   the burn's input-0 key and the claim requires that key's signature, so a
   burn from a key you don't control is *permanently unclaimable*. This is
   the protocol failing loudly by design; learn it the cheap way.
6. **Wait** 144 Bitcoin-testnet4 confirmations (~24h+, often more).
7. **Claim** with the wallet (see `favilla/wallet/README.md`). Claims name
   no recipient and carry no fee; anyone may submit anyone's claim, but
   only the burner's key can authorize it.

## Honest limitations

- Seed availability is testnet-grade; the host may be replaced without
  warning (systemd restarts, but there is downtime), and its public IPv6
  reachability is unverified — treat the connection string as provisional
  until an external peer confirms it.
- You must feed Bitcoin headers yourself. Every node. No exceptions.
- Header catch-up is slow the first time (O(n²) dump, ~5h for a full sync).
  It only hurts once.
- No DNS seeds; peer discovery is manual (`-addnode`) until someone runs one.
- The chain may be **reset or abandoned at any time**. Build nothing on it you
  can't afford to lose.
- Faucet tBTC is the bottleneck for new participants; difficulty-1 CPU
  mining is the slow fallback.

## Come break it

This testnet exists to be broken. Forge claims (wrong amounts, bad Merkle
proofs, tampered signatures, Taproot burn inputs), double-claim burns,
replay claim signatures across burns and networks, feed competing Bitcoin
header chains, kill -9 the node mid-write, connect wrong-chain peers. The
attack surface is enumerated in `favilla/TESTNET.md` ("Invitation to
attack"). Reproducible breaks are gifts; vague unease is not actionable.

---

*No real BTC anywhere in this process. Testnet4 only. Expected value zero —
an experiment, not an investment.*
