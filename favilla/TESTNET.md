# Favilla Public Testnet (`fvlt`)

**Status (2026-10-07): LIVE — seed node running, first real burn in flight.**
The first testnet burn (900,000 tBTC sats → furnace) is broadcast and awaiting
144 Bitcoin-testnet4 confirmations before the first claim can be made.
See "First burn" below.

This is a **public test network**. It exists so strangers can try to break
Favilla before anything real is at stake. There is no real money here:
burns use Bitcoin **testnet4** (tBTC), which is worthless by design, and
FVLA minted on this network is worthless too.

## Chain identity

Consensus rules are identical to the regtest prototype (SPEC.md §§5–13).
Only chain identity differs:

| Parameter | Value |
|---|---|
| Network magic (`pchMessageStart`) | `66 76 6c 74` (ASCII "fvlt") |
| P2P port | 34444 |
| RPC port | 34443 |
| Tor/onion P2P port | 34445 |
| Bech32 HRP | `fvlt` (mainnet HRP `fvla` stays reserved) |
| P2PKH / P2SH / WIF base58 prefixes | 36 (`0x24`) / 97 (`0x61`) / 98 (`0x62`) |
| Genesis bits | `0x1e00ffff` (minimum difficulty, CPU-mineable) |
| Target spacing / retarget | 600 s / 2016 blocks (Bitcoin's algorithm) |
| Min-difficulty blocks | allowed (chain survives sparse miners) |
| Default datadir | `~/.favilla/testnet` |
| CLI selection | `-chain=testnet` or `-testnet` |
| DNS / fixed seeds | none yet — use the seed below |

The global furnace (same hash160 as regtest; only the address encoding changes):

- scriptPubKey: `0014e881fbbaf021322e69c396b9da2b554602d4fde9`
  (nothing-up-my-sleeve: HASH160 of `"ex favilla furnace v1"`)
- testnet address: **`fvlt1qazqlhwhsyyezu6wrj6ua5264gcpdfl0fqtwx7p`**

## How to join

**1. Build the fork.** From `~/workspace/favilla/core` (or your clone):
standard Bitcoin Core build (`cmake -B build && cmake --build build`).
Binaries land in `build/bin/`.

**2. Run a testnet node and connect to the seed:**

```
favillad -chain=testnet -addnode=[2a09:bac5:6446:3046::4cf:6f]:34444 -daemon
```

Seed connection string: **`[2a09:bac5:6446:3046::4cf:6f]:34444`**
(magic `fvlt`, P2P 34444 / RPC 34443).
Caveat: the seed runs on a VM whose public IPv6 could not be verified
reachable from inside the VM itself — if you cannot connect, report it;
that is useful data, not your failure. The seed is testnet-grade
availability: the VM may be replaced (systemd restarts the node, but there
will be downtime).

**3. Run a Bitcoin testnet4 node and FEED HEADERS to your Favilla node.
This step is mandatory, not optional.** Favilla validates burns against
Bitcoin headers *locally* — headers are not propagated over Favilla P2P
(this was a deliberate finding from the regtest phase). If your node has
no headers, every claim block fails validation and your node stalls.

```
bitcoind -testnet4 -daemon            # any Bitcoin Core ≥ 28 (testnet4 = BIP94)
# then, continuously:
favilla-feed-headers                   # see testnet-feed/feed.py — polls your
                                       # testnet4 node and calls submitbitcoinheader
```

A node with no Bitcoin headers cannot validate claims. There is no
way around this; it is a consensus requirement, not a tooling gap.

**4. Get tBTC.** Worthless testnet4 coins from a faucet. What worked for us:
- **cypherfaucet.com** — keyless JSON API, paid 0.01 tBTC on 2026-10-07
  (verify it still serves testnet4 before relying on it)
- **testnet4.dev** — live but requires hCaptcha (needs a browser)
- coinfaucet.eu — testnet3 only, skip it

If faucets are dry: testnet4's rules allow minimum-difficulty blocks after
20 minutes without a block, so patient CPU mining can mint tBTC. Slow, but
it works and it is within the rules.

**5. Burn.** Send tBTC to the furnace address above, from a key **you
control** (a normal single-key wallet is the recommended ritual):

```
fvlt1qazqlhwhsyyezu6wrj6ua5264gcpdfl0fqtwx7p
```

⚠️ **Do not burn from an exchange or custodial wallet.** By design, the
mint goes to the key that signed the burn's first input, and the claim
requires that key's signature. A burn from a key you don't control is
**unclaimable** — the protocol fails loudly rather than silently minting
to someone else. This is intentional (it is the whole point of the
signature gate), but don't learn it the expensive way. Even on testnet:
use your own key.

**6. Wait 144 testnet4 confirmations** (~24h, often more on testnet4 —
block times are irregular). Your Favilla node must have fed the headers
covering the burn block plus the 144 confirmations.

**7. Claim.** With `wallet/furnace.py`:

```
python3 wallet/furnace.py --testnet claim --burn-txid <txid> --key <WIF>
```

The claim names no recipient and carries no payment: consensus mints to
the P2WPKH of the burn's input-0 pubkey, gated on a signature from that
key over the claim authorization message. Then mine (or wait for) a
Favilla block containing the claim.

## Consensus rules in plain language

- **1,000,000 sats burned = 1 FVLA** (1 sat = 100 cinis), era 0.
  The burn cost **doubles every 210,000 Favilla blocks** (~4 years).
- **144 Bitcoin confirmations** before a burn is claimable. Flat rule,
  no exceptions — this is the reorg assumption, and it is load-bearing.
- **Deterministic recipient + signature gate.** Claims don't name a
  recipient; the mint always goes to the burn's input-0 key. The claim
  must carry that key's signature. Anyone may submit anyone's claim
  (no front-running possible — redirection is impossible), but only the
  burner's key can authorize it.
- **The Vigil.** Every mint is locked 210,000 Favilla blocks (~4 years)
  by `OP_CHECKLOCKTIMEVERIFY`. There is no way to spend early. This is
  consensus, not policy.
- **Nullifier set.** Each burn txid can be claimed exactly once, forever.
  Double-claims are rejected at the consensus layer.
- **One global furnace.** A single provably-unspendable address
  (HASH160 of `"ex favilla furnace v1"`). All burns go there; the coins
  can never move again. That is the sacrifice.
- **No premine, no founder reward, no ICO.** The founder burns like
  everyone else, first in line or not.

## Burns so far

**Burn #1 (2026-10-07): permanently UNCLAIMABLE — a live demonstration of
the signature gate.** txid
`9548da37bc878320daee5dc70276949d065031354fa1e910af727a0f0bd5bebe`
(900,000 sats, confirmed at testnet4 height 155531). The burn key's only
durable copy was lost in a VM replacement before it was ever persisted —
and the claim requires that key's signature (SPEC §7 V5), with no
alternative path by design. Those sats are burned to the furnace forever,
claimable by no one. This is exactly the protection the signature gate
exists to provide (the exchange-burn footgun: silent mints to custodians
are impossible; unauthorized claims simply fail). On testnet the tuition
was ~$0. Lesson recorded: burn keys are persisted to durable storage
*before* broadcast, never only in ephemeral scratch.

**Burn #2 (2026-10-07, in flight):** txid
`669d98986a5b6d2e1e5aec120949a208930e86c1e3376457fccc7121216c15bf`
— 999,000 sats to the furnace (broadcast 18:53 UTC), key persisted to
durable storage *before* broadcast and independently verified. The
end-to-end claim test (mint verification, Vigil lock, double-claim
rejection, explorer display) runs once it accumulates 144 testnet4
confirmations (~24h).

## Known limitations (honest list)

- **Seed availability is testnet-grade.** The VM may be replaced without
  warning; systemd restarts the node but there is downtime. The IPv6
  address could not be verified reachable from outside the VM — treat the
  published connection string as provisional until an external peer
  confirms it.
- **You must feed Bitcoin headers yourself.** Every node, no exceptions.
  The seed does not serve headers to you.
- **Header catch-up is slow** (O(n²), ~28 ms/header — a full 155k-header
  sync takes ~5h one time). The header dump is not atomic; a kill landing
  mid-write can corrupt it (recovery: `clearbitcoinheaders` + re-feed).
- **The seed speaks P2P v1 only** (`-v2transport=0`), deliberately: v2
  (BIP324) skips magic-based peer rejection, and strict network separation
  matters more than transport privacy on a testnet.
- **No DNS seeds.** Peer discovery is manual (`-addnode`) until someone
  runs a DNS seeder.
- **Faucet tBTC is the bottleneck** for new participants. Difficulty-1
  mining is the fallback; it is slow.
- Testnet coins are worthless and the chain may be reset or abandoned at
  any time. Do not build anything on it that you cannot afford to lose.

## Invitation to attack

This testnet exists to be broken. If you can break it, we want to know
before mainnet is ever discussed. Areas we most want attacked:

1. **Claim validation (V1–V7).** Forge a claim: wrong burn amount, bad
   Merkle proof, insufficient confirmations, tampered signature message,
   non-P2WPKH burn input, Taproot burn input. The 34-vector suite in
   `tests/test_claims.py` is the current coverage — extend it.
2. **Nullifier handling.** Double-claim the same burn. Claim across a
   reorg that un-confirms the claim block. Try to get the same burn
   minted twice by any path.
3. **Signature gate.** Burn from a key, claim with a different key.
   Malleate the claim authorization message. Replay a claim signature
   on a different burn.
4. **Reorg behavior.** Feed a competing Bitcoin header chain and watch
   the most-work switching. Orphan the header tip your claim depended on.
   Restart mid-reorg.
5. **Persistence.** Kill -9 the node with 100k+ headers fed, restart,
   confirm the chain resumes and claims still validate. Corrupt
   `favilla_btcheaders.dat` mid-write and see what happens.
6. **P2P and chain identity.** Connect a regtest node to the testnet
   port; connect a Bitcoin node; try to get cross-network contamination.
   (v1 transport should reject wrong-magic peers — verify it.)

Report breaks with reproduction steps. A break that is reproducible is a
gift; a vague "it felt wrong" is not actionable.

## Links

- Normative spec: `SPEC.md` (this testnet = §2.2 chain identity + §§5–13 consensus)
- Build: `BUILD.md` · Status log: `STATUS.md` · Whitepaper: `Ex Favilla`
- Wallet: `wallet/furnace.py --testnet` · Explorer: `explorer/explorer.py`
- Header feed: `testnet-feed/` (README explains the operator requirement)

---
*No real BTC anywhere in this process. Testnet4 only. Expected value of
testnet FVLA: zero — it is an experiment, not an investment.*
