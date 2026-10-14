# Favilla (FVLA) — Consensus Specification v0.5

**Scope:** REGTEST PROTOTYPE + PUBLIC TESTNET. No mainnet, no real BTC.
§2 carries two chain-identity tables: the regtest-prototype parameters and
the public-testnet parameters (chosen 2026-10-07, D10 collision analysis
included). Consensus rules are identical on both chains; only chain identity
differs. Mainnet parameters are still deferred (D10/O1).

**Status:** Draft for implementation (Wave 2). Normative for the reference
implementation. Where this spec and the design brief disagree, this spec governs
the prototype and the disagreement is flagged in §14.

**Primary sources:** `ember-design-brief.pdf` v2.0 (2026-10-06),
`phase-0-decision-log.md` (2026-10-06). Vocabulary (cinis, Vigil, Fire, heat,
furnace, sleeping, glow, smoke) is defined in the brief and reused here without
redefinition.

## 0. Conventions

- Keywords MUST, MUST NOT, REQUIRED, SHALL, SHALL NOT, SHOULD, SHOULD NOT,
  RECOMMENDED, MAY, OPTIONAL follow RFC 2119.
- All integers are unsigned unless stated otherwise. **All consensus arithmetic
  is integer-only; floating point MUST NOT appear in any consensus code path.**
  Division is floor division. Intermediate products MUST use ≥128-bit integers
  (see §9).
- Byte order: multi-byte integers in serializations are little-endian. All
  32-byte hashes (txids, block hashes, merkle nodes) are in **Bitcoin
  internal/wire byte order** (NOT display-reversed) everywhere in this spec.
- `SHA256D(x) = SHA256(SHA256(x))`. `HASH160(x) = RIPEMD160(SHA256(x))`.
- `CompactSize` is Bitcoin's variable-length integer encoding.
- A claim that violates a *shape/type* rule is **malformed**. A claim that is
  well-formed but fails a *proof* rule is **invalid**. Both make a containing
  block invalid (§7.5); the distinction governs mempool/DoS handling (§10).
- Fail-closed principle: any ambiguity in validation resolves to rejection.

## 1. Chain identity and block production

Favilla is a standalone UTXO chain. **Prototype block production is plain
proof of work** (merged mining with Bitcoin via AuxPoW is DEFERRED to the
mainnet phase — decision 2026-10-06, see §12).

- Target block time: 600 seconds.
- Difficulty retarget: Bitcoin's 2016-block algorithm, unchanged.
- **Block subsidy: 0 for all heights.** The coinbase of a block MUST have
  `value == total fees of the block's non-coinbase transactions`. Issuance
  happens ONLY through burn claims (§7). (Decision D5, §14.)
- All Bitcoin soft-fork script rules active at Bitcoin's deployment (BIP 34,
  BIP 65 CLTV, BIP 66, BIP 68/112/113, SegWit) are active on Favilla from
  height 0. `OP_CHECKLOCKTIMEVERIFY` semantics are exactly BIP 65 (verified
  2026-10-06 against the BIP text: fails if stack empty, top item negative,
  lock-type mismatch, top item > tx nLockTime, **or the spending input's
  nSequence == 0xFFFFFFFF**).
- Block wire format: standard 80-byte Bitcoin header. (At mainnet, if
  `nVersion & FAVILLA_AUXPOW_VERSION_BIT != 0`, the header is followed by the
  AuxPoW payload per §12 — not present in the prototype wire format.)
- `FAVILLA_AUXPOW_VERSION_BIT = 0x100` (bit 8). *Reserved; unenforced in the
  prototype.*
- `FAVILLA_AUXPOW_CHAIN_ID = 0xFA17`. *Reserved; unenforced in the
  prototype.* (Decision D7, §14.)

### 1.1 Bitcoin validation-tip commitment (D13a)

Every Favilla block at height ≥ 1 commits to the Bitcoin block hash the
miner used as its claim-validation tip ("the committed tip"). The
commitment rides in the coinbase so it is covered by the coinbase → Merkle
root: miners cannot equivocate about which Bitcoin state they validated
against.

- The coinbase MUST contain **exactly one** output whose scriptPubKey is
  exactly `0x6a 0x20 || H` where `H` is 32 bytes (OP_RETURN pushing 32
  bytes). `H` is the committed Bitcoin tip hash in internal byte order.
  Zero or more than one such output ⇒ block INVALID. (Other coinbase
  outputs, including OP_RETURNs of different shapes, are unrestricted by
  this rule.)
- `H == 0x00*32` (the zero hash) is permitted and means "no Bitcoin tip":
  the miner attests the block's validity does not depend on Bitcoin state.
  A block committing the zero hash that contains any version-4 claim is
  INVALID (V3 cannot be evaluated without a tip).
- The genesis block (height 0) is EXEMPT: its coinbase is the fixed §4
  test vector (bare `0x6a` OP_RETURN). The commitment rule applies at
  height ≥ 1.
- The commitment output's value MUST be 0 (it is unspendable; §1's
  `coinbase value == total fees` rule is unaffected).

## 2. Chain parameters

Two Favilla chains share the consensus rules in §§5–13. **Only chain
identity differs between them.** The regtest table records the code truth as
implemented in `core/src/kernel/chainparams.cpp` (checked 2026-10-07); where
it differs from what earlier spec drafts said, the code governs and the
discrepancy is noted.

### 2.1 Regtest prototype (as implemented)

| Parameter | Value | Notes |
|---|---|---|
| Network magic (`pchMessageStart`) | `66 76 6c 61` | ASCII "fvla" |
| P2P port | 28444 | SPEC drafts said 28333 — stale; code uses 28444 |
| RPC port | 28443 | SPEC drafts said 28332 — stale; code uses 28443 |
| Bech32 HRP | `fvla` | SPEC drafts said `fvlrt` — stale; code uses `fvla`. **Inconsistency flagged:** `fvla` was reserved for mainnet; regtest occupying it is a known wart, not to be repeated — mainnet will need a fresh HRP review (D10) |
| P2PKH base58 prefix | 35 (`0x23`) | SPEC drafts said `0x46` — stale |
| P2SH base58 prefix | 95 (`0x5f`) | SPEC drafts said `0x7a` — stale |
| WIF base58 prefix | 96 (`0x60`) | |
| Genesis block | §4 | Fixed test vector below |
| Regtest difficulty bits | `0x207fffff` | No retarget on regtest |

### 2.2 Public testnet (chosen 2026-10-07)

| Parameter | Value | Notes |
|---|---|---|
| Network magic (`pchMessageStart`) | `66 76 6c 74` | ASCII "fvlt"; D10 collision analysis below |
| P2P port | 34444 | D10 port analysis below |
| RPC port | 34443 | P2P − 1, per Core convention |
| Tor/onion P2P port | 34445 | P2P + 1, per Core convention |
| Bech32 HRP | `fvlt` | Mainnet HRP `fvla` stays RESERVED |
| P2PKH base58 prefix | 36 (`0x24`) | Distinct from regtest 35 and Bitcoin families |
| P2SH base58 prefix | 97 (`0x61`) | Distinct from regtest 95 and Bitcoin families |
| WIF base58 prefix | 98 (`0x62`) | |
| xpub-equivalent prefix | `46 4c 9e 77` | "Fvat…" (FVa testnet public) |
| xprv-equivalent prefix | `46 4c a1 a1` | "Fvau…" (FVa testnet private) |
| Genesis block | §4.1 | Fixed test vector below |
| Genesis / powLimit bits | `0x1e00ffff` | Minimum difficulty, CPU-mineable; largest target with `target·4·nPowTargetTimespan < 2^256` so `CalculateNextWorkRequired` cannot overflow (enforced by the `ChainParams_*_sanity` unit test) |
| Target spacing / retarget | 600 s / 2016 blocks | Bitcoin's algorithm, unchanged |
| Min-difficulty blocks | allowed | `fPowAllowMinDifficultyBlocks = true`: a block may use minimum difficulty after 2× spacing with no block — keeps the chain alive with sparse miners |
| Default datadir | `~/.favilla/testnet` | Via `ChainType::TESTNET` base params |
| CLI selection | `-chain=testnet` or `-testnet` | `-chain=test` kept as deprecated alias |
| DNS / fixed seeds | none yet | Phase 2 wires up the seed node |

#### D10 collision analysis (testnet identity, 2026-10-07)

**Network magic `66 76 6c 74` ("fvlt")** was compared against every network
magic listed below and differs from all of them:

- Bitcoin mainnet `f9beb4d9`, testnet3 `0b110907`, testnet4 `1c163f28`,
  signet `0a110907`, regtest `fabfb5da` (all verified against the fork's own
  `chainparams.cpp`);
- Favilla regtest `66766c61` ("fvla") — differs in the final byte;
- Litecoin mainnet `fbc0bdb`, testnet `fdd2c8f1`, regtest `fabfb5da`;
- Dogecoin mainnet `c0c0c0c0`, testnet `fcc1b7dc`, regtest `fabfb5da`;
- Namecoin mainnet `f9beb4fe`, testnet `fabfb5da`.

No other networks' magics were checked. The choice is ASCII-mnemonic like
the regtest magic; none of the checked magics are ASCII text, so confusion
with printable-data false positives is no worse than the existing regtest
choice.

**Ports 34444 (P2P) / 34443 (RPC)** were checked against the well-known P2P
ports of Bitcoin (8333/18333/48333/38333/18444), Litecoin (9333/19333/19444),
Dogecoin (22556/44556), Namecoin (8334/18334), Dash (9999/19999), Bitcoin
Cash (8333), Zcash (8233/18233), Vertcoin (5889/15889), Peercoin (9901),
Feathercoin (9336/19336), Digibyte (12024), Groestlcoin (1331), Viacoin
(5223), and the Favilla regtest ports (28444/28443) — no collision. Both
ports are unassigned in the IANA registry. The task's excluded list
(8333/18333/18444/28332/28333/28443/28444) is avoided.

**Bech32 HRP `fvlt`** collides with no known HRP (`bc`, `tb`, `bcrt`,
`ltc`, `tltc`, …). **Base58 prefixes 36/97/98** collide with no known
single-byte version: Bitcoin mainnet 0/5/128, testnet 111/196/239; Litecoin
48/50/176; Dogecoin 30/22/158; Namecoin 52/13/180; Dash 76/16/204; and they
differ from the Favilla regtest values 35/95/96.

#### Consensus identity (both chains)

Eras (1M sats = 1 FVLA in Fire 0, doubling every 210,000 **Bitcoin** blocks —
D13c), the Vigil (CLTV `claim_height + 210,000`, plus the Bitcoin-time rule
of D13d), 144 Bitcoin confirmations judged against the block's committed
Bitcoin tip (D13b), the nullifier set, signature-gated
deterministic-recipient claims, feeless claims, and zero block subsidy are
**identical** on regtest and testnet. The furnace scriptPubKey keeps the
SAME hash160 (§3); only the human-readable address encoding changes with
the chain's HRP/prefixes.

## 3. The furnace

There is exactly one global furnace. Its scriptPubKey is a P2WPKH program:

```
FURNACE_HASH160 = RIPEMD160(SHA256("ex favilla furnace v1"))   (ASCII, no NUL)
FURNACE_SPK     = 0x0014 || FURNACE_HASH160                     (22 bytes)
```

**Nothing-up-my-sleeve argument.** To spend a P2WPKH output an attacker must
present a public key `P` with `HASH160(P) = FURNACE_HASH160` and a valid
signature under `P`. `FURNACE_HASH160` is the hash of a fixed public English
string, not of any public key. No private key was used in its derivation, so no
trapdoor exists; finding a key whose public key hashes to it requires a
second-preimage attack on HASH160 (~2^160 work), which is infeasible. The
derivation string is published here precisely so anyone can verify no key
material is hidden in it. (Decision: P2WPKH chosen over P2PKH/P2TR for
compactness and modern wallet support; the unspendability argument is identical
for any HASH160-based template.)

**Test vector (exact):**

```
derivation string : "ex favilla furnace v1"
FURNACE_HASH160   : e881fbbaf021322e69c396b9da2b554602d4fde9
FURNACE_SPK       : 0014e881fbbaf021322e69c396b9da2b554602d4fde9
regtest address   : fvla1qazqlhwhsyyezu6wrj6ua5264gcpdfl0ffnewuz   (HRP "fvla", witver 0)
testnet address   : fvlt1qazqlhwhsyyezu6wrj6ua5264gcpdfl0fqtwx7p   (HRP "fvlt", witver 0)
```

*Correction 2026-10-07:* earlier drafts gave the regtest address as
`fvlrt1qazqlhwhsyyezu6wrj6ua5264gcpdfl0f9t56ey`. That was wrong twice over:
the regtest code uses HRP `fvla` (not `fvlrt`, §2.1), and the bech32 checksum
did not even match the stated HRP. The addresses above are recomputed from
`FURNACE_HASH160` and verified.

Consensus matching rule (§7, check V4): a burn-tx output counts toward the
burned total **iff its scriptPubKey is byte-identical to `FURNACE_SPK`**.
Outputs wrapping the same hash in any other template (P2SH-P2WPKH, P2TR, …)
do NOT count — fail closed.

## 4. Genesis block (regtest)

Construction recipe (all values normative for the prototype regtest chain):

- Previous block hash: 32 zero bytes.
- Single transaction: coinbase, version 1, with:
  - 1 input: null prevout, index `0xFFFFFFFF`,
    `scriptSig = 0x00 || 0x0a || "ex favilla"` (OP_0 = BIP34 height 0,
    then push of the 10-byte message `ex favilla`), sequence `0xFFFFFFFF`.
  - 1 output: value 0, `scriptPubKey = 0x6a` (OP_RETURN). **No premine:
    the genesis coinbase creates zero spendable coins.**
  - nLockTime 0.
- `nTime = 1791288000` (2026-10-06 12:00:00 UTC, fixed constant).
- `nBits = 0x207fffff`, `nVersion = 1` (direct-mined, no AuxPoW bit).
- `nonce` ground by the builder until `SHA256D(header) <= target(0x207fffff)`.

**Reference test vector** (computed 2026-10-06; the builder MUST reproduce it
or document any deviation):

```
genesis coinbase hex:
01000000010000000000000000000000000000000000000000000000000000000000000000ffffffff0c000a657820666176696c6c61ffffffff010000000000000000016a00000000
genesis coinbase txid : 6f524b7e3e09da828b482b3c85148e050c7753f1b053f2bd6e92ae4282efba60
genesis merkle root  : 6f524b7e3e09da828b482b3c85148e050c7753f1b053f2bd6e92ae4282efba60
genesis nonce        : 2
genesis header hex   :
01000000000000000000000000000000000000000000000000000000000000000000000060baef8242ae926ebdf253b0f153770c058e14853c2b488b82da093e7e4b526fc0e2c46affff7f2002000000
genesis block hash   : 7cbe5b666f7c8702523033b0218dff488196c2818006ef3c216179ca0858e735
```

*Byte-order note:* like all block/tx hashes in this spec's test vectors, the
hashes above are given in **display order** (byte-reversed), matching the
`uint256{"…"}` asserts in `chainparams.cpp`. This contradicts §0's
internal-order convention — flagged for cleanup; until then, vectors rule.

### 4.1 Genesis block (testnet)

**D13 RESET 2026-10-11:** the pre-D13 testnet chain (6 blocks under the old
§4.1 vector) is abandoned — its blocks lack the §1.1 Bitcoin-tip commitment
and cannot continue under D13 rules. The test vector below replaces the
2026-10-07 vector in full; the old genesis (`000000e16afe7aa…`, message
`ex favilla testnet 2026-10-07`) is historical only.

Construction recipe: identical to §4, except:

- `scriptSig` message: `ex favilla testnet d13 2026-10-11` (33 bytes;
  `scriptSig = 0x00 || 0x21 || msg`).
- `nTime = 1791720000` (2026-10-11 12:00:00 UTC, fixed constant).
- `nBits = 0x1e00ffff` (= `powLimit`; §2.2).
- `nonce` ground by the builder until `SHA256D(header) <= target(0x1e00ffff)`.

**Reference test vector** (computed 2026-10-11; the builder MUST reproduce it
or document any deviation):

```
genesis coinbase hex:
01000000010000000000000000000000000000000000000000000000000000000000000000ffffffff230021657820666176696c6c6120746573746e65742064313320323032362d31302d3131ffffffff010000000000000000016a00000000
genesis coinbase txid : 7e56bc74c84f41212486a1daf6a40f110e13eeab3a11aabd180adb7e482ee939
genesis merkle root  : 7e56bc74c84f41212486a1daf6a40f110e13eeab3a11aabd180adb7e482ee939
genesis nonce        : 64029800
genesis header hex   :
01000000000000000000000000000000000000000000000000000000000000000000000039e92e487edb0a18bdaa113aabee130e110fa4f6daa1862421414fc874bc567e407acb6affff001e6804d103
genesis block hash   : 0000000f26cb4006e674f19fe9d71edd7f981cfcd384460c3259275029e7e744
```

## 5. Claim transaction format (new transaction version)

**Mechanism chosen: new transaction version (`nVersion = 4`).** Justification:
a claim is not a spend — it consumes no UTXOs, carries kilobytes of
cross-chain evidence, and must be fee-exempt by consensus. A distinct version
makes the fee exemption crisp (`version == 4` ⇒ no inputs to sum ⇒ no fee
rule), keeps evidence out of scriptSig/scriptPubKey hacks, and lets the txid
commit to the entire claim including the derived mint output. Rejected:
OP_RETURN-envelope (conflates data-carrying outputs with the mint output and
leaves fee semantics muddy); witness envelope (adds sighash/malleability
complexity for zero benefit — the claim authorizes via a standalone message
signature (§7 V5), not a transaction signature, since it has no spendable
inputs).

`FAVILLA_TX_VERSION_CLAIM = 4`. Serialization (in order, no witness data —
a version-4 transaction carrying witness marker/flag bytes is MALFORMED):

```
nVersion:            int32 LE = 4
vin:                 CompactSize = 1
  prevout_hash:      32 bytes = 0x00 * 32
  prevout_index:     uint32 LE = 0xFFFFFFFF
  scriptSig:         CompactSize = 0          (empty; input is never executed)
  nSequence:         uint32 LE = 0xFFFFFFFF
burn_txid:           32 bytes                 (Bitcoin internal byte order)
burn_header:         80 bytes                 (Bitcoin block header, wire format)
merkle_branch:       CompactSize n, 0 <= n <= 32 (MAX_MERKLE_BRANCH),
                     then n * 32-byte hashes (internal byte order)
merkle_index:        uint32 LE                (position of burn tx in block)
burn_tx:             CompactSize L, 1 <= L <= 400_000 (MAX_BURN_TX_SIZE),
                     then L bytes             (raw Bitcoin transaction)
claim_signature:     CompactSize S, S == 65, then 65 bytes
                     (compact recoverable ECDSA *message* signature, §7 V5)
nLockTime:           uint32 LE = 0
vout:                CompactSize = 1
  value:             int64 LE                 (minted cinis; MUST equal §9 formula)
  scriptPubKey:      CompactSize S, then S bytes = VIGIL_SCRIPT (see §11)
```

- `txid = SHA256D` of the above serialization. (`wtxid = txid`; version-4
  transactions have no witness.)
- The single marker input MUST NOT be executed as script and MUST NOT be
  interpreted as spending any UTXO. It exists so the transaction is
  well-formed under the common input/output machinery while being provably
  inputless.
- The claim names NO recipient. The mint recipient is determined
  deterministically by consensus from the burn (see §7 V4): the P2WPKH of the
  pubkey revealed in the burn transaction's first input. Anyone may submit a
  claim for any burn; redirection is impossible because the recipient is
  fixed.
- The claim DOES carry authorization material: `claim_signature`, a 65-byte
  compact recoverable ECDSA **message** signature made with the private key
  behind the burn's first input, over the standard Bitcoin Signed Message
  envelope of the payload `"FVLA-CLAIM" || network_magic || burn_txid`
  (see §7 V5). This is message authorization, not a transaction signature —
  the claim has no spendable inputs to sign for (hence no witness envelope:
  the signature commits to nothing sighash-like and cannot be malleated into
  a different economic meaning). The standard message format (not a custom
  digest) is what hardware wallets can sign; the wallet MUST NOT ingest raw
  private keys (D13e). Its purpose is to make burns from
  exchanges/custodians fail LOUDLY (unclaimable — the burner holds no key)
  instead of silently minting to the custodian's key.
- A version-4 transaction MUST NOT appear as the first transaction of a block
  (position 0 is the coinbase, which MUST be version 1 or 2). A block MUST
  contain exactly one coinbase.
- Rationale for **raw burn tx** over txid+vout evidence: one self-contained
  source of truth — the txid is recomputed from it (§7 V2), the furnace total
  is read directly from its outputs (§7 V4), and the mint recipient pubkey is
  extracted from its first input (§7 V4). No separate proof formats are needed.

## 6. SPV evidence: what the claim carries vs. what the node knows

**Decision: the claim carries ONLY the 80-byte burn block header plus the
Merkle branch. It does NOT carry the header chain to the tip.** (Closes brief
OPEN 01 for the prototype.)

Justification:

1. Every Favilla full node already maintains a fully-validated Bitcoin header
   chain for claim depth checks (§7 V3). Requiring each claim to
   re-transmit ~144+ headers (~11.5 KB minimum, unbounded in principle) is
   pure redundancy.
2. Depth is measured against the *block's committed Bitcoin tip* (D13a/D13b),
   not the node's live tip. A claimant-supplied chain would have to be
   re-validated (PoW + retargeting) anyway before it could be trusted, which
   is exactly what header sync does; and judging each block against its own
   commitment (rather than each node's possibly-diverged live tip) is what
   keeps nodes in consensus under ordinary header-propagation lag.
3. Fail-closed: if the node's header chain does not contain the claimed
   header, or the claimed header is at depth < 144 below the block's
   committed tip, the claim is invalid — no trust in the claimant is involved
   at any step. (If the *committed tip itself* is unknown to the node, the
   block is held as not-yet-validated, never marked invalid — D13b.)

Node requirement (normative): the node MUST maintain a Bitcoin header chain
in which every header's PoW is checked against its own `nBits` target and
every difficulty retarget follows Bitcoin consensus rules, tracking cumulative
work; the active chain is the most-work chain. Side branches MUST be retained
and MAY overtake the tip when they accumulate more work (reorg support);
header state MUST survive restarts (see §6.2). Header sync SHOULD use P2P
headers-first sync against the paired bitcoind; the exact transport is
implementation-defined. A node whose header chain is shorter than 144 blocks
MUST reject all claims (fail closed) until synced.

### 6.1 Parent-chain rules are selected by the Favilla chain type (audit H1)

The Bitcoin header chain's difficulty rules are parameterized, not hardcoded:

- **Favilla regtest → Bitcoin REGTEST rules**: `powLimit ≈ 2^256`
  (`0x207fffff`), `fPowNoRetargeting`, every header's `nBits` must equal its
  parent's `nBits` exactly. This is the regime the §16 adversarial vectors
  pin; regtest behavior is fixed.
- **Favilla testnet → genuine Bitcoin TESTNET4 rules**: `powLimit = 2^224 − 1`
  (`0x1d00ffff`), full 2016-block retargeting recomputed from the window's
  actual timespan (`CalculateNextWorkRequired` semantics), and the BIP94
  min-difficulty rule: a non-retarget header whose timestamp is more than
  2× the target spacing after its parent's MAY carry minimum-difficulty
  `nBits`; otherwise its `nBits` MUST equal the last non-min-difficulty
  block's `nBits` since the last retarget.

Rationale: the header chain previously validated every header against
regtest rules on all Favilla chains, so every genuine testnet4 header
failed validation and burn→claim was dead on arrival on the testnet.

**Testnet anchor rule (normative):** on Favilla testnet, the first header
submitted to an empty chain MUST be the genuine Bitcoin testnet4 genesis
(hash `00000000da84f2bafbbc53dee25a72ae507ff4914b867c565be350b0da8bf043`).
This anchors the chain to the real testnet4; a fabricated anchor cannot be
used to fake claim depth. (Regtest imposes no anchor: the operator's
simulated chain is the trust root by construction.)

### 6.2 Persistence (audit H2)

The header chain MUST be persisted to the node's datadir
(`favilla_btcheaders.dat`, all headers — active chain AND side branches — in
height order) and reloaded at startup BEFORE network processing begins. The
node SHOULD dump the chain eagerly on every accepted header (headers are
tiny; this is crash-safe without a shutdown hook). A restart MUST NOT lose
submitted headers: after a restart the node MUST report the same tip and
continue accepting headers.

### 6.3 Operator RPCs (normative)

- `submitbitcoinheader <80-byte header hex>` — validate and add one header.
  Idempotent; rejects with `bad-diffbits` / `high-hash` / `prev-unknown` /
  (testnet) `bad-anchor` as applicable.
- `getbitcoinheaderchaininfo` — `{headers, tip_height, tip_hash}`.
- `exportbitcoinheaders` — `{headers, blob}`: the whole chain (active +
  side branches) as a hex blob, same serialization as the datadir file.
- `importbitcoinheaders <blob>` — validate and add every header in an
  exported blob; stops at the first invalid header. Bootstrap path for new
  nodes (including the persistent seed node after a disk loss).
- `clearbitcoinheaders` — escape hatch (audit M1): clears the ENTIRE chain
  from memory AND disk. After a clear the chain MUST be rebuilt (fresh
  anchor); all claims fail closed until 144 headers are present again.

## 7. Claim validation: the four checks as consensus predicates

Let `T` be a version-4 transaction and `H >= 1` the height of the block it is
being validated for inclusion in. (Claims are not valid in the genesis block.)

### 7.1 Structural checks (MALFORMED if violated)

- M1. `T` deserializes exactly under the §5 grammar: `nVersion == 4`, no
  witness bytes, `nLockTime == 0`, exactly one input equal to the marker input
  (null prevout, index `0xFFFFFFFF`, empty scriptSig, sequence `0xFFFFFFFF`),
  exactly one output.
- M2. Field bounds: `len(merkle_branch) <= 32`; `1 <= len(burn_tx) <=
  400_000` (D13f: claims carry no witness, so every byte weighs 4 — a 1 MB
  burn would fill an entire 4M-weight block); `len(claim_signature) == 65`
  (compact recoverable ECDSA message signature; semantic validity — right
  key, right payload — is V5).
- M3. `burn_tx` deserializes as a well-formed Bitcoin transaction (version,
  inputs, outputs, locktime parse; output values non-negative int64).

### 7.2 Semantic checks, in normative order (INVALID if violated)

Let `burn_txid_claimed` be the `burn_txid` field and `B` the standard Bitcoin
txid of `burn_tx`: `SHA256D` of the **witness-stripped** serialization. (The
carried `burn_tx` INCLUDES witness data — V4 needs it for pubkey extraction
— so hashing the raw carried bytes would yield the wtxid, which is wrong.
Parse, strip, then hash.)

- **V1 — Nullifier (double-claim).** `burn_txid_claimed` MUST NOT already be
  present in the nullifier set (§8). (Checked first: cheapest, fail-fast.)
- **V2 — Inclusion.** `B` MUST equal `burn_txid_claimed`. Recompute the Merkle
  root: `cur = B`; for `i, h` in `enumerate(merkle_branch)`:
  `cur = SHA256D(h + cur)` if `(merkle_index >> i) & 1` else
  `SHA256D(cur + h)`. Require `merkle_index < 2^len(merkle_branch)` and
  `cur == burn_header.merkle_root`. (Empty branch is allowed: then the burn tx
  must be the block's sole transaction and `merkle_index` must be 0.)
- **V3 — Depth (144 confirmations), judged against the block's commitment
  (D13b).** Let `C` be the block's committed Bitcoin tip (§1.1) and
  `bh = SHA256D(burn_header)`. `C` MUST be present in the node's Bitcoin
  header index (headers in the index are PoW-valid by §6 construction); if
  `C` is UNKNOWN to the node, the block is not-yet-validated — held pending
  header arrival, never cached as invalid (see below). `bh` MUST lie in
  `C`'s ancestor chain, and with `hc = height(C)`, `hb = height(bh)`:
  `hc - hb >= 144` (`BURN_CONFIRMATIONS`). The node's live tip plays no
  role: two nodes with different live tips evaluate the same block
  identically, which is what kills the propagation-lag consensus split.
  **Validation-state rule:** a block whose committed tip is unknown is
  HELD (not validated, not relayed as valid, not marked invalid, no peer
  penalty — the analogue of Bitcoin's unknown-parent handling);
  implementation-defined holding bounds apply, and validation is re-attempted
  as headers arrive. A block whose committed tip is the zero hash and which
  contains any version-4 claim is INVALID (no tip to judge depth against).
- **V4 — Burn amount and mint recipient.** Parse `burn_tx`:
  - `burned_sats = Σ value(o)` over all outputs `o` with
    `o.scriptPubKey == FURNACE_SPK` byte-identical (§3). (Any OP_RETURN
    outputs in the burn are ignored; they carry no consensus meaning.)
  - The mint recipient is determined deterministically: extract the pubkey
    revealed in the burn transaction's **first input** (index 0) from its
    scriptSig/witness spending data. Accept: P2PKH (pubkey in scriptSig),
    P2WPKH (pubkey in witness), P2SH-P2WPKH (pubkey in witness), single-key
    P2WSH (pubkey in witness). If input 0 does not reveal a 33-byte
    compressed pubkey (e.g. Taproot key-path, or any pubkey-unrecoverable
    input): REJECT the claim as INVALID (`bad-claim-unrecoverable-pubkey`).
    This is a known prototype limitation; lifting it requires prevout
    inclusion proofs.
  - The mint output's pubkey is this extracted pubkey. No choice, no
    override — fully deterministic given the burn. (Anyone may submit the
    claim; a "frontrunner" can only mint to the burner's own key early.
    Double-mint is prevented by the V1 nullifier.)
- **V5 — Signature gate (claim authorization, standard message signature —
  D13e).** `claim_signature` MUST be a 65-byte compact recoverable ECDSA
  signature: `recid (1 byte, 0–3) || r (32 bytes big-endian) || s (32 bytes
  big-endian)`. It MUST verify as a standard **Bitcoin Signed Message**
  signature over the payload
  `P = "FVLA-CLAIM" || network_magic || burn_txid`, where `network_magic`
  is the 4-byte `pchMessageStart` of the Favilla network the claim is
  validated on (domain separation: a signature cannot be replayed across
  Favilla networks) and `burn_txid` is in internal byte order. The signed
  envelope is `"\x18Bitcoin Signed Message:\n" || CompactSize(len(P)) || P`
  (the payload is 46 bytes — 10 (`"FVLA-CLAIM"`) + 4 (network magic) + 32
  (burn txid) — so the length prefix encodes as `0x2e`); the
  signed digest is `SHA256D(envelope)`. Verification: recover the public key
  from (`recid`, `r`, `s`, digest) and require its 33-byte compressed
  encoding to equal the pubkey extracted in V4. Rationale: this is what
  makes burns from exchanges/custodians fail LOUDLY — the burner holds no
  key, so no valid claim can ever exist and nothing mints to the custodian's
  key — instead of silently enriching the custodian. Front-running is
  impossible twice over: the signature cannot be forged, and V4 leaves
  nothing to redirect. Note this is message authorization, not a Bitcoin
  transaction signature; no sighash semantics are involved.
  *Why the standard format (D13e):* the previous custom-digest scheme could
  not be produced by hardware wallets (Ledger/Trezor/Coldcard sign the
  message format, not raw digests), stranding hardware-wallet burners — and
  it pushed wallets toward ingesting raw private keys, a ready-made phishing
  template. The payload bytes are unchanged, so the domain separation and
  replay properties are unchanged. *Wallet interop note:* standard
  `signmessage` outputs `base64(header || r || s)` with
  `header = 27 + recid (+ 4 if compressed)`; wallets translate
  `header − 27 (− 4)` to the `recid` byte specified here.
- **V6 — Issuance.** Compute per §9 with the Fire determined by the burn's
  Bitcoin height (D13c): `fire = burn_btc_height // 210_000` where
  `burn_btc_height` is the height of `burn_header` (known: V3 placed it in
  the committed tip's ancestry),
  `heat = 1_000_000 * 2^fire` (128-bit),
  `cinis = (burned_sats * 100_000_000) // heat` (floor, 128-bit).
  Require `cinis > 0`, else INVALID. (No minimum burn: a small fire counts —
  decision D3, §14.) The mint rate is locked at burn time; Favilla's own
  height `H` plays no role in issuance (only in V7's unlock).
- **V7 — Mint output exactness.** `T.vout` MUST equal exactly one output with
  `value == cinis` and
  `scriptPubKey == VIGIL_SCRIPT(unlock = H + 210_000, pubkey =
  burn_input_0_pubkey)` as defined in §11, where `burn_input_0_pubkey` is the
  pubkey extracted in V4. The output is constructed by the claimant but
  **verified byte-for-byte** by consensus; nothing about the mint is trusted.

### 7.3 Notes

- The block's committed Bitcoin tip, resolved through the node's header
  chain, is the sole authority for V3. Favilla does NOT validate `burn_tx`
  inputs (no UTXO check, no signature check on the Bitcoin side): inclusion
  at depth ≥ 144 below the block's committed tip IS the validity argument
  for the burn (decision D11).
- Merkle-tree mutation (CVE-2012-2459-style duplicate-txid) was considered:
  exploiting it would require a 144-deep Bitcoin block containing duplicate
  txids AND a raw burn tx with the duplicated txid, furnace outputs, and the
  recipient binding — while the nullifier (§8) is keyed by txid alone and
  blocks any second mint regardless. The standard verification algorithm above
  is therefore sufficient; no extra canonical-ness checks are imposed
  (decision D12).
- A claim whose burn is at depth < 144 below the block's committed tip is
  INVALID *now* (not malformed): it may become valid later under a deeper
  commitment. Wallets SHOULD submit at depth ≥ 144; mempools MUST
  NOT hold not-yet-valid claims (see §10).
- **No activation rule for burns:** consensus does not restrict when the burn
  occurred relative to Favilla genesis. Any burn to the furnace with a valid
  binding and ≥144 depth is claimable, even pre-genesis (decision D8, §14).
  The 21,000-block genesis window is social, not consensus.
- **Height-specificity:** V7 ties the mint output to the inclusion height `H`.
  A claim transaction is therefore valid for exactly one Favilla height. (D4.)

### 7.4 Intra-block rules

- Transactions in a block are processed in order. A second claim for the same
  `burn_txid` in one block fails V1 ⇒ the whole block is INVALID.
- Version-4 transactions pay no fee and are exempt from the
  `fee >= 0` / `inputs >= outputs` rules that apply to versions 1–2
  (they have no inputs; see §10).

### 7.5 Block validity consequence

A block containing a malformed OR invalid version-4 transaction is itself
INVALID and MUST be rejected. There is no "provisional" or "deferred"
acceptance of claims. (The D13b "not-yet-validated" state is a property of
*blocks* whose committed Bitcoin tip is unknown to the node — not of claims
— and it never upgrades to acceptance without full validation.)

## 8. Nullifier set

- **Canonical identifier: the burn txid** (`burn_txid`, 32 bytes, internal byte
  order) — confirmed as specified. Rationale: it is the unique, immutable,
  collision-resistant identity of the burn; keying by txid alone (not
  txid+blockhash) means a burn reorged out of Bitcoin and re-mined under the
  same txid still cannot mint twice, and a claimed burn can never be re-claimed
  under a different header (decision D6).
- **Storage model:** in-memory hash set/dictionary, flushed to disk, modeled
  on the coins DB (separate LevelDB table/column family `nullifiers`).
  Key: 32-byte burn txid. Value: claiming Favilla height (uint32 LE) ||
  transaction index within that block (uint32 LE) — retained for auditability.
- **Lookup/insert semantics:** V1 lookup is O(1) during validation. On block
  connection, after all of the block's transactions validate, the block's new
  nullifiers are inserted **atomically in the same batch** as the UTXO updates.
- **Rollback:** each block's undo data records the list of nullifier keys the
  block added. On disconnect, blocks are processed in reverse height order;
  for each, its UTXO changes are undone AND its nullifier keys are deleted.
  **Invariant:** after any connect/disconnect sequence, the nullifier set
  equals exactly the set of burn txids claimed by version-4 transactions in
  the active chain.
- **Growth:** never pruned in v1. Bound: ≤ 32 bytes (+ small overhead) per
  claim ever made; e.g. one million claims ≈ 32 MB plus index overhead —
  acceptable for the prototype era. Pruning policy is an open question (O3,
  §15).

## 9. Era rate rule and the cinis formula

- `FIRE_BLOCKS = 210_000` (Bitcoin blocks). `fire(B) = B // 210_000`
  (integer floor division), where `B` is the burn's Bitcoin block height.
  Fire 0 = Bitcoin blocks 0–209,999; Fire 1 = 210,000–419,999; etc.
  *Semantic change (D13c):* the era was previously determined by the
  claim's Favilla inclusion height; it is now determined by the burn's
  Bitcoin height, so the mint rate is locked at burn time and Favilla
  miners cannot game era boundaries (this also eliminates the Fire-boundary
  inclusion rush — Reviewer B's M1 — since claim timing no longer affects
  the rate). Note: because eras are measured in Bitcoin blocks, the Fire
  active at Favilla's launch is whatever Fire Bitcoin's current height is
  in — there is no "Fire 0 burns" period on Favilla unless Bitcoin is still
  in Fire 0.
- `heat(fire) = 1_000_000 * 2^fire` sats per FVLA, computed in **unsigned
  __int128** (at large `fire` this exceeds 64 bits; no saturation — the
  formula handles it).
- `CINIS_PER_FVLA = 100_000_000`.
- `cinis(burned_sats, B) = floor(burned_sats * 100_000_000 / heat(fire(B)))`,
  numerator computed in unsigned __int128, floor division, integer-only.
  `burned_sats` is a uint64 (Bitcoin money range).
- The claim is INVALID if `cinis == 0` (§7 V6). There is no other minimum:
  in Fire 0, 1 sat ⇒ 100 cinis.
- Worked examples: Fire 0, burn 1,000,000 sats ⇒ 100,000,000 cinis = 1 FVLA.
  Fire 3 (heat 8,000,000), burn 1,000,000 sats ⇒
  floor(10^6 × 10^8 / 8×10^6) = 12,500,000 cinis = 0.125 FVLA.
- Theoretical supply ceiling: 21M BTC × 100 cinis/sat (best rate) =
  2.1×10^17 cinis = 2.1B FVLA < int64 max. No explicit supply cap is needed in
  consensus; money-range checks use int64.
- **The rate is determined by the burn's Bitcoin block height** — locked at
  burn time — not by claim-inclusion time, submission time, or mempool
  arrival (D13c).

## 10. Feeless claims: consensus rule and mempool policy

- **Consensus:** version-4 transactions are exempt from all fee rules. They
  consume no UTXOs, so `fee = inputs − outputs` is not computed for them;
  a zero-fee claim is consensus-valid. Miners MAY include any valid claim;
  consensus does not rank or require them.
- **Mempool policy (NOT consensus — node operators MAY tune, miners decide):**
  - Accept version-4 transactions with fee 0 into the mempool (policy MUST
    NOT impose a minimum fee on them).
  - Validate V7's unlock against the *assumed next height* `H = tip + 1`;
    validate the mint value per §9/V6 (height-independent since D13c — the
    rate is fixed by the burn). For the V3 depth pre-check, assume the
    block's commitment will be the node's current active Bitcoin tip
    (miners SHOULD commit to their freshest tip; the pre-check is advisory —
    final validity is judged against the block's actual commitment at
    block-validation time).
  - **Evict all mempool claims when the chain tip advances**, because V7's
    exact `unlock = H + 210_000` makes each claim valid for exactly one
    height (D4). Wallets SHOULD re-issue a claim (recomputing the mint
    output for the new height — no re-signing needed, since the V5 signed
    payload covers only network magic and burn txid, not height) after each
    tip change until it confirms.
  - Deduplicate by `burn_txid`: at most one mempool claim per burn txid.
  - Do NOT admit claims that are currently invalid (e.g. depth < 144 below
    the current Bitcoin tip); wallets resubmit when the burn matures.
  - RECOMMENDED anti-spam posture (feeless ⇒ spam-attractive): per-peer rate
    limits on version-4 relay, a bounded claim-mempool allocation (suggested:
    50 MB / 50,000 txs, evict oldest-first — no fee to compare), and a
    `MAX_BURN_TX_SIZE` (400,000 bytes) cap already enforced at consensus
    (M2, D13f). Claim validation is CPU-cheap (one header lookup, ≤32
    hashes, one tx parse, one signature recovery).
  - Miners are free to include or ignore valid claims; no consensus rule
    compels inclusion.

## 11. The Vigil

Every version-4 mint output uses one fixed script template with absolute
`OP_CHECKLOCKTIMEVERIFY`:

```
VIGIL_SCRIPT(unlock, pubkey) =
    PUSH(CScriptNum(unlock)) || 0xb1 || 0x75 || PUSH33(pubkey) || 0xac
  = <unlock_height> OP_CHECKLOCKTIMEVERIFY OP_DROP <recipient_pubkey> OP_CHECKSIG
```

- `unlock = H + 210_000` (`VIGIL_BLOCKS`), where `H` is the claim's inclusion
  height. Block-height type only (`unlock < 500_000_000` always); time-based
  locks are not used.
- `CScriptNum(unlock)` is Bitcoin's minimal script-number encoding with its
  length prefix (e.g. unlock `210001` = `0x033451` → push bytes `03 513403`).
- The mint output's scriptPubKey is this **bare script** (not P2SH/P2WSH).
  Bare CLTV scripts are consensus-valid; Favilla relay policy defines
  version-4 mint outputs as standard. (Decisions D2 — recipient is a pubkey,
  not an arbitrary script — and D9.)
- **Test vector:** claim included at Favilla height 1 (`unlock = 210001`),
  recipient pubkey
  `0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798`
  (the secp256k1 generator point, compressed) ⇒ mint scriptPubKey:
  `03513403b175210279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798ac`

**Spend-validation rule (consensus, per BIP 65 as inherited):** a transaction
spending a Vigil output is valid only if, when its input script executes
against the mint output's scriptPubKey:

- scriptSig pushes exactly one signature: `<sig>` (legacy, non-segwit
  sighash over the spending transaction with scriptCode = the Vigil
  scriptPubKey);
- the spending transaction has `nLockTime >= unlock` with matching lock type
  (both block-height, both < 500_000_000);
- **the spending input's `nSequence != 0xFFFFFFFF`** (else CLTV fails per
  BIP 65 — recommended value: 0);
- `<sig>` verifies against `recipient_pubkey` under `OP_CHECKSIG`.

Until Favilla height reaches `unlock`, the output is unspendable by consensus.
After the Vigil, the owner spends the locked UTXO into ordinary outputs; the
native UTXO ledger handles splits and transfers with no further constraints.
(Note: a Vigil output is consumed whole like any UTXO; "partial spends" are
change outputs of the spending transaction.)

**Threat-model note (P0 lock bypass):** the template is fixed — consensus
accepts NO other script shape as a version-4 mint output (V7 byte-equality),
so there is no alternative script path that could omit the CLTV. The unlock
value is committed in the output itself and re-derived from the inclusion
height at validation.

### 11.1 Bitcoin-time Vigil enforcement (D13d)

The CLTV script above locks the mint for 210,000 *Favilla* blocks — but a
sole Favilla miner (the founder, at launch) can produce Favilla blocks far
faster than one per 10 minutes: the chain starts at minimum difficulty and
Bitcoin's retarget can be timewarped, compressing the "four-year" Vigil to
days of wall-clock time. Belt-and-suspenders: spends are additionally gated
on *Bitcoin* time, which no Favilla miner can fast-forward.

- **Rule:** a transaction spending a Vigil-locked mint output is INVALID
  unless the *spending block's* committed Bitcoin tip `C'` satisfies
  `MTP(C') >= burn_mtp + 126_000_000`, where `burn_mtp` is the
  median-time-past of the burn's Bitcoin header (as recorded in the
  version-4 claim that created the spent output) and `126_000_000 =
  210_000 × 600` seconds (≈ 3.99 years).
- `MTP(h)` is Bitcoin's median-time-past: the median of the `nTime` fields
  of the 11 headers ending at `h` (headers `h−10 … h`); requires
  `height(h) >= 10`. It is computed over the node's Bitcoin header chain;
  for headers at depth ≥ 144 all tracked chains agree on the value (a deeper
  disagreement would itself be a >144-block Bitcoin reorg — the accepted
  P1 impossibility of §13.2).
- "Vigil-locked mint output" for this rule means any UTXO whose
  scriptPubKey matches the §11 template shape (push of a script number,
  `OP_CHECKLOCKTIMEVERIFY`, `OP_DROP`, push of 33 bytes, `OP_CHECKSIG`).
- Both locks must hold: the CLTV script (§11, Favilla height) AND this
  Bitcoin-time rule. A spending block that commits the zero hash (D13a) can
  never satisfy this rule — Vigil spends require a real Bitcoin commitment.
- *Rejected weaker alternative:* an MTP-lock on Favilla's *own* chain. A
  sole miner advances Favilla MTP up to ~2 hours per 11 blocks (each block's
  timestamp may sit up to 2h ahead of network time), so a Favilla-MTP Vigil
  is compressible to weeks. Bitcoin's MTP is secured by Bitcoin's hashpower.

## 12. AuxPoW block validation — DEFERRED TO MAINNET PHASE

**DEFERRED 2026-10-06 by Matthew (simplicity reassessment).** Merged mining
is the largest consensus code surface in the design and is orthogonal to
everything novel about Favilla (burns, claims, the Vigil, eras — none care
how blocks are produced). The prototype builds and validates **plain
proof-of-work only**; the AuxPoW port (`src/favilla/deferred/auxpow.{h,cpp}`)
is preserved untouched for the mainnet phase, along with the SPEC-vs-Namecoin
B1–B7 diff in `~/workspace/favilla/STATUS.md`. Phase 0 decision #1 now reads:
**"merged mining at mainnet; prototype plain PoW."**

The normative AuxPoW validation rules below are retained for the mainnet
phase. They are NOT implemented or enforced by the prototype: prototype
blocks use direct PoW exclusively, and a prototype block carrying an AuxPoW
payload is not parseable (the payload is not part of the prototype wire
format).

Reference implementation: Namecoin's AuxPoW (format and algorithms), with the
deviations stated below. This section closes the P0 "invalid AuxPoW accepted"
threat at the spec level.

- Block wire format: 80-byte header; if `nVersion & 0x100`, followed by the
  AuxPoW payload:
  ```
  parent_coinbase_tx:     CompactSize L, then L bytes (full parent coinbase tx)
  parent_coinbase_branch: CompactSize n (<= 32), n * 32-byte hashes,
                          then parent_coinbase_index uint32 LE
  chain_branch:           CompactSize m (<= 32), m * 32-byte hashes
  chain_index:            int32 LE  (MUST equal FAVILLA_AUXPOW_CHAIN_ID = 0xFA17)
  parent_header:          80 bytes  (Bitcoin block header, wire format)
  ```
- `CheckAuxPow` (normative):
  1. Payload deserializes within bounds (`parent_coinbase_tx <= 1_000_000`
     bytes, branches ≤ 32 entries).
  2. `aux_hash = SHA256D(80-byte Favilla header)`.
  3. Recompute the chain merkle root from `(aux_hash, chain_branch,
     chain_index)` with the same left/right algorithm as §7 V2; call it
     `chain_root`.
  4. `cb_txid = SHA256D(parent_coinbase_tx)`; verify its Merkle branch
     against `parent_header.merkle_root` with `parent_coinbase_index`
     (same algorithm).
  5. The parent coinbase's **first input's scriptSig MUST contain** the
     4-byte merged-mining magic `0xFABE6D6D` immediately followed by the
     32-byte `chain_root`. (Trailing size/nonce fields of the merged-mining
     header are NOT consensus-checked in v1 — decision D7.)
  6. Parent PoW: `SHA256D(parent_header) <= favilla_target(header.nBits)`.
     The parent header's own `nBits` is NOT used for this comparison.
  7. `SHA256D(parent_header)` MUST be present in the node's **active**
     Bitcoin header chain (any depth ≥ 0). Checked at block-validation time
     only.
  8. Favilla `nBits` follows the retarget rules (§1); on regtest it is fixed
     `0x207fffff`.
- Direct-mined blocks (`nVersion & 0x100 == 0`): `SHA256D(80-byte header) <=
  favilla_target(header.nBits)`.
- Exactly one proof mode per block; a block MUST NOT mix direct PoW with an
  AuxPoW payload.
- **Parent-reorg posture:** parent-chain membership (step 7) is evaluated at
  validation time only. A later Bitcoin reorg does NOT retroactively invalidate
  an accepted Favilla block — the work was real when checked (decision D7,
  flagged in §14).

## 13. Reorg behavior

### 13.1 Favilla-side reorgs

- Disconnect/connect follows the standard UTXO model: each block's undo data
  records spent-coin restorations AND the list of nullifier keys the block
  added (§8). Disconnecting a block in reverse order restores coins and
  deletes that block's nullifier keys, preserving the §8 invariant.
- Disconnected version-4 transactions are **dropped, not re-queued**: their
  mint output commits to the old inclusion height (§7 V7, `unlock =
  H + 210_000`) and cannot validate at the new height. The burn's nullifier
  entry is removed on disconnect, so the burn is claimable again; the wallet
  SHOULD re-issue a fresh claim for the new tip+1 height. (The mint *value*
  no longer changes on re-issue — D13c fixed the rate at burn time; only the
  unlock height moves.)
- Two competing claims for the same burn on rival forks resolve by fork
  choice: the winning fork's claim stands; the loser's claim becomes
  invalid (V1 nullifier) once the winner's block is in the active chain.

### 13.2 Bitcoin-side reorgs and the 144-block assumption

- The node follows the most-work Bitcoin header chain for its *own* view,
  but claims are validated against each block's **committed** Bitcoin tip
  (§7 V3, D13b) — not the live tip. Two nodes with different live tips
  evaluate the same Favilla block identically.
- If a Bitcoin reorg shallower than 144 blocks removes a burn block *before*
  any claim is included: the burn header is no longer in any new commitment's
  ancestry at depth ≥ 144, so claims referencing it become INVALID. If the
  burn tx re-confirms in the new chain, it becomes claimable again once it
  re-reaches depth 144 below some block's committed tip (the claim then
  carries the new header; the txid — and hence the nullifier key — is
  unchanged).
- If the node wedges on an orphaned Bitcoin tip (e.g. a deep testnet4 reorg
  leaves a stale tip as the most-work chain it has seen), the operator
  escape hatch is `clearbitcoinheaders` (§6.3): it wipes the chain from
  memory and disk, after which a fresh anchor is submitted (testnet: the
  genuine testnet4 genesis) and the chain is rebuilt.
- **Accepted residual risk (threat model P1, explicit):** if a Bitcoin
  reorganization **deeper than 144 blocks** orphans a burn block *after* a
  claim against it has been included in Favilla, the minted FVLA is NOT rolled
  back. Rollback is impossible — FVLA is a bearer asset; the Vigil-locked
  UTXO cannot be clawed back by consensus. The design accepts this because
  triggering it requires redoing ~24 hours of global Bitcoin proof of work,
  which is the entire point of the flat 144-confirmation rule (decision log,
  2026-10-06). The 144-block floor is the mitigation; there is no second
  layer. **Bound (independent review, 2026-10-07):** the "infeasible" in the
  previous sentence is economic, not physical — a 144-block Bitcoin reorg
  costs on the order of nine figures, so the flat rule protects burns worth
  well below that; larger burns are attackable in principle. Scaled
  confirmation depth is a mainnet hardening item. This assumption MUST be
  restated in user-facing documentation:
  **a burn deeper than 144 Bitcoin confirmations below the block's committed
  tip is treated as irreversible by Favilla consensus, unconditionally.**

## 14. Decisions requiring review

Judgment calls where the brief was silent or ambiguous. Each lists the choice
made, why it is the safe (fail-closed) option, and the rejected alternative.
**These need Matthew's (or a reviewer's) explicit sign-off before the spec
freezes.**

- **D1 — Claim authorization: FINAL 2026-10-06 — deterministic recipient +
  signature gate (decided by Matthew; criterion throughout: "easiest path
  for the person making the offering").** History:
  1. *Proposed:* OP_RETURN recipient binding — burn tx must contain exactly
     one `FVLA`-tagged OP_RETURN committing to the claim's `recipient_pubkey`.
     *Rejected 2026-10-06:* forced burns to use Favilla-aware software,
     excluding ordinary Bitcoin wallets.
  2. *Proposed:* signature authorization — claim carries a signature over
     `SHA256("FVLA-CLAIM" || magic || burn_txid || vigil_script)` made with a
     burn-input key, authorizing a *chosen* recipient. *Superseded
     2026-10-06:* unnecessary complexity; front-running protection is
     achieved more simply.
  3. *Adopted then superseded:* pure deterministic recipient — claims name NO
     recipient and carry NO authorization material; consensus derives the
     mint pubkey from the burn's first input. *Superseded 2026-10-06:*
     Matthew flagged the exchange footgun — a burn sent from an
     exchange/custodian wallet would silently mint the FVLA to the
     custodian's key, with nothing telling the burner what happened.
  4. *FINAL:* deterministic recipient (§7 V4) **+ signature gate (§7 V5)**.
     The claim names no recipient — consensus mints to the P2WPKH of the
     pubkey revealed in the burn's input 0 — but the claim MUST include a
     DER-encoded ECDSA signature made with the input-0 private key over
     `SHA256("FVLA-CLAIM" || network_magic || burn_txid)`. Front-running is
     impossible twice over (the signature cannot be forged; the fixed
     recipient leaves nothing to redirect). Burns from exchanges/custodians
     now fail LOUDLY: the burner holds no key, so no valid claim can exist
     and nothing mints anywhere — instead of silently enriching the
     custodian. The burn itself stays a plain Bitcoin payment from any
     wallet; only the claim needs Favilla software (to build the §5
     serialization and sign).
  *Prototype restriction:* input 0 must reveal its pubkey (P2PKH, P2WPKH,
  P2SH-P2WPKH, single-key P2WSH); Taproot key-path burns are unclaimable
  (documented limitation; lifting requires prevout inclusion proofs).
  *Usage guidance (not consensus):* burn from single-key self-custody;
  recommended ritual is a fresh single-use Bitcoin address per offering,
  since the mint address is cryptographically linkable to the burn key.
  *Superseded 2026-10-07 by D13e:* the authorization is no longer a custom
  digest DER signature — it is a standard Bitcoin Signed Message signature
  (65-byte compact, recoverable) over the same payload bytes
  `"FVLA-CLAIM" || network_magic || burn_txid`. Rationale: hardware wallets
  sign the message format but not raw custom digests, and wallets must never
  ingest raw private keys (a ready-made phishing template).
- **D2 — Recipient is a 33-byte compressed pubkey, not an arbitrary
  scriptPubKey.** *Why:* the fixed Vigil template (§11) can only wrap a
  pubkey safely; embedding arbitrary (esp. segwit) scripts inside a bare
  CLTV script does not preserve their semantics. The brief's own mint sketch
  shows `<recipient_pubkey>`. *Rejected:* arbitrary recipient scripts
  (would need P2WSH indirection with subtle semantics).
- **D3 — No minimum burn.** `burned_sats >= 1` only; dust mints per the
  formula. *Why:* the brief is explicit — "A small fire counts; the exchange
  rate does the scaling." The task text's check (3) ("burn outputs … ≥ the
  era's required sats") is read as "the burned total is what the formula
  prices," not as a minimum-ticket rule. *Rejected:* minimum ticket of
  `heat` sats per claim.
- **D4 — Claims are height-specific.** The mint output commits to
  `unlock = H + 210_000`, so a claim is valid for exactly one Favilla height;
  mempools evict claims on tip advance (§10). *Why:* keeps the tx
  self-contained (txid commits to the mint) instead of letting consensus
  mutate outputs at inclusion. *Rejected:* consensus-derived outputs.
- **D5 — Block subsidy is 0 forever; miners earn fees only.** *Why:* the
  brief mandates issuance ONLY from burns ("No premine… Minted only from
  confirmed BTC burns"). Any subsidy would be a second issuance mechanism.
  *Consequence:* long-run miner incentives are an open economic question
  (O5), fine for the prototype.
- **D6 — Nullifier keyed by burn txid alone** (not txid+blockhash). *Why:*
  prevents double-mint even if a burn is reorged out and re-mined; simplest
  key with the strongest uniqueness property. *Consequence:* a burn reorged
  out pre-claim and re-confirmed keeps its claimability (nullifier only set
  on claim) — correct behavior.
- **D7 — AuxPoW strictness choices.** Chain ID `0xFA17`, version bit `0x100`,
  parent header must be on the active parent chain *at validation time only*
  (no retroactive invalidation on later parent reorgs), merge-mining
  commitment checks magic+root only (size/nonce not checked). *Why:* each is
  the minimal check that closes its attack (fake work, wrong chain slot,
  fabricated parent) without over-constraining merged miners. The
  no-retroactive-invalidation rule mirrors how PoW finality works elsewhere
  but is a genuine posture choice — reviewers should confirm.
- **D8 — No consensus activation rule for burns.** Any burn to the furnace
  with a valid binding and ≥144 depth is claimable, even if the burn predates
  Favilla genesis. The 21,000-block genesis window is social, not consensus.
  *Why:* a pre-genesis burn is still a real, public, fairly-priced burn; no
  consensus mechanism distinguishes "early" from "late" without adding
  trusted timestamps. *Rejected:* burn-timestamp ≥ genesis-time rule
  (would need Bitcoin timestamps in consensus — weaker, not stronger).
  *Launch procedure — founder burns first (decided 2026-10-07; tightened
  2026-10-07):* no consensus change is needed to make the founder's
  sacrifice genuinely first. The founder broadcasts the founding burn to
  the furnace BEFORE the *specification* is published. (The furnace hash160
  is necessarily public in the spec — §3 — since nodes need it for V4; what
  makes the founder first is broadcasting the founding burn before the spec,
  and thus the furnace, is public. "Before the furnace address is published"
  would be theater — the address is computable from the published hash160.)
  Operational order: burn → wait for Bitcoin confirmation → publish the
  specification. Firstness is then a verifiable fact of Bitcoin's public
  record, not a promise. The signature gate (V5) is what makes this safe:
  nobody can file a valid claim on the founder's burn without the founder's
  key, and the deterministic recipient (D1 FINAL) means a copied claim would
  still mint to the founder. The covenant SHOULD record the founding burn
  txid at genesis so anyone can verify it is the earliest furnace output.
- **D9 — Mint outputs are bare scripts; spends use legacy sighash.**
  *Why:* simplest construction that keeps the CLTV semantics exact and the
  output human-auditable. *Rejected:* P2WSH-wrapped Vigil (indirection with
  no security gain in v1).
- **D10 — Chain parameters: PARTIALLY CLOSED 2026-10-06/07.** The regtest
  values were placeholders; the **testnet** values (§2.2) are now chosen with
  the full collision analysis documented in §2.2 (magic `66766c74` vs
  Bitcoin/Litecoin/Dogecoin/Namecoin magics; ports 34444/34443 vs well-known
  P2P ports; HRP `fvlt`; prefixes 36/97/98). **Mainnet parameters are still
  fully open** and MUST be re-chosen with fresh collision analysis — nothing
  in §2 may be reused verbatim for mainnet. The furnace derivation string
  and 144-block rule are NOT placeholders. (Known wart: regtest occupies HRP
  `fvla`, which was reserved for mainnet — mainnet needs a fresh HRP
  review.)
- **D11 — Burn-tx inputs are not validated.** Inclusion at depth ≥144 below
  the block's committed Bitcoin tip (D13b) is the entire validity argument
  for the burn's inputs.
  *Why:* re-validating Bitcoin history is redundant; the depth rule is the
  security. A burn tx that Bitcoin itself accepted 144+ blocks ago needs no
  second opinion.
- **D12 — No extra Merkle-malleability checks.** Standard branch verification
  + 144 confirmations + txid-keyed nullifier closes the practical attack
  (§7.3). *Why:* extra canonical-ness rules add consensus surface for no
  reachable exploit.
- **D13 — Bitcoin-anchored claims (decided 2026-10-07 by Matthew: "go with
  best choices, as long as the idea works").** Three independent-review
  findings drove one coherent change: anchor Favilla validation to
  *Bitcoin's* chain, which no Favilla miner can fast-forward or fork at
  will. (1) V3 judged depth against each node's *live* Bitcoin tip, so
  ordinary header-propagation lag could split consensus — node A at +144
  accepts a claim block that node B at +143 marks invalid, with no clean
  un-fail. (2) The Vigil and Fire were counted in Favilla blocks under
  Bitcoin's retarget, so a sole miner (the founder, at launch) could
  compress the "four-year" Vigil to days of wall-clock time — directly
  contradicting "the founder's coins sleep exactly as long as yours."
  (3) V5's custom digest stranded hardware wallets and pushed wallets
  toward ingesting raw private keys (a phishing template).
  - **D13a — Block commits to its Bitcoin validation tip.** Every block at
    height ≥ 1 carries the 32-byte hash of the Bitcoin block the miner used
    as its claim-validation tip in its coinbase (`OP_RETURN` pushing exactly
    32 bytes — §1.1), covered by the coinbase → Merkle root so miners cannot
    equivocate. Zero hash permitted (means "no tip"; invalid with claims);
    genesis exempt (fixed test vector).
  - **D13b — V3 judged against the commitment.** `depth =
    committed_tip_height − burn_block_height ≥ 144`, both from the node's
    header chain as referenced by the block's commitment. Unknown committed
    header ⇒ block held as not-yet-validated (never cached as invalid) —
    the analogue of Bitcoin's unknown-parent handling. *Why:* kills the
    propagation-lag consensus split; every node evaluates a given block
    identically.
  - **D13c — Fire era by the burn's Bitcoin height.**
    `fire = burn_btc_block_height // 210_000`; the mint rate is locked at
    burn time. *Why:* ungameable by Favilla miners, and it eliminates the
    Fire-boundary inclusion rush (Reviewer B's M1) — claim timing no longer
    affects the rate. Note: eras are now measured in Bitcoin blocks, so the
    Fire active at Favilla's launch is whatever Fire Bitcoin is in.
  - **D13d — Vigil additionally enforced in Bitcoin time.** The bare CLTV
    script on Favilla height is kept exactly (D9 — human-auditable,
    belt-and-suspenders). New rule: a Vigil spend is INVALID unless the
    spending block's committed Bitcoin tip has median-time-past ≥
    `burn_block_mtp + 126_000_000` s (≈ 3.99 years). *Why:* a sole Favilla
    miner fast-forwards Favilla height; they cannot fast-forward Bitcoin's
    chain. *Rejected weaker alternative:* MTP-lock on Favilla's own chain —
    a sole miner advances that ~2h per 11 blocks.
  - **D13e — V5 becomes a standard Bitcoin message signature.** Payload
    bytes unchanged (`"FVLA-CLAIM" || network_magic || burn_txid`); the
    signature is now `SHA256D("\x18Bitcoin Signed Message:\n" ||
    CompactSize(len) || payload)` in 65-byte compact recoverable form, with
    the recovered key required to equal burn input-0's key. *Why:*
    hardware-wallet compatibility; wallets must never ingest raw private
    keys.
  - **D13f — Burn-tx cap lowered to 400,000 bytes.** Claims carry no
    witness, so every byte weighs 4 — a 1 MB burn would fill an entire 4M
    weight-unit block. 400 KB covers every standard Bitcoin transaction.
  *Rejected alternative — the indexer model:* derive the ledger
  deterministically from Bitcoin (Runes/Ordinals-style), with no Favilla
  chain until the first unlock; burns mint automatically, no claims, no
  claim miners. *Rejected 2026-10-07:* it sacrifices the signature gate's
  loudness — with no claim step there is no moment of failure, so exchange
  burns would mint silently to the custodian's key, the exact harm D1's
  FINAL rule was built to prevent; it replaces technical consensus with
  social consensus at the highest-stakes moment (who declares the genesis
  cutoff height?); and it strands the live chain. Disclosed altruism
  (whitepaper §VI "Who mines the fire") chosen instead.

## 15. Open questions

Genuine ambiguities the author could not resolve safely within the brief.
These are NOT decided above; they need answers before spec freeze or are
explicitly deferred.

- **O1 — Mainnet chain parameters: STILL OPEN. Testnet: RESOLVED
  2026-10-07.** Testnet magic bytes, P2P/RPC ports, address HRP and
  prefixes, and the testnet genesis block are chosen and collision-checked
  (§2.2, §4.1). For mainnet, all of the above PLUS AuxPoW chain-ID
  uniqueness versus other merged-mined chains remain deferred by design.
  Nothing in §2 may be reused verbatim for mainnet without fresh collision
  analysis.
- **O2 — Production AuxPoW parent-confirmation policy.** The prototype
  accepts any parent header on the active chain at validation time. Should
  production require the parent block to have ≥N confirmations to blunt
  parent-chain reorg churn on young Favilla tips? (Namecoin requires none;
  the tradeoff is reorg frequency vs. miner flexibility.)
- **O3 — Nullifier-set pruning.** v1 never prunes (bounded, §8). If Favilla
  ever processes tens of millions of claims, a commitment-based pruning
  scheme (e.g. RSA/Verkle accumulator, or checkpointed snapshots with social
  consensus) will be needed. No design is proposed here.
- **O4 — Burns without Favilla-aware software: RESOLVED 2026-10-06.**
  D1's final rule is deterministic recipient (§7 V4) plus a signature gate
  (§7 V5). Burns are plain Bitcoin payments to the furnace from ANY wallet —
  no OP_RETURN, no special burn software. Only the *claim* needs Favilla
  software (to construct the §5 serialization with the SPV proof and to sign
  the authorization message with the burn key). The signature gate exists so
  that a burn from an exchange/custodian — whose key the burner does not
  hold — fails LOUDLY (no valid claim can exist) instead of silently minting
  to the custodian's key.
- **O5 — Fee-only mining economics.** With zero subsidy (D5), long-run
  security depends on merge-mining being near-free for Bitcoin miners plus
  whatever fee market develops. This is out of consensus scope but must be
  addressed before any mainnet conversation.

## 16. Adversarial test checklist (for S4/S5)

Each vector MUST be classified identically (accept/reject + malformed vs
invalid) by two independent implementations before the design is considered
ready for code:

1. Valid claim at exactly 144 Bitcoin confirmations below the block's
   committed tip → ACCEPT.
2. Valid claim at 143 confirmations below the committed tip → REJECT
   (invalid, not malformed).
3. Merkle branch with one flipped byte → REJECT (invalid, V2).
4. `burn_header` not in the committed tip's ancestry (e.g. a stale Bitcoin
   fork) → REJECT (invalid, V3).
5. `burn_header` unknown to the node's header chain → REJECT (invalid, V3).
   (Contrast vector 32: it is the *committed tip* being unknown that
   triggers not-yet-validated, not the burn header.)
6. Burn tx with an OP_RETURN output (any content) → ACCEPT (OP_RETURNs are
   ignored; D1 OP_RETURN rule rejected 2026-10-06).
7. Claim for a burn whose input 0 is Taproot key-path (no pubkey recoverable)
   → REJECT (invalid, V4, `bad-claim-unrecoverable-pubkey`).
8. Claim with `vout.scriptPubKey` paying to a pubkey other than burn input 0's
   pubkey → REJECT (invalid, V7); recipient is deterministic.
9. `burn_txid` field ≠ `SHA256D(burn_tx)` → REJECT (invalid, V2).
10. Furnace outputs present but under a non-exact scriptPubKey (e.g.
    P2SH-wrapped furnace hash) → contributes 0; if total ⇒ `cinis == 0` →
    REJECT (invalid, V6).
10a. Claim with `claim_signature` length ≠ 65 bytes (empty, truncated, or
    old-style DER) → REJECT (malformed, M2).
10b. Claim with a valid 65-byte compact message signature made with a
    different key than burn input 0's → REJECT (invalid, V5,
    `bad-claim-sig-verify`).
10c. Claim with a valid compact signature over the wrong payload/envelope
    (e.g. wrong network magic, or a raw digest instead of the Bitcoin
    message envelope) → REJECT (invalid, V5).
10d. Frontrunner takes a valid pending claim and replays it byte-for-byte →
    second copy REJECT (invalid, V1 nullifier). There is no representable
    "redirected" frontrunner claim: V4 fixes the recipient and V5's
    signature cannot be forged; a copy with the signature stripped is
    rejected per 10a.
11. Same burn claimed twice in one block → block INVALID (V1).
12. Same burn claimed in block N, then again in block N+1 → second block
    INVALID (V1).
13. Claim with `vout.value` ≠ formula `cinis` → block INVALID (V7).
14. Claim with `unlock` ≠ `H + 210_000` → block INVALID (V7).
15. Claim with `unlock` computed for the wrong height (stale mempool claim
    mined one block late) → block INVALID (V7).
16. `burn_tx` > 400,000 bytes → MALFORMED (M2).
17. Merkle branch > 32 entries → MALFORMED (M2).
18. Version-4 tx carrying witness bytes → MALFORMED (M1).
19. Version-4 tx in block position 0 → block INVALID (§5).
20. Coinbase with value > total fees (subsidy) → block INVALID (§1).
21. [DEFERRED — AuxPoW not in prototype] AuxPoW block whose parent PoW
    misses the Favilla target → block INVALID (§12.6).
22. [DEFERRED] AuxPoW with `chain_index` ≠ `0xFA17` → block INVALID (§12).
23. [DEFERRED] AuxPoW with parent header not on the active Bitcoin chain →
    block INVALID (§12.7).
24. [DEFERRED] Direct-mined block with insufficient PoW → block INVALID
    (§12). (Prototype: all blocks are direct PoW; insufficient PoW is
    rejected by the standard `high-hash` rule.)
25. Spend of Vigil output at height < `unlock` → INVALID.
26. Spend at height ≥ `unlock` with `nLockTime = unlock`, `nSequence = 0`,
    valid sig → ACCEPT.
27. Same as 26 but `nSequence = 0xFFFFFFFF` → INVALID (BIP 65).
28. Bitcoin reorg < 144 deep removing the burn block before claim inclusion
    → the burn header leaves new commitments' ancestry at depth ≥ 144 →
    pending claims become INVALID until the burn re-deeps below some
    committed tip.
29. Favilla reorg disconnecting a claim block → nullifier entry removed;
    re-issued claim for the new height → ACCEPT.
30. Burn input 0 spending via Taproot key-path → REJECT (invalid, V4,
    `bad-claim-unrecoverable-pubkey`).
31. Claim block whose coinbase lacks the `0x6a 0x20 || 32-byte` commitment
    output (or carries two) → block INVALID (D13a). A block committing the
    zero hash with no claims → ACCEPT (valid, no Bitcoin state used).
32. Claim block whose committed Bitcoin tip is unknown to the node → block
    HELD as not-yet-validated: not relayed as valid, not cached as invalid,
    no peer penalty; validates normally once the header arrives (D13b).
33. V3 against a deliberately stale-but-valid committed tip: burn at exactly
    144 below the stale tip → ACCEPT, deterministically, even though the
    node's live tip is hundreds of blocks ahead (D13b).
34. Spend of a Vigil output in a block whose committed Bitcoin tip has
    `MTP < burn_block_mtp + 126_000_000` → INVALID (D13d, Bitcoin-time
    Vigil) — even if Favilla height ≥ `unlock`.
35. Same spend in a block whose committed Bitcoin tip has
    `MTP >= burn_block_mtp + 126_000_000` (and Favilla height ≥ `unlock`,
    valid CLTV) → ACCEPT (D13d).
36. Burn mined in Bitcoin Fire 0, claimed after Favilla's own height passed
    210,000 → Fire 0 rate applies: era is by the burn's Bitcoin height, not
    claim timing (D13c).
37. Claim carrying an old-style custom-digest DER signature (pre-D13e
    format) → REJECT (invalid, V5) (D13e).
38. Claim with a valid 65-byte compact message signature over the standard
    envelope, recovered key == burn input-0 key → ACCEPT (V5) (D13e).
39. Claim with a valid compact signature over the wrong payload (e.g.
    signed with the regtest magic on testnet) → REJECT (invalid, V5)
    (D13e; domain separation preserved).
40. `burn_tx` of 400,001 bytes → MALFORMED (M2, D13f).

---

*Document history: v0.1 drafted 2026-10-06 (S1, Wave 1). v0.2 2026-10-06:
D1 decided FINAL by Matthew — deterministic recipient (OP_RETURN rule
proposed → rejected; signature authorization proposed → superseded); §5
claim format has no recipient field and no auth material; V4 derives mint
pubkey from burn input 0; V5/V6 renumbered. Regtest prototype scope.
v0.3 2026-10-06 (simplicity reassessment): AuxPoW DEFERRED to mainnet phase
(§12; prototype plain PoW); D1 FINAL revised — deterministic recipient +
signature gate V5 (pure-deterministic superseded over the exchange footgun:
burns from custodians must fail loudly); §5 claim format gains
`claim_signature`; V5/V6/V7 renumbered; §16 vectors updated.
v0.4 2026-10-07 (Phase 2, Wave 1): public testnet chain added. §2 split into
regtest (§2.1, corrected to code truth) and testnet (§2.2) with the D10
collision analysis; §3 furnace test vector corrected (regtest address was
wrong HRP and bad checksum) + testnet address; §4.1 testnet genesis vector;
scope covers regtest + public testnet (no mainnet); D10 partially closed,
O1 testnet resolved.
v0.5 2026-10-07 (Phase 2, Wave 2): D13 Bitcoin-anchored claims (Matthew:
"go with best choices, as long as the idea works"). §1.1: every block at
height ≥ 1 commits to its Bitcoin validation tip in the coinbase (§7 V3
judges depth against the commitment; unknown tip ⇒ block held
not-yet-validated, never cached invalid); §7 V6 / §9: Fire era by the
burn's Bitcoin height (rate locked at burn time — semantic change from
claim-height eras); §11.1: Vigil spends additionally gated on the spending
block's committed Bitcoin tip reaching burn_mtp + 126,000,000 s; §7 V5 /
§5 / M2: claim authorization is now a standard Bitcoin message signature
(65-byte compact recoverable; payload bytes unchanged); M2 burn-tx cap
400,000 bytes; D8 founder-first tightened to "before the *specification*
is published" (operational order: burn → confirm → publish); §16 vectors
31–40 added and affected vectors updated; stale cites fixed (§9 cinis==0 →
V6; §11 P0 note and §13.1 → V7; §10 eviction → V7). §13.2 states the
144-block bound explicitly (nine-figure reorg economics; scaled depth is a
mainnet hardening item).*
