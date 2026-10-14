// Copyright (c) 2026 The Favilla developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.bitcoin.org/licenses/mit-license.php.

#include <favilla/claim.h>

#include <coins.h>
#include <chainparams.h>
#include <consensus/validation.h>
#include <favilla/btcheaders.h>
#include <favilla/favilla.h>
#include <hash.h>
#include <primitives/block.h>
#include <primitives/transaction.h>
#include <pubkey.h>
#include <script/script.h>
#include <streams.h>

#include <cstring>

namespace Favilla {
namespace {

/**
 * The claim-authorization message digest (SPEC §7 V5, D13e): the STANDARD
 * Bitcoin Signed Message digest over the payload
 *   P = "FVLA-CLAIM" || network_magic || burn_txid   (45 bytes fixed)
 * i.e. digest = SHA256D("\x18Bitcoin Signed Message:\n" || CompactSize(45) || P).
 *
 * The payload bytes are unchanged from the pre-D13e scheme (the network
 * magic still domain-separates across Favilla networks), but the digest is
 * now the standard message envelope — the format hardware wallets
 * (Ledger/Trezor/Coldcard) can sign. The old custom-digest path is REMOVED.
 */
uint256 ClaimMessageDigest(const uint256& burn_txid)
{
    static constexpr char kPrefix[] = "\x18"
                                      "Bitcoin Signed Message:\n"; // 0x18 = len 24
    static constexpr unsigned char kDomain[] = "FVLA-CLAIM";       // 10 bytes
    static constexpr size_t kPayloadLen = 10 + 4 + 32;             // domain || magic || burn_txid = 46
    // NOTE: SPEC §7 V5's parenthetical says "45-byte payload" — an arithmetic
    // slip (10+4+32 = 46). The normative rule is CompactSize(len(P)).
    static_assert(kPayloadLen == 46);
    HashWriter hw{};
    // Raw concatenation per the message format — NOT length-prefixed
    // (HashWriter's operator<< for std::string would prepend CompactSize).
    hw.write(std::as_bytes(std::span{kPrefix, sizeof(kPrefix) - 1}));
    WriteCompactSize(hw, kPayloadLen);
    hw.write(std::as_bytes(std::span{kDomain, sizeof(kDomain) - 1}));
    const MessageStartChars& magic{Params().MessageStart()};
    hw.write(std::as_bytes(std::span{magic}));
    hw.write(std::as_bytes(std::span{burn_txid.data(), size_t{32}}));
    return hw.GetHash(); // SHA256D
}

/**
 * Verify a D13e claim signature: 65-byte compact recoverable form
 *   recid (1 byte, 0-3) || r (32 bytes BE) || s (32 bytes BE)
 * over the standard message digest, recovering to exactly the 33-byte
 * compressed pubkey extracted in V4.
 */
bool VerifyClaimSignature(const std::vector<unsigned char>& sig65, const uint256& digest,
                          const std::vector<unsigned char>& pubkey33)
{
    if (sig65.size() != 65 || sig65[0] > 3) return false;
    // Translate to Core's signmessage compact form: header = 27 + recid
    // (+ 4: compressed), then r || s. RecoverCompact derives recid =
    // (header - 27) & 3 and the compressed flag from bit 2 — both round-trip.
    std::vector<unsigned char> coreSig;
    coreSig.reserve(65);
    coreSig.push_back(static_cast<unsigned char>(27 + 4 + sig65[0]));
    coreSig.insert(coreSig.end(), sig65.begin() + 1, sig65.end());
    CPubKey recovered;
    if (!recovered.RecoverCompact(digest, coreSig)) return false;
    if (!recovered.IsFullyValid() || recovered.size() != 33) return false;
    return std::equal(recovered.begin(), recovered.end(), pubkey33.begin(), pubkey33.end());
}

/** SPEC §7 V2 Merkle-branch walk (shared with AuxPoW). */
uint256 MerkleRootFromBranch(const uint256& leaf, const std::vector<uint256>& branch, uint32_t index)
{
    uint256 cur{leaf};
    uint32_t idx{index};
    for (const uint256& h : branch) {
        if (idx & 1) {
            cur = Hash(h, cur);
        } else {
            cur = Hash(cur, h);
        }
        idx >>= 1;
    }
    return cur;
}

/**
 * Extract the pubkey revealed in a burn transaction's input 0.
 * Returns the 33-byte compressed pubkey, or empty if unrecoverable.
 * Used for SPEC §7 V4 deterministic recipient.
 *
 * Supports: P2PKH (pubkey in scriptSig), P2WPKH (pubkey in witness),
 * P2SH-P2WPKH (pubkey in witness), single-key P2WSH (pubkey in witness).
 * Returns empty for Taproot key-path or other pubkey-unrecoverable inputs.
 */
std::vector<unsigned char> ExtractBurnInput0Pubkey(const CTxIn& txin)
{
    // Witness stack first (P2WPKH, P2WSH, P2SH-P2WPKH): look for 33-byte
    // compressed pubkey. For P2WSH, take the first such (single-key only
    // in prototype; multisig burns are not supported for deterministic
    // recipient).
    for (const auto& item : txin.scriptWitness.stack) {
        if (item.size() == 33 && (item[0] == 0x02 || item[0] == 0x03)) {
            return item;
        }
    }
    // scriptSig pushes (P2PKH): look for 33-byte compressed pubkey.
    // P2PKH scriptSig is <sig> <pubkey>; take the last 33-byte push.
    std::vector<unsigned char> candidate;
    auto it{txin.scriptSig.begin()};
    opcodetype opcode;
    std::vector<unsigned char> push;
    while (txin.scriptSig.GetOp(it, opcode, push)) {
        if (opcode <= OP_PUSHDATA4 && push.size() == 33 &&
            (push[0] == 0x02 || push[0] == 0x03)) {
            candidate = push;
        }
    }
    return candidate;
}

/** Deserialize the claim's 80-byte burn header (fixed size, cannot fail to parse). */
CBlockHeader ParseBurnHeader(const CTransaction& tx)
{
    CBlockHeader header;
    DataStream ds{std::as_bytes(std::span{tx.claim_burn_header})};
    ds >> header;
    return header;
}

} // namespace

BlockCommitment GetBlockCommitment(const CBlock& block)
{
    BlockCommitment c;
    if (block.vtx.empty()) return c;
    for (const auto& out : block.vtx[0]->vout) {
        uint256 h;
        if (IsCommitmentScript(out.scriptPubKey, h)) {
            ++c.count;
            c.tip = h;
            c.value = out.nValue;
        }
    }
    return c;
}

ClaimCheckResult CheckClaimContextual(const CTransaction& tx, int nHeight, uint32_t nTxIndex,
                                      TxValidationState& state, const CCoinsViewCache& view,
                                      const std::set<uint256>& blockNullifiers,
                                      const uint256& committedTip)
{
    const uint256& burn_txid{tx.claim_burn_txid};
    const auto InvalidRes = [&](TxValidationResult result, const std::string& reason,
                                const std::string& debug) {
        state.Invalid(result, reason, debug);
        return ClaimCheckResult::INVALID;
    };

    // V1 — Nullifier (double-claim). Checked first: cheapest, fail-fast.
    if (blockNullifiers.count(burn_txid) || view.HaveNullifier(burn_txid)) {
        return InvalidRes(TxValidationResult::TX_CONSENSUS, "bad-claim-double-claim",
                          "burn txid already claimed (nullifier present)");
    }

    // V2 — Inclusion: recompute txid and Merkle root.
    // The burn txid is the STANDARD Bitcoin txid: SHA256D of the
    // witness-stripped serialization. The carried burn_tx INCLUDES witness
    // data (V4 needs it for pubkey extraction), so hashing the raw bytes
    // would give the wtxid — wrong. Parse first, then use GetHash().
    // (M3 already guaranteed this parse succeeds, but re-parse here rather
    // than threading the object through.)
    CTransactionRef burn_tx;
    try {
        DataStream ds{std::as_bytes(std::span{tx.claim_burn_tx})};
        burn_tx = MakeTransactionRef(CTransaction(deserialize, TX_WITH_WITNESS, ds));
    } catch (const std::exception&) {
        return InvalidRes(TxValidationResult::TX_CONSENSUS, "bad-claim-burntx-parse",
                          "burn tx does not deserialize");
    }
    const uint256 computed_txid{burn_tx->GetHash().ToUint256()};
    if (computed_txid != burn_txid) {
        return InvalidRes(TxValidationResult::TX_CONSENSUS, "bad-claim-txid-mismatch",
                          "recomputed burn txid != burn_txid");
    }
    const size_t branch_len{tx.claim_merkle_branch.size()};
    if (branch_len > MAX_MERKLE_BRANCH ||
        (branch_len < 64 && static_cast<uint64_t>(tx.claim_merkle_index) >= (uint64_t{1} << branch_len))) {
        return InvalidRes(TxValidationResult::TX_CONSENSUS, "bad-claim-merkle-index",
                          "merkle index out of range for branch length");
    }
    const CBlockHeader burn_header{ParseBurnHeader(tx)};
    const uint256 computed_root{MerkleRootFromBranch(computed_txid, tx.claim_merkle_branch,
                                                     tx.claim_merkle_index)};
    if (computed_root != burn_header.hashMerkleRoot) {
        return InvalidRes(TxValidationResult::TX_CONSENSUS, "bad-claim-merkle-root",
                          "merkle branch does not recompute to burn header root");
    }
    // Empty branch is allowed: the burn tx must then be the block's sole
    // transaction (root == txid) and the index must be 0 (enforced above).

    // V3 — Depth (144 confirmations), judged against the block's COMMITTED
    // Bitcoin tip (D13b). The node's live tip plays no role: two nodes with
    // different live tips evaluate the same block identically, which is what
    // kills the propagation-lag consensus split.
    if (committedTip.IsNull()) {
        // The zero hash means "no tip" (D13a); depth cannot be evaluated.
        return InvalidRes(TxValidationResult::TX_CONSENSUS, "bad-claim-zero-commitment",
                          "block commits to the zero Bitcoin tip but contains a claim");
    }
    if (!g_btcHeaderChain.HaveHeader(committedTip)) {
        // D13b: the committed tip is unknown to this node. The block is
        // HELD as not-yet-validated — never cached as invalid, no peer
        // penalty; validation is re-attempted as headers arrive. (Contrast:
        // an unknown *burn* header below is INVALID, not held.)
        return ClaimCheckResult::HELD;
    }
    const uint256 burn_hash{burn_header.GetHash()};
    if (!g_btcHeaderChain.IsAncestor(burn_hash, committedTip)) {
        return InvalidRes(TxValidationResult::TX_CONSENSUS, "bad-claim-header-unknown",
                          "burn header not in the committed Bitcoin tip's ancestry");
    }
    const int tip_btc_height{g_btcHeaderChain.GetHeaderHeight(committedTip)};
    const int burn_btc_height{g_btcHeaderChain.GetHeaderHeight(burn_hash)};
    // (Both heights are >= 0 here: the headers are in the index. A node
    // whose header chain is shorter than 144 blocks fails the depth check
    // below — fail closed, SPEC §6.)
    if (tip_btc_height - burn_btc_height < BURN_CONFIRMATIONS) {
        return InvalidRes(TxValidationResult::TX_CONSENSUS, "bad-claim-insufficient-depth",
                          "burn has fewer than 144 Bitcoin confirmations below the committed tip");
    }

    // V4 — Burn amount.
    // (burn_tx was parsed in V2; reuse it here.)
    // Note: any OP_RETURN outputs in the burn are ignored (D1 rejected
    // 2026-10-06); they carry no consensus meaning.
    const CScript furnace_spk{GetFurnaceScriptPubKey()};
    unsigned __int128 burned_sats{0};
    for (const auto& out : burn_tx->vout) {
        // Byte-identical match only (SPEC §3): P2SH/P2TR-wrapped furnace
        // hashes do NOT count — fail closed.
        if (out.scriptPubKey == furnace_spk) {
            burned_sats += static_cast<uint64_t>(out.nValue); // nValue >= 0 per M3
        }
    }
    if (burned_sats > static_cast<unsigned __int128>(std::numeric_limits<uint64_t>::max())) {
        return InvalidRes(TxValidationResult::TX_CONSENSUS, "bad-claim-burned-overflow",
                          "burned total exceeds uint64");
    }
    // Deterministic recipient (D1 FINAL 2026-10-06): the mint pubkey is the
    // pubkey revealed in the burn's first input (index 0). No choice, no
    // override. Anyone may submit the claim; redirection is impossible.
    if (burn_tx->vin.empty()) {
        return InvalidRes(TxValidationResult::TX_CONSENSUS, "bad-claim-burn-no-inputs",
                          "burn tx has no inputs");
    }
    const std::vector<unsigned char> mint_pubkey{ExtractBurnInput0Pubkey(burn_tx->vin[0])};
    if (mint_pubkey.empty()) {
        return InvalidRes(TxValidationResult::TX_CONSENSUS, "bad-claim-unrecoverable-pubkey",
                          "burn input 0 does not reveal a pubkey (e.g. Taproot key-path not supported in prototype)");
    }
    // Sanity: must be a valid compressed pubkey (extraction already filters).
    const CPubKey mint_cpkey{std::span{mint_pubkey}};
    if (!mint_cpkey.IsFullyValid()) {
        return InvalidRes(TxValidationResult::TX_CONSENSUS, "bad-claim-pubkey-invalid",
                          "burn input 0 pubkey is not a valid compressed secp256k1 point");
    }

    // V5 — Signature gate (D13e): claim_signature MUST be a 65-byte compact
    // recoverable STANDARD Bitcoin Signed Message signature over
    //   P = "FVLA-CLAIM" || network_magic || burn_txid
    // (envelope "\x18Bitcoin Signed Message:\n" || CompactSize(45) || P,
    // digest SHA256D). The recovered key must equal the input-0 pubkey.
    // This is message authorization, not a transaction signature — the claim
    // has no spendable inputs. Purpose: burns from exchanges/custodians fail
    // LOUDLY (unclaimable — the burner has no key) instead of silently
    // minting to the custodian's key. Front-running is impossible twice
    // over: the signature cannot be forged, and the deterministic recipient
    // (V4) leaves nothing to redirect anyway.
    // (M2 already enforced the exact 65-byte length.)
    const uint256 msg_digest{ClaimMessageDigest(burn_txid)};
    if (!VerifyClaimSignature(tx.claim_signature, msg_digest, mint_pubkey)) {
        return InvalidRes(TxValidationResult::TX_CONSENSUS, "bad-claim-sig-verify",
                          "claim signature does not recover to burn input 0's pubkey");
    }

    // V6 — Issuance (SPEC §9, D13c). The Fire era is determined by the
    // burn's BITCOIN height: fire = burn_btc_height // 210_000. The mint
    // rate is locked at burn time; the claim's Favilla height plays no role
    // (only V7's unlock uses it).
    int64_t cinis{0};
    if (!CalcCinis(static_cast<uint64_t>(burned_sats), burn_btc_height, cinis) || cinis == 0) {
        return InvalidRes(TxValidationResult::TX_CONSENSUS, "bad-claim-zero-mint",
                          "burn prices to zero cinis in its fire era");
    }

    // V7 — Mint output exactness: value == cinis and scriptPubKey ==
    // VIGIL_SCRIPT(unlock = H + 210_000, pubkey = burn_input_0_pubkey), byte-for-byte.
    // The recipient is deterministic (V4); the claimant constructs the output
    // but consensus verifies it byte-for-byte.
    if (tx.vout.size() != 1) {
        return InvalidRes(TxValidationResult::TX_CONSENSUS, "bad-claim-vout-size",
                          "claim must have exactly one output");
    }
    const uint64_t unlock{(static_cast<uint64_t>(nHeight) + static_cast<uint64_t>(VIGIL_BLOCKS))};
    if (unlock >= MAX_BLOCK_HEIGHT_LOCK) {
        return InvalidRes(TxValidationResult::TX_CONSENSUS, "bad-claim-unlock-overflow",
                          "vigil unlock height out of block-height lock range");
    }
    const CScript expected_spk{GetVigilScriptPubKey(static_cast<uint32_t>(unlock), mint_pubkey)};
    if (tx.vout[0].nValue != cinis) {
        return InvalidRes(TxValidationResult::TX_CONSENSUS, "bad-claim-value-mismatch",
                          "mint output value != issuance formula");
    }
    if (tx.vout[0].scriptPubKey != expected_spk) {
        return InvalidRes(TxValidationResult::TX_CONSENSUS, "bad-claim-script-mismatch",
                          "mint output script != Vigil template");
    }

    (void)nTxIndex; // recorded by the caller in the nullifier entry
    return ClaimCheckResult::VALID;
}

} // namespace Favilla
