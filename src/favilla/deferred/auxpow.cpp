// Copyright (c) 2026 The Favilla developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.bitcoin.org/licenses/mit-license.php.

#include <favilla/auxpow.h>

#include <consensus/validation.h>
#include <favilla/btcheaders.h>
#include <hash.h>
#include <pow.h>
#include <primitives/block.h>
#include <primitives/transaction.h>
#include <streams.h>

#include <algorithm>

namespace Favilla {
namespace {

/**
 * SPEC §7 V2 Merkle-branch walk (shared with AuxPoW steps 3-4):
 *   cur = B; for i, h in enumerate(branch):
 *     cur = SHA256D(h + cur) if (index >> i) & 1 else SHA256D(cur + h)
 * Callers must enforce index < 2^len(branch) (fail closed).
 */
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

} // namespace

bool CheckAuxPow(const CBlockHeader& header, const CAuxPow& auxpow,
                 const Consensus::Params& params, BlockValidationState& state)
{
    // Step 1: payload bounds (also enforced at deserialization; re-checked here
    // for in-memory-constructed payloads).
    if (auxpow.parentCoinbaseTx.size() > MAX_BURN_TX_SIZE) {
        return state.Invalid(BlockValidationResult::BLOCK_CONSENSUS, "bad-auxpow-cb-too-large",
                             "parent coinbase tx exceeds 1 MB");
    }
    if (auxpow.parentCoinbaseBranch.size() > MAX_MERKLE_BRANCH ||
        auxpow.chainBranch.size() > MAX_MERKLE_BRANCH) {
        return state.Invalid(BlockValidationResult::BLOCK_CONSENSUS, "bad-auxpow-branch-too-long",
                             "auxpow merkle branch exceeds 32 hashes");
    }

    // Step 2: aux_hash = SHA256D(80-byte Favilla header).
    const uint256 aux_hash{header.GetHash()};

    // Step 3: chain_index MUST equal our chain ID; recompute the chain root.
    if (auxpow.chainIndex != AUXPOW_CHAIN_ID) {
        return state.Invalid(BlockValidationResult::BLOCK_CONSENSUS, "bad-auxpow-chain-index",
                             "chain_index != FAVILLA_AUXPOW_CHAIN_ID (0xFA17)");
    }
    // Fail closed: with a fixed index of 0xFA17 = 64023, the branch must have
    // at least 16 entries or high index bits would be silently dropped.
    if (auxpow.chainBranch.size() >= 64 ||
        static_cast<uint64_t>(AUXPOW_CHAIN_ID) >= (uint64_t{1} << auxpow.chainBranch.size())) {
        return state.Invalid(BlockValidationResult::BLOCK_CONSENSUS, "bad-auxpow-chain-branch",
                             "chain branch too short for chain index");
    }
    const uint256 chain_root{MerkleRootFromBranch(aux_hash, auxpow.chainBranch,
                                                  static_cast<uint32_t>(AUXPOW_CHAIN_ID))};

    // Step 4: parse the parent coinbase and verify its Merkle branch against
    // the parent header's root.
    CTransactionRef parent_cb;
    try {
        DataStream ds{std::as_bytes(std::span{auxpow.parentCoinbaseTx})};
        parent_cb = MakeTransactionRef(CTransaction(deserialize, TX_WITH_WITNESS, ds));
    } catch (const std::exception&) {
        return state.Invalid(BlockValidationResult::BLOCK_CONSENSUS, "bad-auxpow-cb-parse",
                             "parent coinbase does not deserialize");
    }
    // The txid commits to the exact transmitted bytes: a witness-carrying
    // parent coinbase would make cb_txid the wtxid and fail the branch proof
    // below; reject explicitly (SPEC §12 vs Namecoin ambiguity B2, fail closed).
    if (parent_cb->HasWitness()) {
        return state.Invalid(BlockValidationResult::BLOCK_CONSENSUS, "bad-auxpow-cb-witness",
                             "parent coinbase must not carry witness data");
    }
    const uint256 cb_txid{Hash(auxpow.parentCoinbaseTx)}; // SHA256D of the raw bytes
    if (auxpow.parentCoinbaseBranch.size() >= 64 ||
        static_cast<uint64_t>(auxpow.parentCoinbaseIndex) >= (uint64_t{1} << auxpow.parentCoinbaseBranch.size())) {
        return state.Invalid(BlockValidationResult::BLOCK_CONSENSUS, "bad-auxpow-cb-branch",
                             "parent coinbase branch too short for index");
    }
    CBlockHeader parent_header;
    try {
        DataStream ds{std::as_bytes(std::span{auxpow.parentHeader})};
        ds >> parent_header;
    } catch (const std::exception&) {
        return state.Invalid(BlockValidationResult::BLOCK_CONSENSUS, "bad-auxpow-parent-header",
                             "parent header does not deserialize");
    }
    const uint256 cb_root{MerkleRootFromBranch(cb_txid, auxpow.parentCoinbaseBranch,
                                               auxpow.parentCoinbaseIndex)};
    if (cb_root != parent_header.hashMerkleRoot) {
        return state.Invalid(BlockValidationResult::BLOCK_CONSENSUS, "bad-auxpow-cb-merkle",
                             "parent coinbase merkle proof failed");
    }

    // Step 5: the parent coinbase's first input scriptSig MUST contain the
    // 4-byte merged-mining magic immediately followed by the 32-byte
    // chain_root (internal byte order, per SPEC §0).
    if (parent_cb->vin.empty()) {
        return state.Invalid(BlockValidationResult::BLOCK_CONSENSUS, "bad-auxpow-cb-no-inputs",
                             "parent coinbase has no inputs");
    }
    const CScript& scriptSig{parent_cb->vin[0].scriptSig};
    const unsigned char* magic{Favilla::MERGED_MINING_MAGIC};
    auto it{std::search(scriptSig.begin(), scriptSig.end(), magic, magic + 4)};
    if (it == scriptSig.end() || std::distance(it, scriptSig.end()) < 4 + 32 ||
        !std::equal(chain_root.begin(), chain_root.end(), it + 4)) {
        return state.Invalid(BlockValidationResult::BLOCK_CONSENSUS, "bad-auxpow-mm-commitment",
                             "merged-mining magic + chain root not found in parent coinbase");
    }

    // Step 6: parent PoW against the FAVILLA header's nBits target
    // (the parent header's own nBits is NOT used).
    const uint256 parent_hash{parent_header.GetHash()};
    if (!CheckProofOfWork(parent_hash, header.nBits, params)) {
        return state.Invalid(BlockValidationResult::BLOCK_CONSENSUS, "bad-auxpow-parent-pow",
                             "parent proof of work misses the Favilla target");
    }

    // Step 7: the parent header must be on the node's active Bitcoin header
    // chain (any depth >= 0), evaluated at validation time only.
    if (!g_btcHeaderChain.IsOnActiveChain(parent_hash)) {
        return state.Invalid(BlockValidationResult::BLOCK_CONSENSUS, "bad-auxpow-parent-unknown",
                             "parent header not on the active Bitcoin header chain");
    }

    return true;
}

} // namespace Favilla
