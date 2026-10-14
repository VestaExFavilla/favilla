// Copyright (c) 2026 The Favilla developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.bitcoin.org/licenses/mit-license.php.

#ifndef BITCOIN_FAVILLA_AUXPOW_H
#define BITCOIN_FAVILLA_AUXPOW_H

#include <favilla/favilla.h>
#include <serialize.h>
#include <uint256.h>

#include <array>
#include <cstdint>
#include <ios>
#include <vector>

class CBlockHeader;
class BlockValidationState;
namespace Consensus {
struct Params;
} // namespace Consensus

namespace Favilla {

/**
 * AuxPoW (merged-mining) payload, SPEC §12 wire format:
 *
 *   parent_coinbase_tx:     CompactSize L, then L bytes (full parent coinbase tx)
 *   parent_coinbase_branch: CompactSize n (<= 32), n * 32-byte hashes,
 *                           then parent_coinbase_index uint32 LE
 *   chain_branch:           CompactSize m (<= 32), m * 32-byte hashes
 *   chain_index:            int32 LE (MUST equal AUXPOW_CHAIN_ID = 0xFA17)
 *   parent_header:          80 bytes (Bitcoin block header, wire format)
 *
 * This deliberately differs from Namecoin's CAuxPow serialization (see
 * ~/workspace/favilla/STATUS.md §"SPEC §12 vs Namecoin auxpow.h diff"):
 * no hashBlock field, raw (non-witness) parent coinbase bytes, and the
 * payload sits between the 80-byte header and the transactions in the
 * block wire format.
 */
struct CAuxPow {
    std::vector<unsigned char> parentCoinbaseTx; //!< raw parent coinbase tx bytes (<= MAX_BURN_TX_SIZE)
    std::vector<uint256> parentCoinbaseBranch;  //!< merkle branch to parent header root (<= 32)
    uint32_t parentCoinbaseIndex{0};
    std::vector<uint256> chainBranch; //!< chain merkle branch linking this header (<= 32)
    int32_t chainIndex{0};            //!< MUST equal AUXPOW_CHAIN_ID
    std::array<unsigned char, 80> parentHeader{}; //!< raw 80-byte Bitcoin block header

    bool IsNull() const
    {
        return parentCoinbaseTx.empty() && parentCoinbaseBranch.empty() &&
               chainBranch.empty() && chainIndex == 0;
    }

    SERIALIZE_METHODS(CAuxPow, obj)
    {
        READWRITE(obj.parentCoinbaseTx);
        READWRITE(obj.parentCoinbaseBranch);
        READWRITE(obj.parentCoinbaseIndex);
        READWRITE(obj.chainBranch);
        READWRITE(obj.chainIndex);
        READWRITE(obj.parentHeader);
        if (ser_action.ForRead()) {
            // Fail closed at parse time: unbounded vectors are a memory-DoS vector.
            if (obj.parentCoinbaseTx.size() > MAX_BURN_TX_SIZE) {
                throw std::ios_base::failure("CAuxPow: parent coinbase tx too large");
            }
            if (obj.parentCoinbaseBranch.size() > MAX_MERKLE_BRANCH) {
                throw std::ios_base::failure("CAuxPow: parent coinbase merkle branch too long");
            }
            if (obj.chainBranch.size() > MAX_MERKLE_BRANCH) {
                throw std::ios_base::failure("CAuxPow: chain merkle branch too long");
            }
        }
    }
};

/**
 * Validate an AuxPoW payload against a Favilla block header (SPEC §12,
 * CheckAuxPow steps 1-7). Non-contextual: needs only the header, the payload,
 * the chain params, and the node's Bitcoin header chain (for step 7).
 * Returns false and fills in state on any failure (fail closed).
 */
bool CheckAuxPow(const CBlockHeader& header, const CAuxPow& auxpow,
                 const Consensus::Params& params, BlockValidationState& state);

} // namespace Favilla

#endif // BITCOIN_FAVILLA_AUXPOW_H
