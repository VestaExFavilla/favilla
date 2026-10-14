// Copyright (c) 2026 The Favilla developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.bitcoin.org/licenses/mit-license.php.

#ifndef BITCOIN_FAVILLA_CLAIM_H
#define BITCOIN_FAVILLA_CLAIM_H

#include <cstdint>
#include <set>

class CCoinsViewCache;
class CTransaction;
class TxValidationState;
class uint256;

namespace Favilla {

/** Outcome of contextual claim validation (SPEC §7.2). */
enum class ClaimCheckResult {
    VALID,   //!< the claim is valid for inclusion at nHeight
    INVALID, //!< the claim violates a semantic rule (fail closed)
    HELD,    //!< the block's committed Bitcoin tip is unknown to the node
             //!< (D13b): the block must be HELD as not-yet-validated — never
             //!< cached as invalid, no peer penalty; re-attempt as headers
             //!< arrive. Only possible when committedTip is unknown.
};

/**
 * Contextual (semantic) validation of a version-4 burn-claim transaction for
 * inclusion at Favilla height nHeight (SPEC §7.2). Checks run in the spec's
 * normative order; any violation is INVALID (fail closed), except the D13b
 * committed-tip-unknown case which is HELD:
 *
 *   V1 — burn_txid not already in the nullifier set (nor claimed earlier in
 *          the same block, via blockNullifiers)
 *   V2 — SHA256D(burn_tx) == burn_txid; Merkle branch recomputes to the
 *          burn header's merkle root
 *   V3 — depth judged against the block's COMMITTED Bitcoin tip (D13b):
 *          committed_tip_height - burn_block_height >= 144, with the burn
 *          header in the committed tip's ancestry. Unknown committed tip
 *          => HELD (never invalid). Zero-hash commitment + claim => INVALID.
 *   V4 — burn amount: burned_sats = sum of byte-exact FURNACE_SPK outputs;
 *          mint recipient derived deterministically from the pubkey revealed
 *          in the burn's first input (input 0); Taproot key-path etc. rejected
 *   V5 — signature gate (D13e): claim_signature is a 65-byte compact
 *          recoverable STANDARD Bitcoin Signed Message signature over
 *          "FVLA-CLAIM" || network_magic || burn_txid; the recovered key
 *          must equal the input-0 pubkey. The old custom-digest DER path
 *          is REMOVED.
 *   V6 — cinis = floor(burned_sats * 1e8 / heat(fire)) > 0 with
 *          fire = burn_btc_height // 210_000 (D13c: rate locked at burn time)
 *   V7 — vout == exactly the Vigil mint output for (H + 210_000, input-0 pubkey)
 *
 * committedTip is the block's D13a coinbase commitment (the zero hash means
 * "no tip"). nTxIndex is the transaction's index within the block (recorded
 * in the nullifier entry for auditability). Structural checks (M1/M2/M3) are
 * NOT performed here — they run in CheckTransaction beforehand.
 */
ClaimCheckResult CheckClaimContextual(const CTransaction& tx, int nHeight, uint32_t nTxIndex,
                                      TxValidationState& state, const CCoinsViewCache& view,
                                      const std::set<uint256>& blockNullifiers,
                                      const uint256& committedTip);

} // namespace Favilla

#endif // BITCOIN_FAVILLA_CLAIM_H
