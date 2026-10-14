// Copyright (c) 2017-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <consensus/tx_check.h>

#include <consensus/amount.h>
#include <favilla/favilla.h>
#include <primitives/transaction.h>
#include <consensus/validation.h>
#include <pubkey.h>
#include <streams.h>

namespace {

/**
 * Favilla: structural checks for a version-4 burn-claim transaction
 * (SPEC §7.1). Violations are MALFORMED. Semantic checks (V1-V6) are
 * contextual and live in Favilla::CheckClaimContextual (src/favilla/claim.cpp).
 */
bool CheckClaimTransaction(const CTransaction& tx, TxValidationState& state)
{
    // M1: exact §5 grammar.
    if (tx.nLockTime != 0) {
        return state.Invalid(TxValidationResult::TX_CONSENSUS, "bad-claim-nlocktime",
                             "claim nLockTime must be 0");
    }
    if (tx.vin.size() != 1) {
        return state.Invalid(TxValidationResult::TX_CONSENSUS, "bad-claim-vin-size",
                             "claim must have exactly the marker input");
    }
    const CTxIn& marker = tx.vin[0];
    if (!marker.prevout.IsNull() || !marker.scriptSig.empty() || marker.nSequence != CTxIn::SEQUENCE_FINAL) {
        return state.Invalid(TxValidationResult::TX_CONSENSUS, "bad-claim-marker-input",
                             "claim input must be the null marker input");
    }
    if (tx.vout.size() != 1) {
        return state.Invalid(TxValidationResult::TX_CONSENSUS, "bad-claim-vout-size",
                             "claim must have exactly one (mint) output");
    }

    // M2: field bounds.
    if (tx.claim_merkle_branch.size() > Favilla::MAX_MERKLE_BRANCH) {
        return state.Invalid(TxValidationResult::TX_CONSENSUS, "bad-claim-branch-too-long",
                             "merkle branch exceeds 32 hashes");
    }
    if (tx.claim_burn_tx.size() < 1 || tx.claim_burn_tx.size() > Favilla::MAX_BURN_TX_SIZE) {
        return state.Invalid(TxValidationResult::TX_CONSENSUS, "bad-claim-burntx-size",
                             "burn tx size out of range [1, 400000]");
    }
    // M2: the claim signature is a 65-byte compact recoverable standard
    // Bitcoin Signed Message signature (SPEC §7 V5, D13e): recid || r || s.
    // Wrong length is MALFORMED here; semantic validity (right key, right
    // payload) is V5 in CheckClaimContextual.
    if (tx.claim_signature.size() != 65) {
        return state.Invalid(TxValidationResult::TX_CONSENSUS, "bad-claim-sig-size",
                             "claim signature must be exactly 65 bytes (compact recoverable)");
    }
    // M2 complete: no recipient_pubkey field in the claim (D1 FINAL 2026-10-06:
    // deterministic recipient from burn input 0; §7 V5 signature gate).

    // M3: burn_tx deserializes as a well-formed Bitcoin transaction.
    CTransactionRef burn_tx;
    try {
        DataStream ds{std::span{tx.claim_burn_tx}};
        burn_tx = MakeTransactionRef(CTransaction(deserialize, TX_WITH_WITNESS, ds));
    } catch (const std::exception&) {
        return state.Invalid(TxValidationResult::TX_CONSENSUS, "bad-claim-burntx-parse",
                             "burn tx does not deserialize as a Bitcoin transaction");
    }
    if (burn_tx->vin.empty() || burn_tx->vout.empty()) {
        return state.Invalid(TxValidationResult::TX_CONSENSUS, "bad-claim-burntx-empty",
                             "burn tx has no inputs or no outputs");
    }
    for (const auto& out : burn_tx->vout) {
        if (out.nValue < 0) {
            return state.Invalid(TxValidationResult::TX_CONSENSUS, "bad-claim-burntx-negative-value",
                                 "burn tx output value negative");
        }
    }

    // Mint output value range: int64 per SPEC §9 (no MAX_MONEY cap on mints).
    if (tx.vout[0].nValue < 0) {
        return state.Invalid(TxValidationResult::TX_CONSENSUS, "bad-claim-vout-negative",
                             "mint output value negative");
    }

    // Size limit. Claims carry up to 400 KB of burn evidence (D13f) and have
    // no witness discount; apply the block-weight bound to the unscaled size
    // so a maximum-size claim is not rejected here (the block-level weight
    // limit still bounds blocks).
    if (::GetSerializeSize(TX_NO_WITNESS(tx)) > MAX_BLOCK_WEIGHT) {
        return state.Invalid(TxValidationResult::TX_CONSENSUS, "bad-txns-oversize",
                             "claim transaction too large");
    }

    return true;
}

} // namespace

bool CheckTransaction(const CTransaction& tx, TxValidationState& state)
{
    // Favilla: version-4 burn claims have their own structural grammar.
    if (tx.version == Favilla::TX_VERSION_CLAIM) {
        return CheckClaimTransaction(tx, state);
    }

    // Basic checks that don't depend on any context
    if (tx.vin.empty())
        return state.Invalid(TxValidationResult::TX_CONSENSUS, "bad-txns-vin-empty");
    if (tx.vout.empty())
        return state.Invalid(TxValidationResult::TX_CONSENSUS, "bad-txns-vout-empty");
    // Size limits (this doesn't take the witness into account, as that hasn't been checked for malleability)
    if (::GetSerializeSize(TX_NO_WITNESS(tx)) * WITNESS_SCALE_FACTOR > MAX_BLOCK_WEIGHT) {
        return state.Invalid(TxValidationResult::TX_CONSENSUS, "bad-txns-oversize");
    }

    // Check for negative or overflow output values (see CVE-2010-5139)
    CAmount nValueOut = 0;
    for (const auto& txout : tx.vout)
    {
        if (txout.nValue < 0)
            return state.Invalid(TxValidationResult::TX_CONSENSUS, "bad-txns-vout-negative");
        if (txout.nValue > MAX_MONEY)
            return state.Invalid(TxValidationResult::TX_CONSENSUS, "bad-txns-vout-toolarge");
        nValueOut += txout.nValue;
        if (!MoneyRange(nValueOut))
            return state.Invalid(TxValidationResult::TX_CONSENSUS, "bad-txns-txouttotal-toolarge");
    }

    // Check for duplicate inputs (see CVE-2018-17144)
    // While Consensus::CheckTxInputs does check if all inputs of a tx are available, and UpdateCoins marks all inputs
    // of a tx as spent, it does not check if the tx has duplicate inputs.
    // Failure to run this check will result in either a crash or an inflation bug, depending on the implementation of
    // the underlying coins database.
    std::set<COutPoint> vInOutPoints;
    for (const auto& txin : tx.vin) {
        if (!vInOutPoints.insert(txin.prevout).second)
            return state.Invalid(TxValidationResult::TX_CONSENSUS, "bad-txns-inputs-duplicate");
    }

    if (tx.IsCoinBase())
    {
        if (tx.vin[0].scriptSig.size() < 2 || tx.vin[0].scriptSig.size() > 100)
            return state.Invalid(TxValidationResult::TX_CONSENSUS, "bad-cb-length");
    }
    else
    {
        for (const auto& txin : tx.vin)
            if (txin.prevout.IsNull())
                return state.Invalid(TxValidationResult::TX_CONSENSUS, "bad-txns-prevout-null");
    }

    return true;
}
