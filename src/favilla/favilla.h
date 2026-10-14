// Copyright (c) 2026 The Favilla developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.bitcoin.org/licenses/mit-license.php.

#ifndef BITCOIN_FAVILLA_FAVILLA_H
#define BITCOIN_FAVILLA_FAVILLA_H

#include <script/script.h>
#include <serialize.h>
#include <uint256.h>
#include <consensus/amount.h>

#include <array>
#include <atomic>
#include <cstdint>
#include <limits>
#include <vector>

class CBlock; // forward declaration (primitives/block.h includes favilla.h)

/**
 * Favilla (FVLA) consensus constants and pure helper functions.
 *
 * Normative reference: ~/workspace/favilla/SPEC.md v0.1.
 * All consensus arithmetic in this file is integer-only; no floating point.
 */
namespace Favilla {

//! New transaction version identifying a burn-claim transaction (SPEC §5).
static constexpr uint32_t TX_VERSION_CLAIM{4};

//! DEFERRED TO MAINNET PHASE (2026-10-06 simplicity reassessment):
//! AuxPoW version bit in the block header nVersion (SPEC §12).
//! Not referenced by the prototype build; kept for the mainnet port in
//! src/favilla/deferred/.
static constexpr int32_t AUXPOW_VERSION_BIT{0x100};

//! DEFERRED TO MAINNET PHASE: AuxPoW chain ID (SPEC §1, §12).
static constexpr int32_t AUXPOW_CHAIN_ID{0xFA17};

//! DEFERRED TO MAINNET PHASE: 4-byte merged-mining magic (SPEC §12 step 5).
static constexpr unsigned char MERGED_MINING_MAGIC[4]{0xfa, 0xbe, 0x6d, 0x6d};

//! Required Bitcoin confirmations for a burn before it is claimable (SPEC §7 V3).
static constexpr int BURN_CONFIRMATIONS{144};

//! Maximum size of the raw burn transaction carried by a claim (SPEC §5 M2,
//! D13f: claims carry no witness, so every byte weighs 4 — a 1 MB burn would
//! fill an entire 4M-weight block).
static constexpr size_t MAX_BURN_TX_SIZE{400'000};

//! Maximum number of hashes in a Merkle branch (SPEC §5 M2, §12).
static constexpr size_t MAX_MERKLE_BRANCH{32};

//! Number of blocks in a "fire" (issuance era) (SPEC §9).
static constexpr int64_t FIRE_BLOCKS{210'000};

//! Number of blocks a mint output stays locked (the Vigil) (SPEC §11).
static constexpr int64_t VIGIL_BLOCKS{210'000};

//! Cinis per FVLA (SPEC §9).
static constexpr int64_t CINIS_PER_FVLA{100'000'000};

//! Sats per FVLA at fire 0 (SPEC §9).
static constexpr int64_t HEAT_FIRE0{1'000'000};

//! Lock-time type threshold: unlock heights are always block heights (SPEC §11).
static constexpr uint32_t MAX_BLOCK_HEIGHT_LOCK{500'000'000};

//! Furnace: RIPEMD160(SHA256("ex favilla furnace v1")) — nothing-up-my-sleeve,
//! provably unspendable P2WPKH program (SPEC §3). Test vector verified 2026-10-06.
static constexpr unsigned char FURNACE_HASH160[20]{
    0xe8, 0x81, 0xfb, 0xba, 0xf0, 0x21, 0x32, 0x2e, 0x69, 0xc3,
    0x96, 0xb9, 0xda, 0x2b, 0x55, 0x46, 0x02, 0xd4, 0xfd, 0xe9};

//! The furnace scriptPubKey: 0x0014 || FURNACE_HASH160 (22 bytes, SPEC §3).
inline CScript GetFurnaceScriptPubKey()
{
    return CScript() << OP_0 << std::vector<unsigned char>(std::begin(FURNACE_HASH160), std::end(FURNACE_HASH160));
}

/**
 * The Vigil mint-output script template (SPEC §11):
 *   <unlock> OP_CHECKLOCKTIMEVERIFY OP_DROP <pubkey> OP_CHECKSIG
 * pubkey must be 33 bytes (compressed secp256k1).
 */
inline CScript GetVigilScriptPubKey(uint32_t nUnlockHeight, const std::vector<unsigned char>& pubkey33)
{
    return CScript() << CScriptNum(nUnlockHeight) << OP_CHECKLOCKTIMEVERIFY << OP_DROP
                     << pubkey33 << OP_CHECKSIG;
}
inline CScript GetVigilScriptPubKey(uint32_t nUnlockHeight, const std::array<unsigned char, 33>& pubkey33)
{
    return GetVigilScriptPubKey(nUnlockHeight, std::vector<unsigned char>(pubkey33.begin(), pubkey33.end()));
}

/**
 * Era rate rule and cinis formula (SPEC §9), integer-only.
 *   fire(B) = B // 210_000            (B = the burn's BITCOIN block height, D13c)
 *   heat(fire) = 1_000_000 * 2^fire   (unsigned __int128)
 *   cinis = floor(burned_sats * 100_000_000 / heat)
 * The mint rate is locked at burn time; the claim's Favilla inclusion height
 * plays no role in issuance (only in V7's unlock).
 * Returns false (and leaves cinisOut untouched) if the inputs are out of range;
 * a zero result is NOT an error here — the caller (V6) rejects cinis == 0.
 */
inline bool CalcCinis(uint64_t nBurnedSats, int nBurnBtcHeight, int64_t& cinisOut)
{
    if (nBurnBtcHeight < 0) return false;
    const uint64_t fire = static_cast<uint64_t>(nBurnBtcHeight) / static_cast<uint64_t>(FIRE_BLOCKS);
    // heat = 1e6 * 2^fire overflows unsigned __int128 at fire >= ~121; such
    // heights are unreachable in practice — fail closed.
    if (fire > 120) return false;
    const unsigned __int128 heat = (unsigned __int128)HEAT_FIRE0 * ((unsigned __int128)1 << fire);
    const unsigned __int128 cinis = (unsigned __int128)nBurnedSats * (unsigned __int128)CINIS_PER_FVLA / heat;
    if (cinis > (unsigned __int128)std::numeric_limits<int64_t>::max()) return false;
    cinisOut = static_cast<int64_t>(cinis);
    return true;
}

/** Issuance fire (era) for a burn's Bitcoin block height (SPEC §9, D13c). */
inline uint64_t FireAtBtcHeight(int nBurnBtcHeight)
{
    return static_cast<uint64_t>(nBurnBtcHeight) / static_cast<uint64_t>(FIRE_BLOCKS);
}

/**
 * Bitcoin-time Vigil span (SPEC §11.1, D13d): a Vigil spend is INVALID unless
 * the spending block's committed Bitcoin tip has median-time-past >=
 * burn_mtp + VIGIL_BTC_SECONDS. 210_000 * 600 s ~= 3.99 years.
 */
static constexpr uint64_t VIGIL_BTC_SECONDS{126'000'000};

/**
 * The D13a Bitcoin-tip commitment output shape: OP_RETURN pushing exactly
 * 32 bytes (the committed Bitcoin tip hash, internal byte order).
 * Serialized: 0x6a 0x20 || H (34 bytes total).
 */
inline bool IsCommitmentScript(const CScript& spk, uint256& hashOut)
{
    if (spk.size() != 34 || spk[0] != OP_RETURN || spk[1] != 0x20) return false;
    std::copy(spk.begin() + 2, spk.end(), hashOut.begin());
    return true;
}

/** The D13a commitment carried by a block's coinbase (SPEC §1.1). */
struct BlockCommitment {
    int count{0};       //!< number of commitment-shaped coinbase outputs
    uint256 tip{};      //!< the committed tip (valid iff count == 1)
    CAmount value{0};   //!< value of the commitment output (must be 0)
};

/** Scan the coinbase for D13a commitment outputs (defined in claim.cpp). */
BlockCommitment GetBlockCommitment(const CBlock& block);

/**
 * Shape-match for a §11 Vigil mint script:
 *   <push scriptnum> OP_CHECKLOCKTIMEVERIFY OP_DROP <push33 pubkey> OP_CHECKSIG
 * and nothing else. Used by the D13d Bitcoin-time spend rule to recognize
 * Vigil-locked outputs in the UTXO set (the mint output is verified
 * byte-for-byte at claim time by V7; this only needs the template shape).
 */
inline bool IsVigilScript(const CScript& spk)
{
    auto it{spk.begin()};
    opcodetype opcode;
    std::vector<unsigned char> push;
    // <unlock> push: a minimal script number (1-5 bytes).
    if (!spk.GetOp(it, opcode, push) || opcode > OP_PUSHDATA4) return false;
    if (push.empty() || push.size() > 5) return false;
    if (!spk.GetOp(it, opcode, push) || opcode != OP_CHECKLOCKTIMEVERIFY) return false;
    if (!spk.GetOp(it, opcode, push) || opcode != OP_DROP) return false;
    // <pubkey> push: 33-byte compressed secp256k1 key (V7 fixes this).
    if (!spk.GetOp(it, opcode, push) || opcode > OP_PUSHDATA4) return false;
    if (push.size() != 33 || (push[0] != 0x02 && push[0] != 0x03)) return false;
    if (!spk.GetOp(it, opcode, push) || opcode != OP_CHECKSIG) return false;
    return it == spk.end();
}

/**
 * D13b "held as not-yet-validated" flag. Set when ConnectBlock encounters a
 * block whose committed Bitcoin tip is unknown to the node (the block is
 * stored but left unconnected, never marked invalid). Consumers that feed
 * Bitcoin headers (submitbitcoinheader / importbitcoinheaders) check this
 * and re-run chain activation so held blocks validate as headers arrive.
 */
inline std::atomic<bool> g_held_blocks{false};
inline void SetHeldBlocks() { g_held_blocks.store(true, std::memory_order_relaxed); }
/** Returns true (once) if any block is currently held; clears the flag. */
inline bool ConsumeHeldBlocks()
{
    return g_held_blocks.exchange(false, std::memory_order_relaxed);
}

} // namespace Favilla

#endif // BITCOIN_FAVILLA_FAVILLA_H
