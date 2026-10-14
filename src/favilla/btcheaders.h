// Copyright (c) 2026 The Favilla developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.bitcoin.org/licenses/mit-license.php.

#ifndef BITCOIN_FAVILLA_BTCHEADERS_H
#define BITCOIN_FAVILLA_BTCHEADERS_H

#include <arith_uint256.h>
#include <consensus/params.h>
#include <primitives/block.h>
#include <sync.h>
#include <uint256.h>
#include <util/fs.h>

#include <cstdint>
#include <map>
#include <optional>
#include <string>
#include <vector>

/**
 * Favilla's view of the Bitcoin header chain (SPEC §6).
 *
 * Every Favilla full node maintains a fully-validated Bitcoin header chain:
 * each header's PoW is checked against its own nBits target, difficulty bits
 * follow the parent chain's consensus rules (selected by the Favilla chain
 * type — audit H1), and cumulative work is tracked; the active chain is the
 * most-work chain, with side branches kept and allowed to overtake the tip
 * (reorg support, audit M1). Claims (§7 V3) are validated against the chain
 * active at validation time. (AuxPoW parent membership, SPEC §12 step 7,
 * will use this chain at mainnet; AuxPoW is deferred in the prototype.)
 *
 * Parent-chain rules: Favilla regtest → Bitcoin regtest (constant nBits
 * 0x207fffff, no retargeting); Favilla testnet → genuine Bitcoin testnet4
 * (powLimit 2^224-1, full 2016-block retargeting, BIP94 min-difficulty
 * blocks). On testnet the first submitted header MUST be the genuine
 * testnet4 genesis, anchoring the chain to the real network.
 *
 * Persistence (audit H2): the chain is stored append-tolerant in the node's
 * datadir (`favilla_btcheaders.dat`), reloaded at startup before network
 * processing, and dumped eagerly on every accepted header. The
 * `exportbitcoinheaders` / `importbitcoinheaders` RPCs bootstrap new nodes.
 *
 * If the header chain is shorter than 144 blocks, all claims are rejected
 * (fail closed, SPEC §6).
 *
 * Thread safety: all public methods lock the internal mutex.
 */
class CBitcoinHeaderChain
{
private:
    struct HeaderInfo {
        CBlockHeader header;
        int nHeight{-1};
        arith_uint256 nChainWork{0};
    };

    mutable Mutex m_cs;
    std::map<uint256, HeaderInfo> m_headers GUARDED_BY(m_cs);
    uint256 m_tip GUARDED_BY(m_cs);

    fs::path m_file GUARDED_BY(m_cs);

    bool AddHeaderInternal(const CBlockHeader& header, std::string& err) EXCLUSIVE_LOCKS_REQUIRED(m_cs);

    //! Difficulty-bits linkage check against the parent-chain consensus
    //! rules (audit H1). m_headers must contain prevHash.
    bool CheckParentBits(const CBlockHeader& header, int nHeight, const uint256& prevHash,
                         const Consensus::Params& btc, std::string& err) const
        EXCLUSIVE_LOCKS_REQUIRED(m_cs);

    //! All stored headers in height order (active chain AND side branches).
    std::vector<CBlockHeader> GetHeadersByHeightInternal() const EXCLUSIVE_LOCKS_REQUIRED(m_cs);

    bool DumpInternal() const EXCLUSIVE_LOCKS_REQUIRED(m_cs);

public:
    CBitcoinHeaderChain() = delete;
    explicit CBitcoinHeaderChain(fs::path file);

    //! Set the backing file (must be called before Load).
    void SetFile(fs::path file);

    //! Validate and add a header. Returns false with err set on failure.
    //! Idempotent: re-submitting a known header succeeds.
    bool AddHeader(const CBlockHeader& header, std::string& err);

    //! True iff hash is present AND on the active (most-work) chain.
    bool IsOnActiveChain(const uint256& hash) const;

    //! Height of hash on the active chain, or -1 if unknown/not active.
    int GetActiveHeight(const uint256& hash) const;

    //! Height of the active tip, or -1 if the chain is empty.
    int GetTipHeight() const;

    //! Hash of the active tip (null if empty).
    uint256 GetTipHash() const;

    //! True iff the header is present in the index (any branch — D13b V3
    //! judges depth against the block's committed tip, which need not be
    //! on the node's active chain).
    bool HaveHeader(const uint256& hash) const;

    //! Height of a header in the index (any branch), or -1 if unknown.
    int GetHeaderHeight(const uint256& hash) const;

    //! True iff `ancestor` equals `descendant` or lies on its prev-link
    //! ancestry chain. Both must be in the index.
    bool IsAncestor(const uint256& ancestor, const uint256& descendant) const;

    //! Bitcoin median-time-past of the 11 headers ending at `hash`
    //! (SPEC §11.1, D13d). Returns nullopt if the header is unknown, any
    //! prev link is missing, or its height is below 10.
    std::optional<uint32_t> GetMedianTimePast(const uint256& hash) const;

    //! Number of headers stored.
    size_t Size() const;

    //! All stored headers (active chain and side branches) in height order.
    //! Used by exportbitcoinheaders for node bootstrapping.
    std::vector<CBlockHeader> GetHeadersByHeight() const;

    //! Clear the whole chain (in-memory and on disk). Escape hatch for an
    //! orphaned/invalid tip (audit M1); exposed via clearbitcoinheaders.
    void Clear();

    //! Load headers from the backing file. Missing file is not an error.
    bool Load();

    //! Persist headers to the backing file.
    bool Dump() const;
};

/** Global Bitcoin header chain (initialized at startup). */
extern CBitcoinHeaderChain g_btcHeaderChain;

#endif // BITCOIN_FAVILLA_BTCHEADERS_H
