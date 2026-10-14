// Copyright (c) 2026 The Favilla developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.bitcoin.org/licenses/mit-license.php.

#include <favilla/btcheaders.h>

#include <arith_uint256.h>
#include <chain.h> // CBlockIndex, GetBlockProof
#include <consensus/params.h>
#include <chainparams.h>      // Params() — global Favilla chain params
#include <util/chaintype.h>     // ChainType
#include <logging.h>
#include <pow.h> // CalculateNextWorkRequired, CheckProofOfWork
#include <serialize.h>
#include <streams.h>
#include <tinyformat.h>
#include <util/fs.h>

#include <algorithm>
#include <cstdio>
#include <vector>

namespace {
// Bitcoin parent-chain consensus parameters, selected by Favilla chain type.
//
// Favilla regtest → Bitcoin REGTEST params (constant nBits, no retargeting).
// This preserves the exact prototype behavior the 34 adversarial vectors
// exercise: regtest header validation is unchanged, byte-for-byte in
// outcome.
//
// Favilla testnet → genuine Bitcoin TESTNET4 params (powLimit 2^224-1,
// full 2016-block retargeting, BIP94 min-difficulty blocks). Before this
// fix the testnet chain validated headers against regtest rules, so every
// genuine testnet4 header (genesis nBits 0x1d00ffff, retargeting exists)
// failed validation and burn→claim was dead on arrival (audit H1).
//
// Returns nullptr for chain types with no defined Bitcoin parent chain
// (main/signet/testnet4 slots); callers fail closed with an RPC error.
const Consensus::Params* BitcoinParentParams(ChainType type)
{
    static const Consensus::Params regtest_params = [] {
        Consensus::Params p{};
        p.powLimit = uint256{"7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"};
        p.fPowNoRetargeting = true;
        p.fPowAllowMinDifficultyBlocks = false;
        p.nPowTargetSpacing = 10 * 60;
        p.nPowTargetTimespan = 14 * 24 * 60 * 60;
        return p;
    }();
    // Matches Bitcoin Core's CTestNet4Params (consensus fields only).
    static const Consensus::Params testnet4_params = [] {
        Consensus::Params p{};
        p.powLimit = uint256{"00000000ffffffffffffffffffffffffffffffffffffffffffffffffffffffff"};
        p.fPowNoRetargeting = false;
        p.fPowAllowMinDifficultyBlocks = true;
        p.enforce_BIP94 = true;
        p.nPowTargetSpacing = 10 * 60;
        p.nPowTargetTimespan = 14 * 24 * 60 * 60;
        return p;
    }();
    switch (type) {
    case ChainType::TESTNET:
        return &testnet4_params;
    case ChainType::REGTEST:
        return &regtest_params;
    default:
        break;
    }
    return nullptr;
}

// Genuine Bitcoin testnet4 genesis hash (Bitcoin Core's CTestNet4Params).
// On Favilla testnet the first submitted header MUST be this block: it
// anchors the header chain to the real testnet4 so a fabricated anchor
// cannot be used to fake claim depth.
const uint256 TESTNET4_GENESIS_HASH{
    "00000000da84f2bafbbc53dee25a72ae507ff4914b867c565be350b0da8bf043"};
} // namespace

CBitcoinHeaderChain g_btcHeaderChain{fs::path{}};

CBitcoinHeaderChain::CBitcoinHeaderChain(fs::path file) : m_file{std::move(file)} {}

void CBitcoinHeaderChain::SetFile(fs::path file)
{
    LOCK(m_cs);
    m_file = std::move(file);
}

bool CBitcoinHeaderChain::CheckParentBits(const CBlockHeader& header, int nHeight,
                                         const uint256& prevHash,
                                         const Consensus::Params& btc,
                                         std::string& err) const
{
    const HeaderInfo& prev{m_headers.at(prevHash)};
    if (btc.fPowNoRetargeting) {
        // Bitcoin-regtest rule: no retargeting, nBits is constant. This is
        // the path the 34 regtest adversarial vectors pin; do not change it.
        if (header.nBits != prev.header.nBits) {
            err = "bad-diffbits: nBits differs from parent (parent chain is Bitcoin regtest: no retargeting)";
            return false;
        }
        return true;
    }
    const uint32_t nPowLimitCompact{UintToArith256(btc.powLimit).GetCompact()};
    uint32_t nExpected;
    if (nHeight % btc.DifficultyAdjustmentInterval() == 0) {
        // Full retarget: recompute from the 2016-block window
        // [nHeight-2016, nHeight-1]. This replicates Core's
        // CalculateNextWorkRequired, but computed directly from our stored
        // headers: CalculateNextWorkRequired takes a CBlockIndex whose
        // GetAncestor() walks pprev links, which a synthetic index does not
        // have (null dereference → segfault, found the hard way).
        uint256 cur{prevHash};
        int h{prev.nHeight};
        while (h > nHeight - 2016) {
            auto it{m_headers.find(cur)};
            if (it == m_headers.end()) {
                err = "bad-diffbits: retarget window incomplete (headers before nHeight-2016 missing)";
                return false;
            }
            cur = it->second.header.hashPrevBlock;
            --h;
        }
        auto itFirst{m_headers.find(cur)};
        if (itFirst == m_headers.end()) {
            err = "bad-diffbits: retarget window incomplete (headers before nHeight-2016 missing)";
            return false;
        }
        arith_uint256 bnNew;
        if (btc.enforce_BIP94) {
            // BIP94: the retarget anchors on the FIRST block of the period
            // (which never carries a min-difficulty exception), not the
            // last block.
            bnNew.SetCompact(itFirst->second.header.nBits);
        } else {
            bnNew.SetCompact(prev.header.nBits);
        }
        int64_t nActualTimespan{
            (int64_t)prev.header.nTime - (int64_t)itFirst->second.header.nTime};
        if (nActualTimespan < btc.nPowTargetTimespan / 4)
            nActualTimespan = btc.nPowTargetTimespan / 4;
        if (nActualTimespan > btc.nPowTargetTimespan * 4)
            nActualTimespan = btc.nPowTargetTimespan * 4;
        bnNew *= nActualTimespan;
        bnNew /= btc.nPowTargetTimespan;
        const arith_uint256 bnPowLimit{UintToArith256(btc.powLimit)};
        if (bnNew > bnPowLimit)
            bnNew = bnPowLimit;
        nExpected = bnNew.GetCompact();
    } else if (btc.fPowAllowMinDifficultyBlocks &&
               header.nTime > prev.header.nTime + btc.nPowTargetSpacing * 2) {
        // BIP94 (testnet4): a block whose timestamp is more than 2x the
        // target spacing after its parent may use minimum difficulty.
        nExpected = nPowLimitCompact;
    } else {
        // Otherwise nBits must equal the last non-min-difficulty block's
        // nBits since the last retarget (BIP94 walk-back). Walking stops at
        // the retarget boundary, where the last retarget's nBits applies.
        uint256 cur{prevHash};
        nExpected = prev.header.nBits;
        while (true) {
            auto it{m_headers.find(cur)};
            if (it == m_headers.end()) {
                err = "bad-diffbits: difficulty walk-back hit an unknown header";
                return false;
            }
            const HeaderInfo& info{it->second};
            if (info.nHeight % btc.DifficultyAdjustmentInterval() == 0 ||
                info.header.nBits != nPowLimitCompact) {
                nExpected = info.header.nBits;
                break;
            }
            cur = info.header.hashPrevBlock;
        }
    }
    if (header.nBits != nExpected) {
        err = strprintf("bad-diffbits: nBits 0x%08x, expected 0x%08x under parent-chain difficulty rules",
                        header.nBits, nExpected);
        return false;
    }
    return true;
}

bool CBitcoinHeaderChain::AddHeaderInternal(const CBlockHeader& header, std::string& err)
{
    const uint256 hash{header.GetHash()};
    if (m_headers.count(hash)) {
        return true; // idempotent
    }

    // The parent-chain consensus rules follow the Favilla chain type:
    // regtest headers obey Bitcoin-regtest rules, testnet headers obey
    // genuine Bitcoin-testnet4 rules (audit H1).
    const ChainType chainType{Params().GetChainType()};
    const Consensus::Params* btc{BitcoinParentParams(chainType)};
    if (!btc) {
        err = "unsupported-chain: no Bitcoin parent chain defined for this Favilla chain type";
        return false;
    }

    int nHeight{0};
    arith_uint256 nChainWork{0};
    auto itPrev{m_headers.find(header.hashPrevBlock)};
    if (itPrev == m_headers.end()) {
        if (!m_headers.empty()) {
            err = "prev-unknown: parent header not in chain (orphans not supported)";
            return false;
        }
        if (chainType == ChainType::TESTNET && hash != TESTNET4_GENESIS_HASH) {
            err = "bad-anchor: on Favilla testnet the first header must be the genuine Bitcoin testnet4 genesis";
            return false;
        }
        // First header becomes the base at height 0.
        nChainWork = GetBlockProof(header);
    } else {
        const HeaderInfo& prev{itPrev->second};
        nHeight = prev.nHeight + 1;
        if (!CheckParentBits(header, nHeight, itPrev->first, *btc, err)) {
            return false;
        }
        nChainWork = prev.nChainWork + GetBlockProof(header);
    }

    // PoW is checked against the header's own nBits target (SPEC §6).
    if (!CheckProofOfWork(hash, header.nBits, *btc)) {
        err = "high-hash: proof of work failed";
        return false;
    }

    m_headers.emplace(hash, HeaderInfo{header, nHeight, nChainWork});

    // Active chain = most cumulative work. Side branches are kept and can
    // overtake the tip (reorg support, SPEC §6 / audit M1).
    if (m_tip.IsNull() || nChainWork > m_headers.at(m_tip).nChainWork) {
        m_tip = hash;
    }
    return true;
}

bool CBitcoinHeaderChain::AddHeader(const CBlockHeader& header, std::string& err)
{
    LOCK(m_cs);
    if (!AddHeaderInternal(header, err)) {
        return false;
    }
    // Persist eagerly: headers are tiny and this keeps the node crash-safe
    // without a shutdown hook (audit H2).
    if (!DumpInternal()) {
        LogWarning("CBitcoinHeaderChain: failed to persist headers to %s\n", fs::PathToString(m_file));
    }
    return true;
}

bool CBitcoinHeaderChain::IsOnActiveChain(const uint256& hash) const
{
    LOCK(m_cs);
    if (m_tip.IsNull()) return false;
    auto it{m_headers.find(hash)};
    if (it == m_headers.end()) return false;
    const int targetHeight{it->second.nHeight};
    // Walk back from the tip to the target height.
    uint256 cur{m_tip};
    while (true) {
        auto itCur{m_headers.find(cur)};
        if (itCur == m_headers.end()) return false; // should not happen
        if (itCur->second.nHeight == targetHeight) {
            return cur == hash;
        }
        if (itCur->second.nHeight < targetHeight) return false;
        cur = itCur->second.header.hashPrevBlock;
    }
}

int CBitcoinHeaderChain::GetActiveHeight(const uint256& hash) const
{
    LOCK(m_cs);
    if (m_tip.IsNull()) return -1;
    auto it{m_headers.find(hash)};
    if (it == m_headers.end()) return -1;
    const int targetHeight{it->second.nHeight};
    uint256 cur{m_tip};
    while (true) {
        auto itCur{m_headers.find(cur)};
        if (itCur == m_headers.end()) return -1;
        if (itCur->second.nHeight == targetHeight) {
            return cur == hash ? targetHeight : -1;
        }
        if (itCur->second.nHeight < targetHeight) return -1;
        cur = itCur->second.header.hashPrevBlock;
    }
}

int CBitcoinHeaderChain::GetTipHeight() const
{
    LOCK(m_cs);
    if (m_tip.IsNull()) return -1;
    return m_headers.at(m_tip).nHeight;
}

uint256 CBitcoinHeaderChain::GetTipHash() const
{
    LOCK(m_cs);
    return m_tip;
}

bool CBitcoinHeaderChain::HaveHeader(const uint256& hash) const
{
    LOCK(m_cs);
    return m_headers.count(hash) != 0;
}

int CBitcoinHeaderChain::GetHeaderHeight(const uint256& hash) const
{
    LOCK(m_cs);
    auto it{m_headers.find(hash)};
    if (it == m_headers.end()) return -1;
    return it->second.nHeight;
}

bool CBitcoinHeaderChain::IsAncestor(const uint256& ancestor, const uint256& descendant) const
{
    LOCK(m_cs);
    auto itD{m_headers.find(descendant)};
    auto itA{m_headers.find(ancestor)};
    if (itD == m_headers.end() || itA == m_headers.end()) return false;
    const int hD{itD->second.nHeight};
    const int hA{itA->second.nHeight};
    if (hD < hA) return false;
    // Walk back (hD - hA) prev links from descendant.
    uint256 cur{descendant};
    for (int h{hD}; h > hA; --h) {
        auto it{m_headers.find(cur)};
        if (it == m_headers.end()) return false; // missing link: fail closed
        cur = it->second.header.hashPrevBlock;
    }
    return cur == ancestor;
}

std::optional<uint32_t> CBitcoinHeaderChain::GetMedianTimePast(const uint256& hash) const
{
    LOCK(m_cs);
    auto it{m_headers.find(hash)};
    if (it == m_headers.end()) return std::nullopt;
    // Bitcoin MTP is the median of the nTime of the 11 headers ending at
    // `hash` (headers h-10 .. h); it is only defined at height >= 10.
    if (it->second.nHeight < 10) return std::nullopt;
    uint256 cur{hash};
    uint32_t times[11];
    for (int i{0}; i < 11; ++i) {
        auto itCur{m_headers.find(cur)};
        if (itCur == m_headers.end()) return std::nullopt; // missing link
        times[i] = static_cast<uint32_t>(itCur->second.header.nTime);
        cur = itCur->second.header.hashPrevBlock;
    }
    std::sort(std::begin(times), std::end(times));
    return times[5];
}

size_t CBitcoinHeaderChain::Size() const
{
    LOCK(m_cs);
    return m_headers.size();
}

std::vector<CBlockHeader> CBitcoinHeaderChain::GetHeadersByHeightInternal() const
{
    std::vector<const HeaderInfo*> byHeight;
    byHeight.reserve(m_headers.size());
    for (const auto& [hash, info] : m_headers) {
        byHeight.push_back(&info);
    }
    std::sort(byHeight.begin(), byHeight.end(),
              [](const HeaderInfo* a, const HeaderInfo* b) { return a->nHeight < b->nHeight; });
    std::vector<CBlockHeader> ordered;
    ordered.reserve(byHeight.size());
    for (const HeaderInfo* info : byHeight) {
        ordered.push_back(info->header);
    }
    return ordered;
}

std::vector<CBlockHeader> CBitcoinHeaderChain::GetHeadersByHeight() const
{
    LOCK(m_cs);
    return GetHeadersByHeightInternal();
}

void CBitcoinHeaderChain::Clear()
{
    LOCK(m_cs);
    m_headers.clear();
    m_tip = uint256{};
    // Persist the empty state so a restart does not resurrect the chain.
    if (!DumpInternal()) {
        LogWarning("CBitcoinHeaderChain: failed to persist cleared state to %s\n", fs::PathToString(m_file));
    }
}

bool CBitcoinHeaderChain::DumpInternal() const
{
    if (m_file.empty()) return false;
    try {
        // Serialize ALL headers (active chain AND side branches) in height
        // order, so Load() can re-add them and re-derive the most-work tip.
        // (An earlier version serialized only the active-chain path and
        // silently dropped side branches on restart — audit M1.)
        const std::vector<CBlockHeader> ordered{GetHeadersByHeightInternal()};
        DataStream ds;
        ds << ordered;
        FILE* f{fsbridge::fopen(m_file, "wb")};
        if (!f) return false;
        const bool ok{fwrite(ds.data(), 1, ds.size(), f) == ds.size()};
        fclose(f);
        return ok;
    } catch (const std::exception&) {
        return false;
    }
}

bool CBitcoinHeaderChain::Dump() const
{
    LOCK(m_cs);
    return DumpInternal();
}

bool CBitcoinHeaderChain::Load()
{
    LOCK(m_cs);
    if (m_file.empty()) return false;
    FILE* f{fsbridge::fopen(m_file, "rb")};
    if (!f) return true; // missing file: start empty, not an error
    DataStream ds;
    try {
        char buf[8192];
        size_t n;
        while ((n = fread(buf, 1, sizeof(buf), f)) > 0) {
            ds.write(std::span{reinterpret_cast<const std::byte*>(buf), n});
        }
        fclose(f);
        std::vector<CBlockHeader> ordered;
        ds >> ordered;
        for (const auto& h : ordered) {
            std::string err;
            if (!AddHeaderInternal(h, err)) {
                LogWarning("CBitcoinHeaderChain: stored header failed revalidation: %s\n", err);
                return false;
            }
        }
        return true;
    } catch (const std::exception& e) {
        fclose(f);
        LogWarning("CBitcoinHeaderChain: failed to load %s: %s\n", fs::PathToString(m_file), e.what());
        return false;
    }
}
