# Deferred: AuxPoW merged mining (mainnet phase)

**Status: DEFERRED 2026-10-06 by Matthew (simplicity reassessment).**

The regtest prototype does NOT implement merged mining — it runs plain
regtest proof-of-work. All AuxPoW code was removed from the prototype build
(block validation, block wire format, compact blocks) and set aside here,
untouched, for the mainnet phase.

## What's here

- `auxpow.h` / `auxpow.cpp` — the AuxPoW (merged-mining) payload type
  `Favilla::CAuxPow` and `Favilla::CheckAuxPow`, implementing SPEC §12
  (v0.2 and earlier). Wire format and validation steps follow the spec;
  known deviations from Namecoin's `CAuxPow` are documented as spec bugs
  B1–B7 in `~/workspace/favilla/STATUS.md` ("SPEC §12 vs Namecoin auxpow.h
  diff", 2026-10-06).
- The AuxPoW constants (`AUXPOW_VERSION_BIT = 0x100`,
  `AUXPOW_CHAIN_ID = 0xFA17`, `MERGED_MINING_MAGIC = 0xFABE6D6D`) remain
  declared in `../favilla.h`, marked DEFERRED, so this port compiles
  unchanged when reactivated.

## Reactivation checklist (mainnet phase)

1. Restore `auxpow.h`/`auxpow.cpp` to `src/favilla/` and re-add the source
   to `src/CMakeLists.txt`.
2. Re-apply the block-validation wiring that was scrubbed 2026-10-06
   (see git history for the exact hunks):
   - `src/primitives/block.h`: `CAuxPow auxpow` member + conditional
     wire serialization after the 80-byte header.
   - `src/validation.cpp`: `CheckBlockHeader` AuxPoW bypass,
     `CheckBlock` proof-mode dispatch to `CheckAuxPow`.
   - `src/blockencodings.cpp`: compact-block AuxPoW guard.
3. Re-verify the B1–B7 diff against the then-current Namecoin `auxpow.h`;
   mismatches are spec bugs — report, don't silently adapt.
4. Decide the production parent-confirmation policy (SPEC O2) and
   AuxPoW chain-ID uniqueness vs. other merged-mined chains (SPEC O1).
5. Full adversarial test pass over SPEC §12 before any public network.

## Why deferred

Per the 2026-10-06 simplicity reassessment: merged mining is the largest
consensus code surface in the design and is orthogonal to everything novel
about Favilla (burns, claims, the Vigil, eras — none care how blocks are
produced). The Vigil locks every minted coin for ~4 years, so there is
nothing to steal in the early chain; security can harden on the way to
mainnet. Phase 0 decision #1 now reads: "merged mining at mainnet;
prototype plain PoW."
