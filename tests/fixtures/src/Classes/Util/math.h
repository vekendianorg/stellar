// SPDX-License-Identifier: MIT
// Header-only math helpers for the Stellar fixture library.
//
// Nothing in this header has an out-of-line definition: the one function here
// is `inline`, so the compiler may drop it entirely at -O2 and the only DWARF
// left for it is a declaration plus whatever DW_TAG_inlined_subroutine entries
// the callers produce. That is the distinction a dumper has to get right --
// "absent because it was inlined" is not "absent because it does not exist".
#pragma once

namespace game {

/// Clamp `v` into the inclusive range [lo, hi]. Always inlined.
inline float clampf(float v, float lo, float hi) {
  if (v < lo) return lo;
  if (v > hi) return hi;
  return v;
}

}  // namespace game
