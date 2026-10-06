// SPDX-License-Identifier: MIT
#include "stellar/dwarf/dwarf_context.h"

#include "stellar/diag/log.h"

#include <mutex>
#include <thread>
#include <vector>

namespace stellar::dwarf {

DwarfContext::DwarfContext(const elf::ElfFile& elf)
    : elf_(elf), sections_(elf), abbrev_cache_(16) {}

std::string_view DwarfContext::str_at(std::uint64_t offset) const {
  const util::ByteView s = str();
  if (offset >= s.size()) return {};
  const char* base = reinterpret_cast<const char*>(s.data());
  const std::size_t max = s.size() - offset;
  // .debug_str entries are NUL-terminated; guard against a missing terminator.
  std::size_t len = 0;
  while (len < max && base[offset + len] != '\0') ++len;
  return std::string_view(base + offset, len);
}

std::uint64_t DwarfContext::unit_count() const {
  if (cache_valid_) return cached_count_;
  unit_offsets_.clear();
  const util::ByteView info_v = info();
  std::uint64_t pos = 0;
  while (pos < info_v.size()) {
    UnitHeader h;
    std::string err;
    if (!parse_unit_header(info_v, pos, elf_.endian(), h, &err)) {
      // Stop at the first unparsable unit: everything after it is suspect, and
      // continuing would produce garbage unit boundaries.
      STELLAR_DEBUG("unit discovery stopped at 0x%llx: %s", static_cast<unsigned long long>(pos),
                err.c_str());
      break;
    }
    unit_offsets_.push_back(pos);
    pos = h.die_end;
  }
  cached_count_ = unit_offsets_.size();
  cache_valid_ = true;
  return cached_count_;
}

bool DwarfContext::unit_header(std::uint64_t index, UnitHeader& out,
                               std::string* error) const {
  (void)unit_count();  // ensure the offset cache is populated
  if (index >= unit_offsets_.size()) {
    if (error) *error = "unit index out of range";
    return false;
  }
  return parse_unit_header(info(), unit_offsets_[index], elf_.endian(), out, error);
}

const AbbrevTable* DwarfContext::abbrev_table(const UnitHeader& unit, std::string* error) {
  return abbrev_cache_.get(abbrev(), unit.abbrev_offset, unit.endian, unit.address_size,
                           unit.offset_size(), error);
}

DwarfContext::UnitIterator::UnitIterator(DwarfContext& ctx, const ScanLimits& limits)
    : ctx_(&ctx), limits_(limits) {
  (void)ctx_->unit_count();  // populate the offset cache
  pos_ = 0;
}

bool DwarfContext::UnitIterator::next(UnitHeader& out, std::string* error) {
  if (done_) return false;
  const std::uint64_t total = ctx_->cached_count_;
  if (limits_.max_units && visited_ >= limits_.max_units) {
    done_ = true;
    return false;
  }
  const std::uint64_t stride = limits_.unit_stride ? limits_.unit_stride : 1;

  while (pos_ < total) {
    const std::uint64_t idx = pos_++;
    if (idx < limits_.first_unit) continue;
    if (stride > 1 && ((idx - limits_.first_unit) % stride) != 0) continue;

    std::string err;
    if (!ctx_->unit_header(idx, out, &err)) {
      ++errors_;
      if (error) *error = err;
      continue;  // skip a bad unit rather than aborting the scan
    }
    index_ = idx;  // index of the unit just returned
    ++visited_;
    return true;
  }
  done_ = true;
  return false;
}


DwarfContext::ParallelScan DwarfContext::parallel_scan(
    const std::string& path, unsigned nthreads, const ScanLimits& limits,
    std::atomic<bool>* cancel,
    const std::function<void(const WalkStats&, std::uint64_t)>& progress) {
  ParallelScan out;
  elf::ElfFile elf;
  std::string err;
  if (!elf.open(path, &err)) {
    out.error = err;
    return out;
  }
  DwarfContext probe(elf);
  if (!probe.sections().has_info()) {
    out.error = "no .debug_info: nothing to scan";
    return out;
  }
  std::vector<UnitHeader> headers;
  {
    UnitIterator it(probe, limits);
    UnitHeader h;
    while (it.next(h, &err)) headers.push_back(h);
    out.skipped_errors = it.skipped_errors();
  }

  const unsigned n = std::max(1u, std::min(nthreads == 0 ? std::thread::hardware_concurrency() : nthreads, 8u));

  struct Shared {
    WalkStats merged;
    std::uint64_t skipped = 0;
    bool aborted = false;
    std::mutex m;
  };
  Shared sh;
  sh.merged.tag_counts.assign(0x500, 0);
  sh.skipped = out.skipped_errors;

  std::vector<std::thread> threads;
  for (unsigned t = 0; t < n; ++t) {
    threads.emplace_back([&, t]() {
      // Each worker owns a separate file handle so the hot path is lock-free.
      std::string ignore_err;
      elf::ElfFile ef;
      if (!ef.open(path, &ignore_err)) return;
      DwarfContext ctx(ef);
      const std::uint64_t cap = limits.max_dies == 0 ? 0 : std::max<std::uint64_t>(1, limits.max_dies / n);
      for (std::size_t i = t; i < headers.size(); i += n) {
        if (cancel != nullptr && cancel->load()) {
          std::lock_guard<std::mutex> lk(sh.m);
          sh.aborted = true;
          break;
        }
        const UnitHeader& h = headers[i];
        WalkStats local;
        local.tag_counts.assign(0x500, 0);
        const AbbrevTable* ab = ctx.abbrev_table(h, nullptr);
        if (ab == nullptr) {
          ++local.failed_units;
        } else {
          UnitWalker w(ctx.info(), h, ab);
          w.reset();
          Die d;
          while (w.next(d)) {
            ++local.dies;
            if (d.tag() < local.tag_counts.size()) ++local.tag_counts[d.tag()];
            if (d.depth() > local.max_depth) local.max_depth = d.depth();
            if (cap != 0 && local.dies >= cap) break;
          }
          local.bytes_scanned += h.body_size();
          ++local.units;
        }
        {
          std::lock_guard<std::mutex> lk(sh.m);
          sh.merged.units += local.units;
          sh.merged.dies += local.dies;
          sh.merged.bytes_scanned += local.bytes_scanned;
          sh.merged.max_depth = std::max(sh.merged.max_depth, local.max_depth);
          sh.merged.failed_units += local.failed_units;
          for (std::size_t k = 0; k < sh.merged.tag_counts.size(); ++k)
            sh.merged.tag_counts[k] += local.tag_counts[k];
          if (progress) progress(sh.merged, sh.skipped);
        }
      }
    });
  }
  for (auto& t : threads) t.join();
  out.stats = sh.merged;
  out.aborted = sh.aborted;
  return out;
}

}  // namespace stellar::dwarf
