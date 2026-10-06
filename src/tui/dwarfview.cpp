// SPDX-License-Identifier: MIT
#include "stellar/tui/dwarfview.h"

#include <algorithm>
#include <chrono>
#include <exception>

#include "stellar/dwarf/constants.h"
#include "stellar/dwarf/dwarf_context.h"
#include "stellar/elf/elf_file.h"

namespace stellar::tui {

namespace {
using Clock = std::chrono::steady_clock;
double since(Clock::time_point t0) {
  return std::chrono::duration<double>(Clock::now() - t0).count();
}
}  // namespace

UnitList list_units(const std::string& path, std::uint64_t max_rows) {
  UnitList out;
  try {
    elf::ElfFile elf;
    std::string err;
    if (!elf.open(path, &err)) {
      out.error = err;
      return out;
    }
    dwarf::DwarfContext ctx(elf);
    if (!ctx.sections().has_info()) {
      out.error = "no .debug_info: nothing to list";
      return out;
    }
    out.total = ctx.unit_count();
    dwarf::DwarfContext::UnitIterator it(ctx);
    dwarf::UnitHeader h;
    std::string uerr;
    while (it.next(h, &uerr)) {
      if (out.rows.size() >= max_rows) {
        out.truncated = true;
        break;
      }
      UnitRow r;
      r.index = it.index();
      r.offset = h.offset;
      r.abbrev_offset = h.abbrev_offset;
      r.version = h.version;
      r.address_size = h.address_size;
      out.rows.push_back(r);
    }
    out.unparsable = it.skipped_errors();
    out.ok = true;
  } catch (const std::exception& e) {
    out.ok = false;
    out.error = e.what();
  }
  return out;
}

bool count_unit_dies(const std::string& path, std::uint64_t index, std::uint64_t& dies,
                     std::string* error) {
  try {
    elf::ElfFile elf;
    std::string err;
    if (!elf.open(path, &err)) {
      if (error) *error = err;
      return false;
    }
    dwarf::DwarfContext ctx(elf);
    dwarf::DwarfContext::UnitIterator it(ctx);
    dwarf::UnitHeader h;
    while (it.next(h, &err)) {
      if (it.index() != index) continue;
      const dwarf::AbbrevTable* ab = ctx.abbrev_table(h, &err);
      if (ab == nullptr) {
        if (error) *error = err.empty() ? "abbreviation table unreadable" : err;
        return false;
      }
      dwarf::UnitWalker w(ctx.info(), h, ab);
      w.reset();
      dwarf::Die d;
      dies = 0;
      while (w.next(d)) ++dies;
      return true;
    }
    if (error) *error = "unit not found";
  } catch (const std::exception& e) {
    if (error) *error = e.what();
  }
  return false;
}

ScanJob::~ScanJob() noexcept {
  cancel_.store(true);
  join();
}

void ScanJob::join() noexcept {
  if (worker_.joinable()) worker_.join();
}

bool ScanJob::start(const std::string& path) {
  if (running_.load()) return false;
  join();
  cancel_.store(false);
  {
    std::lock_guard<std::mutex> lock(mutex_);
    snap_ = ScanSnapshot{};
    snap_.phase = ScanSnapshot::Phase::kRunning;
  }
  running_.store(true);
  try {
    worker_ = std::thread([this, path] { run(path); });
  } catch (const std::exception& e) {
    running_.store(false);
    std::lock_guard<std::mutex> lock(mutex_);
    snap_.phase = ScanSnapshot::Phase::kFailed;
    snap_.error = std::string("could not start the scan thread: ") + e.what();
    return false;
  }
  return true;
}

ScanSnapshot ScanJob::snapshot() const {
  std::lock_guard<std::mutex> lock(mutex_);
  return snap_;
}

void ScanJob::run(std::string path) {
  const auto t0 = Clock::now();
  const auto finish = [&](ScanSnapshot::Phase p, std::string err) {
    std::lock_guard<std::mutex> lock(mutex_);
    snap_.phase = p;
    snap_.error = std::move(err);
    snap_.elapsed_seconds = since(t0);
    running_.store(false);
  };
  try {
    elf::ElfFile elf;
    std::string err;
    if (!elf.open(path, &err)) {
      finish(ScanSnapshot::Phase::kFailed, err);
      return;
    }
    dwarf::DwarfContext ctx(elf);
    if (!ctx.sections().has_info()) {
      finish(ScanSnapshot::Phase::kFailed, "no .debug_info: nothing to scan");
      return;
    }
    {
      std::lock_guard<std::mutex> lock(mutex_);
      snap_.units_total = ctx.unit_count();
    }
    // TUI scan: the heavy stage. It is already what cmd_scan does internally,
    // so the UI and CLI agree byte for byte.
    const auto publish = [&](const dwarf::WalkStats& s, std::uint64_t skipped) {
      std::lock_guard<std::mutex> lock(mutex_);
      snap_.units = s.units;
      snap_.dies = s.dies;
      snap_.max_depth = s.max_depth;
      snap_.bytes = s.bytes_scanned;
      snap_.failed_units = s.failed_units;
      snap_.skipped_units = skipped;
      snap_.elapsed_seconds = since(t0);
    };
    dwarf::DwarfContext::ParallelScan res = dwarf::DwarfContext::parallel_scan(
        path, std::max(1u, std::thread::hardware_concurrency()), {}, &cancel_, publish);
    if (cancel_.load()) {
      publish(res.stats, res.skipped_errors);
      finish(ScanSnapshot::Phase::kCancelled, {});
      return;
    }
    if (!res.error.empty()) {
      finish(ScanSnapshot::Phase::kFailed, res.error);
      return;
    }
    {
      std::vector<std::pair<std::string, std::uint64_t>> tags;
      for (std::size_t t = 0; t < res.stats.tag_counts.size(); ++t) {
        if (res.stats.tag_counts[t] == 0) continue;
        tags.emplace_back(std::string(dwarf::tag_name(static_cast<std::uint32_t>(t))),
                          res.stats.tag_counts[t]);
      }
      std::stable_sort(tags.begin(), tags.end(),
                       [](const auto& a, const auto& b) { return a.second > b.second; });
      std::lock_guard<std::mutex> lock(mutex_);
      snap_.tags = std::move(tags);
    }
    finish(ScanSnapshot::Phase::kDone, {});
  } catch (const std::exception& e) {
    finish(ScanSnapshot::Phase::kFailed, e.what());
  }
}

}  // namespace stellar::tui
