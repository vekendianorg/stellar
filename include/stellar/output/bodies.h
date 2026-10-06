// SPDX-License-Identifier: MIT
// Function bodies for the emitters.
//
// Kept out of emit_il2cpp.cpp and emit_tree.cpp because it is the one piece of
// emit state that is neither C# spelling nor source placement: it needs the ELF
// (to turn a virtual address into file bytes) and Capstone (to decode them),
// while the emitters only ever see an ir::Model.
//
// The default is "no bodies". A null BodySource therefore has to produce exactly
// the output these emitters produced before this existed, which is why every
// caller treats nullptr as the normal case rather than a degraded one.

#pragma once

#include <cstdint>
#include <string>
#include <string_view>
#include <unordered_map>
#include <vector>

#include "stellar/disasm/disasm.h"
#include "stellar/elf/elf_file.h"

namespace stellar::output {

/// Where a function's length came from. Reported because the two are not equally
/// trustworthy and a reader should know which bound produced the bytes.
enum class RangeSource : std::uint8_t {
  kNone,     ///< no length at all
  kDwarf,    ///< DW_AT_low_pc / DW_AT_high_pc
  kSymtab,   ///< ELF symbol st_size
};

/// One disassembled function, already formatted.
struct BodyBlock {
  /// False when there is nothing to print; `note` then says why.
  bool ok = false;
  /// The reason there is no body, without the "// Body: " prefix: "no-range",
  /// "capstone-not-built", "unsupported-arch", "not-file-backed".
  std::string note;
  RangeSource range = RangeSource::kNone;
  std::uint64_t insns = 0;
  std::uint64_t bytes = 0;
  /// One ready-to-print line per instruction:
  /// "0x1535394  FD 7B BF A9  stp x29, x30, [sp, #-0x10]!"
  std::vector<std::string> lines;
  /// The "// Body: ..." header line, empty when there is no body.
  [[nodiscard]] std::string header() const;
};

/// Everything the emitters need from outside the model to produce a body.
class BodySource {
 public:
  virtual ~BodySource() = default;
  /// The architecture of the file, for the unsupported-arch case.
  [[nodiscard]] virtual disasm::Arch arch() const = 0;
  /// Reads `size` bytes at virtual address `addr`. False when the range is not
  /// file-backed -- .bss and holes are not code, and reading them would print
  /// zeros as if they were instructions.
  [[nodiscard]] virtual bool bytes_at(std::uint64_t addr, std::uint64_t size,
                                      std::vector<std::uint8_t>& out) const = 0;
  /// The name to annotate a branch to `addr` with, or empty when unknown. Only
  /// a known function address yields a name; nothing is guessed from a target
  /// that merely looks like code.
  [[nodiscard]] virtual std::string name_for(std::uint64_t addr) const = 0;
  /// The ELF symbol table's length for `addr`, or 0 when it has none. This is the
  /// fallback for functions DWARF says nothing about; it is consulted only
  /// after DWARF, and never instead of it.
  ///
  /// `RangeSource::kNone` comes back when neither source knows a length.
  [[nodiscard]] virtual RangeSource fallback_range(std::uint64_t addr,
                                                   std::uint64_t& size) const = 0;
};

/// A BodySource over a real ELF, with a caller-supplied address-to-name map.
///
/// `names` is built by the caller from the model, because only the caller knows
/// which qualified name belongs to which address. It is copied rather than
/// referenced so the source can outlive the map.
class ElfBodySource final : public BodySource {
 public:
  ElfBodySource(const elf::ElfFile& file,
                std::unordered_map<std::uint64_t, std::string> names);

  [[nodiscard]] disasm::Arch arch() const override { return arch_; }
  [[nodiscard]] bool bytes_at(std::uint64_t addr, std::uint64_t size,
                              std::vector<std::uint8_t>& out) const override;
  [[nodiscard]] std::string name_for(std::uint64_t addr) const override;
  [[nodiscard]] RangeSource fallback_range(std::uint64_t addr,
                                           std::uint64_t& size) const override;

  /// Largest function this source will read. A corrupt length must not be able to
  /// turn one line of output into gigabytes; past the cap the body is truncated
  /// and the header says so.
  static constexpr std::uint64_t kMaxFunctionBytes = 64 * 1024;

 private:
  const elf::ElfFile* file_ = nullptr;
  disasm::Arch arch_ = disasm::Arch::kUnsupported;
  std::unordered_map<std::uint64_t, std::string> names_;
};

/// Builds the body for one function. `size` must come from DWARF or the symbol
/// table: a zero size yields RangeSource::kNone and a "no-range" note rather
/// than a guess.
BodyBlock make_body(const BodySource& src, std::uint64_t addr, std::uint64_t size,
                    RangeSource range);

/// The one-line warning printed on stderr when bodies were asked for and cannot
/// be produced. Returns true when it printed something, so the caller only ever
/// says it once.
bool warn_bodies_unavailable(disasm::Arch arch, std::FILE* out);

}  // namespace stellar::output
