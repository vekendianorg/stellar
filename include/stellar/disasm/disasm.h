// SPDX-License-Identifier: MIT
// Disassembly, over an optional Capstone.
//
// Two rules shape this layer. First: never invent. An instruction that did not
// decode is reported as `.byte` with its raw bytes, never as a plausible-looking
// mnemonic, because a wrong instruction in a disassembly is worse than a gap --
// it reads as knowledge. Second: never guess. The architecture and the ARM/Thumb
// mode both come from the caller, which is the only place that knows them from
// the ELF; nothing here infers either from the bytes.
//
// The whole module compiles to nothing useful when Capstone is absent, and the
// emitter's "bodies" option is required to ask for it: `available()` returning
// false is a normal, expected state, not an error. That is why the emitters can
// carry bodies code unconditionally and still produce byte-identical output with
// STELLAR_CAPSTONE=OFF.
#pragma once

#include <cstdint>
#include <memory>
#include <string>
#include <string_view>
#include <vector>

namespace stellar::disasm {

/// The architectures this build can disassemble, and the ELF machine values they
/// correspond to. A machine that is not in here is not "unknown, assume
/// AArch64": it is unsupported, and the caller says so rather than emitting
/// instructions for a processor the file was never built for.
enum class Arch : std::uint8_t {
  kUnsupported = 0,
  kX86,      ///< EM_386
  kX86_64,   ///< EM_X86_64
  kArm,      ///< EM_ARM
  kAArch64,  ///< EM_AARCH64
  kMips,     ///< EM_MIPS
};

/// Maps an ELF e_machine to an Arch. kUnsupported for anything not built here.
[[nodiscard]] Arch arch_for_machine(std::uint16_t e_machine) noexcept;
[[nodiscard]] std::string_view arch_name(Arch a) noexcept;

/// True when this build can actually disassemble `a`. False both when the
/// architecture is not supported and when Capstone was not compiled in, and the
/// two are reported separately so the user is told which it is.
[[nodiscard]] bool capstone_built() noexcept;
[[nodiscard]] bool arch_supported(Arch a) noexcept;
/// The one-line reason a disassembly could not be produced, for the emitter to
/// print when it degrades. Empty when the build can disassemble `a`.
[[nodiscard]] std::string_view unavailable_reason(Arch a) noexcept;

struct Instruction {
  std::uint64_t address = 0;
  /// Length in bytes as decoded. For an undecodable run, how many bytes it spans.
  std::uint32_t size = 0;
  /// Mnemonic plus operands, as Capstone spelled it ("stp x29, x30, [sp, #-16]!").
  std::string text;
  /// True when these bytes did not decode and `text` is a `.byte` run. The bytes
  /// are still reported: knowing where the decoder gave up is more useful than a
  /// silent hole, and it never masquerades as an instruction.
  bool undecodable = false;
  /// Raw bytes covered by this record, hex-encoded without separators.
  std::string bytes_hex;
};

/// A disassembler for one architecture and mode. Move-only: Capstone handles
/// are not copyable and double-closing one is worse than leaking it.
class Disassembler {
 public:
  /// Opens a handle. Returns null when `a` is unsupported or Capstone is absent;
  /// check `reason()` for which, because the two are different messages to a user.
  ///
  /// `thumb` selects Thumb for ARM; it is ignored for every other architecture.
  /// The caller decides, because only the caller knows: a symbol address with bit
  /// 0 set means Thumb in the ARM ELF convention, and inferring it from the
  /// instruction stream would be a guess.
  static std::unique_ptr<Disassembler> open(Arch a, bool thumb);
  ~Disassembler();
  Disassembler(const Disassembler&) = delete;
  Disassembler& operator=(const Disassembler&) = delete;

  [[nodiscard]] std::string_view reason() const noexcept;

  /// Decodes `bytes`, which live at `base_address`. Reads nothing outside the
  /// given span.
  ///
  /// Every result is capped: at most kMaxInstructions records, and a single
  /// undecodable run is coalesced into one record of at most kMaxUndecodableRun
  /// bytes. Both caps exist because the input is untrusted -- a corrupt length
  /// must not be able to produce gigabytes of text.
  [[nodiscard]] std::vector<Instruction> disassemble(const std::uint8_t* bytes,
                                                     std::size_t size,
                                                     std::uint64_t base_address);

  static constexpr std::size_t kMaxInstructions = 20000;
  static constexpr std::size_t kMaxUndecodableRun = 16;

 private:
  Disassembler() = default;
  struct Impl;
  std::unique_ptr<Impl> impl_;
  std::string reason_;
};

}  // namespace stellar::disasm