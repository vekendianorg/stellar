// SPDX-License-Identifier: MIT
// The Capstone wrapper. See disasm.h for why it is shaped this way.
//
// This file compiles either way. With STELLAR_WITH_CAPSTONE undefined,
// capstone_built() is a constant false and open() always fails, so no Capstone
// symbol is referenced and the project links exactly as it did before the
// dependency existed.

#include "stellar/disasm/disasm.h"

#include "stellar/elf/elf_types.h"

#if defined(STELLAR_WITH_CAPSTONE)
#include <capstone/capstone.h>
#endif

#include <algorithm>

namespace stellar::disasm {
namespace {

constexpr std::string_view kNoReason;

/// Hex-encodes `len` bytes, upper case, no separators: "FD7BBFA9".
std::string to_hex(const std::uint8_t* p, std::size_t len) {
  static const char* digits = "0123456789ABCDEF";
  std::string out;
  out.reserve(len * 2);
  for (std::size_t i = 0; i < len; ++i) {
    out.push_back(digits[p[i] >> 4]);
    out.push_back(digits[p[i] & 0xf]);
  }
  return out;
}

}  // namespace

Arch arch_for_machine(std::uint16_t e_machine) noexcept {
  switch (e_machine) {
    case elf::kEm386: return Arch::kX86;
    case elf::kEmX86_64: return Arch::kX86_64;
    case elf::kEmArm: return Arch::kArm;
    case elf::kEmAarch64: return Arch::kAArch64;
    case elf::kEmMips: return Arch::kMips;
    default: return Arch::kUnsupported;
  }
}

std::string_view arch_name(Arch a) noexcept {
  switch (a) {
    case Arch::kX86: return "x86";
    case Arch::kX86_64: return "x86-64";
    case Arch::kArm: return "ARM";
    case Arch::kAArch64: return "AArch64";
    case Arch::kMips: return "MIPS";
    case Arch::kUnsupported: break;
  }
  return "unsupported";
}

bool capstone_built() noexcept {
#if defined(STELLAR_WITH_CAPSTONE)
  return true;
#else
  return false;
#endif
}

bool arch_supported(Arch a) noexcept {
  if (a == Arch::kUnsupported) return false;
#if defined(STELLAR_WITH_CAPSTONE)
  // Capstone is built with exactly the architectures listed in the header, so
  // "supported by this build" is "is not the sentinel". If a port is ever
  // compiled out at the CMake level, this switch has to learn about it.
  return true;
#else
  return false;
#endif
}

std::string_view unavailable_reason(Arch a) noexcept {
  if (a == Arch::kUnsupported) return "unsupported-arch";
  if (!capstone_built()) return "capstone-not-built";
  return kNoReason;
}

struct Disassembler::Impl {
#if defined(STELLAR_WITH_CAPSTONE)
  csh handle = 0;
  bool open_handle = false;
#endif
};

Disassembler::~Disassembler() {
#if defined(STELLAR_WITH_CAPSTONE)
  if (impl_ && impl_->open_handle) cs_close(&impl_->handle);
#endif
}

std::unique_ptr<Disassembler> Disassembler::open(Arch a, bool thumb) {
  auto d = std::unique_ptr<Disassembler>(new Disassembler());
  const std::string_view why = unavailable_reason(a);
  if (!why.empty()) {
    d->reason_ = std::string(why);
    return d;
  }
#if defined(STELLAR_WITH_CAPSTONE)
  d->impl_ = std::make_unique<Impl>();
  // Capstone 5 declares cs_mode as its own enum, so the modes cannot be combined
  // with `|` in a constant expression: they are OR-ed through a plain unsigned.
  cs_arch cs_a = CS_ARCH_ARM;
  auto cs_m = static_cast<unsigned>(CS_MODE_LITTLE_ENDIAN);
  switch (a) {
    case Arch::kX86:
      cs_a = CS_ARCH_X86;
      cs_m = CS_MODE_32;
      break;
    case Arch::kX86_64:
      cs_a = CS_ARCH_X86;
      cs_m = CS_MODE_64;
      break;
    case Arch::kArm:
      cs_a = CS_ARCH_ARM;
      // Thumb is the caller's decision, never inferred from the bytes: only the
      // ELF says which encoding a symbol was compiled as.
      cs_m = thumb ? static_cast<unsigned>(CS_MODE_THUMB) : static_cast<unsigned>(CS_MODE_ARM);
      break;
    case Arch::kAArch64:
      cs_a = CS_ARCH_ARM64;
      cs_m = CS_MODE_ARM;
      break;
    case Arch::kMips:
      cs_a = CS_ARCH_MIPS;
      cs_m = static_cast<unsigned>(CS_MODE_MIPS32) | static_cast<unsigned>(CS_MODE_LITTLE_ENDIAN);
      break;
    case Arch::kUnsupported:
      d->reason_ = "unsupported-arch";
      return d;
  }
  const cs_err rc = cs_open(cs_a, static_cast<cs_mode>(cs_m), &d->impl_->handle);
  if (rc != CS_ERR_OK) {
    d->impl_.reset();
    d->reason_ = "capstone-open-failed";
  } else {
    d->impl_->open_handle = true;
  }
#endif
  return d;
}

std::string_view Disassembler::reason() const noexcept { return reason_; }

#if !defined(STELLAR_WITH_CAPSTONE)

std::vector<Instruction> Disassembler::disassemble(const std::uint8_t*, std::size_t,
                                                   std::uint64_t) {
  // Capstone was not compiled in. Returning nothing is the honest answer: the
  // emitter prints "capstone-not-built" rather than inventing a body.
  return {};
}

#else

std::vector<Instruction> Disassembler::disassemble(const std::uint8_t* bytes, std::size_t size,
                                                   std::uint64_t base_address) {
  std::vector<Instruction> out;
  if (bytes == nullptr || size == 0 || impl_ == nullptr || !impl_->open_handle) return out;
  out.reserve(std::min<std::size_t>(size, 8));

  std::size_t consumed = 0;
  std::size_t produced = 0;
  while (consumed < size && produced < kMaxInstructions) {
    cs_insn* insn = nullptr;
    const std::size_t remaining = size - consumed;
    // count = 1: decode one instruction at a time, so a truncated tail becomes a
    // decoded prefix plus a byte run rather than a discarded remainder.
    const unsigned n = cs_disasm(impl_->handle, bytes + consumed, remaining,
                                 base_address + consumed, 1, &insn);
    if (n == 0 || insn == nullptr) {
      // The decoder stopped. Coalesce what it choked on into one .byte run so a
      // data island inside a function does not become thousands of records.
      const std::size_t run = remaining < kMaxUndecodableRun ? remaining : kMaxUndecodableRun;
      Instruction rec;
      rec.address = base_address + consumed;
      rec.size = static_cast<std::uint32_t>(run);
      rec.undecodable = true;
      rec.bytes_hex = to_hex(bytes + consumed, run);
      rec.text = ".byte 0x" + to_hex(bytes + consumed, 1);
      out.push_back(std::move(rec));
      consumed += run;
      ++produced;
      continue;
    }
    const std::size_t len = insn->size == 0 ? 1 : insn->size;
    Instruction rec;
    rec.address = insn->address;
    rec.size = static_cast<std::uint32_t>(len > remaining ? remaining : len);
    // `mnemonic` and `op_str` are fixed-size arrays in cs_insn, never null, so
    // these are read directly rather than null-checked.
    rec.text = insn->mnemonic;
    if (insn->op_str[0] != '\0') {
      rec.text += ' ';
      rec.text += insn->op_str;
    }
    rec.bytes_hex = to_hex(insn->bytes, len > remaining ? remaining : len);
    out.push_back(std::move(rec));
    consumed += len;
    ++produced;
    cs_free(insn, 1);
  }
  return out;
}

#endif

}  // namespace stellar::disasm
