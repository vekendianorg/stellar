// SPDX-License-Identifier: MIT
// Turning a function's bytes into printable instructions. See bodies.h.

#include "stellar/output/bodies.h"

#include <algorithm>
#include <cinttypes>
#include <cstdio>
#include <string>

namespace stellar::output {
namespace {

/// "0x1535394" -- lower case, 0x-prefixed, no padding. The address of an
/// instruction is read, not interpreted, so it is printed exactly as it is.
std::string hex_addr(std::uint64_t v) {
  char buf[32];
  std::snprintf(buf, sizeof buf, "0x%" PRIx64, v);
  return buf;
}

/// "FD 7B BF A9" -- the bytes, upper case, one space between each pair.
std::string spaced_hex(std::string_view packed) {
  std::string out;
  out.reserve(packed.size() * 2);
  for (std::size_t i = 0; i + 1 < packed.size(); i += 2) {
    if (!out.empty()) out.push_back(' ');
    out.push_back(packed[i]);
    out.push_back(packed[i + 1]);
  }
  return out;
}

/// The target of a `bl`/`b`/`jmp`-style branch, or 0 when the instruction is not
/// a direct branch.
///
/// Only direct branches to a known address are ever annotated. Nothing else is
/// inferable from the instruction text alone: a `mov` of an address is not a call,
/// a string load is not a call, and guessing either would put a name in the output
/// that the binary never said.
std::uint64_t branch_target(std::string_view text) {
  // Capstone renders a direct branch target as the bare hex address with no
  // leading '#', e.g. "bl 0x7db0". Anything with a dereference, a register
  // operand or a leading '#' is indirect and is left alone.
  const std::size_t sp = text.find(' ');
  if (sp == std::string_view::npos) return 0;
  std::string_view ops = text.substr(sp + 1);
  if (ops.empty() || ops.front() == '#' || ops.front() == '[' || ops.front() == 'x') return 0;
  // A direct target is hex digits only, optionally signed for a backwards branch.
  std::size_t i = 0;
  if (ops[i] == '-') ++i;
  bool any = false;
  for (; i < ops.size(); ++i) {
    const char c = ops[i];
    const bool hex = (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F');
    if (!hex) return 0;
    any = true;
  }
  if (!any) return 0;
  std::string digits(ops);
  try {
    return std::stoull(digits, nullptr, 16);
  } catch (...) {
    return 0;
  }
}

}  // namespace

std::string BodyBlock::header() const {
  if (!ok) return note.empty() ? std::string() : "// Body: " + note;
  const char* src = range == RangeSource::kDwarf ? "dwarf" : "symtab";
  return "// Body: asm Insns: " + std::to_string(insns) + " Bytes: " + std::to_string(bytes) +
         " Range: " + src;
}

ElfBodySource::ElfBodySource(const elf::ElfFile& file,
                             std::unordered_map<std::uint64_t, std::string> names)
    : file_(&file),
      arch_(disasm::arch_for_machine(file.header().e_machine)),
      names_(std::move(names)) {}

bool ElfBodySource::bytes_at(std::uint64_t addr, std::uint64_t size,
                             std::vector<std::uint8_t>& out) const {
  if (file_ == nullptr || size == 0) return false;
  std::uint64_t offset = 0;
  // vaddr_to_offset consults PT_LOAD and refuses an address that is not backed by
  // file contents, which is exactly the .bss and padding case: those bytes are
  // not in the file, so they cannot be disassembled and must not be read.
  if (!file_->vaddr_to_offset(addr, offset)) return false;
  // Clamp to the end of the PT_LOAD segment containing `addr`. A length that
  // runs off the end of its segment is corrupt or simply wrong, and reading
  // past it would disassemble the next object as if it were this function. This
  // is the last of three guards (size cap, PT_LOAD check, bounds-checked view);
  // all three exist because a length here comes from untrusted input.
  std::uint64_t avail = 0;
  for (const elf::Phdr64& ph : file_->program_headers()) {
    if (ph.p_type != elf::kPtLoad) continue;
    if (addr < ph.p_vaddr || addr >= ph.p_vaddr + ph.p_memsz) continue;
    avail = ph.p_vaddr + ph.p_filesz - addr;
    break;
  }
  if (avail == 0) return false;
  if (size > avail) size = avail;
  if (size > kMaxFunctionBytes) size = kMaxFunctionBytes;
  // Read through the mapping rather than a section: code lives in .text, and
  // only the program headers say where a virtual address really is. view_at is
  // bounds-checked, so a corrupt offset cannot walk off the file.
  const util::ByteView v = file_->mapping().view_at(offset, size);
  if (v.size() != size) return false;
  const std::uint8_t* base = v.data();
  if (base == nullptr) return false;
  out.assign(base, base + size);
  return true;
}

std::string ElfBodySource::name_for(std::uint64_t addr) const {
  const auto it = names_.find(addr);
  return it == names_.end() ? std::string() : it->second;
}

RangeSource ElfBodySource::fallback_range(std::uint64_t addr,
                                          std::uint64_t& size) const {
  size = 0;
  if (file_ == nullptr || addr == 0) return RangeSource::kNone;
  for (const elf::Symbol& s : file_->symbols()) {
    // STT_FUNC only: a size on an object symbol describes data, and using it as a
    // code length would print the object after the function as instructions.
    if (s.type() != static_cast<std::uint8_t>(elf::StT::kFunc)) continue;
    if (s.value == 0 || s.size == 0) continue;
    // Thumb functions are entered with bit 0 set; the symbol value is not. One
    // comparison covers both, so the match does not depend on the caller having
    // stripped the tag.
    if (s.value != (addr & ~1ull)) continue;
    size = s.size;
    return RangeSource::kSymtab;
  }
  return RangeSource::kNone;
}

BodyBlock make_body(const BodySource& src, std::uint64_t addr, std::uint64_t size,
                    RangeSource range) {
  BodyBlock b;
  // A length is required, and it comes from DWARF first and the ELF symbol table
  // second. Neither knowing one is "no-range" rather than a guess: claiming to
  // know the instructions after the end of a function is the one failure this
  // whole module exists to prevent.
  if (range == RangeSource::kNone) {
    std::uint64_t fb = 0;
    range = src.fallback_range(addr, fb);
    size = fb;
  }
  // Assigned after the fallback so the header reports the source actually used.
  b.range = range;
  if (addr == 0 || size == 0 || range == RangeSource::kNone) {
    b.note = "no-range";
    return b;
  }
  const disasm::Arch arch = src.arch();
  if (arch == disasm::Arch::kUnsupported) {
    b.note = "unsupported-arch";
    return b;
  }
  const std::string_view why = disasm::unavailable_reason(arch);
  if (!why.empty()) {
    b.note = std::string(why);
    return b;
  }
  std::vector<std::uint8_t> code;
  if (!src.bytes_at(addr, size, code)) {
    b.note = "not-file-backed";
    return b;
  }
  // Thumb is decided by the caller from the ELF; a disassembly of ARM code in
  // the wrong mode produces plausible nonsense, so this is never inferred here.
  const bool thumb = (addr & 1u) != 0 && arch == disasm::Arch::kArm;
  auto d = disasm::Disassembler::open(arch, thumb);
  if (!d || !d->reason().empty()) {
    b.note = d && !d->reason().empty() ? std::string(d->reason()) : std::string("capstone-open-failed");
    return b;
  }
  const std::vector<disasm::Instruction> insns = d->disassemble(code.data(), code.size(), addr & ~1ull);
  b.lines.reserve(insns.size());
  for (const disasm::Instruction& i : insns) {
    std::string line = hex_addr(i.address) + "  " + spaced_hex(i.bytes_hex) + "  " + i.text;
    if (!i.undecodable) {
      // Only a direct branch to a known function earns an annotation.
      const std::uint64_t target = branch_target(i.text);
      if (target != 0) {
        const std::string name = src.name_for(target);
        if (!name.empty()) line += "  // -> " + name;
      }
    }
    b.lines.push_back(std::move(line));
  }
  b.ok = true;
  b.insns = insns.size();
  std::uint64_t total = 0;
  for (const disasm::Instruction& i : insns) total += i.size;
  b.bytes = total;
  return b;
}

bool warn_bodies_unavailable(disasm::Arch arch, std::FILE* out) {
  const std::string_view why = disasm::unavailable_reason(arch);
  if (why.empty()) return false;
  std::fprintf(out, "note: --bodies=asm requested but disassembly is unavailable (%.*s); "
                    "no function bodies will be emitted\n",
               static_cast<int>(why.size()), why.data());
  return true;
}

}  // namespace stellar::output
