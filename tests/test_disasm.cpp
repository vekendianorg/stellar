// SPDX-License-Identifier: MIT
// The disassembler wrapper and the body builder.
//
// These tests are written so they mean the same thing in both build
// configurations. STELLAR_CAPSTONE=OFF is not a degraded mode that skips these:
// the arch table, the reason strings and the "no range, no body" rules are the
// same either way, and an emitter that invents a body when it cannot disassemble
// is the failure worth catching. Only the decode assertions are guarded, and
// they say why they are guarded rather than silently passing.
#include <cstdint>
#include <string>
#include <vector>

#include "stellar/disasm/disasm.h"
#include "stellar/elf/elf_file.h"
#include "stellar/output/bodies.h"

#include "test_framework.h"

using namespace stellar;

namespace {

/// A BodySource over bytes chosen by the test, so the range rules can be driven
/// without needing a real ELF for every case.
class FakeSource final : public output::BodySource {
 public:
  std::vector<std::uint8_t> bytes;
  bool file_backed = true;
  std::uint64_t fb_size = 0;
  std::unordered_map<std::uint64_t, std::string> names;

  [[nodiscard]] disasm::Arch arch() const override { return machine; }
  [[nodiscard]] bool bytes_at(std::uint64_t, std::uint64_t size,
                              std::vector<std::uint8_t>& out) const override {
    if (!file_backed) return false;
    out.assign(bytes.begin(),
               bytes.begin() + static_cast<long>(size < bytes.size() ? size : bytes.size()));
    return true;
  }
  [[nodiscard]] std::string name_for(std::uint64_t a) const override {
    const auto it = names.find(a);
    return it == names.end() ? std::string() : it->second;
  }
  [[nodiscard]] output::RangeSource fallback_range(std::uint64_t a,
                                                   std::uint64_t& size) const override {
    if (fb_size == 0 || a != 0x1000) {
      size = 0;
      return output::RangeSource::kNone;
    }
    size = fb_size;
    return output::RangeSource::kSymtab;
  }

  // Named differently from the arch() accessor it backs: a data member called
  // `arch` would shadow the override and stop FakeSource satisfying BodySource.
  disasm::Arch machine = disasm::Arch::kAArch64;
};

}  // namespace

// --- the arch table --------------------------------------------------------

STELLAR_TEST(Disasm, ArchTableCoversExactlyTheFourDocumentedMachines) {
  // Five machines map to four architectures (x86 and x86-64 share a port), and
  // anything else is unsupported rather than defaulted.
  EXPECT_TRUE(disasm::arch_for_machine(elf::kEmX86_64) == disasm::Arch::kX86_64);
  EXPECT_TRUE(disasm::arch_for_machine(elf::kEm386) == disasm::Arch::kX86);
  EXPECT_TRUE(disasm::arch_for_machine(elf::kEmArm) == disasm::Arch::kArm);
  EXPECT_TRUE(disasm::arch_for_machine(elf::kEmAarch64) == disasm::Arch::kAArch64);
  EXPECT_TRUE(disasm::arch_for_machine(elf::kEmMips) == disasm::Arch::kMips);
  // RISC-V, PowerPC and an out-of-range value are all unsupported. Defaulting
  // them to AArch64 would decode valid instructions for the wrong CPU.
  EXPECT_TRUE(disasm::arch_for_machine(243) == disasm::Arch::kUnsupported);
  EXPECT_TRUE(disasm::arch_for_machine(0xffff) == disasm::Arch::kUnsupported);
}

STELLAR_TEST(Disasm, UnsupportedArchIsNamedUnsupportedNotUnknown) {
  EXPECT_TRUE(disasm::unavailable_reason(disasm::Arch::kUnsupported) == "unsupported-arch");
  EXPECT_TRUE(disasm::arch_name(disasm::Arch::kUnsupported) == "unsupported");
}

STELLAR_TEST(Disasm, TheTwoReasonsForNoDisassemblyAreDistinct) {
  // "this build has no Capstone" and "this CPU is not supported" are different
  // messages, because only one of them is fixed by rebuilding.
  const std::string_view built = disasm::unavailable_reason(disasm::Arch::kAArch64);
  if (disasm::capstone_built()) {
    EXPECT_TRUE(built.empty());
    EXPECT_TRUE(disasm::arch_supported(disasm::Arch::kAArch64));
  } else {
    EXPECT_TRUE(built == "capstone-not-built");
    EXPECT_FALSE(disasm::arch_supported(disasm::Arch::kAArch64));
  }
  // Unsupported is reported as unsupported in either configuration.
  EXPECT_TRUE(disasm::unavailable_reason(disasm::Arch::kUnsupported) == "unsupported-arch");
}

STELLAR_TEST(Disasm, OpeningAnUnsupportedArchFailsAndSaysWhy) {
  auto d = disasm::Disassembler::open(disasm::Arch::kUnsupported, false);
  EXPECT_TRUE(d != nullptr);
  EXPECT_TRUE(d->reason() == "unsupported-arch");
  // And it decodes nothing at all, rather than something plausible.
  const std::uint8_t code[] = {0xfd, 0x7b, 0xbf, 0xa9};
  EXPECT_TRUE(d->disassemble(code, sizeof(code), 0x1000).empty());
}

// --- range rules: nothing is guessed --------------------------------------

STELLAR_TEST(Bodies, NoLengthMeansNoBodyAndTheReasonIsPrinted) {
  FakeSource src;
  src.machine = disasm::Arch::kAArch64;
  const output::BodyBlock b =
      output::make_body(src, 0x1000, 0, output::RangeSource::kNone);
  EXPECT_FALSE(b.ok);
  // Without a length the answer is "no-range", never an instruction.
  EXPECT_TRUE(b.note == "no-range");
  EXPECT_TRUE(b.header() == "// Body: no-range");
  EXPECT_TRUE(b.lines.empty());
}

STELLAR_TEST(Bodies, SymbolTableLengthIsUsedOnlyAfterDwarfIsSilent) {
  FakeSource src;
  src.fb_size = 4;
  // DWARF knows: the DWARF length is used and the symbol table never consulted.
  const output::BodyBlock d = output::make_body(src, 0x1000, 4, output::RangeSource::kDwarf);
  EXPECT_TRUE(d.range == output::RangeSource::kDwarf);
  // DWARF silent, symbol table knows: the body is produced and attributed.
  const output::BodyBlock s = output::make_body(src, 0x1000, 0, output::RangeSource::kNone);
  if (disasm::capstone_built()) {
    EXPECT_TRUE(s.ok);
    EXPECT_TRUE(s.range == output::RangeSource::kSymtab);
    EXPECT_TRUE(s.header().find("Range: symtab") != std::string::npos);
  } else {
    // The range is still attributed correctly even though it cannot be decoded.
    EXPECT_TRUE(s.range == output::RangeSource::kSymtab);
    EXPECT_TRUE(s.note == "capstone-not-built");
  }
}

STELLAR_TEST(Bodies, AnUnsupportedArchitectureNeverProducesInstructions) {
  FakeSource src;
  src.machine = disasm::Arch::kUnsupported;
  src.bytes = {0xfd, 0x7b, 0xbf, 0xa9};
  const output::BodyBlock b = output::make_body(src, 0x1000, 4, output::RangeSource::kDwarf);
  EXPECT_FALSE(b.ok);
  EXPECT_TRUE(b.note == "unsupported-arch");
  EXPECT_TRUE(b.lines.empty());
}

STELLAR_TEST(Bodies, BytesThatAreNotFileBackedYieldNoBody) {
  FakeSource src;
  src.machine = disasm::Arch::kAArch64;
  src.file_backed = false;
  const output::BodyBlock b = output::make_body(src, 0x1000, 4, output::RangeSource::kDwarf);
  EXPECT_FALSE(b.ok);
  EXPECT_TRUE(b.lines.empty());
  // Which reason is reported depends on the build, and both are true: without
  // Capstone there is no disassembler at all, which is the more useful thing to
  // say. What must hold in either configuration is that no body is invented.
  EXPECT_TRUE(b.note == "not-file-backed" || b.note == "capstone-not-built");
}

// --- decoding, only meaningful when Capstone is present -------------------

#if defined(STELLAR_WITH_CAPSTONE)

STELLAR_TEST(Disasm, DecodesAarch64PrologueAndReportsRawBytes) {
  // stp x29, x30, [sp, #-0x10]! ; the canonical AArch64 frame setup.
  const std::uint8_t code[] = {0xfd, 0x7b, 0xbf, 0xa9, 0xc0, 0x03, 0x5f, 0xd6};
  auto d = disasm::Disassembler::open(disasm::Arch::kAArch64, false);
  ASSERT_TRUE(d != nullptr && d->reason().empty());
  const auto insns = d->disassemble(code, sizeof(code), 0x1000);
  ASSERT_EQ_SIZE(insns, 2);
  EXPECT_EQ(insns[0].address, std::uint64_t{0x1000});
  EXPECT_EQ(insns[0].size, std::uint32_t{4});
  // The bytes are reported exactly as given, so a reader can check the decode.
  EXPECT_TRUE(insns[0].bytes_hex == "FD7BBFA9");
  EXPECT_TRUE(insns[0].text.rfind("stp", 0) == 0);
  EXPECT_FALSE(insns[0].undecodable);
  // The second is ret, and addresses advance by the decoded length.
  EXPECT_EQ(insns[1].address, std::uint64_t{0x1004});
  EXPECT_TRUE(insns[1].text.rfind("ret", 0) == 0);
}

STELLAR_TEST(Disasm, UndecodableBytesAreReportedAsBytesAndNotAsInstructions) {
  // 0xffffffff is not a valid AArch64 encoding. Note that 0x00000000 *is*: it
  // decodes as `udf #0`, the architecturally defined "permanently undefined"
  // instruction. Guessing that would have been wrong and the test would have
  // encoded the guess.
  const std::uint8_t junk[] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
  auto d = disasm::Disassembler::open(disasm::Arch::kAArch64, false);
  ASSERT_TRUE(d != nullptr && d->reason().empty());
  const auto insns = d->disassemble(junk, sizeof(junk), 0x1000);
  ASSERT_TRUE(!insns.empty());
  // Whatever it produced, nothing is presented as a decoded instruction.
  for (const disasm::Instruction& i : insns) {
    EXPECT_TRUE(i.undecodable);
    EXPECT_TRUE(i.text.rfind(".byte", 0) == 0);
    EXPECT_FALSE(i.bytes_hex.empty());
  }
  // And the whole run is coalesced, not one record per byte.
  EXPECT_EQ(insns.size(), std::size_t{1});
}

STELLAR_TEST(Disasm, OutputIsCappedSoACorruptLengthCannotRunAway) {
  // 200 kB of 0x00 decodes to nothing under AArch64, and the cap must stop the
  // .byte runs from becoming 200 k records.
  std::vector<std::uint8_t> junk(200000, 0x00);
  auto d = disasm::Disassembler::open(disasm::Arch::kAArch64, false);
  ASSERT_TRUE(d != nullptr && d->reason().empty());
  const auto insns = d->disassemble(junk.data(), junk.size(), 0x1000);
  EXPECT_TRUE(insns.size() <= disasm::Disassembler::kMaxInstructions);
  EXPECT_TRUE(!insns.empty());
}

STELLAR_TEST(Bodies, ABodyIsProducedForRealAarch64BytesWithADwarfHeader) {
  FakeSource src;
  src.machine = disasm::Arch::kAArch64;
  src.bytes = {0xfd, 0x7b, 0xbf, 0xa9, 0xc0, 0x03, 0x5f, 0xd6};
  const output::BodyBlock b = output::make_body(src, 0x1000, 8, output::RangeSource::kDwarf);
  ASSERT_TRUE(b.ok);
  EXPECT_EQ(b.insns, std::uint64_t{2});
  EXPECT_EQ(b.bytes, std::uint64_t{8});
  EXPECT_TRUE(b.header().find("Range: dwarf") != std::string::npos);
  EXPECT_TRUE(b.header().find("Insns: 2") != std::string::npos);
  // Each line carries address, bytes and text, in that order.
  ASSERT_EQ_SIZE(b.lines, 2);
  EXPECT_TRUE(b.lines[0].rfind("0x1000", 0) == 0);
  EXPECT_TRUE(b.lines[0].find("FD 7B BF A9") != std::string::npos);
}

#endif  // STELLAR_WITH_CAPSTONE
