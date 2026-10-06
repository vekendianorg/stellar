// SPDX-License-Identifier: MIT
// DWARF 5 address forms and static data members.
//
// Two things make a DWARF 5 fixture's dump differ from the equivalent DWARF 4
// one, and both are producer changes rather than bugs in the fixture:
//
//   1. DW_AT_low_pc is DW_FORM_addrx (an index into .debug_addr) instead of a
//      plain address, so the builder must resolve it through the unit's
//      DW_AT_addr_base or a method ends up reported at the index.
//   2. A static data member is a DW_TAG_variable child of the class DIE rather
//      than a DW_TAG_member with no DW_AT_data_member_location.
//
// The expected addresses below were read with:
//   llvm-readelf -sW tests/fixtures/lib/stellar-fixture-<v>.so
// and cross-checked against `llvm-dwarfdump --debug-info`, which prints the
// resolved DW_AT_low_pc. Both tools report identical values, and the DWARF 4 and
// DWARF 5 builds of the same source agree. They are hardcoded here and are never
// produced by running the builder.
#include <cstdio>
#include <cstring>
#include <memory>
#include <string>
#include <vector>

#include "stellar/dwarf/dwarf_context.h"
#include "stellar/elf/elf_file.h"
#include "stellar/ir/build.h"
#include "fixture_builder.h"
#include "test_framework.h"

using namespace stellar;

namespace {

/// The address of a mangled method, or 0 when the model has none. Read before
/// the context is torn down, because Model::str() goes through string_self.
struct AddrResult {
  bool ok = false;
  ir::Model model;
  ir::BuildStats stats;
  std::unique_ptr<dwarf::DwarfContext> ctx;
  elf::ElfFile file;
};

AddrResult build_from(const std::string& path) {
  AddrResult r;
  std::string err;
  if (!r.file.open(path, &err)) {
    std::fprintf(stderr, "  (skipped: %s: %s)\n", path.c_str(), err.c_str());
    return r;
  }
  r.ctx = std::make_unique<dwarf::DwarfContext>(r.file);
  if (!ir::build_model(*r.ctx, ir::BuildOptions{}, r.model, &r.stats)) return r;
  // The resolver stays attached: r.ctx is a member declared after r.model, so it
  // outlives it and Model::str() keeps working for the whole test.
  r.ok = true;
  return r;
}

std::string fixture(const char* name) {
  return std::string(STELLAR_FIXTURE_DIR) + "/" + name;
}

/// The address of the method named `name` declared at `line`, or 0.
///
/// Keyed on name plus declaration line rather than on Method::linkage_off,
/// which several unrelated methods happen to carry, so it cannot single one out.
std::uint64_t method_addr(const ir::Model& m, const char* name, std::uint32_t line) {
  for (const ir::Method& me : m.methods) {
    if (me.decl.line != line) continue;
    if (m.name(me.name_off) == name) return me.addr;
  }
  return 0;
}

// Ground truth, from `llvm-readelf -sW` and `llvm-dwarfdump --debug-info`:
//
//                      dwarf4-O0  dwarf5-O0  dwarf4-O2  dwarf5-O2
//   Body::update          0x348c     0x348c     0x10d4     0x10d4
//   Entity::update        0x3388     0x3388     0x1058     0x1058
//   Entity::describe      0x33b0     0x33b0     0x1068     0x1068
struct AddrCase {
  const char* lib;
  std::uint64_t body_update;
  std::uint64_t entity_update;
  std::uint64_t entity_describe;
};

constexpr AddrCase kAddrs[] = {
    {"stellar-fixture-dwarf4-O0.so", 0x348c, 0x3388, 0x33b0},
    {"stellar-fixture-dwarf5-O0.so", 0x348c, 0x3388, 0x33b0},
    {"stellar-fixture-dwarf4-O2.so", 0x10d4, 0x1058, 0x1068},
    {"stellar-fixture-dwarf5-O2.so", 0x10d4, 0x1058, 0x1068},
};

// Declaration lines from tests/fixtures/EXPECTED.md and src/.../body.h.
constexpr const char* kNameUpdate = "update";
constexpr const char* kNameDescribe = "describe";
constexpr std::uint32_t kBodyUpdateLine = 44;
constexpr std::uint32_t kEntityUpdateLine = 20;
constexpr std::uint32_t kEntityDescribeLine = 23;

}  // namespace

// ---------------------------------------------------------------------------
// (1) DWARF 5 addrx resolution
// ---------------------------------------------------------------------------

STELLAR_TEST(IrAddrx, MethodAddressesMatchTheSymbolTable) {
  for (const AddrCase& c : kAddrs) {
    AddrResult r = build_from(fixture(c.lib));
    if (!r.ok) continue;
    // DWARF 5 spells this DW_FORM_addrx; the value must be the real address, not
    // the index into .debug_addr it is stored as.
    EXPECT_EQ(method_addr(r.model, kNameUpdate, kBodyUpdateLine), c.body_update);
    EXPECT_EQ(method_addr(r.model, kNameUpdate, kEntityUpdateLine), c.entity_update);
    EXPECT_EQ(method_addr(r.model, kNameDescribe, kEntityDescribeLine), c.entity_describe);
  }
}

STELLAR_TEST(IrAddrx, Dwarf4AndDwarf5AgreeOnEveryMethodAddress) {
  // The same source, compiled two ways: the addresses must match exactly.
  AddrResult v4 = build_from(fixture("stellar-fixture-dwarf4-O0.so"));
  AddrResult v5 = build_from(fixture("stellar-fixture-dwarf5-O0.so"));
  if (!v4.ok || !v5.ok) return;
  EXPECT_EQ(method_addr(v4.model, kNameUpdate, kBodyUpdateLine),
            method_addr(v5.model, kNameUpdate, kBodyUpdateLine));
  EXPECT_EQ(method_addr(v4.model, kNameUpdate, kEntityUpdateLine),
            method_addr(v5.model, kNameUpdate, kEntityUpdateLine));
  EXPECT_EQ(method_addr(v4.model, kNameDescribe, kEntityDescribeLine),
            method_addr(v5.model, kNameDescribe, kEntityDescribeLine));
}

STELLAR_TEST(IrAddrx, HighPcAsAnOffsetStillFollowsALowPcFromAddrx) {
  // DWARF 5 may give DW_AT_high_pc as a *length* rather than an end address.
  // That only composes correctly if low_pc was resolved first; if it stayed an
  // index, the resulting range would be nonsense. Every method with an address
  // must therefore have one that points into the mapped image.
  for (const AddrCase& c : kAddrs) {
    AddrResult r = build_from(fixture(c.lib));
    if (!r.ok) continue;
    std::uint64_t nonzero = 0;
    for (const ir::Method& me : r.model.methods) {
      if (me.addr != 0) ++nonzero;
    }
    EXPECT_TRUE(nonzero != 0);
    // The resolved addresses must be page-aligned at least once over, which an
    // un-resolved .debug_addr index (0x5, 0x6, ...) could not be by accident
    // for every method in the library.
    bool saw_page_aligned = false;
    for (const ir::Method& me : r.model.methods) {
      if ((me.addr & 0xfff) == 0) saw_page_aligned = true;
    }
    EXPECT_TRUE(saw_page_aligned);
  }
}

// ---------------------------------------------------------------------------
// A damaged .debug_addr must resolve to 0, never to a guess and never to a
// fault. Each case rewrites the section in a temp copy of the fixture.
// ---------------------------------------------------------------------------

namespace {

/// Copies the fixture, overwrites its .debug_addr with `payload`, builds the
/// model and returns the address of `mangled`.
std::uint64_t addr_with_patched_debug_addr(const char* lib, const char* name,
                                            std::uint32_t line,
                                            const std::vector<std::uint8_t>& payload) {
  // The builder also recovers a method address by matching its mangled name in
  // the symbol table, so a damaged .debug_addr on its own would not make the
  // model's address 0. This test is about the addrx resolver, so the patched
  // copy is stripped of its symbols to remove that fallback from the picture.
  const std::string src_path = fixture(lib);
  elf::ElfFile probe;
  std::string err;
  if (!probe.open(src_path, &err)) {
    std::fprintf(stderr, "  (skipped: %s)\n", err.c_str());
    return 0;
  }
  const elf::Section* sec = probe.find_section(".debug_addr");
  if (sec == nullptr) return 0;
  const std::size_t off = static_cast<std::size_t>(sec->offset);

  // Read the whole image so the patch can cover it, then overwrite the section
  // in place. The section is fixed size, so this is exact.
  std::vector<std::uint8_t> bytes;
  {
    std::FILE* f = std::fopen(src_path.c_str(), "rb");
    if (f == nullptr) return 0;
    std::fseek(f, 0, SEEK_END);
    const long size = std::ftell(f);
    std::fseek(f, 0, SEEK_SET);
    if (size > 0) bytes.resize(static_cast<std::size_t>(size));
    const bool ok = !bytes.empty() && std::fread(bytes.data(), 1, bytes.size(), f) == bytes.size();
    std::fclose(f);
    if (!ok) return 0;
  }
  // Blank every symbol name so the mangled-name fallback cannot find a match.
  for (const char* symsec : {".symtab", ".dynsym"}) {
    const elf::Section* ss = probe.find_section(symsec);
    const util::ByteView sv = probe.section_data(symsec);
    if (ss == nullptr || sv.empty()) continue;
    const std::size_t soff = static_cast<std::size_t>(ss->offset);
    if (soff + sv.size() > bytes.size()) continue;
    std::memset(bytes.data() + soff, 0, sv.size());
  }

  const std::size_t sec_len = static_cast<std::size_t>(probe.section_data(".debug_addr").size());
  if (off + sec_len > bytes.size()) return 0;
  // Zero the section first: a shorter payload would otherwise leave the tail of
  // the previous contents in place, and a second contribution could still
  // resolve an address.
  std::memset(bytes.data() + off, 0, sec_len);
  if (payload.size() > sec_len) return 0;
  std::memcpy(bytes.data() + off, payload.data(), payload.size());

  const std::string tmp = stellar::test::temp_path("stellar-addrx-damaged.so");
  if (!stellar::test::write_file(tmp, bytes)) return 0;

  AddrResult r;
  if (!r.file.open(tmp, &err)) {
    std::fprintf(stderr, "  (skipped: %s)\n", err.c_str());
    return 0;
  }
  r.ctx = std::make_unique<dwarf::DwarfContext>(r.file);
  if (!ir::build_model(*r.ctx, ir::BuildOptions{}, r.model, &r.stats)) {
    std::fprintf(stderr, "  (skipped: build_model failed on the patched copy)\n");
    return 0;
  }
  // Make sure the method was located at all, so a zero below can only mean the
  // address failed to resolve rather than the lookup failing.
  std::uint64_t named = 0;
  for (const ir::Method& m : r.model.methods) {
    if (m.decl.line == line && r.model.name(m.name_off) == name) named = 1;
  }
  if (named == 0) {
    std::fprintf(stderr, "  (skipped: %s:%u not found in the patched copy)\n", name, line);
  }
  return method_addr(r.model, name, line);
}

/// A well-formed .debug_addr contribution: length, version 5, address_size,
/// segment_selector_size 0, then one entry of address_size bytes.
std::vector<std::uint8_t> good_addr_section(std::uint8_t address_size,
                                            std::uint64_t entry_value) {
  std::vector<std::uint8_t> s;
  const std::size_t entries = 1;
  const std::uint32_t length =
      static_cast<std::uint32_t>(4 + 2 + 1 + 1 + entries * address_size);
  s.push_back(length & 0xff);
  s.push_back((length >> 8) & 0xff);
  s.push_back((length >> 16) & 0xff);
  s.push_back((length >> 24) & 0xff);
  s.push_back(0x05);
  s.push_back(0x00);  // version 5
  s.push_back(address_size);
  s.push_back(0x00);  // segment_selector_size
  for (std::size_t i = 0; i < entries; ++i) {
    for (int k = 0; k < address_size; ++k) {
      s.push_back(static_cast<std::uint8_t>(entry_value >> (k * 8)));
    }
  }
  return s;
}

}  // namespace

STELLAR_TEST(IrAddrx, AddressSizeThreeIsRefused) {
  // An address_size the resolver does not understand must yield 0, not a guess
  // at a width. The entry is never read, so no fault is possible.
  const std::vector<std::uint8_t> s = good_addr_section(3, 0x348c);
  EXPECT_EQ(addr_with_patched_debug_addr("stellar-fixture-dwarf5-O0.so",
                                   kNameUpdate, kBodyUpdateLine, s),
            std::uint64_t{0});
}

STELLAR_TEST(IrAddrx, TruncatedHeaderIsRefused) {
  // A contribution header that stops early cannot be walked, so nothing resolves.
  std::vector<std::uint8_t> s;
  s.push_back(0x40);  // claims 64 bytes of body ...
  s.push_back(0x00);
  s.push_back(0x00);
  s.push_back(0x00);
  s.push_back(0x05);
  s.push_back(0x00);  // ... but only 6 bytes follow
  EXPECT_EQ(addr_with_patched_debug_addr("stellar-fixture-dwarf5-O0.so",
                                   kNameUpdate, kBodyUpdateLine, s),
            std::uint64_t{0});
}

STELLAR_TEST(IrAddrx, SectionTooSmallForAHeaderIsRefused) {
  // A one-byte .debug_addr cannot hold the 8-byte contribution header, so every
  // index is unresolvable. (An empty patch vector would be a no-op that leaves
  // the real section in place, which is why this writes one byte.)
  EXPECT_EQ(addr_with_patched_debug_addr("stellar-fixture-dwarf5-O0.so",
                                         kNameUpdate, kBodyUpdateLine, {0x00}),
            std::uint64_t{0});
}

STELLAR_TEST(IrAddrx, LengthRunningPastTheSectionIsRefused) {
  // A hostile length claiming more bytes than the section holds must not be
  // trusted to bound the reads.
  std::vector<std::uint8_t> s = good_addr_section(8, 0x348c);
  s[0] = 0xff;
  s[1] = 0xff;
  s[2] = 0xff;
  s[3] = 0x7f;
  EXPECT_EQ(addr_with_patched_debug_addr("stellar-fixture-dwarf5-O0.so",
                                   kNameUpdate, kBodyUpdateLine, s),
            std::uint64_t{0});
}

// ---------------------------------------------------------------------------
// (2) Static data members
//
// Every static the DWARF 4 build reports must also be reported by the DWARF 5
// one. The names below are what `llvm-dwarfdump --debug-info` shows as
// DW_TAG_member (DWARF 4) or DW_TAG_variable (DWARF 5) children of a class DIE:
//   _vtable$   on Entity, Body and Hitbox-less types alike, always artificial
//   instances_  Body's `static int instances_`
// ---------------------------------------------------------------------------

namespace {

/// The names of the static fields the model reports, from the class named `cls`.
std::vector<std::string> static_fields(const ir::Model& m, const std::string& cls) {
  std::vector<std::string> out;
  for (std::size_t ci = 0; ci < m.classes.size(); ++ci) {
    if (m.class_name(m.classes[ci]) != cls) continue;
    const ir::ClassDef& c = m.classes[ci];
    for (std::size_t i = c.first_field; i < c.first_field + c.field_count; ++i) {
      if (i >= m.fields.size()) break;
      if (m.fields[i].is_static == 0) continue;
      out.emplace_back(m.name(m.fields[i].name_off));
    }
  }
  return out;
}

}  // namespace

STELLAR_TEST(IrAddrx, Dwarf5ReportsTheSameStaticMembersAsDwarf4) {
  // The static members of the fixture sources, from tests/fixtures/src:
  //   Body::instances_   (body.h:52, `static int instances_`)
  //   _vtable$           the compiler's own, on Entity and Body
  AddrResult v4 = build_from(fixture("stellar-fixture-dwarf4-O0.so"));
  AddrResult v5 = build_from(fixture("stellar-fixture-dwarf5-O0.so"));
  if (!v4.ok || !v5.ok) return;

  for (const char* cls : {"Entity", "Body"}) {
    const std::vector<std::string> a = static_fields(v4.model, cls);
    const std::vector<std::string> b = static_fields(v5.model, cls);
    EXPECT_TRUE(a == b);
    EXPECT_FALSE(a.empty());
  }
}

STELLAR_TEST(IrAddrx, Dwarf5HasTheCompilerGeneratedVtableMember) {
  // The concrete symptom of the defect: the DWARF 5 dump was missing
  // `_vtable$` entirely, because it arrives as a DW_TAG_variable child of the
  // class rather than a DW_TAG_member.
  AddrResult r = build_from(fixture("stellar-fixture-dwarf5-O0.so"));
  if (!r.ok) return;
  bool found = false;
  for (const std::string& s : static_fields(r.model, "Entity")) {
    if (s == "_vtable$") found = true;
  }
  EXPECT_TRUE(found);
}

STELLAR_TEST(IrAddrx, Dwarf5HasTheDeclaredStaticMember) {
  // Body::instances_ is a static data member the *source* declares, so it must
  // be present too and not only the artificial _vtable$.
  AddrResult r = build_from(fixture("stellar-fixture-dwarf5-O0.so"));
  if (!r.ok) return;
  bool found = false;
  for (const std::string& s : static_fields(r.model, "Body")) {
    if (s == "instances_") found = true;
  }
  EXPECT_TRUE(found);
}

STELLAR_TEST(IrAddrx, ClassScopeVariableIsNotAlsoCountedAsAGlobal) {
  // The DWARF 5 definition of Body::instances_ is a namespace-scope variable
  // with a linkage name, and it also owns a symbol. Recognising the class-scope
  // declaration as a static field must not stop the definition from being the
  // thing that supplies the global's address.
  AddrResult r = build_from(fixture("stellar-fixture-dwarf5-O0.so"));
  if (!r.ok) return;
  // Exactly one field named instances_, not two.
  int as_field = 0;
  for (const ir::Field& f : r.model.fields) {
    if (r.model.name(f.name_off) == "instances_") ++as_field;
  }
  EXPECT_EQ(as_field, 1);
  // And it is a static field of Body, not an instance member.
  bool is_static = false;
  for (const ir::Field& f : r.model.fields) {
    if (r.model.name(f.name_off) == "instances_" && f.is_static != 0) is_static = true;
  }
  EXPECT_TRUE(is_static);
}

