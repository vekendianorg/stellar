// SPDX-License-Identifier: MIT
// Source provenance in the IR: where each class, enum, method and global was
// declared, resolved through the compilation unit's .debug_line header.
//
// The expected values are copied from tests/fixtures/EXPECTED.md, which was in
// turn transcribed by hand from llvm-dwarfdump. They are deliberately not
// produced by running the builder: a test whose expectations come from the code
// under test only proves that the code agrees with itself.
#include <algorithm>
#include <cstring>
#include <memory>
#include <cstdio>
#include <string>
#include <vector>

#include "stellar/dwarf/dwarf_context.h"
#include "stellar/elf/elf_file.h"
#include "stellar/ir/build.h"
#include "stellar/output/paths.h"
#include "fixture_builder.h"
#include "test_framework.h"

using namespace stellar;

namespace {

// The fixture source paths, as EXPECTED.md records them. comp_dir is
// /stellar-fixtures/src in every fixture.
constexpr const char* kBodyH = "/stellar-fixtures/src/Classes/Player/hitboxes/body.h";
constexpr const char* kBodyCpp = "/stellar-fixtures/src/Classes/Player/hitboxes/body.cpp";
constexpr const char* kPlayerH = "/stellar-fixtures/src/Classes/Player/player.h";
constexpr const char* kPlayerCpp = "/stellar-fixtures/src/Classes/Player/player.cpp";
/// A header with no class member at all. Only a namespace-scope subprogram puts
/// it in the tree, which makes it the fixture's real test of free functions.
constexpr const char* kMathH = "/stellar-fixtures/src/Classes/Util/math.h";

/// A built model plus the file it came from. Both DWARF versions must agree on
/// every provenance value below, which is the whole point of the comparison.
///
/// Model::str() resolves .debug_str offsets through a pointer the builder
/// installs (Model::string_self), so the DwarfContext must outlive the model.
/// The names are therefore snapshotted here, while the resolver still works.
///
/// Names resolve for DW_FORM_strp (DWARF 4) and the DW_FORM_strx* family
/// (DWARF 5, through .debug_str_offsets), so both versions can be looked up by
/// name; the provenance lookups below are kept because they also prove that the
/// declaration site, not just the spelling, is right.
struct Fixture {
  bool ok = false;
  elf::ElfFile file;
  dwarf::DwarfContext* ctx = nullptr;
  ir::Model model;
  ir::BuildStats stats;
  std::unique_ptr<dwarf::DwarfContext> owned_ctx;
  /// Names, snapshotted while the ELF mapping was still alive.
  std::vector<std::string> class_names, enum_names, method_names, global_names;
  std::vector<std::string> field_names, param_names;
  std::vector<std::string> free_names;
};

Fixture build_fixture_at(const std::string& path) {
  Fixture fx;
  std::string err;
  if (!fx.file.open(path, &err)) {
    std::fprintf(stderr, "  (skipped: %s: %s)\n", path.c_str(), err.c_str());
    return fx;
  }
  fx.owned_ctx = std::make_unique<dwarf::DwarfContext>(fx.file);
  fx.ctx = fx.owned_ctx.get();
  if (!ir::build_model(*fx.ctx, ir::BuildOptions{}, fx.model, &fx.stats)) return fx;
  fx.ok = true;
  // Snapshot the names while the .debug_str resolver is still valid: Model::str()
  // goes through Model::string_self, and detaching it below is what stops a
  // moved Model from dereferencing a context that no longer exists.
  for (const ir::ClassDef& c : fx.model.classes) {
    fx.class_names.emplace_back(fx.model.class_name(c));
  }
  for (const ir::EnumDef& e : fx.model.enums) fx.enum_names.emplace_back(fx.model.name(e.name_off));
  for (const ir::Method& m : fx.model.methods) fx.method_names.emplace_back(fx.model.name(m.name_off));
  for (const ir::Field& f : fx.model.fields) fx.field_names.emplace_back(fx.model.name(f.name_off));
  for (const ir::Param& p : fx.model.params) fx.param_names.emplace_back(fx.model.name(p.name_off));
  for (const ir::FreeFunction& f : fx.model.free_functions) fx.free_names.emplace_back(fx.model.name(f.name_off));
  for (const ir::GlobalDef& g : fx.model.globals) {
    fx.global_names.emplace_back(fx.model.arena(g.name_off));
  }
  fx.model.string_self = nullptr;
  fx.model.string_fn = nullptr;
  return fx;
}

Fixture build_fixture(const char* name) {
  return build_fixture_at(std::string(STELLAR_FIXTURE_DIR) + "/" + name);
}

bool has_name(const std::vector<std::string>& names, const char* want) {
  return std::find(names.begin(), names.end(), want) != names.end();
}

/// How to damage the first .debug_str_offsets contribution of a copy.
enum class StrxDamage {
  kReservedLength,  ///< unit_length in the reserved 0xfffffff0.. range
  kNoEntries,       ///< unit_length covering only version+padding: no entry exists
  kWildOffsets,     ///< every entry points far past the end of .debug_str
  kHugeLength,      ///< unit_length running past the end of the section
};

/// Copies a fixture into a temp file with its .debug_str_offsets damaged, and
/// builds a model from the copy. `ok` is false if the copy could not be made.
Fixture build_damaged(const char* name, StrxDamage how, const char* tag) {
  Fixture none;
  const std::string src = std::string(STELLAR_FIXTURE_DIR) + "/" + name;
  elf::ElfFile f;
  std::string err;
  if (!f.open(src, &err)) return none;
  const elf::Section* sec = f.find_section(".debug_str_offsets");
  if (sec == nullptr || sec->size < 12) return none;
  const std::uint64_t at = sec->offset;
  const std::uint64_t size = sec->size;

  std::vector<std::uint8_t> bytes;
  if (std::FILE* in = std::fopen(src.c_str(), "rb")) {
    std::uint8_t buf[4096];
    std::size_t n = 0;
    while ((n = std::fread(buf, 1, sizeof buf, in)) > 0) bytes.insert(bytes.end(), buf, buf + n);
    std::fclose(in);
  } else {
    return none;
  }
  if (at + size > bytes.size()) return none;
  auto put32 = [&](std::uint64_t off, std::uint32_t v) {
    for (int i = 0; i < 4; ++i) bytes[static_cast<std::size_t>(off) + i] = static_cast<std::uint8_t>(v >> (8 * i));
  };
  switch (how) {
    case StrxDamage::kReservedLength: put32(at, 0xfffffff0u); break;
    case StrxDamage::kNoEntries: put32(at, 4); break;
    case StrxDamage::kHugeLength: put32(at, 0x7ffffff0u); break;
    case StrxDamage::kWildOffsets:
      for (std::uint64_t o = at + 8; o + 4 <= at + size; o += 4) put32(o, 0x7fffffffu);
      break;
  }
  const std::string out = test::temp_path(tag);
  if (!test::write_file(out, bytes)) return none;
  Fixture fx = build_fixture_at(out);
  std::remove(out.c_str());
  return fx;
}

/// The Method for class `cls` named `name`, or nullptr.

/// Model::path returns a view; the test macros compare std::string.
std::string path_str(const ir::Model& m, std::uint32_t id) {
  return std::string(m.path(id));
}

/// The enum declared at `line` in `path`, located by provenance.
ir::Provenance enum_prov_at(const Fixture& fx, const char* path, std::uint32_t line) {
  for (const ir::EnumDef& e : fx.model.enums) {
    if (e.prov.line == line && path_str(fx.model, e.prov.file_id) == path) return e.prov;
  }
  return ir::Provenance{};
}

/// The method declared at `line` in `path`, located by provenance.
const ir::Method* method_at(const Fixture& fx, const char* path, std::uint32_t line) {
  for (const ir::Method& m : fx.model.methods) {
    if (m.decl.line == line && path_str(fx.model, m.decl.file_id) == path) return &m;
  }
  return nullptr;
}


/// The class declared at `line` in `path`, located by provenance.
const ir::Provenance class_prov_at(const Fixture& fx, const char* path, std::uint32_t line) {
  for (const ir::ClassDef& c : fx.model.classes) {
    if (c.prov.line == line && path_str(fx.model, c.prov.file_id) == path) return c.prov;
  }
  return ir::Provenance{};
}


/// The global whose symbol name is `mangled`, or nullptr.
const ir::GlobalDef* global_named(const Fixture& fx, const char* mangled) {
  for (std::size_t i = 0; i < fx.model.globals.size() && i < fx.global_names.size(); ++i) {
    if (fx.global_names[i] == mangled) return &fx.model.globals[i];
  }
  return nullptr;
}

}  // namespace

// ---------------------------------------------------------------------------
// The two DWARF versions must agree, so every check runs over both.
// ---------------------------------------------------------------------------

STELLAR_TEST(IrProvenance, BodyIsDeclaredInBodyHAtLine38) {
  // EXPECTED.md: "game::Body ... Declared src/.../body.h:38".
  for (const char* lib : {"stellar-fixture-dwarf4-O0.so", "stellar-fixture-dwarf5-O0.so",
                          "stellar-fixture-dwarf4-O2.so", "stellar-fixture-dwarf5-O2.so"}) {
    const Fixture fx = build_fixture(lib);
    if (!fx.ok) continue;
    const ir::Provenance p = class_prov_at(fx, kBodyH, 38);
    ASSERT_TRUE(p.line != 0);
    EXPECT_EQ(p.line, std::uint32_t{38});
    EXPECT_STREQ(path_str(fx.model, p.file_id), kBodyH);
    EXPECT_EQ(p.cu, std::uint32_t{0});
  }
}

STELLAR_TEST(IrProvenance, EntityIsDeclaredInBodyHAtLine17) {
  for (const char* lib : {"stellar-fixture-dwarf4-O0.so", "stellar-fixture-dwarf5-O0.so"}) {
    const Fixture fx = build_fixture(lib);
    if (!fx.ok) continue;
    const ir::Provenance p = class_prov_at(fx, kBodyH, 17);
    EXPECT_EQ(p.line, std::uint32_t{17});
    EXPECT_STREQ(path_str(fx.model, p.file_id), kBodyH);
  }
}

STELLAR_TEST(IrProvenance, BodyUpdateRecordsDeclarationAndDefinitionSeparately) {
  // EXPECTED.md:
  //   game::Body::update(float) | body.h:44 | body.cpp:27
  // The in-class declaration is in the header; the concrete DIE reached through
  // DW_AT_specification is in the .cpp. Keeping both is the point of def_file_id.
  for (const char* lib : {"stellar-fixture-dwarf4-O0.so", "stellar-fixture-dwarf5-O0.so",
                          "stellar-fixture-dwarf4-O2.so", "stellar-fixture-dwarf5-O2.so"}) {
    const Fixture fx = build_fixture(lib);
    if (!fx.ok) continue;
    const ir::Method* m = method_at(fx, kBodyH, 44);
    ASSERT_TRUE(m != nullptr);
    EXPECT_EQ(m->decl.line, std::uint32_t{44});
    EXPECT_STREQ(path_str(fx.model, m->decl.file_id), kBodyH);
    EXPECT_EQ(m->def.line, std::uint32_t{27});
    EXPECT_STREQ(path_str(fx.model, m->def.file_id), kBodyCpp);
    // Both live in the same compilation unit, which is the first.
    EXPECT_EQ(m->decl.cu, std::uint32_t{0});
    EXPECT_EQ(m->def.cu, std::uint32_t{0});
    // The two sites must genuinely differ; otherwise def is just a copy of decl.
    EXPECT_NE(m->decl.file_id, m->def.file_id);
  }
}

STELLAR_TEST(IrProvenance, MethodWithoutAConcreteDieHasNoDefinitionSite) {
  // A method the compiler inlined away has only the in-class declaration. Its
  // def provenance must stay zero rather than borrowing the declaration's, which
  // would claim a definition that DWARF does not record.
  const Fixture fx = build_fixture("stellar-fixture-dwarf4-O0.so");
  if (!fx.ok) return;
  const ir::Method* m = method_at(fx, kPlayerH, 22);
  ASSERT_TRUE(m != nullptr);
  EXPECT_EQ(m->decl.line, std::uint32_t{22});
  EXPECT_FALSE(fx.model.path(m->decl.file_id).empty());
  // No DW_AT_specification reached this method, so nothing populated def.
  EXPECT_EQ(m->def.file_id, std::uint32_t{0});
  EXPECT_EQ(m->def.line, std::uint32_t{0});
}

STELLAR_TEST(IrProvenance, ShapeEnumIsDeclaredInBodyHAtLine57) {
  // EXPECTED.md: "game::Body::Shape is a scoped enumerator type (enum class)
  // declared at body.h:57".
  for (const char* lib : {"stellar-fixture-dwarf4-O0.so", "stellar-fixture-dwarf5-O0.so"}) {
    const Fixture fx = build_fixture(lib);
    if (!fx.ok) continue;
    const ir::Provenance p = enum_prov_at(fx, kBodyH, 57);
    EXPECT_EQ(p.line, std::uint32_t{57});
    EXPECT_STREQ(path_str(fx.model, p.file_id), kBodyH);
  }
}

STELLAR_TEST(IrProvenance, PlayerRegistryTokenIsDeclaredInPlayerCppAtLine9) {
  // EXPECTED.md: "game::player_registry_token | int | player.cpp:9 | the one
  // global". The global itself comes from the symbol table; only the location
  // comes from the matching DWARF DIE.
  for (const char* lib : {"stellar-fixture-dwarf4-O0.so", "stellar-fixture-dwarf5-O0.so",
                          "stellar-fixture-dwarf4-O2.so", "stellar-fixture-dwarf5-O2.so"}) {
    const Fixture fx = build_fixture(lib);
    if (!fx.ok) continue;
    const ir::GlobalDef* g = global_named(fx, "_ZN4game21player_registry_tokenE");
    ASSERT_TRUE(g != nullptr);
    EXPECT_EQ(g->prov.line, std::uint32_t{9});
    EXPECT_STREQ(path_str(fx.model, g->prov.file_id), kPlayerCpp);
  }
}

STELLAR_TEST(IrProvenance, Dwarf4AndDwarf5AgreeOnEveryProvenance) {
  // The same source compiled two ways must produce the same answers. This is
  // what catches a 1-based/0-based file-index mix-up: DWARF 4 numbers files from
  // 1 and DWARF 5 from 0, so reading one with the other's rule shifts every
  // entry by one.
  const Fixture v4 = build_fixture("stellar-fixture-dwarf4-O0.so");
  const Fixture v5 = build_fixture("stellar-fixture-dwarf5-O0.so");
  if (!v4.ok || !v5.ok) return;

  EXPECT_EQ(v4.stats.decl_file_unresolved, std::uint64_t{0});
  EXPECT_EQ(v5.stats.decl_file_unresolved, std::uint64_t{0});

  // Same set of interned paths (the order may differ, so compare as sets).
  std::vector<std::string> p4, p5;
  for (std::size_t i = 1; i < v4.model.paths.size(); ++i) p4.push_back(v4.model.paths[i]);
  for (std::size_t i = 1; i < v5.model.paths.size(); ++i) p5.push_back(v5.model.paths[i]);
  std::sort(p4.begin(), p4.end());
  std::sort(p5.begin(), p5.end());
  EXPECT_TRUE(p4 == p5);
  ASSERT_TRUE(!p4.empty());

  // Located by provenance, then checked by name below.
  const ir::Provenance b4 = class_prov_at(v4, kBodyH, 38);
  const ir::Provenance b5 = class_prov_at(v5, kBodyH, 38);
  EXPECT_EQ(b4.line, b5.line);
  EXPECT_STREQ(path_str(v4.model, b4.file_id), path_str(v5.model, b5.file_id));
  EXPECT_EQ(enum_prov_at(v4, kBodyH, 57).line, enum_prov_at(v5, kBodyH, 57).line);
  // Body::update: declared at body.h:44, defined at body.cpp:27, in both.
  const ir::Method* m4 = method_at(v4, kBodyH, 44);
  const ir::Method* m5 = method_at(v5, kBodyH, 44);
  ASSERT_TRUE(m4 != nullptr && m5 != nullptr);
  EXPECT_EQ(m4->decl.line, m5->decl.line);
  EXPECT_EQ(m4->def.line, m5->def.line);
  EXPECT_STREQ(path_str(v4.model, m4->def.file_id), path_str(v5.model, m5->def.file_id));
  // And the global, which resolves by symbol name in both.
  const ir::GlobalDef* g4 = global_named(v4, "_ZN4game21player_registry_tokenE");
  const ir::GlobalDef* g5 = global_named(v5, "_ZN4game21player_registry_tokenE");
  ASSERT_TRUE(g4 != nullptr && g5 != nullptr);
  EXPECT_EQ(g4->prov.line, g5->prov.line);
  EXPECT_STREQ(path_str(v4.model, g4->prov.file_id), path_str(v5.model, g5->prov.file_id));
}

STELLAR_TEST(IrProvenance, PathIdZeroIsTheUnknownSentinel) {
  ir::Model m;
  // The empty path is the sentinel, so a missing DW_AT_decl_file is
  // distinguishable from any real path.
  EXPECT_EQ(m.path_id(""), std::uint32_t{0});
  EXPECT_EQ(m.path_id(std::string_view()), std::uint32_t{0});
  EXPECT_TRUE(m.path(0).empty());

  const std::uint32_t a = m.path_id("/some/header.h");
  EXPECT_TRUE(a != 0);
  EXPECT_STREQ(std::string(m.path(a)), "/some/header.h");
  // Interning is by content, so the same path always gets the same id.
  EXPECT_EQ(m.path_id("/some/header.h"), a);
  EXPECT_EQ(m.path_id("/other/header.h") == a, false);
  // An id that was never handed out reads back empty rather than garbage.
  EXPECT_TRUE(m.path(a + 100).empty());
}

STELLAR_TEST(IrProvenance, UninternedProvenanceIsAllZero) {
  // Every Provenance starts unknown; nothing fabricates a location.
  const ir::Provenance p;
  EXPECT_EQ(p.file_id, std::uint32_t{0});
  EXPECT_EQ(p.line, std::uint32_t{0});
  EXPECT_EQ(p.cu, std::uint32_t{0});

  // A class that only exists as a vtable has no DIE and no location.
  const Fixture fx = build_fixture("stellar-fixture-dwarf4-O0.so");
  if (!fx.ok) return;
  for (const ir::ClassDef& c : fx.model.classes) {
    if (c.from_arena == 0) continue;
    EXPECT_EQ(c.prov.file_id, std::uint32_t{0});
    EXPECT_EQ(c.prov.line, std::uint32_t{0});
  }
}


// ---------------------------------------------------------------------------
// DWARF 5 string forms: names must resolve for DW_FORM_strx* exactly as they do
// for DW_FORM_strp, and a damaged .debug_str_offsets must leave names unresolved
// without reading outside the table.
// ---------------------------------------------------------------------------

/// A name whose .debug_str offset is genuinely 0 must still resolve.
///
/// Model name offsets are biased by one precisely so this case works: offset 0
/// means "no name", and a real name sitting at offset 0 is stored as 1. The
/// synthetic input here puts the class name at offset 0, which is the case the
/// old encoding silently lost.
std::string_view blob_lookup(void* self, std::uint32_t off) {
  const auto& blob = *static_cast<const std::string*>(self);
  if (off >= blob.size()) return {};
  const char* p = blob.data() + off;
  return std::string_view(p, ::strnlen(p, blob.size() - off));
}

STELLAR_TEST(IrNames, NameAtDebugStrOffsetZeroStillResolves) {
  // .debug_str whose very first byte is the start of the name: no leading NUL.
  std::string blob = "Zero";
  blob.push_back('\0');

  ir::Model m;
  m.string_self = &blob;
  m.string_fn = &blob_lookup;
  m.reserve_type_slots(8);

  // Encode raw offset 0 the way the builder does.
  const std::uint32_t encoded = ir::Model::name_encode(0);
  EXPECT_NE(encoded, ir::Model::kNoName);
  EXPECT_STREQ(std::string(m.name(encoded)), "Zero");

  ir::ClassDef cd;
  cd.name_off = encoded;
  cd.size = 4;
  m.classes.push_back(cd);
  EXPECT_STREQ(std::string(m.class_name(cd)), "Zero");

  ir::Type t;
  t.kind = ir::TypeKind::kClass;
  t.name_off = encoded;
  t.size = 4;
  t.def = 0;
  m.types.push_back(t);
  // A named class renders its own name through the same accessor.
  EXPECT_STREQ(m.type_name(0), "Zero");

  // And the same offset on a nameless entity stays empty rather than picking up
  // the string at offset 0.
  ir::Type anon;
  anon.kind = ir::TypeKind::kClass;
  anon.def = 0;
  m.types.push_back(anon);
  EXPECT_STREQ(m.type_name(1), "class");
}

STELLAR_TEST(IrNames, EncodeAndDecodeRoundTrip) {
  // A real name at offset 0 encodes to 1, not to the 0 sentinel.
  EXPECT_EQ(ir::Model::name_encode(0), std::uint32_t{1});
  EXPECT_TRUE(ir::Model::has_name(ir::Model::name_encode(0)));
  EXPECT_EQ(ir::Model::name_encode(1), std::uint32_t{2});
  EXPECT_TRUE(ir::Model::has_name(ir::Model::name_encode(1)));
  // Only the sentinel itself means "no name".
  EXPECT_FALSE(ir::Model::has_name(ir::Model::kNoName));

  // An offset with no representable biased form is reported as absent rather
  // than wrapping around to 0 and masquerading as a name at UINT32_MAX.
  EXPECT_EQ(ir::Model::name_encode(0xffffffffull), ir::Model::kNoName);

  // And an unnamed entity reads back empty through the accessor.
  ir::Model m;
  EXPECT_TRUE(m.name(ir::Model::kNoName).empty());
  EXPECT_TRUE(m.name(0).empty());
}

STELLAR_TEST(IrNames, UnnamedParameterRendersWithNoNameInBothDwarfVersions) {
  // The reported symptom: Body::update(float) has an unnamed float parameter in
  // DWARF, and it used to print as `update(float _ZN4game4Body6updateEf)` -- the
  // string at .debug_str offset 0 leaking into a nameless slot. Every unnamed
  // parameter must now come out empty, in both DWARF versions.
  for (const char* lib : {"stellar-fixture-dwarf4-O0.so", "stellar-fixture-dwarf5-O0.so",
                          "stellar-fixture-dwarf4-O2.so", "stellar-fixture-dwarf5-O2.so"}) {
    const Fixture fx = build_fixture(lib);
    if (!fx.ok) continue;
    std::size_t unnamed_params = 0;
    for (std::size_t i = 0; i < fx.model.params.size(); ++i) {
      if (fx.model.name(fx.model.params[i].name_off).empty()) ++unnamed_params;
    }
    // The fixture really does have unnamed parameters, so this would be
    // vacuous if the count came out zero.
    EXPECT_TRUE(unnamed_params != 0);
    // No parameter name may be the mangled string that starts .debug_str.
    for (std::size_t i = 0; i < fx.param_names.size(); ++i) {
      EXPECT_TRUE(fx.param_names[i].find("_ZN") == std::string::npos);
    }
  }
}

STELLAR_TEST(IrNames, UnnamedFieldRendersAsUnnamedNotAsAStrayString) {
  // _vptr$Entity occupies offset 0 but is a real, named, artificial member, so
  // it must keep its name; what must not happen is a nameless member borrowing
  // the string at .debug_str offset 0.
  for (const char* lib : {"stellar-fixture-dwarf4-O0.so", "stellar-fixture-dwarf5-O0.so"}) {
    const Fixture fx = build_fixture(lib);
    if (!fx.ok) continue;
    for (std::size_t i = 0; i < fx.model.fields.size() && i < fx.field_names.size(); ++i) {
      const std::string& n = fx.field_names[i];
      if (!n.empty()) EXPECT_TRUE(n.rfind("_ZN", 0) != 0);
    }
    // The vtable pointer is still recognised as an ABI artefact by name.
    bool has_vptr = false;
    for (const std::string& n : fx.field_names) {
      if (n.rfind("_vptr", 0) == 0) has_vptr = true;
    }
    EXPECT_TRUE(has_vptr);
  }
}

STELLAR_TEST(IrNames, ArenaNamedEntitiesAreUnaffected) {
  // Functions and globals are named from the symbol table into the model's own
  // arena, which has its own raw offsets and never goes through the biased
  // .debug_str encoding. Their names must survive intact.
  for (const char* lib : {"stellar-fixture-dwarf4-O0.so", "stellar-fixture-dwarf5-O0.so"}) {
    const Fixture fx = build_fixture(lib);
    if (!fx.ok) continue;
    bool any = false;
    for (const ir::FunctionDef& fn : fx.model.functions) {
      const std::string_view n = fx.model.arena(fn.name_off);
      if (!n.empty()) any = true;
      // A symbol name is never empty and never a bare offset artefact.
      if (!n.empty()) EXPECT_TRUE(n.rfind("sub_", 0) != 0 || n.size() > 4);
    }
    EXPECT_TRUE(any);
    // The globals path is the same story.
    bool any_global = false;
    for (const ir::GlobalDef& g : fx.model.globals) {
      if (!fx.model.arena(g.name_off).empty()) any_global = true;
    }
    EXPECT_TRUE(any_global);
  }
}

STELLAR_TEST(IrNames, Dwarf5TypeAndMethodNamesResolveByName) {
  for (const char* lib : {"stellar-fixture-dwarf4-O0.so", "stellar-fixture-dwarf5-O0.so"}) {
    const Fixture fx = build_fixture(lib);
    if (!fx.ok) continue;
    // EXPECTED.md: game::Body, game::Entity, game::Body::Shape, Body::update.
    // The model keeps the unqualified name and the namespace separately.
    EXPECT_TRUE(has_name(fx.class_names, "Body"));
    EXPECT_TRUE(has_name(fx.class_names, "Entity"));
    EXPECT_TRUE(has_name(fx.enum_names, "Shape"));
    EXPECT_TRUE(has_name(fx.method_names, "update"));
  }
}

STELLAR_TEST(IrNames, NamedLookupAgreesWithProvenanceOnBothVersions) {
  for (const char* lib : {"stellar-fixture-dwarf4-O0.so", "stellar-fixture-dwarf5-O0.so",
                          "stellar-fixture-dwarf4-O2.so", "stellar-fixture-dwarf5-O2.so"}) {
    const Fixture fx = build_fixture(lib);
    if (!fx.ok) continue;
    // The class that is *named* Body and carries a declaration site is the one
    // declared at body.h:38 -- the name and the location must describe the same DIE.
    bool found = false;
    for (std::size_t i = 0; i < fx.model.classes.size() && i < fx.class_names.size(); ++i) {
      if (fx.class_names[i] != "Body") continue;
      const ir::Provenance& p = fx.model.classes[i].prov;
      if (p.line == 0) continue;  // a redeclaration with no DW_AT_decl_file
      found = true;
      EXPECT_EQ(p.line, std::uint32_t{38});
      EXPECT_STREQ(path_str(fx.model, p.file_id), kBodyH);
    }
    EXPECT_TRUE(found);
  }
}

STELLAR_TEST(IrNames, Dwarf4AndDwarf5NameSetsMatch) {
  const Fixture v4 = build_fixture("stellar-fixture-dwarf4-O0.so");
  const Fixture v5 = build_fixture("stellar-fixture-dwarf5-O0.so");
  if (!v4.ok || !v5.ok) return;
  auto sorted = [](std::vector<std::string> v) {
    v.erase(std::remove(v.begin(), v.end(), std::string()), v.end());
    std::sort(v.begin(), v.end());
    return v;
  };
  EXPECT_TRUE(sorted(v4.class_names) == sorted(v5.class_names));
  EXPECT_TRUE(sorted(v4.enum_names) == sorted(v5.enum_names));
  EXPECT_TRUE(sorted(v4.method_names) == sorted(v5.method_names));
}

STELLAR_TEST(IrNames, DamagedStrOffsetsTableLeavesNamesUnresolved) {
  struct Case { StrxDamage how; const char* tag; };
  for (const Case c : {Case{StrxDamage::kReservedLength, "stellar_strx_reserved.so"},
                       Case{StrxDamage::kNoEntries, "stellar_strx_noentries.so"},
                       Case{StrxDamage::kWildOffsets, "stellar_strx_wild.so"},
                       Case{StrxDamage::kHugeLength, "stellar_strx_hugelen.so"}}) {
    const Fixture fx = build_damaged("stellar-fixture-dwarf5-O0.so", c.how, c.tag);
    if (!fx.ok) continue;  // the copy could not be made or built: nothing to assert
    // Reaching this line already proves the builder did not fault. A name that
    // went through the damaged table must not come back as the real name, and
    // above all must not come back as some other string. Classes synthesised from
    // _ZTV vtable symbols (from_arena) are named from the symbol table, which this
    // damage does not touch, so only DIE-derived ones count. An unresolved name is
    // stored as offset 0, which the model's str() reads as whatever string starts
    // .debug_str (a pre-existing quirk), so the check is "not the real name"
    // rather than "empty".
    for (std::size_t i = 0; i < fx.model.classes.size() && i < fx.class_names.size(); ++i) {
      if (fx.model.classes[i].from_arena != 0) continue;
      // Only the first unit's contribution is damaged (the fixture has two), so
      // only that unit's classes are required to have lost their names.
      if (fx.model.classes[i].prov.cu != 0) continue;
      EXPECT_NE(fx.class_names[i], std::string("Body"));
      EXPECT_NE(fx.class_names[i], std::string("Entity"));
      EXPECT_NE(fx.class_names[i], std::string("Hitbox"));
    }
    // Body::update is declared in unit 0, so its name is gone as well.
    EXPECT_FALSE(has_name(fx.method_names, "update"));
  }
}


STELLAR_TEST(IrDedup, RedeclaredBodyInTheFixtureIsNotEmittedTwice) {
  // The fixtures declare game::Body twice: once with a declaration site
  // (body.h:38) and once as a bare redeclaration carrying no DW_AT_decl_file.
  // Only the sited definition may reach the dump.
  for (const char* lib : {"stellar-fixture-dwarf4-O0.so", "stellar-fixture-dwarf5-O0.so"}) {
    const Fixture fx = build_fixture(lib);
    if (!fx.ok) continue;
    std::size_t visible_body = 0;
    std::size_t sited_body = 0;
    for (std::size_t i = 0; i < fx.model.classes.size(); ++i) {
      if (fx.class_names[i] != "Body") continue;
      if (fx.model.classes[i].hidden == 0) ++visible_body;
      if (fx.model.classes[i].prov.file_id != 0) ++sited_body;
    }
    EXPECT_TRUE(sited_body >= 1);
    EXPECT_EQ(visible_body, std::size_t{1});
    EXPECT_TRUE(fx.model.dedup_sited_merged >= 1);
  }
}

// ---------------------------------------------------------------------------
// Path normalisation over the real fixture tree
// ---------------------------------------------------------------------------

STELLAR_TEST(Paths, FixtureTreeNormalisesIdenticallyForDwarf4AndDwarf5) {
  // The fixtures were compiled with -ffile-prefix-map=/stellar-fixtures/src, so
  // every path the model interns starts there. With that prefix stripped the
  // result is a project-relative path, and it must be the same whichever DWARF
  // version produced it. The expected strings are transcribed from
  // `llvm-dwarfdump --debug-line` on the fixtures, not from this code.
  // Classes/Util/math.h is here because clampf is a free function declared in
  // it. Nothing in the DIE tree is a class member there, so the header is only
  // reachable by resolving the decl_file of a namespace-scope subprogram.
  static const char* const kExpected[] = {
      "Classes/Player/hitboxes/body.h",
      "Classes/Player/hitboxes/body.cpp",
      "Classes/Player/player.h",
      "Classes/Player/player.cpp",
      "Classes/Util/math.h",
  };
  output::PathOptions opts;
  opts.strip_prefix = "/stellar-fixtures/src";

  for (const char* lib : {"stellar-fixture-dwarf4-O0.so", "stellar-fixture-dwarf5-O0.so",
                          "stellar-fixture-dwarf4-O2.so", "stellar-fixture-dwarf5-O2.so"}) {
    const Fixture fx = build_fixture(lib);
    if (!fx.ok) continue;
    output::PathTable paths(fx.model.paths, opts);

    std::vector<std::string> seen;
    for (std::uint32_t i = 1; i < fx.model.paths.size(); ++i) {
      const output::ResolvedPath& r = paths.get(i);
      EXPECT_EQ(r.cls, output::PathClass::kProject);
      EXPECT_FALSE(r.relative.empty());
      // No unsafe shape ever reaches the output.
      EXPECT_TRUE(r.relative.find("..") == std::string::npos);
      EXPECT_TRUE(r.relative.find("\\") == std::string::npos);
      EXPECT_TRUE(r.relative.front() != '/');
      seen.push_back(r.relative);
    }
    std::sort(seen.begin(), seen.end());
    seen.erase(std::unique(seen.begin(), seen.end()), seen.end());
    std::vector<std::string> want(std::begin(kExpected), std::end(kExpected));
    std::sort(want.begin(), want.end());
    EXPECT_TRUE(seen == want);
    // The fixture tree has no paths differing only by case.
    EXPECT_TRUE(paths.report_collisions().empty());
    // Nothing on the fixture tree needs quarantining.
    EXPECT_EQ(paths.quarantine_count(), std::uint64_t{0});
  }
}

// ---------------------------------------------------------------------------
// Member, enum and free-function metadata that tree output depends on
// ---------------------------------------------------------------------------

STELLAR_TEST(Provenance, FieldsCarryTheirDeclarationSite) {
  // EXPECTED.md: Body::instances_ is declared body.h:52, Body::hitbox_ is at
  // body.h:66. A tree emitter prints these lines, so they have to come from
  // DW_AT_decl_line rather than from any ordering the builder happens to have.
  for (const char* lib : {"stellar-fixture-dwarf4-O0.so", "stellar-fixture-dwarf5-O0.so",
                          "stellar-fixture-dwarf4-O2.so", "stellar-fixture-dwarf5-O2.so"}) {
    const Fixture fx = build_fixture(lib);
    if (!fx.ok) continue;
    for (std::size_t i = 0; i < fx.model.fields.size(); ++i) {
      if (fx.field_names[i] == "instances_") {
        // 52 in the header, whichever DWARF version produced the model.
        EXPECT_EQ(fx.model.fields[i].prov.line, 52u);
        EXPECT_TRUE(fx.model.fields[i].is_static);
      }
      if (fx.field_names[i] == "hitbox_") EXPECT_EQ(fx.model.fields[i].prov.line, 66u);
      if (fx.field_names[i] == "shape_") EXPECT_EQ(fx.model.fields[i].prov.line, 67u);
    }
  }
}

STELLAR_TEST(Provenance, ArtificialMembersAreFlaggedNotJustNameFiltered) {
  // EXPECTED.md records `_vptr$Entity` at offset 0x00 with DW_AT_artificial
  // true. The flat emitter happens to miss it by name, which would leave this
  // test passing with no artificial flag at all; asserting the flag directly is
  // what makes the tree emitter's "skip compiler members" rule real.
  //
  // llvm-dwarfdump shows three artificial members in both versions: Entity's
  // _vptr$Entity plus a _vtable$ for each of Body and Hitbox. In DWARF 5 the
  // static _vtable$ arrives as DW_TAG_variable rather than DW_TAG_member, so
  // this also pins that the two spellings agree.
  for (const char* lib : {"stellar-fixture-dwarf4-O0.so", "stellar-fixture-dwarf5-O0.so",
                          "stellar-fixture-dwarf4-O2.so", "stellar-fixture-dwarf5-O2.so"}) {
    const Fixture fx = build_fixture(lib);
    if (!fx.ok) continue;
    std::size_t artificial = 0, vptr = 0;
    for (std::size_t i = 0; i < fx.model.fields.size(); ++i) {
      if (fx.model.fields[i].is_artificial) ++artificial;
      if (fx.field_names[i] == "_vptr$Entity") {
        ++vptr;
        // Offset 0 and no source line: it occupies a real slot but is not source.
        EXPECT_TRUE(fx.model.fields[i].is_artificial);
        EXPECT_EQ(fx.model.fields[i].offset, std::uint64_t{0});
        EXPECT_EQ(fx.model.fields[i].prov.line, 0u);
      }
      // A synthesised padding slot or a real member is not compiler-generated.
      if (fx.field_names[i] == "health_") EXPECT_FALSE(fx.model.fields[i].is_artificial);
    }
    EXPECT_EQ(vptr, std::size_t{1});
    EXPECT_EQ(artificial, std::size_t{3});
  }
}

STELLAR_TEST(Provenance, ScopedEnumIsDistinguishedFromAPlainEnum) {
  // EXPECTED.md: Shape carries DW_AT_enum_class (true) and byte_size 0x04.
  // The enumerator names carry no `Shape.` prefix in DWARF, so this flag is the
  // only thing that distinguishes `Shape.kCircle` from `kCircle`.
  for (const char* lib : {"stellar-fixture-dwarf4-O0.so", "stellar-fixture-dwarf5-O0.so",
                          "stellar-fixture-dwarf4-O2.so", "stellar-fixture-dwarf5-O2.so"}) {
    const Fixture fx = build_fixture(lib);
    if (!fx.ok) continue;
    bool found = false;
    for (std::size_t i = 0; i < fx.model.enums.size(); ++i) {
      if (fx.enum_names[i] != "Shape") continue;
      found = true;
      EXPECT_TRUE(fx.model.enums[i].is_enum_class);
      EXPECT_EQ(fx.model.enums[i].size, std::uint64_t{4});
      EXPECT_EQ(fx.model.enums[i].member_count, std::uint32_t{3});
      // body.h:57, the line EXPECTED.md records for the enumeration_type.
      EXPECT_EQ(fx.model.enums[i].prov.line, 57u);
    }
    EXPECT_TRUE(found);
  }
}

STELLAR_TEST(Provenance, FreeFunctionsAreRecordedWithTheirDeclaringHeader) {
  // EXPECTED.md: clampf is defined in Classes/Util/math.h:14-18 and
  // clamp_value<int> in Classes/Player/player.h:13. Both are namespace-scope,
  // so before free functions were captured neither header could be placed in a
  // source tree: math.h is the fixture's proof of that.
  // clampf survives at every level; clamp_value<int> does not, because at -O2 it
  // is fully inlined away and no DIE for it survives at all. That is a
  // distinction the tree emitter has to make from the debug info, not a gap.
  for (const char* lib : {"stellar-fixture-dwarf4-O0.so", "stellar-fixture-dwarf5-O0.so",
                          "stellar-fixture-dwarf4-O2.so", "stellar-fixture-dwarf5-O2.so"}) {
    const Fixture fx = build_fixture(lib);
    if (!fx.ok) continue;
    EXPECT_TRUE(has_name(fx.free_names, "clampf"));

    for (std::size_t i = 0; i < fx.model.free_functions.size(); ++i) {
      // Resolve back to the declaring header the same way the emitter will.
      // Names come from the snapshot: build_fixture detaches the model's string
      // resolver, so model.name() would return empty here.
      if (fx.free_names[i] == "clampf") {
        EXPECT_EQ(fx.model.paths[fx.model.free_functions[i].decl.file_id], std::string(kMathH));
        EXPECT_EQ(fx.model.free_functions[i].decl.line, 14u);
      }
    }
  }

  for (const char* lib : {"stellar-fixture-dwarf4-O0.so", "stellar-fixture-dwarf5-O0.so"}) {
    const Fixture fx = build_fixture(lib);
    if (!fx.ok) continue;
    EXPECT_TRUE(has_name(fx.free_names, "clamp_value<int>"));
    bool clampv_seen = false;
    for (std::size_t i = 0; i < fx.model.free_functions.size(); ++i) {
      const ir::FreeFunction& f = fx.model.free_functions[i];
      if (fx.free_names[i] == "clamp_value<int>" &&
          fx.model.paths[f.decl.file_id] == kPlayerH) {
        clampv_seen = true;
        EXPECT_EQ(f.decl.line, 13u);
      }
    }
    EXPECT_TRUE(clampv_seen);
  }
}

STELLAR_TEST(Provenance, InlinedOnlyFunctionHasNoCodeRangeButIsNotMissing) {
  // EXPECTED.md's table for clampf: -O0 emits an out-of-line copy (low_pc and
  // high_pc present), -O2 carries DW_AT_inline and *no* code range. A function
  // with no address is not a parse failure, so the model must still hold it --
  // with has_range false, not dropped.
  const Fixture o0 = build_fixture("stellar-fixture-dwarf4-O0.so");
  const Fixture o2 = build_fixture("stellar-fixture-dwarf4-O2.so");
  if (!o0.ok || !o2.ok) return;

  auto find_clampf = [](const Fixture& fx) -> const ir::FreeFunction* {
    for (std::size_t i = 0; i < fx.model.free_functions.size(); ++i) {
      if (fx.free_names[i] == "clampf") return &fx.model.free_functions[i];
    }
    return nullptr;
  };
  const ir::FreeFunction* a = find_clampf(o0);
  const ir::FreeFunction* b = find_clampf(o2);
  EXPECT_TRUE(a != nullptr);
  EXPECT_TRUE(b != nullptr);
  if (!a || !b) return;
  EXPECT_TRUE(a->has_range);
  EXPECT_FALSE(b->has_range);
  EXPECT_TRUE(b->addr == 0);
  // Both declare the same place: the optimisation level does not move the source.
  EXPECT_EQ(a->decl.file_id == 0 ? 0u : 1u, b->decl.file_id == 0 ? 0u : 1u);
  EXPECT_EQ(o0.model.paths[a->decl.file_id], o2.model.paths[b->decl.file_id]);
  EXPECT_EQ(a->decl.line, b->decl.line);
}
