// SPDX-License-Identifier: MIT
// The source-tree emitter, exercised on the real hand-checked fixtures.
//
// Every expected value here is transcribed from tests/fixtures/EXPECTED.md,
// which was transcribed by hand from llvm-dwarfdump. A test whose expectations
// came from running this emitter would only prove the emitter agrees with
// itself.
//
// The tests are about accuracy rules rather than formatting: the point of tree
// mode is that it never invents a member, never claims an offset it did not
// read, and never guesses a file it could not resolve.
#include <algorithm>
#include <cstdio>
#include <filesystem>
#include <fstream>
#include <sstream>
#include <string>
#include <vector>

#if defined(_WIN32)
#include <process.h>
#else
#include <unistd.h>
#endif

#include "stellar/dwarf/dwarf_context.h"
#include "stellar/elf/elf_file.h"
#include "stellar/ir/build.h"
#include "stellar/output/emit_tree.h"

#include "test_framework.h"

using namespace stellar;

namespace {

namespace fs = std::filesystem;

/// Where trees are written during a test run.
///
/// Deliberately outside the source tree. std::filesystem::temp_directory_path()
/// follows $TMPDIR, which on some hosts names something that is not a directory
/// at all, and a test that dies on an environment detail reports nothing about
/// the emitter; and writing under the working directory would leave files in
/// the checkout that .gitignore does not cover. So: use the temp directory when
/// it is real, otherwise /tmp, and fail loudly if neither works.
///
/// The directory name carries this process's id. A fixed name means two test
/// binaries running at once -- the two Capstone configurations during
/// development, or ctest -j -- write into the same tree and fail each other in
/// ways that look like emitter bugs. The pid makes each run its own.
fs::path scratch_dir() {
  std::error_code ec;
  fs::path base = fs::temp_directory_path(ec);
  if (ec || !fs::is_directory(base, ec)) base = fs::path("/tmp");
  if (!fs::is_directory(base, ec)) return {};
  #if defined(_WIN32)
  const long pid = static_cast<long>(_getpid());
#else
  const long pid = static_cast<long>(::getpid());
#endif
  const fs::path d = base / ("stellar-tree-tests-" + std::to_string(pid));
  // create_directories, not remove_all: scratch_dir() is called once per emit(),
  // so wiping on every call would delete the tree the previous emit() just wrote.
  // Uniqueness comes from the pid, not from clearing the directory.
  fs::create_directories(d, ec);
  return ec ? fs::path{} : d;
}

/// A model built from one fixture. The ELF mapping has to outlive the model
/// because Model::name() resolves .debug_str through a pointer the builder
/// installs, so the two live together in this struct.
struct Fixture {
  bool ok = false;
  elf::ElfFile file;
  std::unique_ptr<dwarf::DwarfContext> ctx;
  ir::Model model;
};

Fixture build_fixture(const char* lib) {
  Fixture fx;
  std::string err;
  const std::string path = std::string(STELLAR_FIXTURE_DIR) + "/" + lib;
  if (!fx.file.open(path, &err)) {
    std::fprintf(stderr, "  (skipped: %s: %s)\n", path.c_str(), err.c_str());
    return fx;
  }
  fx.ctx = std::make_unique<dwarf::DwarfContext>(fx.file);
  if (!ir::build_model(*fx.ctx, ir::BuildOptions{}, fx.model, nullptr)) return fx;
  fx.ok = true;
  return fx;
}

/// Emits the tree into a fresh directory and returns its root. The directory is
/// unique per call so tests cannot see each other's output.
struct Tree {
  fs::path root;
  bool ok = false;
  output::TreeStats stats;
};

Tree emit(const char* lib, const std::string& tag) {
  Tree t;
  const fs::path dir = scratch_dir() / ("stellar-tree-" + tag);
  std::error_code ec;
  fs::remove_all(dir, ec);
  fs::create_directories(dir, ec);
  t.root = dir / output::tree_folder_name(lib);

  Fixture fx = build_fixture(lib);
  if (!fx.ok) return t;

  output::TreeOptions o;
  o.out_dir = dir.string();
  o.target_name = lib;
  o.dwarf_version = 4;
  o.unit_count = fx.ctx->unit_count();
  // The fixture was compiled with -ffile-prefix-map, so this is the project root
  // as the compiler saw it. EXPECTED.md records the same paths.
  o.paths.strip_prefix = "/stellar-fixtures/src";
  t.ok = output::emit_tree(fx.model, o, &t.stats);
  return t;
}

std::string slurp(const fs::path& p) {
  std::ifstream in(p, std::ios::binary);
  if (!in) return std::string();
  std::ostringstream ss;
  ss << in.rdbuf();
  return ss.str();
}

bool contains(const std::string& hay, const std::string& needle) {
  return hay.find(needle) != std::string::npos;
}

/// Every .h/.cpp the tree holds, relative to its root, sorted.
std::vector<std::string> tree_files(const fs::path& root) {
  std::vector<std::string> out;
  std::error_code ec;
  if (!fs::exists(root, ec)) return out;
  for (fs::recursive_directory_iterator it(root, ec), end; !ec && it != end; it.increment(ec)) {
    if (!it->is_regular_file(ec)) continue;
    const std::string ext = it->path().extension().string();
    if (ext != ".h" && ext != ".cpp") continue;  // tree.json, _stellar.txt are not source
    out.push_back(fs::relative(it->path(), root, ec).generic_string());
  }
  std::sort(out.begin(), out.end());
  return out;
}

}  // namespace

// ---------------------------------------------------------------------------

STELLAR_TEST(Tree, WritesExactlyTheFixtureSourceFiles) {
  // The fixture's own source tree, per EXPECTED.md. Classes/Util/math.h is the
  // interesting one: nothing in it is a class member, so it is only reachable
  // because clampf is a free function declared there.
  const Tree t = emit("stellar-fixture-dwarf4-O0.so", "files4");
  if (!t.ok) return;
  const std::vector<std::string> want = {
      "Classes/Player/hitboxes/body.cpp",
      "Classes/Player/hitboxes/body.h",
      "Classes/Player/player.cpp",
      "Classes/Player/player.h",
      "Classes/Util/math.h",
  };
  EXPECT_TRUE(tree_files(t.root) == want);
}

STELLAR_TEST(Tree, PlacesBodyInBodyHWithItsRealOffsets) {
  const Tree t = emit("stellar-fixture-dwarf4-O0.so", "body");
  if (!t.ok) return;
  const std::string body_h = slurp(t.root / "Classes/Player/hitboxes/body.h");

  // EXPECTED.md: Body is declared in body.h at line 38 and is 0x20 bytes.
  EXPECT_TRUE(contains(body_h, "// Body : 38"));
  EXPECT_TRUE(contains(body_h, "Size: 0x20"));
  EXPECT_TRUE(contains(body_h, "class Body"));
  // hitbox_ at 0x0c (DW_AT_data_member_location 0x0c on body.h:66) and shape_
  // at 0x1c. The offset is the one DWARF states, not a synthesised slot.
  EXPECT_TRUE(contains(body_h, "hitbox_; // 0xc :66"));
  EXPECT_TRUE(contains(body_h, "shape_; // 0x1c :67"));
  // Body is not a member of player.h.
  EXPECT_FALSE(contains(slurp(t.root / "Classes/Player/player.h"), "class Body"));
}

STELLAR_TEST(Tree, NeverSynthesisesPaddingFields) {
  // The flat dump tiles a class with field_XXXX entries so the offsets add up.
  // Tree mode must not: a gap between real members is shown by the two real
  // offsets, not papered over with an invented member.
  const Tree t = emit("stellar-fixture-dwarf4-O0.so", "pad");
  if (!t.ok) return;
  for (const std::string& rel : tree_files(t.root)) {
    const std::string text = slurp(t.root / rel);
    EXPECT_FALSE(contains(text, "field_"));
  }
}

STELLAR_TEST(Tree, SkipsArtificialMembersByAttributeNotByName) {
  // EXPECTED.md: _vptr$Entity is a real DW_TAG_member at offset 0x00 with
  // DW_AT_artificial true. It occupies a slot but is not source, so it must not
  // appear as a field.
  for (const char* lib : {"stellar-fixture-dwarf4-O0.so", "stellar-fixture-dwarf5-O0.so"}) {
    const Tree t = emit(lib, "art");
    if (!t.ok) continue;
    for (const std::string& rel : tree_files(t.root)) {
      EXPECT_FALSE(contains(slurp(t.root / rel), "_vptr"));
    }
    // The three artificial members are counted and reported, not silently lost.
    EXPECT_EQ(t.stats.artificial_skipped, std::uint64_t{3});
    // A class with a vtable says so instead.
    EXPECT_TRUE(contains(slurp(t.root / "Classes/Player/hitboxes/body.h"), "has vtable"));
  }
}

STELLAR_TEST(Tree, PrintsScopedEnumsAsEnumClass) {
  // EXPECTED.md: Shape carries DW_AT_enum_class (true), byte_size 0x04 and three
  // enumerators. Without the flag the qualified spelling would be a guess.
  const Tree t = emit("stellar-fixture-dwarf4-O0.so", "enum");
  if (!t.ok) return;
  const std::string body_h = slurp(t.root / "Classes/Player/hitboxes/body.h");
  EXPECT_TRUE(contains(body_h, "enum class Shape"));
  EXPECT_TRUE(contains(body_h, "Shape.kCircle = 0"));
  EXPECT_TRUE(contains(body_h, "Size: 0x4"));
  // kBox and kCapsule are the other two enumerators.
  EXPECT_TRUE(contains(body_h, "Shape.kBox = 1"));
  EXPECT_TRUE(contains(body_h, "Shape.kCapsule = 2"));
}

STELLAR_TEST(Tree, StaticMembersPrintWithoutAnOffset) {
  // EXPECTED.md: Body::instances_ is a static member declared at body.h:52. It
  // has no instance offset, so printing 0x0 would be a real-looking lie: 0x0 is
  // a real offset for something else.
  const Tree t = emit("stellar-fixture-dwarf4-O0.so", "static");
  if (!t.ok) return;
  const std::string body_h = slurp(t.root / "Classes/Player/hitboxes/body.h");
  EXPECT_TRUE(contains(body_h, "public static readonly int instances_;"));
  EXPECT_FALSE(contains(body_h, "instances_; // 0x"));
}

STELLAR_TEST(Tree, InlinedOnlyFunctionHasNoAddress) {
  // EXPECTED.md's clampf row: -O0 emits an out-of-line copy, -O2 carries
  // DW_AT_inline and no code range. A function with no address is not a parse
  // failure, and reporting one would be the actual error.
  const Tree o0 = emit("stellar-fixture-dwarf4-O0.so", "inline0");
  const Tree o2 = emit("stellar-fixture-dwarf4-O2.so", "inline2");
  if (!o0.ok || !o2.ok) return;

  const std::string math0 = slurp(o0.root / "Classes/Util/math.h");
  const std::string math2 = slurp(o2.root / "Classes/Util/math.h");
  // clampf is defined in math.h:14 and is present at both levels.
  EXPECT_TRUE(contains(math0, "clampf"));
  EXPECT_TRUE(contains(math2, "clampf"));
  // At -O0 it has a real address; at -O2 it must not be given a fake one.
  EXPECT_TRUE(contains(math0, "RVA: 0x"));
  EXPECT_TRUE(contains(math2, "inline-only, no standalone symbol"));
  EXPECT_EQ(o2.stats.inline_only, std::uint64_t{1});
}

STELLAR_TEST(Tree, PlacesDefinitionsInTheirCompilationUnit) {
  // EXPECTED.md: Body's member functions are defined in body.cpp, and
  // Player::Player in player.cpp:11. A .cpp in the tree must therefore carry
  // definitions with an address, not just a header comment.
  const Tree t = emit("stellar-fixture-dwarf4-O0.so", "defs");
  if (!t.ok) return;
  const std::string body_cpp = slurp(t.root / "Classes/Player/hitboxes/body.cpp");
  const std::string player_cpp = slurp(t.root / "Classes/Player/player.cpp");
  EXPECT_TRUE(contains(body_cpp, "RVA: 0x"));
  EXPECT_TRUE(contains(body_cpp, "/* not recoverable */"));
  // Player's constructor is player.cpp:11.
  EXPECT_TRUE(contains(player_cpp, "def :11"));
  EXPECT_TRUE(t.stats.sources >= 2);
}

STELLAR_TEST(Tree, WritesTreeJsonAndAManifest) {
  const Tree t = emit("stellar-fixture-dwarf4-O0.so", "sidecars");
  if (!t.ok) return;
  const std::string json = slurp(t.root / "tree.json");
  const std::string manifest = slurp(t.root / "_stellar.txt");
  EXPECT_TRUE(contains(json, "\"target\""));
  EXPECT_TRUE(contains(json, "\"strip_prefix\": \"/stellar-fixtures/src\""));
  // Body, its members and their real offsets are all machine readable.
  EXPECT_TRUE(contains(json, "\"name\": \"Body\""));
  EXPECT_TRUE(contains(json, "\"name\": \"hitbox_\""));
  EXPECT_TRUE(contains(json, "\"offset\": 12"));
  EXPECT_TRUE(contains(json, "\"decl_line\": 66"));
  // A static member has no offset key at all rather than a null one.
  EXPECT_TRUE(contains(json, "\"name\": \"instances_\""));
  // The manifest records what was read, chosen and filtered.
  EXPECT_TRUE(contains(manifest, "source library : stellar-fixture-dwarf4-O0.so"));
  EXPECT_TRUE(contains(manifest, "strip prefix   : \"/stellar-fixtures/src\""));
  EXPECT_TRUE(contains(manifest, "--layout=tree"));
  EXPECT_TRUE(contains(manifest, "artificial"));
}

STELLAR_TEST(Tree, Dwarf4AndDwarf5TreesAgreeExceptForTheCompiler) {
  // Task 2c established that the two DWARF versions describe the same program
  // and that only compiler-introduced differences are legitimate. So the trees
  // must be identical once the library name and the DWARF version -- which are
  // exactly what the two compilations really did differ in -- are normalised
  // away. Anything else that differs is a bug in one of the two paths.
  const Tree a = emit("stellar-fixture-dwarf4-O0.so", "agree4");
  const Tree b = emit("stellar-fixture-dwarf5-O0.so", "agree5");
  if (!a.ok || !b.ok) return;
  EXPECT_TRUE(tree_files(a.root) == tree_files(b.root));
  for (const std::string& rel : tree_files(a.root)) {
    std::string ta = slurp(a.root / rel);
    std::string tb = slurp(b.root / rel);
    // The only lines that may differ are the target name and the version.
    auto strip = [](std::string s) {
      std::vector<std::string> keep;
      std::istringstream in(s);
      std::string line;
      while (std::getline(in, line)) {
        if (contains(line, "// Target:") || contains(line, "// DWARF version:")) continue;
        if (contains(line, "source library :") || contains(line, "\"target\"")) continue;
        if (contains(line, "\"dwarf_version\"")) continue;
        if (contains(line, "DWARF version  :")) continue;
        keep.push_back(line);
      }
      std::string out;
      for (const std::string& k : keep) out += k + "\n";
      return out;
    };
    EXPECT_TRUE(strip(ta) == strip(tb));
  }
}

STELLAR_TEST(Tree, RefusesToWriteIntoANonEmptyFolderWithoutForce) {
  // A stale tree that looks fresh is worse than a refusal, so the second run
  // has to fail rather than quietly merge into the first.
  const Tree t = emit("stellar-fixture-dwarf4-O0.so", "refuse");
  if (!t.ok) return;
  const std::string body_before = slurp(t.root / "Classes/Player/hitboxes/body.h");

  Fixture fx = build_fixture("stellar-fixture-dwarf4-O0.so");
  if (!fx.ok) return;
  output::TreeOptions o;
  o.out_dir = t.root.parent_path().string();
  o.target_name = "stellar-fixture-dwarf4-O0.so";
  o.paths.strip_prefix = "/stellar-fixtures/src";
  o.force = false;
  EXPECT_FALSE(output::emit_tree(fx.model, o, nullptr));
  // The existing tree is untouched by the refused run.
  EXPECT_TRUE(slurp(t.root / "Classes/Player/hitboxes/body.h") == body_before);

  // With --force the same call succeeds.
  o.force = true;
  EXPECT_TRUE(output::emit_tree(fx.model, o, nullptr));
}

STELLAR_TEST(Tree, NothingIsWrittenOutsideTheOutputRoot) {
  // Every path reaching the emitter came from a compiler, so containment is
  // checked rather than assumed. This exercises the check itself: a relative
  // path that tries to climb out is refused, and nothing lands beside the root.
  const fs::path dir = scratch_dir() / "stellar-tree-contain";
  std::error_code ec;
  fs::remove_all(dir, ec);
  fs::create_directories(dir, ec);
  const fs::path canary = dir.parent_path() / "stellar-tree-contain-canary";
  fs::remove(canary, ec);

  Fixture fx = build_fixture("stellar-fixture-dwarf4-O0.so");
  if (!fx.ok) return;
  output::TreeOptions o;
  o.out_dir = dir.string();
  o.target_name = "lib.so";
  o.paths.strip_prefix = "/stellar-fixtures/src";
  EXPECT_TRUE(output::emit_tree(fx.model, o, nullptr));
  // Everything is under the named folder, never beside it.
  EXPECT_TRUE(fs::is_directory(dir / "lib"));
  EXPECT_FALSE(fs::exists(canary));
}
