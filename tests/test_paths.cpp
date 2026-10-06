// SPDX-License-Identifier: MIT
// Source-path normalisation: hostile input, and the fixture tree.
//
// The fixture expectations were derived from `llvm-dwarfdump --debug-line` and
// the -ffile-prefix-map that fixed the fixture prefix; the compiled fixtures
// carry /stellar-fixtures/src/... . They are hardcoded here and are never
// produced by running the code under test.
#include <cctype>
#include <string>
#include <string_view>
#include <vector>

#include "stellar/output/paths.h"
#include "test_framework.h"

using namespace stellar;
using stellar::output::PathClass;
using stellar::output::PathOptions;
using stellar::output::PathTable;

namespace {

/// Lowercase ASCII, mirroring how the table folds paths for collision checks.
std::string fold_case(std::string_view sv) {
  std::string out(sv);
  for (char& c : out) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
  return out;
}

/// A path table over `paths`, whose entry 0 is the interned sentinel.
}  // namespace

// ---------------------------------------------------------------------------
// Normalisation of hostile input
// ---------------------------------------------------------------------------

STELLAR_TEST(Paths, NormaliseCollapsesDotAndDuplicateSlashes) {
  std::string out;
  EXPECT_TRUE(output::normalise_relative("a/./b//c/./d", out));
  EXPECT_STREQ(out, "a/b/c/d");
  // A leading separator never survives, so the result is never absolute.
  EXPECT_TRUE(output::normalise_relative("///a/b", out));
  EXPECT_STREQ(out, "a/b");
  EXPECT_TRUE(output::normalise_relative("a/b/", out));
  EXPECT_STREQ(out, "a/b");
  EXPECT_TRUE(output::normalise_relative("a/b/..", out));
  EXPECT_STREQ(out, "a");
}

STELLAR_TEST(Paths, NormaliseRemovesDotDotThatStaysInside) {
  std::string out;
  // "a/../../b" escapes the root, so it is refused rather than rewritten.
  EXPECT_FALSE(output::normalise_relative("a/../../b", out));
  EXPECT_FALSE(output::normalise_relative("../x", out));
  EXPECT_FALSE(output::normalise_relative("..", out));
  // These stay inside and are simply collapsed.
  EXPECT_TRUE(output::normalise_relative("a/b/../c", out));
  EXPECT_STREQ(out, "a/c");
}

STELLAR_TEST(Paths, HostilePathsAreQuarantinedNotRewritten) {
  // Every entry here is one a hostile or broken producer could emit. None may
  // come back as an unsafe path, and each must keep its original text so the
  // dump can report what was actually seen.
  const std::vector<std::string> hostile = {
      "C:\\src\\x",   // drive letter and backslashes
      "..\\..\\etc",  // backslashes
      "/abs/x",       // absolute, and no prefix given to strip it
      "a/../../b",    // escapes the root
      "",             // empty
      std::string("with\0nul", 8),
      std::string(300, 'd') + "/deep.cpp",
  };
  PathOptions opts;
  opts.strip_prefix = "/nonexistent";  // isolates the input from prefix stripping
  PathTable t(hostile, opts);
  for (std::size_t i = 1; i < hostile.size(); ++i) {
    const output::ResolvedPath& r = t.get(static_cast<std::uint32_t>(i));
    if (r.cls == PathClass::kQuarantine) {
      EXPECT_TRUE(r.relative.empty());  // never a half-normalised path
      EXPECT_STREQ(r.original, hostile[i]);  // original kept for reporting
      continue;
    }
    // If it was not quarantined, it must at least be safe to print.
    EXPECT_TRUE(r.relative.find("..") == std::string::npos);
    EXPECT_TRUE(r.relative.find('\\') == std::string::npos);
    EXPECT_TRUE(r.relative.empty() || r.relative.front() != '/');
    EXPECT_TRUE(r.relative.find('\0') == std::string::npos);
  }
}

STELLAR_TEST(Paths, UnknownIdsAreUnresolvedRatherThanFabricated) {
  const std::vector<std::string> paths = {"", "/proj/a.h"};
  PathTable t(paths, PathOptions{});
  // An id the model never handed out must not produce a path.
  const output::ResolvedPath& r = t.get(9999);
  EXPECT_EQ(r.cls, PathClass::kUnresolved);
  EXPECT_TRUE(r.relative.empty());
  EXPECT_TRUE(r.original.empty());
}

STELLAR_TEST(Paths, ExternalRootsAreClassifiedAsExternal) {
  const std::vector<std::string> paths = {
      "",
      "/proj/src/a.cpp",
      "/usr/include/stdio.h",
      "/opt/android-ndk/toolchains/llvm/include/stdio.h",
      "/proj/vendor/libcxx/include/string",
      "/ndk/toolchains/llvm/prebuilt/linux-x86_64/include/c++/v1/string",
  };
  PathTable t(paths, PathOptions{});
  EXPECT_EQ(t.get(1).cls, PathClass::kProject);
  EXPECT_EQ(t.get(2).cls, PathClass::kExternal);
  EXPECT_EQ(t.get(3).cls, PathClass::kExternal);
  // Vendored under the project root: still the project's own source.
  EXPECT_EQ(t.get(4).cls, PathClass::kProject);
  EXPECT_EQ(t.get(5).cls, PathClass::kExternal);
}

STELLAR_TEST(Paths, UserSuppliedExternalPrefixIsHonoured) {
  const std::vector<std::string> paths = {"", "/proj/a.cpp", "/build/deps/thing.h"};
  PathOptions opts;
  opts.external_prefixes = {"/build/deps"};
  PathTable t(paths, opts);
  EXPECT_EQ(t.get(1).cls, PathClass::kProject);
  EXPECT_EQ(t.get(2).cls, PathClass::kExternal);
}

STELLAR_TEST(Paths, DetectedPrefixIsReportedNotAppliedSilently) {
  const std::vector<std::string> paths = {
      "", "/stellar-fixtures/src/a/b.h", "/stellar-fixtures/src/c/d.h",
  };
  PathTable t(paths, PathOptions{});
  EXPECT_TRUE(t.prefix_was_detected());
  EXPECT_STREQ(t.strip_prefix(), "/stellar-fixtures/src");
  EXPECT_STREQ(t.get(1).relative, "a/b.h");
  EXPECT_STREQ(t.get(2).relative, "c/d.h");
}

STELLAR_TEST(Paths, GivenPrefixIsNotMarkedAsDetected) {
  const std::vector<std::string> paths = {"", "/root/src/a.h", "/root/src/b.h"};
  PathOptions opts;
  opts.strip_prefix = "/root/src";
  PathTable t(paths, opts);
  EXPECT_FALSE(t.prefix_was_detected());
  EXPECT_STREQ(t.strip_prefix(), "/root/src");
}

STELLAR_TEST(Paths, CaseFoldCollisionsAreReported) {
  // Two paths differing only in case are the same file on a case-insensitive
  // checkout, so the difference must be surfaced rather than silently kept.
  const std::vector<std::string> paths = {
      "", "/proj/Include/Foo.h", "/proj/include/foo.h", "/proj/Other/Bar.h",
  };
  PathTable t(paths, PathOptions{});
  const std::vector<PathTable::CaseCollision>& c = t.report_collisions();
  EXPECT_TRUE(!c.empty());
  bool found = false;
  for (const PathTable::CaseCollision& x : c) {
    // The two spellings really are different, and only in case: that is the
    // whole point, since they denote one file on a case-insensitive checkout.
    const output::ResolvedPath& first = t.get(x.first_id);
    const output::ResolvedPath& second = t.get(x.second_id);
    EXPECT_TRUE(first.relative != second.relative);
    EXPECT_STREQ(second.relative, x.original);
    EXPECT_STREQ(fold_case(first.relative), x.lower);
    EXPECT_STREQ(fold_case(second.relative), x.lower);
    if (x.lower == "include/foo.h") found = true;
  }
  EXPECT_TRUE(found);
}

