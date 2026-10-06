// SPDX-License-Identifier: MIT
// Source-shaped tree emitter: one .h per declaring file, one .cpp per
// compilation unit, plus a machine-readable tree.json and a root manifest.
//
// The difference from emit_il2cpp.cpp is not the C# spelling, it is the honesty
// rule. The flat dump reconstructs a C#-shaped view of the whole binary, which
// means it has to invent padding slots to make a class tile, and it cannot say
// where anything came from. The tree emitter instead mirrors the source tree the
// debug info describes, so every rule in it is a rule about not inventing:
//
//   * no padding fields are ever synthesised; a gap between two members is left
//     as the gap it is, with both real offsets shown;
//   * DW_AT_artificial members are skipped by attribute, not by name, because
//     _vptr$X occupies a real offset but is not source;
//   * DW_AT_declaration types print as `class X;` with no members at all, since
//     a forward declaration carries none;
//   * a function with no code range prints as inline-only. Having no address is
//     not a parse failure and must not be reported as a missing method;
//   * anything whose declaring file cannot be resolved goes to _unresolved/.
//     It is never guessed into a plausible-looking project path.
//
// Files are written streaming, one at a time, and never held in memory as a
// whole. Every write is checked: a tree that silently loses a file is worse
// than one that fails.
#pragma once

#include <cstdint>
#include <cstdio>
#include <string>
#include <vector>

#include "stellar/ir/model.h"
#include "stellar/output/bodies.h"
#include "stellar/output/paths.h"

namespace stellar::output {

/// Which of the two layouts to produce. The default is the existing flat dump.
enum class Layout : std::uint8_t {
  kSingleFile,
  kTree,
};

struct TreeOptions {
  /// Root the tree is written under. The tree goes in a folder named after the
  /// library inside it, so `out/` plus libfoo.so gives `out/libfoo/...`.
  std::string out_dir;
  /// Recorded in the manifest and used for the tree folder name.
  std::string target_name = "target.so";
  /// Producer string, as DWARF gave it.
  std::string producer;
  /// DWARF version, as the scan reported it (4 or 5).
  std::uint32_t dwarf_version = 0;
  std::uint64_t unit_count = 0;
  /// Path handling, shared with the flat layout's reporting.
  PathOptions paths;
  /// Overwrite a non-empty output folder instead of refusing.
  bool force = false;
  /// Emit the tree as a folder on disk (default).
  bool folder = true;
  /// Also (or only) pack the tree into a .zip next to the folder.
  bool zip = false;
  /// Cap on emitted lines per file (0 = unlimited). Used by tests.
  std::uint64_t max_lines = 0;
  /// When non-null, definitions also get their disassembly (--bodies=asm). Null
  /// keeps the output identical to a build that never had this option.
  const BodySource* bodies = nullptr;
};

/// What the tree emitter wrote, so the manifest and the caller can report it.
struct TreeStats {
  std::uint64_t files = 0;  ///< .h and .cpp files written
  std::uint64_t headers = 0;
  std::uint64_t sources = 0;
  std::uint64_t types = 0;
  std::uint64_t methods = 0;
  std::uint64_t free_functions = 0;
  std::uint64_t fields = 0;
  std::uint64_t lines = 0;
  std::uint64_t bytes = 0;
  /// Declarations dropped because they had no resolvable source file.
  std::uint64_t unresolved = 0;
  /// Members skipped because DW_AT_artificial was set.
  std::uint64_t artificial_skipped = 0;
  /// Types printed as a forward declaration because DW_AT_declaration was set.
  std::uint64_t declarations_only = 0;
  /// Functions with no code range, printed as inline-only.
  std::uint64_t inline_only = 0;
  /// Files skipped because they were classified external and not requested.
  std::uint64_t external_skipped = 0;
  /// Files skipped because their path could not be made safe.
  std::uint64_t quarantined = 0;
  /// Declarations the tree mode does not represent. Reported in the manifest
  /// rather than silently dropped.
  std::uint64_t filtered = 0;
  TreeStats& operator+=(const TreeStats& o) {
    files += o.files;
    headers += o.headers;
    sources += o.sources;
    types += o.types;
    methods += o.methods;
    free_functions += o.free_functions;
    fields += o.fields;
    lines += o.lines;
    bytes += o.bytes;
    unresolved += o.unresolved;
    artificial_skipped += o.artificial_skipped;
    declarations_only += o.declarations_only;
    inline_only += o.inline_only;
    external_skipped += o.external_skipped;
    quarantined += o.quarantined;
    filtered += o.filtered;
    return *this;
  }
};

/// The folder the tree lives in. A folder called libfoo.so reads as the
/// library itself, so the tree drops the shared-object suffix: libfoo.so
/// becomes libfoo/. target_name is still the real library name everywhere
/// inside the tree.
inline std::string tree_folder_name(std::string_view target_name) {
  std::string_view name = target_name;
  for (std::string_view const suffix : {".dylib", ".dll", ".lib", ".a"}) {
    if (name.size() > suffix.size() &&
        name.compare(name.size() - suffix.size(), suffix.size(), suffix) == 0) {
      name.remove_suffix(suffix.size());
      return std::string(name);
    }
  }
  const std::size_t so = name.rfind(".so");
  if (so != std::string_view::npos &&
      (so + 3 == name.size() || name[so + 3] == '.' || name[so + 3] == '-' ||
       (name[so + 3] >= '0' && name[so + 3] <= '9'))) {
    name.remove_suffix(name.size() - so);
  }
  return name.empty() ? std::string(target_name) : std::string(name);
}

/// Writes the tree under `opts.out_dir`. Returns false and reports the reason
/// on stderr if the output folder is occupied (without --force), if the folder
/// cannot be created, or if any individual file fails to write.
bool emit_tree(const ir::Model& model, const TreeOptions& opts, TreeStats* stats = nullptr);

}  // namespace stellar::output
