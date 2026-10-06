// SPDX-License-Identifier: MIT
// Source-path normalisation and classification.
//
// Deliberately separate from normalize.h, which is the C# type-name presentation
// layer: nothing here has to do with how a type is spelled in the dump, only
// with where a declaration came from on disk.
//
// The rules are all defensive. A path reaching this layer came from a compiler
// and may contain anything at all, so the contract is:
//
//   * the result never contains "..", a leading "/", a drive letter, a
//     backslash or an embedded NUL;
//   * "." segments and duplicate separators are collapsed;
//   * a path that cannot be made safe -- because it escapes the root, is empty,
//     or is otherwise unrepresentable -- is quarantined with the original text
//     kept for reporting rather than being silently rewritten.
//
// Nothing here guesses. An unknown prefix is reported, not applied.
#pragma once

#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

namespace stellar::output {

/// Where a declaration lives, relative to the project root.
enum class PathClass : std::uint8_t {
  kProject,     ///< inside the project's own source tree
  kExternal,    ///< a toolchain, sysroot or system header
  kUnresolved,  ///< outside every known root and not classifiable
  kQuarantine,  ///< not safely representable; the original string is kept
};

[[nodiscard]] std::string_view path_class_name(PathClass c) noexcept;

/// How to classify paths, and how to make them project-relative.
struct PathOptions {
  /// Strip this prefix from absolute paths. When empty, the prefix is detected
  /// as the longest common directory of the project's files and REPORTED via
  /// detected_prefix(); it is never applied silently.
  std::string strip_prefix;
  /// Extra directories to treat as external. Repeatable on the command line.
  std::vector<std::string> external_prefixes;
  /// Include files classified as external in the output at all (default off).
  bool include_external = false;
};

/// One file id, resolved.
struct ResolvedPath {
  std::uint32_t file_id = 0;
  /// Project-relative, forward-slashed, guaranteed safe. Empty when quarantined.
  std::string relative;
  /// The path exactly as DWARF gave it, kept verbatim for quarantine reporting.
  std::string original;
  PathClass cls = PathClass::kUnresolved;
};

/// Turns the model's interned paths into relative, classified ones.
///
/// One instance per dump: it owns the index from the model's path ids and the
/// prefix it settled on, so callers can report both afterwards.
class PathTable {
 public:
  /// The model supplies the interned paths; they are read once here and never
  /// again, so the table outlives the ELF mapping.
  explicit PathTable(const std::vector<std::string>& model_paths, PathOptions opts);

  /// Classifies and normalises `file_id`. An id the model never handed out is
  /// kUnresolved rather than a fabricated path.
  [[nodiscard]] const ResolvedPath& get(std::uint32_t file_id);

  /// The prefix that was actually stripped, whether given or detected. Reported
  /// so a detected root is never applied without the user being told.
  [[nodiscard]] const std::string& strip_prefix() const { return strip_prefix_; }
  [[nodiscard]] bool prefix_was_detected() const { return detected_; }

  [[nodiscard]] std::uint64_t project_count() const { return project_; }
  [[nodiscard]] std::uint64_t external_count() const { return external_; }
  [[nodiscard]] std::uint64_t unresolved_count() const { return unresolved_; }
  std::uint64_t quarantine_count() const { return quarantine_; }

  /// Lowercased path -> first id seen with it, for case-fold collision
  /// reporting. Only populated once report_collisions() has been called.
  struct CaseCollision {
    std::string lower;
    std::string original;
    std::uint32_t first_id = 0;
    std::uint32_t second_id = 0;
  };
  /// Paths that differ only by case. Cheap to detect and worth reporting: on a
  /// case-insensitive checkout they are the same file.
  [[nodiscard]] const std::vector<CaseCollision>& report_collisions();

 private:
  PathOptions opts_;
  const std::vector<std::string>* model_paths_;
  std::string strip_prefix_;
  bool detected_ = false;
  std::vector<ResolvedPath> resolved_;
  std::vector<bool> done_;
  std::vector<CaseCollision> collisions_;
  bool collisions_checked_ = false;
  std::uint64_t project_ = 0;
  std::uint64_t external_ = 0;
  std::uint64_t unresolved_ = 0;
  std::uint64_t quarantine_ = 0;
};

/// Collapses "." segments and duplicate separators, and drops any ".." segment
/// together with the segment before it. Exposed for testing; returns false when
/// the result would escape the root, in which case `out` is left untouched.
[[nodiscard]] bool normalise_relative(std::string_view in, std::string& out);

/// True when `path` lies under an NDK/toolchain sysroot or a system include
/// directory. Recognised by shape, because the actual prefix differs per build.
[[nodiscard]] bool looks_like_external_path(std::string_view path);

}  // namespace stellar::output