#include "stellar/output/paths.h"

#include <algorithm>
#include <cctype>
#include <unordered_map>

namespace stellar::output {
namespace {

/// Lowercase ASCII, for case-fold comparison only. Not for display.
std::string fold_case(std::string_view s) {
  std::string out(s);
  for (char& c : out) {
    c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
  }
  return out;
}

/// True when `path` starts with `prefix` on a segment boundary, so "/usr/inc"
/// does not match "/usr/include/x".
bool under_prefix(std::string_view path, std::string_view prefix) {
  if (prefix.empty()) return false;
  if (path.size() < prefix.size()) return false;
  if (path.compare(0, prefix.size(), prefix) != 0) return false;
  return path.size() == prefix.size() || path[prefix.size()] == '/';
}

/// The directory part of a path, without a trailing slash. "/a/b/c" -> "/a/b".
std::string_view parent_dir(std::string_view p) {
  const std::size_t slash = p.find_last_of('/');
  if (slash == std::string_view::npos) return {};
  if (slash == 0) return p.substr(0, 1);
  return p.substr(0, slash);
}

}  // namespace

std::string_view path_class_name(PathClass c) noexcept {
  switch (c) {
    case PathClass::kProject: return "project";
    case PathClass::kExternal: return "external";
    case PathClass::kUnresolved: return "unresolved";
    case PathClass::kQuarantine: return "quarantine";
  }
  return "unresolved";
}

bool normalise_relative(std::string_view in, std::string& out) {
  std::string acc;
  acc.reserve(in.size());
  const std::size_t n = in.size();
  std::size_t i = 0;
  // Segments separated by '/' or '\'; a leading run is dropped so the result is
  // never absolute.
  while (i < n) {
    while (i < n && (in[i] == '/' || in[i] == '\\')) ++i;  // collapse separators
    if (i >= n) break;
    const std::size_t start = i;
    while (i < n && in[i] != '/' && in[i] != '\\') ++i;
    const std::string_view seg = in.substr(start, i - start);
    if (seg == ".") continue;  // current directory: nothing to add
    if (seg == "..") {
      // Escaping the root is not representable: refuse rather than silently
      // dropping the segment and pretending the path was fine.
      if (acc.empty()) return false;
      const std::size_t slash = acc.find_last_of('/');
      if (slash == std::string::npos) {
        acc.clear();
      } else {
        acc.resize(slash);
      }
      continue;
    }
    if (!acc.empty()) acc.push_back('/');
    acc.append(seg);
  }
  out = std::move(acc);
  return true;
}

bool looks_like_external_path(std::string_view path) {
  static const char* const kSysroots[] = {
      "/usr/include", "/usr/local/include", "/opt/android-ndk", "/ndk",
      "/sysroot", "/toolchains", "/usr/lib/gcc", "/usr/local/lib/gcc",
  };
  for (const char* s : kSysroots) {
    if (under_prefix(path, s)) return true;
  }
  // libc++ / libstdc++ headers, wherever the toolchain put them.
  if (path.find("/include/c++/") != std::string_view::npos) return true;
  if (path.find("/c++/v") != std::string_view::npos) return true;
  if (path.rfind("/c++/", 0) == 0) return true;
  return false;
}

PathTable::PathTable(const std::vector<std::string>& model_paths, PathOptions opts)
    : opts_(std::move(opts)), model_paths_(&model_paths) {
  // Exactly one cache entry per interned path, so get() can never index past
  // model_paths: id 0 is the sentinel and lives inside model_paths already.
  resolved_.resize(model_paths.size());
  done_.assign(model_paths.size(), false);

  // Choose the prefix to strip. A given prefix is used as-is; otherwise the
  // longest common directory of the project's paths is detected and recorded so
  // the caller can report it rather than applying it silently.
  strip_prefix_ = opts_.strip_prefix;
  if (!strip_prefix_.empty()) {
    while (strip_prefix_.size() > 1 && strip_prefix_.back() == '/') strip_prefix_.pop_back();
  } else {
    bool have = false;
    std::string_view common;
    for (const std::string& p : model_paths) {
      if (p.empty() || p.front() != '/') continue;
      const std::string_view dir = parent_dir(p);
      if (!have) {
        common = dir;
        have = true;
        continue;
      }
      std::size_t i = 0;
      while (i < common.size() && i < dir.size() && common[i] == dir[i]) ++i;
      common = common.substr(0, i);
      if (common.empty()) break;
    }
    strip_prefix_.assign(have ? common : std::string());
    // The common prefix of "/a/x" and "/a/y" is "/a/", but "/a/" is not a valid
    // prefix to strip by: under_prefix requires a separator at the boundary, so
    // "/a/" would match nothing and quietly leave every path absolute.
    while (strip_prefix_.size() > 1 && strip_prefix_.back() == '/') strip_prefix_.pop_back();
    detected_ = true;
  }
}

const ResolvedPath& PathTable::get(std::uint32_t file_id) {
  static const ResolvedPath kEmpty{};
  if (file_id == 0 || file_id >= done_.size()) return kEmpty;
  if (done_[file_id]) return resolved_[file_id];
  done_[file_id] = true;

  ResolvedPath& out = resolved_[file_id];
  out.file_id = file_id;
  const std::string& raw = (*model_paths_)[file_id];
  out.original = raw;

  // Nothing that can be printed safely.
  if (raw.empty() || raw.find('\0') != std::string::npos) {
    out.cls = PathClass::kQuarantine;
    ++quarantine_;
    return out;
  }
  if (raw.size() >= 2 && raw[1] == ':' &&
      std::isalpha(static_cast<unsigned char>(raw[0]))) {
    out.cls = PathClass::kQuarantine;  // "C:\..."
    ++quarantine_;
    return out;
  }
  if (raw.find('\\') != std::string::npos) {
    out.cls = PathClass::kQuarantine;  // a backslash is never a separator here
    ++quarantine_;
    return out;
  }

  // Classify before stripping: external roots are absolute, and stripping would
  // otherwise make them look like project files.
  bool external = looks_like_external_path(raw);
  for (const std::string& e : opts_.external_prefixes) {
    if (under_prefix(raw, e)) external = true;
  }

  std::string work = raw;
  if (!strip_prefix_.empty() && under_prefix(raw, strip_prefix_)) {
    work = raw.substr(strip_prefix_.size());
    if (work.empty()) work = raw;
  }

  std::string rel;
  if (!normalise_relative(work, rel) || rel.empty()) {
    out.cls = PathClass::kQuarantine;
    ++quarantine_;
    return out;
  }
  out.relative = std::move(rel);
  if (external) {
    out.cls = PathClass::kExternal;
    ++external_;
  } else {
    out.cls = PathClass::kProject;
    ++project_;
  }
  return out;
}

const std::vector<PathTable::CaseCollision>& PathTable::report_collisions() {
  if (collisions_checked_) return collisions_;
  collisions_checked_ = true;
  // Separate map for "first id seen under this folded key": collisions_ is the
  // result, and appending to it while walking it would invalidate the walk.
  std::unordered_map<std::string, std::uint32_t> first_seen;
  first_seen.reserve(resolved_.size() * 2);
  for (std::uint32_t i = 1; i < resolved_.size(); ++i) {
    const ResolvedPath& r = get(i);
    if (r.cls == PathClass::kQuarantine) continue;
    const std::string key = fold_case(r.relative);
    const auto seen = first_seen.find(key);
    if (seen == first_seen.end()) {
      first_seen.emplace(key, i);
      continue;
    }
    // Same path under a different spelling: identical text is not a collision.
    const ResolvedPath& first = resolved_[seen->second];
    if (first.relative != r.relative) {
      collisions_.push_back({key, r.relative, seen->second, i});
    }
  }
  return collisions_;
}

}  // namespace stellar::output