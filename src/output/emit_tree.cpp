#include "stellar/output/emit_tree.h"

#include <algorithm>
#include <atomic>
#include <cerrno>
#include <cstring>
#include <filesystem>
#include <thread>
#include <map>
#include <set>
#include <system_error>

#include "stellar/diag/progress.h"
#include "stellar/output/normalize.h"
#include "stellar/output/zip.h"

namespace stellar::output {
namespace {

namespace fs = std::filesystem;

/// One output file: the path relative to the tree root, and what belongs in it.
/// Grouping declarations by file first is what keeps memory bounded -- only the
/// index of declarations is held, and each file's text is generated and streamed
/// as it is written, then thrown away.
/// A model index tagged with which table it came from, so one vector can hold
/// both classes and enums without the emitter having to re-derive the type.
struct TypeRef {
  std::uint32_t index = 0;
  std::uint8_t is_enum = 0;
};

struct FileGroup {
  /// Relative, already safe: no "..", no leading "/", no backslash.
  std::string relative;
  PathClass cls = PathClass::kProject;
  /// True for a .cpp: a compilation unit rather than a header.
  bool is_source = false;
  /// Types declared here, tagged so a class is never read as an enum.
  std::vector<TypeRef> types;
  /// Method indices whose declaration is here.
  std::vector<std::uint32_t> methods;
  /// FreeFunction indices declared here.
  std::vector<std::uint32_t> free_functions;
  /// OutOfLineDef indices whose definition is here.
  std::vector<std::uint32_t> orphans;
};

/// Lowercase hex with no "0x" prefix, at least `min_digits` wide. Minimum, not
/// fixed: a 0x1c member offset must print as "1c", and truncation to a fixed
/// width would silently print a plausible but wrong offset.
std::string hex_lower(std::uint64_t v, int min_digits) {
  static const char* digits = "0123456789abcdef";
  std::string out;
  do {
    out.push_back(digits[v & 0xfu]);
    v >>= 4;
  } while (v != 0);
  while (static_cast<int>(out.size()) < min_digits) out.push_back('0');
  for (std::size_t i = 0, j = out.size() - 1; i < j; ++i, --j) std::swap(out[i], out[j]);
  return out;
}

/// True when `name` is safe to use as a single path segment: no separator, no
/// traversal, no dot-only name, nothing empty or NUL-bearing. A source file name
/// comes from a compiler, so this is checked rather than assumed.
bool safe_segment(std::string_view name) {
  if (name.empty() || name.size() > 200) return false;
  if (name == "." || name == "..") return false;
  for (char c : name) {
    if (c == '/' || c == '\\' || c == '\0') return false;
    // Control characters would make an unreadable path and can hide a real one.
    if (static_cast<unsigned char>(c) < 0x20 || c == 0x7f) return false;
  }
  return true;
}

/// Truncates a segment to at most 200 chars by replacing the middle with a short
/// hash so the result is still distinguishable and filesystem-safe.
std::string truncate_segment(std::string_view name) {
  if (name.size() <= 200) return std::string(name);
  // Simple FNV-1a hash, 8 hex chars = 32 bits.
  std::uint32_t h = 0x811c9dc5u;
  for (unsigned char c : name) {
    h ^= c;
    h *= 0x01000193u;
  }
  char hex[9];
  std::snprintf(hex, sizeof hex, "%08x", h);
  // Keep 96 chars prefix + 8 hex + 96 chars suffix = 200 exactly.
  const std::size_t keep = 96;
  std::string out;
  out.reserve(200);
  out.append(name.substr(0, keep));
  out.append(hex);
  out.append(name.substr(name.size() - keep));
  return out;
}

/// Splits an already-normalised relative path on '/'. Only meaningful after
/// normalise_relative, so there are no empty or dot segments to worry about.
std::vector<std::string> split_segments(const std::string& rel) {
  std::vector<std::string> out;
  std::string cur;
  for (char c : rel) {
    if (c == '/') {
      if (!cur.empty()) out.push_back(truncate_segment(cur));
      cur.clear();
    } else {
      cur.push_back(c);
    }
  }
  if (!cur.empty()) out.push_back(truncate_segment(cur));
  return out;
}

/// Makes every directory of `rel` under `root`, then checks the result is still
/// inside `root`. The containment check is done on the real path after
/// resolution, so a symlink planted inside the output folder cannot redirect a
/// write outside it.
bool ensure_contained(const fs::path& root, const std::string& rel) {
  std::string norm;
  if (!normalise_relative(rel, norm) || norm.empty()) return false;
  for (const std::string& seg : split_segments(norm)) {
    if (!safe_segment(seg)) return false;
  }
  return true;
}

/// A write sink that counts lines and bytes and refuses to fail silently.
/// Every fputs goes through here so "report write errors, never ignore them" is
/// a property of the type rather than of each call site remembering to check.
class Out {
 public:
  explicit Out(std::FILE* f) : f_(f) {}
  bool line(std::string_view s) {
    if (std::fwrite(s.data(), 1, s.size(), f_) != s.size()) return fail();
    if (std::fputc('\n', f_) == EOF) return fail();
    ++lines_;
    bytes_ += s.size() + 1;
    return true;
  }
  bool fail() {
    ok_ = false;
    return false;
  }
  bool ok() const { return ok_; }
  std::uint64_t lines() const { return lines_; }
  std::uint64_t bytes() const { return bytes_; }

 private:
  std::FILE* f_ = nullptr;
  bool ok_ = true;
  std::uint64_t lines_ = 0;
  std::uint64_t bytes_ = 0;
};

/// The header comment every generated file starts with. It has to say where the
/// data came from, because the whole point of the tree is that a reader can tell
/// reconstruction from source.
bool write_file_header(Out& o, const TreeOptions& opts, const std::string& rel, bool source) {
  return o.line("// Reconstructed from DWARF, not original source.") &&
         o.line("// Source file: " + rel + (source ? "  (compilation unit)" : "")) &&
         o.line("// Target: " + opts.target_name) &&
         o.line("// DWARF version: " + std::to_string(opts.dwarf_version)) &&
         o.line("// Producer: " + (opts.producer.empty() ? "(none)" : opts.producer)) &&
         o.line("// Compilation units: " + std::to_string(opts.unit_count)) &&
         o.line("#pragma once") && o.line("");
}

/// Where a declaration with this provenance belongs, relative to the tree root.
/// Returns an empty string when the declaration must not be written at all
/// (external and not requested).
///
/// The three-way split is the accuracy rule: project paths mirror the source
/// tree, external paths go under _external/ only when asked for, and anything
/// unresolvable goes to _unresolved/ under a name that says it is unresolved.
/// Nothing is guessed into a project path, ever.
std::string destination_for(PathTable& table, const TreeOptions& opts, const ir::Provenance& prov,
                            std::string_view fallback_name, bool source_hint, TreeStats& st) {
  const ResolvedPath& r = table.get(prov.file_id);
  switch (r.cls) {
    case PathClass::kProject: {
      if (r.relative.empty()) break;
      std::string rel = r.relative;
      // Trust the extension the compiler recorded: a .cpp in DWARF is a
      // translation unit, a .h is a header. Only guess when there is no suffix.
      const std::size_t slash = rel.find_last_of('/');
      const std::size_t dot = rel.find_last_of('.');
      if (dot == std::string::npos || (slash != std::string::npos && dot < slash)) {
        rel += source_hint ? ".cpp" : ".h";
      }
      return rel;
    }
    case PathClass::kExternal:
      if (!opts.paths.include_external) {
        ++st.external_skipped;
        return std::string();
      }
      if (r.relative.empty()) break;
      return "_external/" + r.relative;
    case PathClass::kQuarantine:
      ++st.quarantined;
      break;
    case PathClass::kUnresolved:
      break;
  }
  // Unresolved or quarantined: keep it, clearly labelled, under _unresolved/.
  // A type with no usable name still gets a line in the unresolved file rather
  // than vanishing, so the count of what could not be placed is checkable.
  ++st.unresolved;
  std::string name(fallback_name);
  std::string clean;
  if (!normalise_relative(name, clean) || clean.empty()) clean = "unknown";
  // Flatten: _unresolved/ is a single folder, and a name with '/' in it would
  // silently create subdirectories that look like a source tree.
  for (char& c : clean) {
    if (c == '/') c = '_';
  }
  // Template-ish names contain characters that FAT/sdcardfs refuse
  // ('<', '>', '?', '*', ':'): keep the name readable but make the file
  // removable on any filesystem, and disambiguate with a short hash so two
  // names that sanitise the same do not merge into one file.
  for (char& c : clean) {
    switch (c) {
      case '<': case '>': case '?': case '*': case ':': case '"':
      case '|': case ',': case '(': case ')': case ' ': case '\t':
        c = '_';
        break;
      default: break;
    }
  }
  if (clean.size() > 180) clean.resize(180);
  if (!safe_segment(clean)) clean = "unknown";
  {
    std::uint32_t h = 0x811c9dc5u;
    for (unsigned char cu : name) { h ^= cu; h *= 0x01000193u; }
    char hex[9];
    std::snprintf(hex, sizeof hex, "%08x", h);
    clean += std::string("-") + hex;
  }
  return "_unresolved/" + clean + (source_hint ? ".cpp" : ".h");
}

/// Emits one class or enum.
///
/// Members are sorted by declaration line so the file reads in source order, and
/// the line stays in the trailing comment so a reader can see the gaps: if the
/// source had a comment or a blank run between two members, that is visible as
/// jumping line numbers instead of being papered over. No padding field is ever
/// inserted -- a gap is shown by the two real offsets, not by an invented member.
bool emit_type(Out& o, const ir::Model& m, const TypeRef& ref, TreeStats& st) {
  if (ref.is_enum) {
    const ir::EnumDef& e = m.enums[ref.index];
    const std::string_view nm = m.name(e.name_off);
    // DW_AT_enum_class is the only thing distinguishing `Shape.kCircle` from
    // `kCircle`; without it the qualified spelling would be a guess.
    const char* kw = e.is_enum_class ? "enum class" : "enum";
    if (!o.line(std::string("// ") + std::string(nm) + (e.prov.line ? " : " + std::to_string(e.prov.line) : "") +
                "  // Size: 0x" + hex_lower(e.size, 1) +
                (e.size != 0 ? " Confidence: exact" : " Confidence: partial")))
      return false;
    // An enum with no name is not a write error. `enum { A = 0, B = 1 };` is
    // ordinary C++, and a name the debug info does not carry must not be
    // invented -- so it is printed anonymously rather than dropped, and the
    // enum class keyword goes with the name it qualified (an anonymous enum
    // class is not a thing). Failing here is what aborted a whole tree over one
    // unnamed enum, leaving a half-written folder that looked finished.
    if (!o.line(nm.empty() ? std::string("enum")
                           : std::string(kw) + " " + std::string(nm)))
      return false;
    if (!o.line("{")) return false;
    for (std::uint32_t k = 0; k < e.member_count; ++k) {
      const std::uint32_t mi = e.first_member + k;
      if (mi >= m.enum_members.size()) break;
      const ir::EnumMember& em = m.enum_members[mi];
      const std::string_view en = m.name(em.name_off);
      // A scoped enum prints as Shape.kCircle; a plain one has no prefix in the
      // source and adding one would change the meaning.
      if (!o.line("    " + std::string(e.is_enum_class && !nm.empty() ? std::string(nm) + "." : std::string()) +
                  std::string(en) + " = " + std::to_string(em.value) + ","))
        return false;
    }
    if (!o.line("};") || !o.line("")) return false;
    ++st.types;
    return true;
  }

  const ir::ClassDef& c = m.classes[ref.index];
  const std::string_view nm = m.class_name(c);
  const char* kw = c.kind == 2 ? "union" : (c.kind == 1 ? "class" : "struct");
  if (!o.line(std::string("// ") + std::string(nm) + (c.prov.line ? " : " + std::to_string(c.prov.line) : "") +
              "  // Size: 0x" + hex_lower(c.size, 1) +
              (c.size != 0 ? " Confidence: exact" : " Confidence: partial")))
    return false;

  // A class with an artificial vtable member has a vtable. Announcing it is
  // better than emitting nothing and letting the reader wonder why there is no
  // vptr field -- the member itself is correctly skipped.
  bool has_vtable = false;
  std::vector<std::uint32_t> members;
  for (std::uint32_t k = 0; k < c.field_count; ++k) {
    const std::uint32_t fi = c.first_field + k;
    if (fi >= m.fields.size()) break;
    if (m.fields[fi].is_artificial) {
      ++st.artificial_skipped;
      has_vtable = true;
      continue;
    }
    members.push_back(fi);
  }
  std::stable_sort(members.begin(), members.end(), [&](std::uint32_t a, std::uint32_t b) {
    return m.fields[a].prov.line < m.fields[b].prov.line;
  });

  std::string decl = std::string(kw) + " " + std::string(nm);
  if (c.base != ir::kNoType) {
    const std::string b = normalize_type(m.type_name(c.base));
    if (!b.empty()) decl += " : public " + b;
  }
  // The brace goes before the vtable note: a "//" comment would swallow it and
  // the class would have no body.
  std::string vtable_note = has_vtable ? "  // has vtable" : std::string();

  // A type whose only DIE carries DW_AT_declaration carries no members at all.
  // Printing a body here would invent them.
  if (members.empty() && c.field_count == 0 && c.method_count == 0) {
    if (!o.line(decl + ";")) return false;
    if (!o.line("")) return false;
    ++st.types;
    ++st.declarations_only;
    return true;
  }
  // The brace has to precede the note: a "//" comment runs to end of line and
  // would swallow it, leaving a class declaration with no body.
  if (!o.line(decl + "{" + vtable_note)) return false;

  for (std::uint32_t fi : members) {
    const ir::Field& f = m.fields[fi];
    const std::string_view fname = m.name(f.name_off);
    if (fname.empty() || is_abi_artifact(fname)) continue;
    std::string t = normalize_type(m.type_name(f.type));
    if (t.empty()) t = "/* unknown */";
    // A static member has no instance offset, so none is printed. Printing 0x0
    // would be a real-looking lie: 0x0 is a real offset for something else.
    if (f.is_static) {
      if (!o.line("    public static readonly " + t + " " + std::string(fname) + ";"))
        return false;
    } else {
      std::string off = f.offset_known ? "0x" + hex_lower(f.offset, 1) : "offset unavailable";
      if (!o.line("    public " + t + " " + std::string(fname) + "; // " + off +
                  (f.prov.line ? " :" + std::to_string(f.prov.line) : "")))
        return false;
    }
    ++st.fields;
  }

  // Inline member declarations. The body is not in the debug info, so it is
  // labelled rather than reconstructed.
  for (std::uint32_t k = 0; k < c.method_count; ++k) {
    const std::uint32_t mi = c.first_method + k;
    if (mi >= m.methods.size()) break;
    const ir::Method& mm = m.methods[mi];
    if (mm.is_artificial) continue;
    const std::string_view mname = m.name(mm.name_off);
    if (mname.empty() || is_generated_method(mname)) continue;
    if (!o.line("    // " + std::string(mname) +
                (mm.decl.line ? " :" + std::to_string(mm.decl.line) : "") + "  /* not recoverable */"))
      return false;
  }
  if (!o.line("};") || !o.line("")) return false;
  ++st.types;
  return true;
}


/// Escapes a string for JSON. Only the characters JSON actually reserves are
/// escaped; the paths here are ASCII in practice but a debug producer string is
/// arbitrary and must not be able to break the file.
std::string json_escape(std::string_view in) {
  std::string out;
  out.reserve(in.size() + 8);
  for (char c : in) {
    switch (c) {
      case '"': out += "\\\""; break;
      case '\\': out += "\\\\"; break;
      case '\n': out += "\\n"; break;
      case '\r': out += "\\r"; break;
      case '\t': out += "\\t"; break;
      default:
        if (static_cast<unsigned char>(c) < 0x20) {
          static const char* d = "0123456789abcdef";
          out += "\\u00";
          out.push_back(d[(static_cast<unsigned char>(c) >> 4) & 0xf]);
          out.push_back(d[static_cast<unsigned char>(c) & 0xf]);
        } else {
          out.push_back(c);
        }
    }
  }
  return out;
}

/// Writes tree.json: file -> types -> members -> offsets and provenance.
///
/// Emitted streaming in the same order as the files, and it carries the same
/// information as the C# -- offsets, lines and provenance -- so a consumer never
/// has to parse the comments to get a value.
bool write_tree_json(const fs::path& root, const ir::Model& m, const TreeOptions& opts,
                     const std::map<std::string, FileGroup>& groups,
                     const std::vector<std::string>& written, PathTable& table, TreeStats& st) {
  std::FILE* f = std::fopen((root / "tree.json").string().c_str(), "wb");
  if (f == nullptr) {
    std::fprintf(stderr, "error: cannot open tree.json for writing: %s\n", std::strerror(errno));
    return false;
  }
  Out o(f);
  o.line("{");
  o.line("  \"target\": \"" + json_escape(opts.target_name) + "\",");
  o.line("  \"dwarf_version\": " + std::to_string(opts.dwarf_version) + ",");
  o.line("  \"producer\": \"" + json_escape(opts.producer) + "\",");
  o.line("  \"strip_prefix\": \"" + json_escape(table.strip_prefix()) + "\",");
  o.line("  \"strip_prefix_detected\": " + std::string(table.prefix_was_detected() ? "true" : "false") + ",");
  o.line("  \"files\": [");
  bool first_file = true;
  for (const std::string& rel : written) {
    const FileGroup& g = groups.at(rel);
    o.line(std::string("    {") + (first_file ? "" : ","));
    first_file = false;
    o.line("      \"path\": \"" + json_escape(rel) + "\",");
    o.line(std::string("      \"kind\": \"") + (g.is_source ? "source" : "header") + "\",");
    o.line("      \"class\": \"" + std::string(path_class_name(g.cls)) + "\",");
    o.line("      \"types\": [");
    bool first_type = true;
    for (const TypeRef& tr : g.types) {
      o.line(std::string("        {") + (first_type ? "" : ","));
      first_type = false;
      if (tr.is_enum) {
        const ir::EnumDef& e = m.enums[tr.index];
        o.line("          \"name\": \"" + json_escape(m.name(e.name_off)) + "\",");
        o.line("          \"kind\": \"enum\",");
        o.line(std::string("          \"scoped\": ") + (e.is_enum_class ? "true" : "false") + ",");
        o.line("          \"size\": " + std::to_string(e.size) + ",");
        o.line("          \"decl_line\": " + std::to_string(e.prov.line));
        o.line("        }");
        continue;
      }
      const ir::ClassDef& c = m.classes[tr.index];
      o.line("          \"name\": \"" + json_escape(m.class_name(c)) + "\",");
      o.line(std::string("          \"kind\": \"") + (c.kind == 2 ? "union" : (c.kind == 1 ? "class" : "struct")) + "\",");
      o.line("          \"size\": " + std::to_string(c.size) + ",");
      o.line("          \"decl_line\": " + std::to_string(c.prov.line) + ",");
      o.line("          \"members\": [");
      std::vector<std::uint32_t> members;
      for (std::uint32_t k = 0; k < c.field_count; ++k) {
        const std::uint32_t fi = c.first_field + k;
        if (fi >= m.fields.size()) break;
        if (m.fields[fi].is_artificial) continue;  // not source; never reported
        members.push_back(fi);
      }
      bool first_m = true;
      for (std::uint32_t fi : members) {
        const ir::Field& fld = m.fields[fi];
        o.line(std::string("            {") + (first_m ? "" : ","));
        first_m = false;
        o.line("              \"name\": \"" + json_escape(m.name(fld.name_off)) + "\",");
        o.line("              \"type\": \"" + json_escape(normalize_type(m.type_name(fld.type))) + "\",");
        o.line(std::string("              \"static\": ") + (fld.is_static ? "true" : "false") + ",");
        if (!fld.is_static) {
          o.line(std::string("              \"offset\": ") +
                 (fld.offset_known ? std::to_string(fld.offset) : "null") + ",");
        }
        o.line("              \"decl_line\": " + std::to_string(fld.prov.line));
        o.line("            }");
      }
      o.line("          ]");
      o.line("        }");
    }
    o.line("      ]");
    o.line("    }");
  }
  o.line("  ]");
  o.line("}");
  st.lines += o.lines();
  st.bytes += o.bytes();
  const bool wrote = std::fclose(f) == 0 && o.ok();
  if (!wrote) {
    std::fprintf(stderr, "error: failed writing tree.json: %s\n", std::strerror(errno));
    return false;
  }
  return true;
}

/// The root manifest. Everything a reader needs to judge the dump without
/// re-running it: what was read, what was chosen, and what was left out.
bool write_manifest(const fs::path& root, const ir::Model& m, const TreeOptions& opts,
                    const std::vector<std::string>& written, PathTable& table, TreeStats st) {
  std::FILE* f = std::fopen((root / "_stellar.txt").string().c_str(), "wb");
  if (f == nullptr) {
    std::fprintf(stderr, "error: cannot open _stellar.txt for writing: %s\n", std::strerror(errno));
    return false;
  }
  Out o(f);
  o.line("stellar tree manifest");
  o.line("=====================");
  o.line("source library : " + opts.target_name);
  o.line("DWARF version  : " + std::to_string(opts.dwarf_version));
  o.line("producer       : " + (opts.producer.empty() ? "(none)" : opts.producer));
  o.line("units          : " + std::to_string(opts.unit_count));
  o.line("strip prefix   : \"" + table.strip_prefix() + "\"" +
         (table.prefix_was_detected() ? "  (auto-detected)" : "  (given)"));
  o.line("");
  o.line("files written  : " + std::to_string(st.files) + "  (" + std::to_string(st.headers) +
         " headers, " + std::to_string(st.sources) + " sources)");
  o.line("types          : " + std::to_string(st.types));
  o.line("  forward decls: " + std::to_string(st.declarations_only));
  o.line("fields         : " + std::to_string(st.fields));
  o.line("methods        : " + std::to_string(st.methods));
  o.line("free functions : " + std::to_string(st.free_functions));
  o.line("  inline-only  : " + std::to_string(st.inline_only));
  o.line("");
  o.line("filtered       : " + std::to_string(st.filtered) +
         "  (hidden or vtable-derived types with no source location)");
  o.line("artificial     : " + std::to_string(st.artificial_skipped) +
         "  (DW_AT_artificial members skipped)");
  o.line("external       : " + std::to_string(st.external_skipped) +
         "  (files skipped; use --include-external to emit them under _external/)");
  o.line("unresolved     : " + std::to_string(st.unresolved) +
         "  (no resolvable source file; written under _unresolved/)");
  o.line("quarantined    : " + std::to_string(st.quarantined) + "  (unsafe paths refused)");
  o.line("");
  o.line("options used");
  o.line("  --layout=tree");
  if (!opts.paths.strip_prefix.empty()) o.line("  --strip-prefix=" + opts.paths.strip_prefix);
  else if (table.prefix_was_detected()) o.line("  --strip-prefix  (auto-detected)");
  if (opts.paths.include_external) o.line("  --include-external");
  for (const std::string& e : opts.paths.external_prefixes) o.line("  --external-prefix=" + e);
  if (opts.force) o.line("  --force");
  if (opts.max_lines != 0) o.line("  --max-lines=" + std::to_string(opts.max_lines));
  o.line("");
  o.line("files");
  for (const std::string& rel : written) o.line("  " + rel);
  st.lines += o.lines();
  st.bytes += o.bytes();
  const bool wrote = std::fclose(f) == 0 && o.ok();
  if (!wrote) {
    std::fprintf(stderr, "error: failed writing _stellar.txt: %s\n", std::strerror(errno));
    return false;
  }
  return true;
}

/// Writes both root-level sidecars, in that order.
bool write_sidecars(const fs::path& root, const ir::Model& m, const TreeOptions& opts,
                    const std::map<std::string, FileGroup>& groups,
                    const std::vector<std::string>& written, PathTable& table, TreeStats& st) {
  return write_tree_json(root, m, opts, groups, written, table, st) &&
         write_manifest(root, m, opts, written, table, st);
}

/// Groups a declaration's destination, creating the group on first use.
FileGroup& group_for(std::map<std::string, FileGroup>& groups, const std::string& rel, PathClass cls,
                     bool is_source) {
  auto it = groups.find(rel);
  if (it == groups.end()) it = groups.emplace(rel, FileGroup{rel, cls, is_source, {}, {}, {}, {}}).first;
  return it->second;
}

}  // namespace

bool emit_tree(const ir::Model& model, const TreeOptions& opts, TreeStats* stats) {
  TreeStats st;
  std::error_code ec;

  // The tree lives in a folder named after the library, so two libraries dumped
  // into one output root do not collide.
  const fs::path root = fs::path(opts.out_dir.empty() ? "output" : opts.out_dir) / tree_folder_name(opts.target_name);

  // Refuse to write into a folder that already has content. Overwriting is
  // possible but must be asked for: a stale tree that looks fresh is worse than
  // a refusal.
  if (fs::exists(root, ec)) {
    bool non_empty = false;
    if (fs::is_directory(root, ec)) {
      for (fs::directory_iterator it(root, ec), end; !ec && it != end; it.increment(ec)) {
        (void)it;
        non_empty = true;
        break;
      }
    } else {
      non_empty = true;
    }
    if (non_empty && !opts.force) {
      std::fprintf(stderr, "error: %s already exists and is not empty (use --force)\n",
                   root.string().c_str());
      return false;
    }
  }
  fs::create_directories(root, ec);
  if (ec) {
    std::fprintf(stderr, "error: cannot create %s: %s\n", root.string().c_str(), ec.message().c_str());
    return false;
  }

  auto& pr = diag::progress();
  pr.stage("Grouping declarations");
  pr.declare("Types", 0, false);
  pr.primary("Types");
  PathTable table(model.paths, opts.paths);
  table.report_collisions();
  st.quarantined += table.quarantine_count();

  // ---- group declarations by destination file -----------------------------
  std::map<std::string, FileGroup> groups;

  auto add_type = [&](const ir::Provenance& prov, std::string_view nm) {
    const std::string rel =
        destination_for(table, opts, prov, nm.empty() ? "unknown_type" : nm, false, st);
    if (rel.empty()) return;
    group_for(groups, rel, table.get(prov.file_id).cls, false);
  };

  // Classes and enums, in declaration order, placed in their declaring header.
  for (std::size_t i = 0; i < model.classes.size(); ++i) {
    const ir::ClassDef& c = model.classes[i];
    // A hidden entry is a redeclaration deduplicate() already folded into a
    // sibling, and an arena entry has no DIE at all: neither has a source file.
    if (c.hidden || c.from_arena) {
      ++st.filtered;
      continue;
    }
    const std::string rel = destination_for(table, opts, c.prov, model.class_name(c), false, st);
    if (rel.empty()) continue;
    group_for(groups, rel, table.get(c.prov.file_id).cls, false).types.push_back(
        TypeRef{static_cast<std::uint32_t>(i), 0});
    pr.add("Types");
  }
  for (std::size_t i = 0; i < model.enums.size(); ++i) {
    const ir::EnumDef& e = model.enums[i];
    const std::string rel = destination_for(table, opts, e.prov, model.name(e.name_off), false, st);
    if (rel.empty()) continue;
    group_for(groups, rel, table.get(e.prov.file_id).cls, false).types.push_back(
        TypeRef{static_cast<std::uint32_t>(i), 1});
    pr.add("Types");
  }

  // Definitions whose declaration could not be paired. They are the only proof
  // that a .cpp exists, so they are placed by their own definition site.
  for (std::size_t i = 0; i < model.out_of_line_defs.size(); ++i) {
    const ir::OutOfLineDef& od = model.out_of_line_defs[i];
    const std::string rel = destination_for(table, opts, od.def, model.name(od.name_off), true, st);
    if (rel.empty()) continue;
    group_for(groups, rel, table.get(od.def.file_id).cls, true).orphans.push_back(
        static_cast<std::uint32_t>(i));
  }

  // Out-of-line definitions go in the .cpp of their definition file, which is a
  // different DIE from the declaration and often a different file entirely.
  for (std::size_t i = 0; i < model.methods.size(); ++i) {
    const ir::Method& m = model.methods[i];
    if (m.is_artificial || m.addr == 0) continue;
    if (m.def.file_id == 0) continue;
    const std::string rel = destination_for(table, opts, m.def, model.name(m.name_off), true, st);
    if (rel.empty()) continue;
    group_for(groups, rel, table.get(m.def.file_id).cls, true).methods.push_back(
        static_cast<std::uint32_t>(i));
  }
  for (std::size_t i = 0; i < model.free_functions.size(); ++i) {
    const ir::FreeFunction& f = model.free_functions[i];
    // An inline-only function has no definition site: it belongs in the header
    // where it was declared, and saying so is the point.
    const ir::Provenance& p = f.decl;
    const std::string rel = destination_for(table, opts, p, model.name(f.name_off), !f.has_range, st);
    if (rel.empty()) continue;
    FileGroup& g = group_for(groups, rel, table.get(p.file_id).cls, f.has_range && f.addr != 0);
    g.free_functions.push_back(static_cast<std::uint32_t>(i));
  }

  // ---- write the files, streaming one at a time ---------------------------
  pr.stage("Writing tree");
  pr.set("Types", 0);
  pr.declare("Files", static_cast<std::uint64_t>(groups.size()));
  pr.declare("Methods", 0, false);
  pr.primary("Files");
  bool ok = true;
  std::vector<std::string> written;
  written.reserve(groups.size());

  struct GroupResult {
    TreeStats stats;
    std::string error;
    bool ok = false;
  };
  auto write_group = [&](const std::string& rel, const FileGroup& g) -> GroupResult {
    TreeStats gst;
    bool ok_ = true;
    // ---- relocated per-group body ----
    if (!ensure_contained(root, rel)) {
      std::fprintf(stderr, "error: refusing to write outside the output root: %s\n", rel.c_str());
      ok_ = false;
    } else {
    if (!ensure_contained(root, rel)) {
      std::fprintf(stderr, "error: refusing to write outside the output root: %s\n", rel.c_str());
      ok_ = false;
      goto group_end;
    }
    const fs::path full = root / rel;
    fs::path dir = full.parent_path();
    fs::create_directories(dir, ec);
    if (ec) {
      std::fprintf(stderr, "error: cannot create %s: %s\n", dir.string().c_str(), ec.message().c_str());
      ok_ = false;
      goto group_end;
    }
    // Re-check containment after resolution so a symlink cannot redirect us.
    const fs::path canon_root = fs::weakly_canonical(root, ec);
    ec.clear();
    const fs::path canon_dir = fs::weakly_canonical(dir, ec);
    ec.clear();
    const std::string cr = canon_root.string(), cd = canon_dir.string();
    const char sep = fs::path::preferred_separator;
    if (cr.empty() || cd.compare(0, cr.size(), cr) != 0 ||
        (cd.size() > cr.size() && cd[cr.size()] != sep && cd[cr.size()] != '/')) {
      std::fprintf(stderr, "error: refusing to write outside the output root: %s\n", rel.c_str());
      ok_ = false;
      goto group_end;
    }

    std::FILE* f = std::fopen(full.string().c_str(), "wb");
    if (f == nullptr) {
      std::fprintf(stderr, "error: cannot open %s for writing: %s\n", full.string().c_str(),
                   std::strerror(errno));
      ok_ = false;
      goto group_end;
    }
    Out o(f);
    write_file_header(o, opts, rel, g.is_source);

    for (const TypeRef& tr : g.types) {
      if (!emit_type(o, model, tr, st)) {
        ok_ = false;
        goto group_end;
      }
      pr.add("Types");
    }
    for (std::uint32_t mi : g.methods) {
      const ir::Method& m = model.methods[mi];
      const std::string_view nm = model.name(m.name_off);
      if (nm.empty() || is_generated_method(nm)) continue;
      o.line("// " + std::string(nm) + "  // RVA: 0x" + hex_lower(m.addr, 1) +
             " VA: 0x" + hex_lower(m.addr, 1) +
             (m.decl.line ? " decl :" + std::to_string(m.decl.line) : "") +
             (m.def.line ? " def :" + std::to_string(m.def.line) : ""));
      o.line("// " + std::string(model.type_name(m.ret_type)) + " " + std::string(nm) + "()");
      o.line("/* not recoverable */");
      if (opts.bodies != nullptr) {
        const BodyBlock b =
            make_body(*opts.bodies, m.addr, m.has_range ? m.size : 0,
                      m.has_range ? RangeSource::kDwarf : RangeSource::kNone);
        const std::string h = b.header();
        if (!h.empty()) o.line("// " + h);
        for (const std::string& l : b.lines) o.line("//   " + l);
      }
      o.line("");
      ++gst.methods;
      pr.add("Methods");
    }
    for (std::uint32_t fi : g.free_functions) {
      const ir::FreeFunction& ff = model.free_functions[fi];
      const std::string_view nm = model.name(ff.name_off);
      if (nm.empty()) continue;
      if (ff.has_range && ff.addr != 0) {
        o.line("// " + std::string(nm) + "  // RVA: 0x" + hex_lower(ff.addr, 1) +
               " VA: 0x" + hex_lower(ff.addr, 1) +
               (ff.decl.line ? " decl :" + std::to_string(ff.decl.line) : ""));
        o.line("/* not recoverable */");
        if (opts.bodies != nullptr) {
          const BodyBlock b =
              make_body(*opts.bodies, ff.addr, ff.has_range ? ff.size : 0,
                        ff.has_range ? RangeSource::kDwarf : RangeSource::kNone);
          const std::string h = b.header();
          if (!h.empty()) o.line("// " + h);
          for (const std::string& l : b.lines) o.line("//   " + l);
        }
        o.line("");
      } else {
        // No code range. This is not a failure: the function exists in source and
        // was inlined everywhere. Printing a fake RVA would be the real error.
        ++gst.inline_only;
        o.line("// " + std::string(nm) + (ff.decl.line ? " :" + std::to_string(ff.decl.line) : "") +
               "  // inline-only, no standalone symbol");
        o.line("");
      }
      ++gst.free_functions;
      pr.add("Methods");
    }
    for (std::uint32_t oi : g.orphans) {
      const ir::OutOfLineDef& od = model.out_of_line_defs[oi];
      const std::string_view nm = model.name(od.name_off);
      if (nm.empty()) continue;
      // Only the mangled name survived deduplication, so it is reported as such
      // rather than presented as a source-level identifier.
      o.line("// " + std::string(nm) + "  // RVA: 0x" + hex_lower(od.addr, 1) +
             " VA: 0x" + hex_lower(od.addr, 1) +
             (od.def.line ? " def :" + std::to_string(od.def.line) : "") +
             "  // declaration not paired; mangled name only");
      o.line("/* not recoverable */");
      if (opts.bodies != nullptr) {
        const BodyBlock b = make_body(*opts.bodies, od.addr, od.has_range ? od.size : 0,
                                      od.has_range ? RangeSource::kDwarf : RangeSource::kNone);
        const std::string h = b.header();
        if (!h.empty()) o.line("// " + h);
        for (const std::string& l : b.lines) o.line("//   " + l);
      }
      o.line("");
      ++gst.methods;
    }

    gst.lines += o.lines();
    gst.bytes += o.bytes();
    const bool wrote = std::fclose(f) == 0 && o.ok();
    if (!wrote) {
      std::fprintf(stderr, "error: failed writing %s: %s\n", full.string().c_str(), std::strerror(errno));
      ok_ = false;
      goto group_end;
    }
    ++gst.files;
    pr.add("Files");
    pr.checkpoint();
    if (g.is_source) ++gst.sources; else ++gst.headers;
    // `written` is deliberately not touched here: several threads run this
    // body at once, and appending to one shared vector from all of them is a
    // data race (and listed every file twice). The caller appends in the
    // ordered loop after the join, which is deterministic as well as safe.
    }
group_end:;
    if (!ok_) return {gst, "error writing " + rel};
    return {gst, "", true};
  };

  const unsigned hw = std::thread::hardware_concurrency();
  const unsigned nthreads = std::max(1u, std::min<unsigned>(hw == 0 ? 4 : hw, 8u));
  std::vector<GroupResult> results(groups.size());
  // Order threads over a positional list of groups so the final numbers are
  // deterministic regardless of which core wrote which file.
  std::vector<std::pair<std::string, const FileGroup*>> seq;
  seq.reserve(groups.size());
  for (const auto& [rel, g] : groups) seq.emplace_back(rel, &g);
  std::vector<std::thread> threads;
  std::atomic<std::size_t> next{0};
  for (unsigned t = 0; t < nthreads; ++t) {
    threads.emplace_back([&](unsigned) {
      for (;;) {
        const std::size_t i = next.fetch_add(1);
        if (i >= seq.size()) break;
        results[i] = write_group(seq[i].first, *seq[i].second);
      }
    }, t);
  }
  for (auto& t : threads) t.join();
  bool any_err = false;
  for (std::size_t i = 0; i < seq.size(); ++i) {
    st += results[i].stats;
    if (results[i].ok) {
      written.push_back(seq[i].first);
    } else {
      any_err = true;
      // Said out loud. This is the only report a failed group gets, and a caller
      // that says "the tree could not be written (see stderr)" while stderr is
      // empty hands the user nothing to act on. The order is positional, so the
      // message does not depend on which thread finished first.
      std::fprintf(stderr, "error: %s\n", results[i].error.c_str());
    }
  }

  ok = !any_err;
  if (ok) ok = write_sidecars(root, model, opts, groups, written, table, st);
  if (ok && opts.zip) {
    // The archive lives next to the folder so the two never collide. When only
    // the zip was asked for, the folder goes away: the user asked for one
    // artefact, not two.
    const fs::path zip_path = fs::path(opts.out_dir.empty() ? "output" : opts.out_dir) /
                              (tree_folder_name(opts.target_name) + ".zip");
    std::string zip_err;
    if (!write_zip(root, zip_path, &zip_err)) {
      std::fprintf(stderr, "error: cannot write %s: %s\n", zip_path.string().c_str(),
                   zip_err.c_str());
      ok = false;
    } else if (!opts.folder) {
      fs::remove_all(root, ec);
      if (ec) {
        std::fprintf(stderr, "error: cannot remove %s: %s\n", root.string().c_str(),
                     ec.message().c_str());
        ok = false;
      }
    }
  }
  if (stats != nullptr) *stats = st;
  return ok;
}

}  // namespace stellar::output