// SPDX-License-Identifier: MIT
#include "stellar/dwarf/line.h"

#include <algorithm>

#include "stellar/dwarf/constants.h"

namespace stellar::dwarf {
namespace {

void set_error(std::string* error, const char* msg) {
  if (error != nullptr) *error = msg;
}

/// NUL-terminated string at `offset` in `section`, as a std::string. Returns
/// false when the offset is outside the section or the string is unterminated.
bool cstr_at(util::ByteView section, std::uint64_t offset, std::string& out) {
  if (offset >= section.size()) return false;
  const std::size_t start = static_cast<std::size_t>(offset);
  const std::size_t avail = section.size() - start;
  const std::uint8_t* base = section.data() + start;
  const void* nul = std::memchr(base, 0, avail);
  if (nul == nullptr) return false;
  const std::size_t len = static_cast<const std::uint8_t*>(nul) - base;
  out.assign(reinterpret_cast<const char*>(base), len);
  return true;
}

/// Joins `name` onto `dir` with exactly one separator, collapsing a trailing
/// slash on `dir` and a leading slash on `name` so the result has no "//".
/// An absolute `name` ignores `dir` entirely.
std::string join_path(std::string_view dir, std::string_view name) {
  if (!name.empty() && name.front() == '/') return std::string(name);
  while (!dir.empty() && dir.back() == '/') dir.remove_suffix(1);
  if (dir.empty()) return std::string(name);
  std::string out(dir);
  out += '/';
  out.append(name);
  return out;
}

/// One DWARF 5 entry, accumulated field by field as the format table is walked.
struct EntryAccum {
  std::string name;
  std::uint64_t dir_index = 0;
  std::uint64_t timestamp = 0;
  std::uint64_t size = 0;
  std::uint8_t md5[16] = {};
  bool has_md5 = false;
  bool saw_path = false;
};

/// Reads one DWARF 5 directory or file entry according to `fmt`, appending the
/// fields it recognises into `acc` and skipping any it does not.
///
/// Only the forms clang and GCC actually emit for these tables are handled:
/// string, line_strp, strp, udata and data16. An unknown form is a hard error
/// rather than a skipped field, because skipping it would desynchronise every
/// later entry in the table.
bool read_v5_entry(util::Cursor& c, const std::vector<LineEntryFormat>& fmt,
                   const LineSections& sec, unsigned offset_size, EntryAccum& acc) {
  for (const LineEntryFormat& f : fmt) {
    switch (f.form) {
      case form::kString: {
        const std::string_view sv = c.read_cstr();
        if (!c.ok()) return false;
        if (f.content_type == lnct::kPath) { acc.name.assign(sv); acc.saw_path = true; }
        break;
      }
      case form::kLineStrp: {
        std::uint64_t off = 0;
        if (!c.read_uint(offset_size, off)) return false;
        if (f.content_type == lnct::kPath) {
          if (!cstr_at(sec.line_str, off, acc.name)) return false;
          acc.saw_path = true;
        }
        break;
      }
      case form::kStrp: {
        std::uint64_t off = 0;
        if (!c.read_uint(offset_size, off)) return false;
        if (f.content_type == lnct::kPath) {
          if (!cstr_at(sec.str, off, acc.name)) return false;
          acc.saw_path = true;
        }
        break;
      }
      case form::kUdata: {
        std::uint64_t v = 0;
        if (!c.read_uleb128(v)) return false;
        if (f.content_type == lnct::kDirectoryIndex) acc.dir_index = v;
        else if (f.content_type == lnct::kTimestamp) acc.timestamp = v;
        else if (f.content_type == lnct::kSize) acc.size = v;
        break;
      }
      case form::kData16: {
        if (f.content_type != lnct::kMd5) {
          // A data16 we do not attribute is still 16 bytes wide and must be
          // stepped over or the rest of the table is garbage.
          if (!c.skip(16)) return false;
          break;
        }
        if (!c.read_bytes(acc.md5, 16)) return false;
        acc.has_md5 = true;
        break;
      }
      default:
        return false;
    }
  }
  return true;
}

/// DWARF <= 4 lists: NUL-terminated directory names, then NUL-terminated file
/// entries of {name, dir_index, mtime, length}. Index 0 is not a list position.
bool read_v4_lists(util::Cursor& c, LineHeader& out) {
  while (true) {
    const std::string_view d = c.read_cstr();
    if (!c.ok()) { set_error(nullptr, "unterminated include directory"); return false; }
    if (d.empty()) break;  // empty string terminates the list
    out.include_directories.emplace_back(d);
  }
  while (true) {
    const std::string_view n = c.read_cstr();
    if (!c.ok()) { set_error(nullptr, "unterminated file name"); return false; }
    if (n.empty()) break;  // empty name terminates the list
    LineFileEntry fe;
    fe.name.assign(n);
    if (!c.read_uleb128(fe.dir_index)) return false;
    if (!c.read_uleb128(fe.timestamp)) return false;
    if (!c.read_uleb128(fe.size)) return false;
    out.file_names.push_back(std::move(fe));
  }
  return true;
}

/// DWARF 5 lists: a format table, a count, then that many typed entries.
bool read_v5_lists(util::Cursor& c, const LineSections& sec, unsigned offset_size,
                   LineHeader& out) {
  std::uint64_t count = 0;
  std::uint64_t nfmt = 0;
  std::vector<LineEntryFormat> fmt;
  EntryAccum acc;

  // Directories. The format table precedes the entry count; reading them the
  // other way round consumes the count as a content type and every field after
  // it is garbage. (Verified against clang's own DWARF 5 output.)
  if (!c.read_uleb128(nfmt)) return false;
  if (nfmt > 64) return false;  // implausible; refuse rather than allocate
  fmt.resize(static_cast<std::size_t>(nfmt));
  for (LineEntryFormat& f : fmt) {
    if (!c.read_uleb128(f.content_type)) return false;
    if (!c.read_uleb128(f.form)) return false;
  }
  if (!c.read_uleb128(count)) return false;
  for (std::uint64_t i = 0; i < count; ++i) {
    acc = EntryAccum{};
    if (!read_v5_entry(c, fmt, sec, offset_size, acc)) return false;
    if (!acc.saw_path) return false;  // an entry with no path is meaningless
    out.include_directories.push_back(std::move(acc.name));
  }

  // Files.
  if (!c.read_uleb128(nfmt)) return false;
  if (nfmt > 64) return false;
  fmt.resize(static_cast<std::size_t>(nfmt));
  for (LineEntryFormat& f : fmt) {
    if (!c.read_uleb128(f.content_type)) return false;
    if (!c.read_uleb128(f.form)) return false;
  }
  if (!c.read_uleb128(count)) return false;
  for (std::uint64_t i = 0; i < count; ++i) {
    acc = EntryAccum{};
    if (!read_v5_entry(c, fmt, sec, offset_size, acc)) return false;
    if (!acc.saw_path) return false;
    LineFileEntry fe;
    fe.name = std::move(acc.name);
    fe.dir_index = acc.dir_index;
    fe.timestamp = acc.timestamp;
    fe.size = acc.size;
    if (acc.has_md5) { std::copy(acc.md5, acc.md5 + 16, fe.md5); fe.has_md5 = true; }
    out.file_names.push_back(std::move(fe));
  }
  return true;
}

}  // namespace

bool parse_line_header(LineSections sections, std::uint64_t offset,
                       std::string_view cu_name, std::string_view comp_dir,
                       util::Endian endian, LineHeader& out, std::string* error) {
  out = LineHeader{};
  out.offset = offset;
  out.cu_name = std::string(cu_name);
  out.comp_dir = std::string(comp_dir);

  if (sections.line.empty()) { set_error(error, "no .debug_line section"); return false; }
  if (offset > sections.line.size()) { set_error(error, "stmt_list past end of .debug_line"); return false; }

  util::Cursor c(sections.line.data() + offset, sections.line.size() - offset, endian);

  // unit_length excludes the initial length field, exactly as in .debug_info.
  std::uint32_t len32 = 0;
  if (!c.read_u32(len32)) { set_error(error, "truncated unit_length"); return false; }
  if (len32 == 0xffffffffu) {
    out.length_size = 8;
    if (!c.read_u64(out.total_length)) { set_error(error, "truncated 64-bit unit_length"); return false; }
  } else {
    out.length_size = 4;
    out.total_length = len32;
  }
  if (out.total_length == 0) { set_error(error, "zero-length line program"); return false; }

  const std::size_t unit_end = static_cast<std::size_t>(out.length_size) +
                               static_cast<std::size_t>(out.total_length);
  // The header is bounded by the unit, so a bogus length cannot make the cursor
  // walk into the next unit's bytes.
  if (unit_end > sections.line.size() - offset) {
    set_error(error, "line program extends past end of .debug_line");
    return false;
  }

  if (!c.read_u16(out.version)) { set_error(error, "truncated version"); return false; }
  if (out.version < 2 || out.version > 5) { set_error(error, "unsupported .debug_line version"); return false; }

  const unsigned offset_size = out.length_size;

  if (out.version >= 5) {
    // DWARF 5 inserts address_size and segment_selector_size before the
    // header length; getting this order wrong shifts every field after it.
    if (!c.read_u8(out.address_size)) { set_error(error, "truncated address_size"); return false; }
    if (!c.read_u8(out.segment_selector_size)) { set_error(error, "truncated segment_selector_size"); return false; }
  }

  if (!c.read_uint(offset_size, out.header_length)) { set_error(error, "truncated header_length"); return false; }

  if (!c.read_u8(out.min_inst_length)) { set_error(error, "truncated min_inst_length"); return false; }
  // max_ops_per_inst exists from DWARF 4 on; DWARF 2/3 go straight to
  // default_is_stmt, so leaving it at 1 is the correct value for them.
  if (out.version >= 4) {
    if (!c.read_u8(out.max_ops_per_inst)) { set_error(error, "truncated max_ops_per_inst"); return false; }
  }
  if (!c.read_u8(out.default_is_stmt)) { set_error(error, "truncated default_is_stmt"); return false; }

  std::uint8_t line_base_raw = 0;
  if (!c.read_u8(line_base_raw)) { set_error(error, "truncated line_base"); return false; }
  out.line_base = static_cast<std::int8_t>(line_base_raw);  // two's complement, per spec
  if (!c.read_u8(out.line_range)) { set_error(error, "truncated line_range"); return false; }
  if (out.line_range == 0) { set_error(error, "line_range is zero"); return false; }
  if (!c.read_u8(out.opcode_base)) { set_error(error, "truncated opcode_base"); return false; }

  if (out.opcode_base > 0) {
    out.standard_opcode_lengths.resize(static_cast<std::size_t>(out.opcode_base) - 1);
    for (std::uint8_t& n : out.standard_opcode_lengths) {
      if (!c.read_u8(n)) { set_error(error, "truncated standard_opcode_lengths"); return false; }
    }
  }

  const bool lists_ok = out.version >= 5
                            ? read_v5_lists(c, sections, offset_size, out)
                            : read_v4_lists(c, out);
  if (!lists_ok) { set_error(error, "malformed directory/file table"); return false; }
  if (!c.ok()) { set_error(error, "truncated header"); return false; }

  // header_length counts from immediately after the initial length field to the
  // first opcode, so the program starts that far into the unit. unit_length
  // covers the same span plus the program itself, which is what bounds it.
  out.program_start = offset + static_cast<std::size_t>(out.length_size) + out.header_length;
  out.program_end = offset + unit_end;
  if (out.program_start < offset || out.program_start > out.program_end) {
    set_error(error, "header_length inconsistent with unit_length");
    return false;
  }
  return true;
}

std::string LineHeader::directory_path(std::uint64_t index) const {
  // Before DWARF 5 index 0 is the compilation directory, not a list position.
  if (files_are_one_based() && index == 0) return comp_dir;
  // Index past the end of the table resolves to nothing rather than to a guess.
  const std::uint64_t i = files_are_one_based() ? index - 1 : index;
  if (i >= include_directories.size()) return {};
  const std::string& dir = include_directories[static_cast<std::size_t>(i)];
  // An absolute directory is already complete. A relative one is relative to
  // the compilation directory in *both* regimes: clang's DWARF 5 output lists
  // "Classes/Player/hitboxes" alongside an absolute directory 0 holding the
  // comp_dir, so joining is what turns the pair into a usable path.
  if (!dir.empty() && dir.front() == '/') return dir;
  return join_path(comp_dir, dir);
}

std::string LineHeader::file_path(std::uint64_t index) const {
  // The two regimes index the same vector differently; normalise to 0-based.
  std::uint64_t i = index;
  if (files_are_one_based()) {
    if (index == 0) return {};  // file 0 does not exist before DWARF 5
    i = index - 1;
  }
  if (i >= file_names.size()) return {};
  const LineFileEntry& fe = file_names[static_cast<std::size_t>(i)];

  // An absolute file name is complete on its own; joining would corrupt it.
  if (!fe.name.empty() && fe.name.front() == '/') return fe.name;

  // An unresolved directory means the table does not say where this file lives.
  // Returning the bare name would be a guess, so return nothing.
  const std::string dir = directory_path(fe.dir_index);
  if (dir.empty()) return {};
  return join_path(dir, fe.name);
}

}  // namespace stellar::dwarf
