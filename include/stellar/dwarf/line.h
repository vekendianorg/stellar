// SPDX-License-Identifier: MIT
// The `.debug_line` line-table program HEADER.
//
// This is the prologue only: the fields, the include-directory list and the
// file-name table, plus the byte range the opcode program occupies. The
// line-number opcode state machine is deliberately NOT here -- nothing in this
// file interprets DW_LNS_* -- so the two can be reviewed and tested apart.
//
// Layout, and the differences that matter between versions:
//
//   DWARF <= 4                          DWARF 5
//   ------------------------------      -----------------------------------
//   unit_length                         unit_length
//   version:u16                         version:u16
//   header_length                       address_size:u8
//   min_inst_length:u8                  segment_selector_size:u8
//   max_ops_per_inst:u8   (v>=4 only)   header_length
//   default_is_stmt:u8                  min_inst_length:u8
//   line_base:i8                        max_ops_per_inst:u8
//   line_range:u8                       default_is_stmt:u8
//   opcode_base:u8                      line_base:i8
//   standard_opcode_lengths             line_range:u8
//   include_directories: cstr list      opcode_base:u8
//   file_names: {cstr,udata,udata,udata} standard_opcode_lengths
//                                      directory_entry_format: {uleb,uleb}[]
//                                      directories: count + entries
//                                      file_name_entry_format: {uleb,uleb}[]
//                                      file_names: count + entries
//
// The two indexing regimes are the trap. In DWARF <= 4 the lists are NUL-
// terminated and the indices are 1-BASED -- file 0 does not exist, and
// directory 0 means "the CU's DW_AT_comp_dir". In DWARF 5 the lists are
// counted, the entries are typed by format tables, and the indices are
// 0-BASED, with directory 0 being an ordinary entry that producers fill in
// with the compilation directory. Reading one with the other's rules silently
// yields the wrong file for every line.
#pragma once

#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

#include "stellar/util/bytes.h"

namespace stellar::dwarf {

/// DW_LNCT_* content types for the DWARF 5 directory/file entry formats.
namespace lnct {
enum : std::uint64_t {
  kPath = 0x1,
  kDirectoryIndex = 0x2,
  kTimestamp = 0x3,
  kSize = 0x4,
  kMd5 = 0x5,
};
}

/// One entry of a `directory_entry_format` / `file_name_entry_format` table.
struct LineEntryFormat {
  std::uint64_t content_type = 0;  ///< DW_LNCT_*
  std::uint64_t form = 0;          ///< DW_FORM_*
};

/// One row of the file-name table.
struct LineFileEntry {
  std::string name;
  /// Directory index, interpreted per `LineHeader::files_are_one_based()`.
  std::uint64_t dir_index = 0;
  std::uint64_t timestamp = 0;
  std::uint64_t size = 0;
  /// MD5 digest when the format table carries DW_LNCT_MD5; all zero otherwise.
  std::uint8_t md5[16] = {};
  bool has_md5 = false;
};

/// A parsed `.debug_line` unit header.
struct LineHeader {
  std::uint64_t offset = 0;      ///< byte offset of this unit within .debug_line
  std::uint64_t total_length = 0;///< unit_length as stored (excludes the field)
  unsigned length_size = 4;      ///< 4 (DWARF32) or 8 (DWARF64)
  std::uint16_t version = 0;

  // DWARF 5 only; 0 for DWARF <= 4, which has no such fields.
  std::uint8_t address_size = 0;
  std::uint8_t segment_selector_size = 0;

  /// Length of the header in bytes, counting from just after unit_length.
  std::uint64_t header_length = 0;

  std::uint8_t min_inst_length = 1;
  std::uint8_t max_ops_per_inst = 1;
  std::uint8_t default_is_stmt = 1;
  std::int8_t line_base = 0;
  std::uint8_t line_range = 0;
  std::uint8_t opcode_base = 0;
  /// `opcode_base - 1` entries; the operand count of each standard opcode.
  std::vector<std::uint8_t> standard_opcode_lengths;

  /// Include directories, in file order. Indexed per `files_are_one_based()`.
  std::vector<std::string> include_directories;
  std::vector<LineFileEntry> file_names;

  /// Byte range of the opcode program, for a later state machine to walk.
  /// `program_end` is one past the last byte; both are relative to the start of
  /// the .debug_line section, not to `offset`.
  std::uint64_t program_start = 0;
  std::uint64_t program_end = 0;

  /// The CU's DW_AT_comp_dir and DW_AT_name, needed to resolve relative paths.
  /// Supplied by the caller because they live in .debug_info, not here.
  std::string comp_dir;
  std::string cu_name;

  [[nodiscard]] bool is_dwarf64() const { return length_size == 8; }

  /// True for DWARF <= 4, where file and directory indices are 1-based. Note this
  /// also covers DWARF 2 and 3, which use the same list encoding as DWARF 4.
  [[nodiscard]] bool files_are_one_based() const { return version < 5; }

  /// Full path of file `index`, or an empty string when the index is out of
  /// range or the table does not say enough to build one. Never guesses: an
  /// unresolvable index yields "" rather than a plausible-looking path.
  ///
  /// Relative names are joined onto the directory; an absolute name is used
  /// as-is. In DWARF <= 4 a directory index of 0 means the CU's DW_AT_comp_dir.
  [[nodiscard]] std::string file_path(std::uint64_t index) const;

  /// Include directory `index` under the same rules as `file_path`.
  [[nodiscard]] std::string directory_path(std::uint64_t index) const;
};

/// Sections the header parser reads strings out of.
struct LineSections {
  util::ByteView line;       ///< .debug_line (required)
  util::ByteView line_str;   ///< .debug_line_str (DWARF 5 DW_FORM_line_strp)
  util::ByteView str;        ///< .debug_str (DW_FORM_strp)
};

/// Parses the header of the line-table program at `offset` inside `.debug_line`.
///
/// `cu_name` and `comp_dir` are the enclosing CU's DW_AT_name / DW_AT_comp_dir
/// and are stored in the result for path resolution; they are not validated.
/// Returns false with `error` set on truncated or self-inconsistent input, and
/// never reads outside the section.
bool parse_line_header(LineSections sections, std::uint64_t offset,
                       std::string_view cu_name, std::string_view comp_dir,
                       util::Endian endian, LineHeader& out, std::string* error);

}  // namespace stellar::dwarf
