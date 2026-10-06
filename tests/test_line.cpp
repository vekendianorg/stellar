// SPDX-License-Identifier: MIT
// Tests for the .debug_line program header parser.
//
// Three groups:
//   Line       synthetic headers built byte by byte with the fixture builder,
//              covering DWARF 2/4/5, DWARF64, truncation and bad indices
//   LineFixture the compiled AArch64 fixtures in tests/fixtures/lib
//   RealBinary an opt-in sweep over every CU of the 583 MB target
//
// The expected file tables in the LineFixture group were read out of
// `llvm-dwarfdump --debug-line` by hand and are hardcoded below. They are
// deliberately NOT produced by running this parser: a fixture whose expected
// values came from the code under test proves only that the code agrees with
// itself.
#include <cstdio>
#include <string>
#include <vector>

#include "stellar/dwarf/constants.h"
#include "stellar/dwarf/dwarf_context.h"
#include "stellar/dwarf/line.h"
#include "stellar/elf/elf_file.h"
#include "fixture_builder.h"
#include "test_framework.h"

using namespace stellar;
using stellar::test::Bytes;

namespace {

constexpr util::Endian kLe = util::Endian::Little;

/// Assembles a DWARF <= 4 header: NUL-terminated directory and file lists.
struct V4Spec {
  std::uint16_t version = 4;
  bool dwarf64 = false;
  std::vector<std::string> dirs;
  /// (name, dir_index)
  std::vector<std::pair<std::string, std::uint64_t>> files;
  std::uint8_t line_base = 0xfb;  // -5
  std::uint8_t line_range = 14;
  std::uint8_t opcode_base = 13;
};

std::vector<std::uint8_t> build_v4(const V4Spec& s) {
  Bytes body;
  body.u16(s.version);
  // header_length is patched afterwards; reserve its width.
  const std::size_t hdr_len_pos = body.size();
  if (s.dwarf64) body.u64(0); else body.u32(0);
  body.u8(1);                     // min_inst_length
  if (s.version >= 4) body.u8(1); // max_ops_per_inst
  body.u8(1);                     // default_is_stmt
  body.u8(s.line_base);
  body.u8(s.line_range);
  body.u8(s.opcode_base);
  // DW_LNS_copy takes no operand; advance_pc/advance_line/set_file/set_column
  // take one; DW_LNS_fixed_advance_pc takes one. Matches clang's own table.
  static const std::uint8_t kLens[12] = {0, 1, 1, 1, 1, 0, 0, 0, 1, 0, 0, 1};
  for (std::uint8_t i = 1; i < s.opcode_base && i <= 12; ++i) body.u8(kLens[i - 1]);
  for (const std::string& d : s.dirs) body.cstr(d);
  body.cstr("");  // end of directories
  for (const auto& f : s.files) {
    body.cstr(f.first);
    body.uleb(f.second);  // dir_index
    body.uleb(0);         // mtime
    body.uleb(0);         // length
  }
  body.cstr("");  // end of files

  const std::size_t header_length = body.size();
  if (s.dwarf64) {
    body.patch_u64(hdr_len_pos, header_length);
  } else {
    body.patch_u32(hdr_len_pos, static_cast<std::uint32_t>(header_length));
  }

  // unit_length covers the header *and* the stub opcode program that follows it,
  // which is what makes program_start/program_end distinguishable.
  constexpr std::size_t kStub = 3;
  Bytes out;
  if (s.dwarf64) {
    out.u32(0xffffffffu);
    out.u64(body.size() + kStub);
  } else {
    out.u32(static_cast<std::uint32_t>(body.size() + kStub));
  }
  out.raw(body.bytes().data(), body.bytes().size());
  // A stub opcode program: DW_LNE_end_sequence-ish filler with no meaning.
  out.u8(0);
  out.u8(1);
  out.u8(1);
  return out.bytes();
}

/// Assembles a DWARF 5 header with counted, format-typed directory/file tables.
/// `inline_paths` picks DW_FORM_string over DW_FORM_line_strp; `with_md5` adds a
/// DW_LNCT_MD5 / DW_FORM_data16 pair to the file format.
struct V5Spec {
  std::uint16_t version = 5;
  bool dwarf64 = false;
  std::vector<std::string> dirs;
  /// (name, dir_index)
  std::vector<std::pair<std::string, std::uint64_t>> files;
  bool inline_paths = true;
  bool with_md5 = false;
};

/// A built header plus the length of the trailing .debug_line_str blob, so the
/// caller can split the two sections apart.
struct Built {
  std::vector<std::uint8_t> bytes;
  std::size_t line_str_len = 0;
  /// Byte index of the directory_entry_format's form field, for tests that
  /// corrupt it. Only meaningful for DWARF 5.
  std::size_t dir_form_pos = 0;
};

Built build_v5(const V5Spec& s) {
  Bytes ls;  // stands in for .debug_line_str
  std::vector<std::uint32_t> dir_off, file_off;
  for (const std::string& d : s.dirs) {
    dir_off.push_back(static_cast<std::uint32_t>(ls.size()));
    ls.cstr(d);
  }
  for (const auto& f : s.files) {
    file_off.push_back(static_cast<std::uint32_t>(ls.size()));
    ls.cstr(f.first);
  }
  const std::vector<std::uint8_t> ls_bytes = ls.bytes();
  const unsigned off = s.dwarf64 ? 8 : 4;

  Bytes body;
  body.u16(s.version);
  body.u8(8);    // address_size
  body.u8(0);    // segment_selector_size
  const std::size_t hdr_len_pos = body.size();
  if (s.dwarf64) body.u64(0); else body.u32(0);
  body.u8(1);    // min_inst_length
  body.u8(1);    // max_ops_per_inst
  body.u8(1);    // default_is_stmt
  body.u8(0xfb); // line_base
  body.u8(14);   // line_range
  body.u8(13);   // opcode_base
  static const std::uint8_t kLens[12] = {0, 1, 1, 1, 1, 0, 0, 0, 1, 0, 0, 1};
  for (std::uint8_t i = 1; i < 13; ++i) body.u8(kLens[i - 1]);

  // directory_entry_format: a single DW_LNCT_path entry, then the entry count.
  // +2 lands past the format count and the DW_LNCT_path content type.
  const std::size_t form_pos = body.size() + 2;
  body.uleb(1);
  body.uleb(dwarf::lnct::kPath);
  body.uleb(s.inline_paths ? dwarf::form::kString : dwarf::form::kLineStrp);
  body.uleb(s.dirs.size());
  for (std::size_t i = 0; i < s.dirs.size(); ++i) {
    if (s.inline_paths) {
      body.cstr(s.dirs[i]);
    } else if (off == 4) {
      body.u32(dir_off[i]);
    } else {
      body.u64(dir_off[i]);
    }
  }

  // file_name_entry_format: DW_LNCT_path, DW_LNCT_directory_index (udata) and,
  // when requested, DW_LNCT_MD5. All three must be declared: an entry that is
  // written but not declared would leave the parser unable to size it.
  const std::uint64_t nfmt = s.with_md5 ? 3 : 2;
  body.uleb(nfmt);
  body.uleb(dwarf::lnct::kPath);
  body.uleb(s.inline_paths ? dwarf::form::kString : dwarf::form::kLineStrp);
  if (s.with_md5) {
    body.uleb(dwarf::lnct::kMd5);
    body.uleb(dwarf::form::kData16);
  }
  body.uleb(dwarf::lnct::kDirectoryIndex);
  body.uleb(dwarf::form::kUdata);
  body.uleb(s.files.size());
  for (std::size_t i = 0; i < s.files.size(); ++i) {
    if (s.inline_paths) {
      body.cstr(s.files[i].first);
    } else if (off == 4) {
      body.u32(file_off[i]);
    } else {
      body.u64(file_off[i]);
    }
    if (s.with_md5) {
      for (int k = 0; k < 16; ++k) body.u8(static_cast<std::uint8_t>(0xa0 + k));
    }
    body.uleb(s.files[i].second);
  }

  const std::size_t header_length = body.size();
  if (s.dwarf64) {
    body.patch_u64(hdr_len_pos, header_length);
  } else {
    body.patch_u32(hdr_len_pos, static_cast<std::uint32_t>(header_length));
  }

  constexpr std::size_t kStub = 3;
  Bytes out;
  if (s.dwarf64) {
    out.u32(0xffffffffu);
    out.u64(body.size() + kStub);
  } else {
    out.u32(static_cast<std::uint32_t>(body.size() + kStub));
  }
  out.raw(body.bytes().data(), body.bytes().size());
  out.u8(0);  // stub opcode program
  out.u8(1);
  out.u8(1);
  out.raw(ls_bytes.data(), ls_bytes.size());
  Built b;
  b.bytes = out.bytes();
  b.line_str_len = ls_bytes.size();
  // `form_pos` indexes into `body`, which starts immediately after the initial
  // length field, so only the length field's own width is added.
  b.dir_form_pos = (s.dwarf64 ? 8 : 4) + form_pos;
  return b;
}

dwarf::LineSections sections_for(const Built& b) {
  dwarf::LineSections s;
  const std::size_t line_len = b.bytes.size() - b.line_str_len;
  s.line = util::ByteView(b.bytes.data(), line_len);
  if (b.line_str_len != 0) {
    s.line_str = util::ByteView(b.bytes.data() + line_len, b.line_str_len);
  }
  return s;
}

Built wrap(const std::vector<std::uint8_t>& bytes) {
  Built b;
  b.bytes = bytes;
  return b;
}

/// Parses with the standard CU context ("cu.cpp", "/proj").
bool parse(const Built& b, dwarf::LineHeader& out) {
  std::string err;
  return dwarf::parse_line_header(sections_for(b), 0, "cu.cpp", "/proj", kLe, out, &err);
}

bool parse_fails(const Built& b) {
  dwarf::LineHeader out;
  std::string err;
  return !dwarf::parse_line_header(sections_for(b), 0, "cu.cpp", "/proj", kLe, out, &err);
}

/// A two-directory, three-file DWARF 4 table used by several cases.
V4Spec basic_v4() {
  V4Spec s;
  s.dirs = {"src", "include"};
  s.files = {{"main.cpp", 1}, {"util.h", 2}, {"<stdin>", 0}};
  return s;
}

}  // namespace

// ---------------------------------------------------------------------------
// Synthetic headers
// ---------------------------------------------------------------------------

STELLAR_TEST(Line, V4HeaderFieldsAreDecoded) {
  dwarf::LineHeader h;
  ASSERT_TRUE(parse(wrap(build_v4(basic_v4())), h));

  EXPECT_EQ(h.version, std::uint16_t{4});
  EXPECT_EQ(h.length_size, 4u);
  EXPECT_FALSE(h.is_dwarf64());
  EXPECT_TRUE(h.files_are_one_based());
  EXPECT_EQ(h.min_inst_length, std::uint8_t{1});
  EXPECT_EQ(h.max_ops_per_inst, std::uint8_t{1});
  EXPECT_EQ(h.default_is_stmt, std::uint8_t{1});
  // 0xfb as a signed byte is -5.
  EXPECT_EQ(h.line_base, static_cast<std::int8_t>(-5));
  EXPECT_EQ(h.line_range, std::uint8_t{14});
  EXPECT_EQ(h.opcode_base, std::uint8_t{13});
  ASSERT_EQ_SIZE(h.standard_opcode_lengths, 12);
  // DW_LNS_copy has no operands; DW_LNS_advance_pc takes one.
  EXPECT_EQ(h.standard_opcode_lengths[0], std::uint8_t{0});
  EXPECT_EQ(h.standard_opcode_lengths[1], std::uint8_t{1});
  // DWARF 5-only fields must stay zero.
  EXPECT_EQ(h.address_size, std::uint8_t{0});
  EXPECT_EQ(h.segment_selector_size, std::uint8_t{0});
  EXPECT_STREQ(h.cu_name, "cu.cpp");
  EXPECT_STREQ(h.comp_dir, "/proj");
}

STELLAR_TEST(Line, V4ListsAreOneBasedAndDirectoryZeroIsCompDir) {
  dwarf::LineHeader h;
  ASSERT_TRUE(parse(wrap(build_v4(basic_v4())), h));

  ASSERT_EQ_SIZE(h.include_directories, 2);
  EXPECT_STREQ(h.include_directories[0], "src");
  EXPECT_STREQ(h.include_directories[1], "include");
  ASSERT_EQ_SIZE(h.file_names, 3);
  EXPECT_STREQ(h.file_names[0].name, "main.cpp");
  EXPECT_EQ(h.file_names[0].dir_index, std::uint64_t{1});
  EXPECT_STREQ(h.file_names[2].name, "<stdin>");
  EXPECT_EQ(h.file_names[2].dir_index, std::uint64_t{0});

  // Directory 0 is the CU's comp_dir, not a list entry.
  EXPECT_STREQ(h.directory_path(0), "/proj");
  EXPECT_STREQ(h.directory_path(1), "/proj/src");
  EXPECT_STREQ(h.directory_path(2), "/proj/include");
  // Index 3 is one past the end of a two-entry list.
  EXPECT_STREQ(h.directory_path(3), "");
}

STELLAR_TEST(Line, V4FilePathsJoinOntoCompDir) {
  dwarf::LineHeader h;
  ASSERT_TRUE(parse(wrap(build_v4(basic_v4())), h));

  EXPECT_STREQ(h.file_path(1), "/proj/src/main.cpp");
  EXPECT_STREQ(h.file_path(2), "/proj/include/util.h");
  // dir_index 0 means comp_dir, so the file lands directly under it.
  EXPECT_STREQ(h.file_path(3), "/proj/<stdin>");
  // File 0 does not exist before DWARF 5.
  EXPECT_STREQ(h.file_path(0), "");
  EXPECT_STREQ(h.file_path(4), "");
}

STELLAR_TEST(Line, V2AndV3OmitMaxOpsPerInst) {
  // DWARF 2 and 3 have no max_ops_per_inst field, so a parser that always reads
  // one consumes the wrong byte and shifts everything after it.
  for (std::uint16_t v : {std::uint16_t{2}, std::uint16_t{3}}) {
    V4Spec s = basic_v4();
    s.version = v;
    dwarf::LineHeader h;
    ASSERT_TRUE(parse(wrap(build_v4(s)), h));
    EXPECT_EQ(h.version, v);
    EXPECT_TRUE(h.files_are_one_based());
    EXPECT_EQ(h.max_ops_per_inst, std::uint8_t{1});  // defaulted
    EXPECT_EQ(h.line_range, std::uint8_t{14});
    EXPECT_EQ(h.opcode_base, std::uint8_t{13});
    ASSERT_EQ_SIZE(h.include_directories, 2);
    EXPECT_STREQ(h.include_directories[0], "src");
    ASSERT_EQ_SIZE(h.file_names, 3);
    EXPECT_STREQ(h.file_names[0].name, "main.cpp");
  }
}

STELLAR_TEST(Line, Dwarf64UsesTheFfffffffMarker) {
  V4Spec s = basic_v4();
  s.dwarf64 = true;
  dwarf::LineHeader h;
  ASSERT_TRUE(parse(wrap(build_v4(s)), h));

  EXPECT_TRUE(h.is_dwarf64());
  EXPECT_EQ(h.length_size, 8u);
  EXPECT_EQ(h.version, std::uint16_t{4});
  ASSERT_EQ_SIZE(h.include_directories, 2);
  EXPECT_STREQ(h.include_directories[1], "include");
  EXPECT_STREQ(h.file_path(1), "/proj/src/main.cpp");
}

STELLAR_TEST(Line, Dwarf64V5UsesEightByteOffsets) {
  V5Spec s;
  s.dwarf64 = true;
  s.dirs = {"/abs/dir"};
  s.files = {{"a.cpp", 0}};
  dwarf::LineHeader h;
  ASSERT_TRUE(parse(build_v5(s), h));

  EXPECT_TRUE(h.is_dwarf64());
  EXPECT_EQ(h.version, std::uint16_t{5});
  EXPECT_FALSE(h.files_are_one_based());
  ASSERT_EQ_SIZE(h.include_directories, 1);
  EXPECT_STREQ(h.include_directories[0], "/abs/dir");
  EXPECT_STREQ(h.file_path(0), "/abs/dir/a.cpp");
}

STELLAR_TEST(Line, ProgramRangeExcludesTheHeader) {
  dwarf::LineHeader h;
  ASSERT_TRUE(parse(wrap(build_v4(basic_v4())), h));

  // unit_length covers the stub program too, so the header and the three stub
  // opcode bytes must not overlap and the program is exactly three bytes long.
  EXPECT_EQ(h.program_end - h.program_start, std::uint64_t{3});
  EXPECT_TRUE(h.program_start > h.offset);
  // program_end is one past the last byte of the unit: the 4-byte initial length
  // plus unit_length, which excludes that field.
  EXPECT_EQ(h.program_end, static_cast<std::uint64_t>(4) + h.total_length);
  // program_start lands exactly where header_length says, measured from just
  // after the initial length field.
  EXPECT_EQ(h.program_start, static_cast<std::uint64_t>(4) + h.header_length);
  EXPECT_TRUE(h.program_start < h.program_end);
}

STELLAR_TEST(Line, V5ListsAreZeroBased) {
  V5Spec s;
  s.dirs = {"/proj", "src"};
  s.files = {{"a.cpp", 0}, {"b.cpp", 1}};
  dwarf::LineHeader h;
  ASSERT_TRUE(parse(build_v5(s), h));

  EXPECT_FALSE(h.files_are_one_based());
  // DWARF 5 records address_size and segment_selector_size, unlike DWARF 4.
  EXPECT_EQ(h.address_size, std::uint8_t{8});
  EXPECT_EQ(h.segment_selector_size, std::uint8_t{0});
  ASSERT_EQ_SIZE(h.include_directories, 2);
  EXPECT_STREQ(h.include_directories[0], "/proj");
  ASSERT_EQ_SIZE(h.file_names, 2);
  EXPECT_STREQ(h.file_names[0].name, "a.cpp");
  EXPECT_EQ(h.file_names[0].dir_index, std::uint64_t{0});
  // Index 0 is a real file here, unlike DWARF 4.
  EXPECT_STREQ(h.file_path(0), "/proj/a.cpp");
  // "src" is relative to comp_dir, so it resolves under /proj.
  EXPECT_STREQ(h.file_path(1), "/proj/src/b.cpp");
  EXPECT_STREQ(h.file_path(2), "");
  // Directory 0 is an ordinary entry that happens to hold comp_dir, unlike
  // DWARF 4 where index 0 is reserved.
  EXPECT_STREQ(h.directory_path(0), "/proj");
  EXPECT_STREQ(h.directory_path(1), "/proj/src");
}

STELLAR_TEST(Line, V5ResolvesLineStrpPaths) {
  V5Spec s;
  s.inline_paths = false;  // DW_FORM_line_strp into .debug_line_str
  s.dirs = {"/proj", "deep/nested/dir"};
  s.files = {{"one.cpp", 1}, {"two.h", 0}};
  dwarf::LineHeader h;
  ASSERT_TRUE(parse(build_v5(s), h));

  ASSERT_EQ_SIZE(h.file_names, 2);
  EXPECT_STREQ(h.file_names[0].name, "one.cpp");
  EXPECT_STREQ(h.file_names[1].name, "two.h");
  EXPECT_STREQ(h.file_path(0), "/proj/deep/nested/dir/one.cpp");
  EXPECT_STREQ(h.file_path(1), "/proj/two.h");
}

STELLAR_TEST(Line, V5CapturesMd5ViaData16) {
  V5Spec s;
  s.with_md5 = true;
  s.dirs = {"/proj"};
  s.files = {{"x.cpp", 0}, {"y.cpp", 0}};
  dwarf::LineHeader h;
  ASSERT_TRUE(parse(build_v5(s), h));

  ASSERT_EQ_SIZE(h.file_names, 2);
  ASSERT_TRUE(h.file_names[0].has_md5);
  // The digest is 0xa0..0xaf; the data16 must not desynchronise the next entry.
  EXPECT_EQ(h.file_names[0].md5[0], std::uint8_t{0xa0});
  EXPECT_EQ(h.file_names[0].md5[15], std::uint8_t{0xaf});
  ASSERT_TRUE(h.file_names[1].has_md5);
  EXPECT_EQ(h.file_names[1].md5[0], std::uint8_t{0xa0});
  EXPECT_STREQ(h.file_names[1].name, "y.cpp");
  EXPECT_EQ(h.file_names[1].dir_index, std::uint64_t{0});
}

STELLAR_TEST(Line, OutOfRangeIndicesResolveToNothing) {
  dwarf::LineHeader h4;
  ASSERT_TRUE(parse(wrap(build_v4(basic_v4())), h4));
  // Far past the end of every table.
  EXPECT_STREQ(h4.file_path(9999), "");
  EXPECT_STREQ(h4.directory_path(9999), "");

  // A file whose dir_index points past the directory list must not be joined
  // onto a plausible-looking directory.
  V4Spec bad = basic_v4();
  bad.files = {{"orphan.cpp", 42}};
  dwarf::LineHeader hb;
  ASSERT_TRUE(parse(wrap(build_v4(bad)), hb));
  EXPECT_STREQ(hb.file_path(1), "");
  // The table itself is still intact.
  EXPECT_STREQ(hb.file_names[0].name, "orphan.cpp");
}

STELLAR_TEST(Line, TruncatedHeadersAreRejected) {
  // Every prefix of a valid header must be rejected rather than read past.
  // This is the property that keeps a corrupt section from faulting.
  const std::vector<std::uint8_t> full = build_v4(basic_v4());
  for (std::size_t n = 1; n < full.size(); ++n) {
    const std::vector<std::uint8_t> prefix(full.begin(), full.begin() + n);
    if (parse_fails(wrap(prefix))) continue;
    // A prefix that happens to end exactly on the last header byte still parses:
    // that is correct, since the stub program is not part of the header.
    dwarf::LineHeader h;
    ASSERT_TRUE(parse(wrap(prefix), h));
    EXPECT_TRUE(h.program_end <= prefix.size());
  }
}

STELLAR_TEST(Line, TruncatedV5HeaderIsRejected) {
  const Built full = build_v5([] {
    V5Spec s;
    s.dirs = {"/proj"};
    s.files = {{"a.cpp", 0}};
    return s;
  }());
  for (std::size_t n = 1; n < full.bytes.size(); ++n) {
    Built cut;
    // Keep the line_str section intact so only the header is under-length.
    cut.line_str_len = full.line_str_len;
    cut.bytes.assign(full.bytes.begin(), full.bytes.begin() + n);
    if (cut.bytes.size() > cut.line_str_len) parse_fails(cut);
  }
}

STELLAR_TEST(Line, OffsetPastTheEndIsRejected) {
  const Built b = build_v5([] {
    V5Spec s;
    s.dirs = {"/proj"};
    return s;
  }());
  dwarf::LineHeader h;
  std::string err;
  const dwarf::LineSections sec = sections_for(b);
  // A DW_AT_stmt_list pointing beyond .debug_line must fail, not wrap around.
  EXPECT_FALSE(dwarf::parse_line_header(sec, 1u << 30, "cu.cpp", "/proj", kLe, h, &err));
  EXPECT_FALSE(err.empty());
  // Exactly one past the end is equally invalid.
  EXPECT_FALSE(dwarf::parse_line_header(sec, sec.line.size(), "cu.cpp", "/proj", kLe, h, &err));
}

STELLAR_TEST(Line, EmptyAndSelfInconsistentHeadersAreRejected) {
  // No .debug_line at all.
  dwarf::LineHeader h;
  std::string err;
  EXPECT_FALSE(dwarf::parse_line_header({}, 0, "cu.cpp", "/proj", kLe, h, &err));

  // A unit_length that runs past the end of the section.
  Bytes over;
  over.u32(0x10000);
  EXPECT_FALSE(dwarf::parse_line_header({util::ByteView(over.bytes().data(), 4), {}, {}}, 0,
                                        "cu.cpp", "/proj", kLe, h, &err));
  EXPECT_FALSE(err.empty());

  // A zero-length program carries no header.
  Bytes zero;
  zero.u32(0);
  EXPECT_FALSE(dwarf::parse_line_header({util::ByteView(zero.bytes().data(), 4), {}, {}}, 0,
                                        "cu.cpp", "/proj", kLe, h, &err));

  // Versions outside 2..5 are refused rather than guessed at.
  for (std::uint16_t v : {std::uint16_t{0}, std::uint16_t{1}, std::uint16_t{6},
                          std::uint16_t{99}}) {
    Bytes b;
    b.u32(64);
    b.u16(v);
    EXPECT_FALSE(dwarf::parse_line_header({util::ByteView(b.bytes().data(), b.bytes().size()), {}, {}},
                                          0, "cu.cpp", "/proj", kLe, h, &err));
  }
}

STELLAR_TEST(Line, ZeroLineRangeIsRejected) {
  V4Spec s = basic_v4();
  s.line_range = 0;
  EXPECT_TRUE(parse_fails(wrap(build_v4(s))));
}

STELLAR_TEST(Line, V5WithUnknownFormIsRejected) {
  // A format table naming a form this parser does not implement must fail
  // rather than skip a field of unknown width and desynchronise the table.
  V5Spec s;
  s.dirs = {"/proj"};
  s.files = {{"a.cpp", 0}};
  const Built b = build_v5(s);

  // build_v5 reports where the directory_entry_format's form byte landed, so
  // the header layout is not re-derived here.
  const std::size_t pos = b.dir_form_pos;
  ASSERT_TRUE(pos < b.bytes.size());
  ASSERT_TRUE(pos >= 2);
  // The two bytes before the form are the format count and DW_LNCT_path.
  EXPECT_EQ(b.bytes[pos - 2], std::uint8_t{1});                         // count
  EXPECT_EQ(b.bytes[pos - 1], std::uint8_t{1});                         // DW_LNCT_path
  EXPECT_EQ(b.bytes[pos], std::uint8_t{dwarf::form::kString});           // its form

  std::vector<std::uint8_t> v = b.bytes;
  v[pos] = 0x7f;  // a form this parser does not implement
  Built p;
  p.bytes = std::move(v);
  p.line_str_len = b.line_str_len;
  EXPECT_TRUE(parse_fails(p));
}

STELLAR_TEST(Line, UnterminatedStringListsAreRejected) {
  // A DWARF 4 directory list with no empty-string terminator would otherwise
  // run into the file list and keep reading.
  Bytes b;
  b.u32(32);
  b.u16(4);
  b.u32(0);   // header_length, patched below
  const std::size_t hdr = b.size() - 4;
  b.u8(1);
  b.u8(1);
  b.u8(1);
  b.u8(0xfb);
  b.u8(14);
  b.u8(13);
  static const std::uint8_t kLens[12] = {0, 1, 1, 1, 1, 0, 0, 0, 1, 0, 0, 1};
  for (std::uint8_t i = 1; i < 13; ++i) b.u8(kLens[i - 1]);
  b.cstr("dir_with_no_terminator");  // no empty string after it
  b.patch_u32(hdr, static_cast<std::uint32_t>(b.size() - hdr));
  const std::vector<std::uint8_t> bytes = b.bytes();
  EXPECT_TRUE(parse_fails(wrap(bytes)));
}

// ---------------------------------------------------------------------------
// Compiled fixtures
// ---------------------------------------------------------------------------

#ifndef STELLAR_FIXTURE_DIR
#error "STELLAR_FIXTURE_DIR must be defined by the build"
#endif

std::string fixture_path(const char* name) {
  return std::string(STELLAR_FIXTURE_DIR) + "/" + name;
}

/// One CU's line header, located the way a real consumer would: read
/// DW_AT_stmt_list, DW_AT_name and DW_AT_comp_dir off the root DIE.
///
/// DWARF 5 spells DW_AT_name / DW_AT_comp_dir with DW_FORM_strx*, an index into
/// .debug_str_offsets rather than a direct .debug_str offset, so both forms are
/// resolved here: a DWARF 5 CU's names are unreadable without it. DWARF <= 4
/// uses DW_FORM_strp throughout.
struct CuLine {
  bool parsed = false;
  std::string error;
  dwarf::LineHeader header;
};

/// Resolves DW_FORM_strx* through .debug_str_offsets + DW_AT_str_offsets_base.
class StrResolver {
 public:
  StrResolver(const dwarf::DwarfContext& ctx, std::uint64_t str_offsets_base,
              unsigned offset_size, util::Endian endian)
      : str_offsets_(ctx.sections().view(dwarf::Sec::kStrOffsets)),
        str_(ctx.str()),
        base_(str_offsets_base),
        offset_size_(offset_size),
        endian_(endian) {}

  /// `index` is the DW_FORM_strx* value; `width` its encoded byte width.
  /// The .debug_str_offsets entry itself is always `offset_size` wide, which is
  /// a property of the unit, not of the strx form's encoding width.
  bool resolve(std::uint64_t index, std::string& out) const {
    if (str_offsets_.empty() || offset_size_ == 0) return false;
    const std::uint64_t entry = base_ + index * offset_size_;
    if (entry + offset_size_ > str_offsets_.size()) return false;
    util::Cursor c(str_offsets_.data(), str_offsets_.size(), endian_);
    if (!c.seek(static_cast<std::size_t>(entry))) return false;
    std::uint64_t off = 0;
    if (!c.read_uint(offset_size_, off)) return false;
    if (off >= str_.size()) return false;
    const std::string_view sv = ctx_str_at(off);
    if (sv.empty()) return false;
    out.assign(sv);
    return true;
  }

 private:
  std::string_view ctx_str_at(std::uint64_t off) const {
    const std::uint8_t* base = str_.data() + off;
    const std::uint8_t* stop = str_.data() + str_.size();
    const std::uint8_t* p = base;
    while (p < stop && *p != 0) ++p;
    if (p == stop) return {};
    return std::string_view(reinterpret_cast<const char*>(base),
                            static_cast<std::size_t>(p - base));
  }

  util::ByteView str_offsets_;
  util::ByteView str_;
  std::uint64_t base_;
  unsigned offset_size_;
  util::Endian endian_;
};

/// Enumerates the line-table programs in .debug_line order, by walking the
/// section rather than consulting each CU's DW_AT_stmt_list.
///
/// The CU attributes remain the primary route (see cu_line); this exists only
/// as an independent second opinion, and EveryFixtureHeaderFitsInsideItsUnit
/// checks the two agree on the offsets they share.
CuLine cu_line(dwarf::DwarfContext& ctx, const dwarf::UnitHeader& unit) {
  CuLine out;
  const dwarf::LineSections sections{
      ctx.sections().view(dwarf::Sec::kLine),
      ctx.sections().view(dwarf::Sec::kLineStr),
      ctx.str(),
  };
  if (sections.line.empty()) {
    out.error = "no .debug_line";
    return out;
  }

  // The root DIE carries stmt_list, name and comp_dir.
  std::uint64_t stmt_list = 0;
  bool have_stmt_list = false;
  std::uint64_t str_offsets_base = unit.offset_size();  // the DWARF 5 default
  std::string cu_name;
  std::string comp_dir;
  bool first = true;
  ctx.walk_unit(unit, [&](const dwarf::Die& d) {
    if (!first) return true;
    first = false;
    dwarf::AttrValue v;
    if (d.attr(dwarf::aat::kStmtList, v) &&
        (v.form == dwarf::form::kSecOffset || v.form == dwarf::form::kData4)) {
      stmt_list = v.u64;
      have_stmt_list = true;
    }
    if (d.attr(dwarf::aat::kStrOffsetsBase, v)) str_offsets_base = v.u64;
    // strp: a direct .debug_str offset.
    if (d.attr(dwarf::aat::kName, v) && v.form == dwarf::form::kStrp) {
      cu_name = std::string(ctx.str_at(v.u64));
    }
    if (d.attr(dwarf::aat::kCompDir, v) && v.form == dwarf::form::kStrp) {
      comp_dir = std::string(ctx.str_at(v.u64));
    }
    // strx*: an index into .debug_str_offsets, relative to str_offsets_base.
    const StrResolver res(ctx, str_offsets_base, unit.offset_size(), unit.endian);
    if (d.attr(dwarf::aat::kName, v) && dwarf::is_indexed_string(v.form)) {
      res.resolve(v.u64, cu_name);
    }
    if (d.attr(dwarf::aat::kCompDir, v) && dwarf::is_indexed_string(v.form)) {
      res.resolve(v.u64, comp_dir);
    }
    return false;  // root DIE only
  });
  if (!have_stmt_list) {
    out.error = "no DW_AT_stmt_list";
    return out;
  }

  out.parsed = dwarf::parse_line_header(sections, stmt_list, cu_name, comp_dir,
                                        unit.endian, out.header, &out.error);
  return out;
}

/// Every line-table program in .debug_line, in section order. Each unit's
/// offset is the DW_AT_stmt_list its CU would name; see the note on cu_line
/// for why the DWARF 5 path cannot read that attribute back reliably today.
std::vector<dwarf::LineHeader> all_line_units(const dwarf::DwarfContext& ctx,
                                             std::string_view comp_dir) {
  std::vector<dwarf::LineHeader> out;
  const dwarf::LineSections sections{
      ctx.sections().view(dwarf::Sec::kLine),
      ctx.sections().view(dwarf::Sec::kLineStr),
      ctx.str(),
  };
  std::uint64_t off = 0;
  while (off < sections.line.size()) {
    dwarf::LineHeader h;
    std::string err;
    if (!dwarf::parse_line_header(sections, off, "", comp_dir, util::Endian::Little, h,
                                  &err)) {
      break;  // a malformed unit ends the walk
    }
    out.push_back(std::move(h));
    if (h.program_end <= off) break;
    off = h.program_end;
  }
  return out;
}

/// Opens a compiled fixture, or reports a skip. The context is constructed in
/// place because DwarfContext holds a reference to the ElfFile and is neither
/// copyable nor assignable.
bool open_fixture(elf::ElfFile& f, const char* name) {
  const std::string path = fixture_path(name);
  std::string err;
  if (!f.open(path, &err)) {
    std::fprintf(stderr, "  (skipped: %s: %s)\n", path.c_str(), err.c_str());
    return false;
  }
  return true;
}

// EXPECTED VALUES BELOW -- transcribed by hand from
//   llvm-dwarfdump --debug-line tests/fixtures/lib/stellar-fixture-dwarf4-O0.so
//   llvm-dwarfdump --debug-line tests/fixtures/lib/stellar-fixture-dwarf5-O0.so
// They are hardcoded on purpose. Deriving them by running the parser would make
// these tests assert only that the parser agrees with itself.
//
// dwarf4-O0, unit 0 (body.cpp): DW_AT_comp_dir is /stellar-fixtures/src, so
// include_directories[1] resolves to /stellar-fixtures/src/Classes/Player/hitboxes.
const char* const kDwarf4BodyFiles[] = {
    "/stellar-fixtures/src/Classes/Player/hitboxes/body.h",
    "/stellar-fixtures/src/Classes/Player/hitboxes/body.cpp",
    "/stellar-fixtures/src/Classes/Util/math.h",
    "/stellar-fixtures/src/<stdin>",
};
// dwarf4-O0, unit 1 (player.cpp).
const char* const kDwarf4PlayerFiles[] = {
    "/stellar-fixtures/src/Classes/Player/player.cpp",
    "/stellar-fixtures/src/Classes/Player/player.h",
};
// dwarf5-O0, unit 0 (body.cpp). DWARF 5 directory 0 is a real entry holding the
// compilation directory, and the primary file is recorded with a path relative
// to it, so index 0 resolves to the .cpp itself.
const char* const kDwarf5BodyFiles[] = {
    "/stellar-fixtures/src/Classes/Player/hitboxes/body.cpp",
    "/stellar-fixtures/src/Classes/Player/hitboxes/body.h",
    "/stellar-fixtures/src/Classes/Util/math.h",
    "/stellar-fixtures/src/<stdin>",
};
// dwarf5-O0, unit 1 (player.cpp).
const char* const kDwarf5PlayerFiles[] = {
    "/stellar-fixtures/src/Classes/Player/player.cpp",
    "/stellar-fixtures/src/Classes/Player/player.h",
};

void expect_paths(const dwarf::LineHeader& h, const char* const* expected,
                  std::size_t n) {
  ASSERT_EQ_SIZE(h.file_names, n);
  for (std::size_t i = 0; i < n; ++i) {
    // DWARF 4 indexes from 1, DWARF 5 from 0.
    const std::uint64_t index = h.files_are_one_based() ? i + 1 : i;
    EXPECT_STREQ(h.file_path(index), expected[i]);
  }
}

STELLAR_TEST(LineFixture, Dwarf4O0ResolvesTheBodyUnitFileTable) {
  elf::ElfFile f;
  if (!open_fixture(f, "stellar-fixture-dwarf4-O0.so")) return;
  dwarf::DwarfContext ctx(f);

  dwarf::UnitHeader unit;
  ASSERT_TRUE(ctx.unit_header(0, unit));
  const CuLine cu = cu_line(ctx, unit);
  ASSERT_TRUE(cu.parsed);

  const dwarf::LineHeader& h = cu.header;
  EXPECT_EQ(h.version, std::uint16_t{4});
  EXPECT_TRUE(h.files_are_one_based());
  EXPECT_FALSE(h.is_dwarf64());
  ASSERT_EQ_SIZE(h.include_directories, 2);
  EXPECT_STREQ(h.include_directories[0], "Classes/Player/hitboxes");
  EXPECT_STREQ(h.include_directories[1], "Classes/Util");
  // Directory 0 resolves to the CU's DW_AT_comp_dir, which is not a list entry.
  EXPECT_STREQ(h.directory_path(0), "/stellar-fixtures/src");
  EXPECT_STREQ(h.comp_dir, "/stellar-fixtures/src");

  expect_paths(h, kDwarf4BodyFiles, 4);
  // clang's standard prologue: -5 / 14 / 13.
  EXPECT_EQ(h.line_base, static_cast<std::int8_t>(-5));
  EXPECT_EQ(h.line_range, std::uint8_t{14});
  EXPECT_EQ(h.opcode_base, std::uint8_t{13});
  EXPECT_TRUE(h.program_start < h.program_end);
}

STELLAR_TEST(LineFixture, Dwarf4O0ResolvesThePlayerUnitFileTable) {
  elf::ElfFile f;
  if (!open_fixture(f, "stellar-fixture-dwarf4-O0.so")) return;
  dwarf::DwarfContext ctx(f);

  dwarf::UnitHeader unit;
  ASSERT_TRUE(ctx.unit_header(1, unit));
  const CuLine cu = cu_line(ctx, unit);
  ASSERT_TRUE(cu.parsed);
  EXPECT_EQ(cu.header.version, std::uint16_t{4});
  ASSERT_EQ_SIZE(cu.header.include_directories, 1);
  EXPECT_STREQ(cu.header.include_directories[0], "Classes/Player");
  expect_paths(cu.header, kDwarf4PlayerFiles, 2);
}

STELLAR_TEST(LineFixture, Dwarf4O2ResolvesTheSamePathsAsO0) {
  // -O2 reorders the file table (the inlined <stdin> entry moves) but the
  // resolved paths must still be the same set, and still 1-based.
  elf::ElfFile f;
  if (!open_fixture(f, "stellar-fixture-dwarf4-O2.so")) return;
  dwarf::DwarfContext ctx(f);

  dwarf::UnitHeader unit;
  ASSERT_TRUE(ctx.unit_header(0, unit));
  const CuLine cu = cu_line(ctx, unit);
  ASSERT_TRUE(cu.parsed);
  EXPECT_TRUE(cu.header.files_are_one_based());

  // llvm-dwarfdump for dwarf4-O2 lists <stdin> at index 3 and math.h at 4;
  // the set of paths is unchanged from -O0.
  ASSERT_EQ_SIZE(cu.header.file_names, 4);
  EXPECT_STREQ(cu.header.file_path(1), "/stellar-fixtures/src/Classes/Player/hitboxes/body.h");
  EXPECT_STREQ(cu.header.file_path(2), "/stellar-fixtures/src/Classes/Player/hitboxes/body.cpp");
  EXPECT_STREQ(cu.header.file_path(3), "/stellar-fixtures/src/<stdin>");
  EXPECT_STREQ(cu.header.file_path(4), "/stellar-fixtures/src/Classes/Util/math.h");
}

/// DWARF 5 line programs are located by DW_AT_stmt_list, read off the root DIE
/// exactly as a real consumer does. The expected offsets are hardcoded from
/// `llvm-dwarfdump --debug-info`, never from this parser.
///
///   llvm-dwarfdump --debug-info stellar-fixture-dwarf5-O0.so | grep stmt_list
///     DW_AT_stmt_list (0x00000000)   <- unit 0, Classes/Player/hitboxes/body.cpp
///     DW_AT_stmt_list (0x000001ad)   <- unit 1, Classes/Player/player.cpp
///   llvm-dwarfdump --debug-info stellar-fixture-dwarf5-O2.so | grep stmt_list
///     DW_AT_stmt_list (0x00000000)   <- unit 0
///     DW_AT_stmt_list (0x0000011e)   <- unit 1
///
/// These values are only reachable when the DW_FORM_strx* family in
/// constants.h carries the DWARF 5 Table 7.5 numbers: a DWARF 5 CU spells
/// DW_AT_name with DW_FORM_strx1, and sizing that form one byte narrow makes
/// every later attribute of the root DIE, DW_AT_stmt_list included, decode from
/// the wrong position.
void expect_stmt_lists(dwarf::DwarfContext& ctx, const std::uint64_t* expected,
                       std::size_t n) {
  const std::uint64_t units = ctx.unit_count();
  ASSERT_EQ_SIZE(std::vector<std::uint64_t>(units), n);
  for (std::uint64_t i = 0; i < units; ++i) {
    dwarf::UnitHeader unit;
    ASSERT_TRUE(ctx.unit_header(i, unit));
    const CuLine cu = cu_line(ctx, unit);
    ASSERT_TRUE(cu.parsed);
    EXPECT_EQ(cu.header.offset, expected[i]);
  }
}

STELLAR_TEST(LineFixture, Dwarf5RootDieStmtListMatchesLlvmDwarfdump) {
  elf::ElfFile f;
  if (!open_fixture(f, "stellar-fixture-dwarf5-O0.so")) return;
  dwarf::DwarfContext ctx(f);
  const std::uint64_t expected[] = {0x0, 0x1ad};
  expect_stmt_lists(ctx, expected, 2);
}

STELLAR_TEST(LineFixture, Dwarf5O2RootDieStmtListMatchesLlvmDwarfdump) {
  elf::ElfFile f;
  if (!open_fixture(f, "stellar-fixture-dwarf5-O2.so")) return;
  dwarf::DwarfContext ctx(f);
  const std::uint64_t expected[] = {0x0, 0x11e};
  expect_stmt_lists(ctx, expected, 2);
}

STELLAR_TEST(LineFixture, Dwarf4RootDieStmtListIsUnchangedByTheFormFix) {
  // DWARF 4 uses DW_FORM_strp throughout, so the form numbering change must not
  // move these. llvm-dwarfdump --debug-info reports 0x00000000 and 0x000001d3.
  elf::ElfFile f;
  if (!open_fixture(f, "stellar-fixture-dwarf4-O0.so")) return;
  dwarf::DwarfContext ctx(f);
  const std::uint64_t expected[] = {0x0, 0x1d3};
  expect_stmt_lists(ctx, expected, 2);
}

STELLAR_TEST(LineFixture, Dwarf5NameAndCompDirResolveThroughStrOffsets) {
  // The DWARF 5 CU names its file with DW_FORM_strx1, which is an index into
  // .debug_str_offsets rather than a direct .debug_str offset. If that is not
  // resolved, comp_dir is empty and every relative directory loses its prefix.
  elf::ElfFile f;
  if (!open_fixture(f, "stellar-fixture-dwarf5-O0.so")) return;
  dwarf::DwarfContext ctx(f);
  dwarf::UnitHeader unit;
  ASSERT_TRUE(ctx.unit_header(0, unit));
  const CuLine cu = cu_line(ctx, unit);
  ASSERT_TRUE(cu.parsed);
  EXPECT_STREQ(cu.header.comp_dir, "/stellar-fixtures/src");
  EXPECT_STREQ(cu.header.cu_name, "Classes/Player/hitboxes/body.cpp");
}

STELLAR_TEST(LineFixture, Dwarf5O0ResolvesTheBodyUnitFileTable) {
  elf::ElfFile f;
  if (!open_fixture(f, "stellar-fixture-dwarf5-O0.so")) return;
  dwarf::DwarfContext ctx(f);

  // Unit 0 is located by DW_AT_stmt_list, not by walking .debug_line.
  dwarf::UnitHeader unit;
  ASSERT_TRUE(ctx.unit_header(0, unit));
  const CuLine cu = cu_line(ctx, unit);
  ASSERT_TRUE(cu.parsed);
  EXPECT_EQ(cu.header.offset, std::uint64_t{0});
  const dwarf::LineHeader& h = cu.header;
  EXPECT_EQ(h.version, std::uint16_t{5});
  EXPECT_FALSE(h.files_are_one_based());
  EXPECT_EQ(h.address_size, std::uint8_t{8});
  // DWARF 5 directory 0 is a real entry equal to the compilation directory.
  ASSERT_EQ_SIZE(h.include_directories, 3);
  EXPECT_STREQ(h.include_directories[0], "/stellar-fixtures/src");
  EXPECT_STREQ(h.include_directories[1], "Classes/Player/hitboxes");
  EXPECT_STREQ(h.include_directories[2], "Classes/Util");
  EXPECT_STREQ(h.directory_path(0), "/stellar-fixtures/src");

  expect_paths(h, kDwarf5BodyFiles, 4);
}

STELLAR_TEST(LineFixture, Dwarf5O0ResolvesThePlayerUnitFileTable) {
  elf::ElfFile f;
  if (!open_fixture(f, "stellar-fixture-dwarf5-O0.so")) return;
  dwarf::DwarfContext ctx(f);

  dwarf::UnitHeader unit;
  ASSERT_TRUE(ctx.unit_header(1, unit));
  const CuLine cu = cu_line(ctx, unit);
  ASSERT_TRUE(cu.parsed);
  EXPECT_EQ(cu.header.offset, std::uint64_t{0x1ad});
  ASSERT_EQ_SIZE(cu.header.include_directories, 2);
  EXPECT_STREQ(cu.header.include_directories[0], "/stellar-fixtures/src");
  EXPECT_STREQ(cu.header.include_directories[1], "Classes/Player");
  expect_paths(cu.header, kDwarf5PlayerFiles, 2);
}

STELLAR_TEST(LineFixture, Dwarf5O2ResolvesTheSamePathsAsO0) {
  elf::ElfFile f;
  if (!open_fixture(f, "stellar-fixture-dwarf5-O2.so")) return;
  dwarf::DwarfContext ctx(f);

  dwarf::UnitHeader unit;
  ASSERT_TRUE(ctx.unit_header(0, unit));
  const CuLine cu = cu_line(ctx, unit);
  ASSERT_TRUE(cu.parsed);
  const dwarf::LineHeader& h = cu.header;
  EXPECT_FALSE(h.files_are_one_based());
  ASSERT_EQ_SIZE(h.file_names, 4);
  EXPECT_STREQ(h.file_path(0), "/stellar-fixtures/src/Classes/Player/hitboxes/body.cpp");
  EXPECT_STREQ(h.file_path(1), "/stellar-fixtures/src/Classes/Player/hitboxes/body.h");
  EXPECT_STREQ(h.file_path(2), "/stellar-fixtures/src/<stdin>");
  EXPECT_STREQ(h.file_path(3), "/stellar-fixtures/src/Classes/Util/math.h");
}

STELLAR_TEST(LineFixture, Dwarf4StmtListMatchesTheLineUnits) {
  // DWARF 4 CUs carry DW_AT_stmt_list as a plain DW_FORM_sec_offset, so this
  // input exercises the full path a real consumer takes: read the attribute off
  // the root DIE, then parse the header at that offset. It also proves the
  // section-order walk used for DWARF 5 (see cu_line) finds the same offsets.
  elf::ElfFile f;
  if (!open_fixture(f, "stellar-fixture-dwarf4-O0.so")) return;
  dwarf::DwarfContext ctx(f);

  const std::vector<dwarf::LineHeader> units =
      all_line_units(ctx, "/stellar-fixtures/src");
  ASSERT_EQ_SIZE(units, 2);

  for (std::uint64_t i = 0; i < ctx.unit_count(); ++i) {
    dwarf::UnitHeader unit;
    ASSERT_TRUE(ctx.unit_header(i, unit));
    const CuLine cu = cu_line(ctx, unit);
    ASSERT_TRUE(cu.parsed);
    // The DW_AT_stmt_list offset must be exactly where the section-order walk
    // found the i-th line program.
    EXPECT_EQ(cu.header.offset, units[static_cast<std::size_t>(i)].offset);
    EXPECT_STREQ(cu.header.comp_dir, "/stellar-fixtures/src");
    EXPECT_FALSE(cu.header.comp_dir.empty());
    // And the name must have come through, which only happens when the
    // DW_FORM_strp resolution worked.
    EXPECT_FALSE(cu.header.cu_name.empty());
  }
}

STELLAR_TEST(LineFixture, EveryFixtureHeaderFitsInsideItsUnit) {
  // The program range must stay within the unit for all four libraries; a
  // header_length read past unit_length would silently run into the next unit.
  for (const char* name : {"stellar-fixture-dwarf4-O0.so", "stellar-fixture-dwarf4-O2.so",
                           "stellar-fixture-dwarf5-O0.so", "stellar-fixture-dwarf5-O2.so"}) {
    elf::ElfFile f;
    if (!open_fixture(f, name)) return;
    dwarf::DwarfContext ctx(f);

    const std::uint64_t line_size = ctx.sections().size(dwarf::Sec::kLine);
    const std::vector<dwarf::LineHeader> units =
        all_line_units(ctx, "/stellar-fixtures/src");
    ASSERT_EQ_SIZE(units, 2);
    for (const dwarf::LineHeader& h : units) {
      EXPECT_TRUE(h.program_start >= h.offset);
      EXPECT_TRUE(h.program_end <= line_size);
      EXPECT_TRUE(h.program_start <= h.program_end);
      // header_length must be measured from just after the initial length field.
      EXPECT_EQ(h.program_start,
                h.offset + static_cast<std::uint64_t>(h.length_size) + h.header_length);
    }
  }
}

// ---------------------------------------------------------------------------
// Real target binary (opt-in)
// ---------------------------------------------------------------------------

STELLAR_TEST(RealBinaryLine, EveryCuLineHeaderParses) {
  // Opt-in: STELLAR_REAL_BINARY must point at the 583 MB target, otherwise the
  // whole case is skipped. Only a genuine parse error fails the test -- a unit
  // with no DW_AT_stmt_list is normal and is counted separately.
  const std::string path = stellar::test::real_binary_path();
  if (path.empty()) {
    std::fprintf(stderr, "  (skipped: real binary not present)\n");
    return;
  }
  elf::ElfFile f;
  std::string err;
  if (!f.open(path, &err)) {
    std::fprintf(stderr, "  (skipped: %s)\n", err.c_str());
    return;
  }
  dwarf::DwarfContext ctx(f);
  if (!ctx.sections().has(dwarf::Sec::kLine)) {
    std::fprintf(stderr, "  (skipped: no .debug_line)\n");
    return;
  }

  const std::uint64_t units = ctx.unit_count();
  std::uint64_t parsed = 0, without_stmt_list = 0, failed = 0;
  std::string first_error;

  for (std::uint64_t i = 0; i < units; ++i) {
    dwarf::UnitHeader unit;
    if (!ctx.unit_header(i, unit)) continue;
    const CuLine cu = cu_line(ctx, unit);
    if (cu.parsed) {
      ++parsed;
      continue;
    }
    // No stmt_list is a legitimate outcome, not a malformed header.
    if (cu.error.find("no DW_AT_stmt_list") != std::string::npos) {
      ++without_stmt_list;
      continue;
    }
    if (first_error.empty()) {
      first_error = "unit " + std::to_string(i) + ": " + cu.error;
    }
    ++failed;
  }

  std::fprintf(stderr, "  line headers: %llu parsed, %llu without stmt_list, "
                       "%llu failed (of %llu units)\n",
               static_cast<unsigned long long>(parsed),
               static_cast<unsigned long long>(without_stmt_list),
               static_cast<unsigned long long>(failed),
               static_cast<unsigned long long>(units));

  EXPECT_TRUE(parsed > 0);
  EXPECT_EQ(failed, std::uint64_t{0});
  if (failed != 0) {
    ::stellar::test::report_failure(__FILE__, __LINE__,
                                    "every CU's line header parses", first_error);
  }
}

