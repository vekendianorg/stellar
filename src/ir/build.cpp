// SPDX-License-Identifier: MIT
#include "stellar/ir/build.h"

#include <algorithm>
#include <cctype>
#include <cstdio>
#include <memory>
#include <unordered_map>

#include "stellar/diag/log.h"
#include "stellar/diag/metrics.h"
#include "stellar/diag/progress.h"
#include "stellar/dwarf/eh_frame.h"
#include "stellar/dwarf/constants.h"
#include "stellar/dwarf/line.h"

namespace stellar::ir {
namespace {

using namespace stellar::dwarf;

/// Resolver shim so the model can read .debug_str without owning the context.
std::string_view str_thunk(void* self, std::uint32_t off) {
  return static_cast<DwarfContext*>(self)->str_at(off);
}

/// Per-CU line-header cache.
///
/// DW_AT_decl_file is an index into the *compilation unit's own* file table, so
/// resolving one source location means parsing that unit's .debug_line header.
/// There are 1183 units in the real target and millions of DIEs, so the header
/// is parsed at most once per unit and reused; a unit with no .debug_line, or a
/// header that fails to parse, resolves nothing (id 0), which is the honest
/// answer rather than a guess.
///
/// `parsed` is kept separate from the header because "the section is absent" and
/// "the header parsed but the index is out of range" are different failures
/// that both legitimately yield id 0.
class LineCache {
 public:
  explicit LineCache(DwarfContext& ctx) : ctx_(ctx) {}

  /// Fills `prov` from `die`'s DW_AT_decl_file / DW_AT_decl_line, using the file
  /// table of unit `unit`. Returns false when nothing could be resolved.
  /// `cu` is the unit's index, recorded in `prov.cu` regardless of the outcome.
  bool resolve(const Die& die, const UnitHeader& unit, std::uint32_t cu, Model& model,
               Provenance& prov);

  /// DW_AT_str_offsets_base of `unit`'s root DIE, or 0 when it has none.
  [[nodiscard]] std::uint64_t str_offsets_base(const UnitHeader& unit);

  /// Text of a DW_AT_linkage_name on a DIE from `unit`, resolving the DWARF 5
  /// DW_FORM_strx* family against that unit's .debug_str_offsets.
  [[nodiscard]] std::string linkage_name(const AttrValue& v, const UnitHeader& unit);

  /// The address of a DW_AT_low_pc, whichever form the producer used. DWARF <= 4
  /// stores a plain address; DWARF 5 stores a DW_FORM_addrx* index that has to be
  /// resolved through .debug_addr. Returns 0 when it cannot be resolved, which is
  /// also the value the builder already treats as "no address".
  [[nodiscard]] std::uint64_t low_pc(const AttrValue& v, const UnitHeader& unit) {
    if (!is_indexed_address(v.form)) return v.u64;
    std::uint64_t out = 0;
    if (!addrx_addr(v, addr_base(unit), out)) return 0;
    return out;
  }

  /// The end address of a DW_AT_high_pc, given the function's already-resolved
  /// start.
  ///
  /// DWARF 4 spells high_pc as an absolute address; DWARF 5 spells it as a length
  /// added to low_pc. Reading one with the other's rule yields a range that looks
  /// plausible and is wrong -- a length of 0x60 added to nothing, or an absolute
  /// address subtracted into a negative length -- so the version decides, and
  /// `low` has to be resolved first for the offset form to mean anything.
  ///
  /// Returns false when the range cannot be established. That is the normal case
  /// for an inlined function, which has a DIE and no code: the caller reports
  /// "no-range" rather than inventing a length.
  [[nodiscard]] bool high_pc(const AttrValue& v, const UnitHeader& unit, std::uint64_t low,
                             std::uint64_t& out) {
    // An address form means the attribute holds the end address. Anything else is
    // a constant, and for a subprogram a constant means a length relative to
    // low_pc -- which is what clang and gcc actually emit even under DWARF 4,
    // where the specification permits it. llvm-dwarfdump hides the difference by
    // adding low_pc before printing, so a length of 0x10 is displayed as an
    // "address" that is really low_pc + 0x10.
    //
    // Reading a length as an address yields a range entirely below the function,
    // and reading an address as a length yields one entirely above it. Neither is
    // obviously wrong on inspection, so the form -- not the version -- decides.
    if (v.form == form::kAddr) {
      out = v.u64;
      return out != 0;
    }
    if (is_indexed_address(v.form)) {
      std::uint64_t abs = 0;
      if (!addrx_addr(v, addr_base(unit), abs)) return false;
      out = abs;
      return true;
    }
    // A length is only usable once the start is known: with an unresolved low_pc
    // there is nothing to add it to.
    if (low == 0) return false;
    out = low + v.u64;
    return true;
  }

  /// The model's name_off for a string attribute: DW_FORM_strp is its own
  /// .debug_str offset, and the DW_FORM_strx* family is looked up through
  /// `unit`'s .debug_str_offsets contribution. Returns Model::kNoName for every
  /// other form and for anything that cannot be resolved safely: a missing
  /// DW_AT_str_offsets_base, an index past the contribution, or an offset past
  /// the end of .debug_str. The model stores names as .debug_str offsets, so this
  /// is what lets DWARF 5 names land in the same field a DWARF 4 strp does.
  ///
  /// The result is BIASED (see Model::name_encode) so that 0 can mean "unnamed"
  /// unambiguously; readers must use Model::name(), never str() directly.
  [[nodiscard]] std::uint32_t str_offset(const AttrValue& v, const UnitHeader& unit);

  /// Diagnostics: how many DIEs named a file that could not be turned into a
  /// path. Non-zero is expected on DWARF <= 4 (where a missing .debug_line is
  /// normal) and would be a bug on DWARF 5.
  [[nodiscard]] std::uint64_t unresolved() const { return unresolved_; }
  [[nodiscard]] std::uint64_t no_line_section() const { return no_line_section_; }
  [[nodiscard]] std::uint64_t headers_parsed() const { return parsed_headers_; }

 private:
  DwarfContext& ctx_;
  /// DW_AT_stmt_list -> parsed header. A null entry means "attempted, unusable".
  std::unordered_map<std::uint64_t, std::shared_ptr<LineHeader>> headers_;
  /// Unit offset -> DW_AT_str_offsets_base, read once per unit.
  std::unordered_map<std::uint64_t, std::uint64_t> str_bases_;
  /// Unit offset -> DW_AT_addr_base, read once per unit.
  std::unordered_map<std::uint64_t, std::uint64_t> addr_bases_;
  std::uint64_t unresolved_ = 0;
  std::uint64_t no_line_section_ = 0;
  std::uint64_t parsed_headers_ = 0;

  /// The header at `stmt_list`, or nullptr when it cannot be obtained.
  std::shared_ptr<LineHeader> header_for(const UnitHeader& unit,
                                         std::uint64_t stmt_list,
                                         const std::string& cu_name,
                                         const std::string& comp_dir);

  /// Text of a string-valued attribute; see the out-of-line definition.
  [[nodiscard]] std::string string_of(const AttrValue& v, std::uint64_t base) const;

  /// Resolves a DW_FORM_strx* index to its .debug_str offset. `base` is the
  /// unit's DW_AT_str_offsets_base. Every read is bounded by the contribution
  /// the base points into, so a hostile table cannot make this read outside it.
  [[nodiscard]] bool strx_offset(const AttrValue& v, std::uint64_t base,
                                 std::uint64_t& out) const;

  /// DW_AT_addr_base of `unit`'s root DIE, or 0 when it has none.
  [[nodiscard]] std::uint64_t addr_base(const UnitHeader& unit);

  /// Resolves a DW_FORM_addrx* index to an address. `base` is the unit's
  /// DW_AT_addr_base. Returns false -- leaving the caller's address 0 -- when
  /// the base is missing, the contribution header is unusable, the index runs
  /// past the contribution, or address_size is neither 4 nor 8. Bounded exactly
  /// like strx_offset: no read reaches outside the contribution.
  [[nodiscard]] bool addrx_addr(const AttrValue& v, std::uint64_t base,
                               std::uint64_t& out) const;

};
bool LineCache::strx_offset(const AttrValue& v, std::uint64_t base,
                            std::uint64_t& out) const {
  unsigned index_width = 0;  // 0 = ULEB, already decoded into v.u64
  if (v.form == form::kStrx1) index_width = 1;
  else if (v.form == form::kStrx2) index_width = 2;
  else if (v.form == form::kStrx3) index_width = 3;
  else if (v.form == form::kStrx4) index_width = 4;
  else if (v.form != form::kStrx) return false;  // incl. the GNU split-DWARF form
  (void)index_width;  // the index value is already in v.u64 for every width

  const util::ByteView table = ctx_.sections().view(Sec::kStrOffsets);
  const std::size_t size = table.size();
  // A DWARF 5 contribution starts with a header (unit_length, version, padding),
  // and DW_AT_str_offsets_base points just past it, so a valid base is at least 8.
  if (base < 8 || base > size) return false;

  util::Cursor c(table.data(), size, util::Endian::Little);
  // The header is 8 bytes for the 32-bit format and 16 for 64-bit (an 0xffffffff
  // escape, then a 64-bit length). Work out which one `base` follows.
  unsigned off_size = 4;
  std::uint64_t header_start = base - 8;
  std::uint64_t length = 0;
  std::uint32_t first = 0;
  if (base >= 16 && c.seek(static_cast<std::size_t>(base - 16)) && c.read_u32(first) &&
      first == 0xffffffffu) {
    off_size = 8;
    header_start = base - 16;
    if (!c.read_u64(length)) return false;
  } else {
    if (!c.seek(static_cast<std::size_t>(header_start)) || !c.read_u32(first)) return false;
    if (first >= 0xfffffff0u) return false;  // reserved / 64-bit escape in the wrong place
    length = first;
  }
  const std::uint64_t length_field = off_size == 8 ? 12 : 4;
  // End of this contribution; a length that runs past the section is hostile.
  if (length > size || header_start + length_field + length > size) return false;
  const std::uint64_t end = header_start + length_field + length;

  const std::uint64_t index = v.u64;
  // Overflow-safe: compare the index against the room that is left.
  if (index > (end - base) / off_size) return false;
  const std::uint64_t entry = base + index * off_size;
  if (entry + off_size > end) return false;
  if (!c.seek(static_cast<std::size_t>(entry))) return false;
  return off_size == 8 ? c.read_u64(out) : [&] {
    std::uint32_t v32 = 0;
    if (!c.read_u32(v32)) return false;
    out = v32;
    return true;
  }();
}

std::uint64_t LineCache::addr_base(const UnitHeader& unit) {
  const auto it = addr_bases_.find(unit.offset);
  if (it != addr_bases_.end()) return it->second;
  std::uint64_t base = 0;
  const AbbrevTable* ab = ctx_.abbrev_table(unit, nullptr);
  if (ab != nullptr) {
    UnitWalker w(ctx_.info(), unit, ab);
    w.reset();
    Die root;
    if (w.next(root)) {
      AttrValue r;
      if (root.attr(aat::kAddrBase, r)) base = r.u64;
    }
  }
  addr_bases_.emplace(unit.offset, base);
  return base;
}

bool LineCache::addrx_addr(const AttrValue& v, std::uint64_t base,
                           std::uint64_t& out) const {
  // The index itself is already decoded into v.u64 for every width; the form
  // only matters for deciding that this attribute is indexed at all.
  if (!is_indexed_address(v.form)) return false;

  const util::ByteView table = ctx_.sections().view(Sec::kAddr);
  const std::size_t size = table.size();
  // The contribution starts with a header (unit_length, version, address_size,
  // segment_selector_size), so a base that points at an entry is at least 8.
  if (base < 8 || base > size) return false;

  util::Cursor c(table.data(), size, util::Endian::Little);
  // Work out where this contribution starts, so its end can bound every read
  // below. As in strx_offset, the 64-bit format is an 0xffffffff escape followed
  // by a 64-bit length; otherwise the first word is the length.
  unsigned off_size = 4;
  std::uint64_t header_start = base - 8;
  std::uint64_t length = 0;
  std::uint32_t first = 0;
  if (base >= 16 && c.seek(static_cast<std::size_t>(base - 16)) && c.read_u32(first) &&
      first == 0xffffffffu) {
    off_size = 8;
    header_start = base - 16;
    if (!c.read_u64(length)) return false;
  } else {
    if (!c.seek(static_cast<std::size_t>(header_start)) || !c.read_u32(first)) return false;
    if (first >= 0xfffffff0u) return false;  // reserved / escape in the wrong place
    length = first;
  }
  const std::uint64_t length_field = off_size == 8 ? 12 : 4;
  if (length > size || header_start + length_field + length > size) return false;
  const std::uint64_t end = header_start + length_field + length;

  // The header proper: version, address_size, segment_selector_size.
  if (!c.seek(static_cast<std::size_t>(header_start + length_field)) ) return false;
  std::uint16_t version = 0;
  std::uint8_t address_size = 0;
  std::uint8_t segment_size = 0;
  if (!c.read_u16(version) || !c.read_u8(address_size) || !c.read_u8(segment_size)) {
    return false;
  }
  (void)version;
  // Only 4- and 8-byte addresses are meaningful here; anything else would make
  // every entry's width a guess, so it is refused rather than assumed.
  if (address_size != 4 && address_size != 8) return false;
  if (segment_size != 0) return false;  // a segmented address is not a plain VA

  const std::uint64_t index = v.u64;
  // Overflow-safe: compare the index against the room that is left.
  if (index > (end - base) / address_size) return false;
  const std::uint64_t entry = base + index * address_size;
  if (entry + address_size > end) return false;
  if (!c.seek(static_cast<std::size_t>(entry))) return false;

  if (address_size == 8) {
    if (!c.read_u64(out)) return false;
  } else {
    std::uint32_t v32 = 0;
    if (!c.read_u32(v32)) return false;
    out = v32;
  }
  return true;
}

std::string LineCache::string_of(const AttrValue& v, std::uint64_t base) const {
  if (v.form == form::kStrp) return std::string(ctx_.str_at(v.u64));
  if (v.form == form::kString && v.has_block) {
    return std::string(reinterpret_cast<const char*>(v.block.data()), v.block.size());
  }
  if (v.form == form::kLineStrp) {
    const util::ByteView ls = ctx_.sections().view(Sec::kLineStr);
    if (v.u64 >= ls.size()) return {};
    const char* p = reinterpret_cast<const char*>(ls.data());
    const std::size_t max = ls.size() - static_cast<std::size_t>(v.u64);
    std::size_t len = 0;
    while (len < max && p[v.u64 + len] != '\0') ++len;
    return std::string(p + v.u64, len);
  }
  if (!is_indexed_string(v.form)) return {};
  std::uint64_t off = 0;
  if (!strx_offset(v, base, off)) return {};
  return std::string(ctx_.str_at(off));
}

std::uint32_t LineCache::str_offset(const AttrValue& v, const UnitHeader& unit) {
  // Bias on the way out so that every caller's name_off is already in the
  // model's encoding and none of them has to know about it.
  std::uint64_t off = 0;
  if (v.form == form::kStrp) {
    // The common DWARF 4 case, kept free of any lookup.
    off = v.u64;
  } else if (is_indexed_string(v.form)) {
    if (!strx_offset(v, str_offsets_base(unit), off)) return Model::kNoName;
  } else {
    return Model::kNoName;
  }
  // An offset at or past the end of .debug_str is not a name. Offset 0 IS a
  // name when it resolves: name_encode() stores it as 1, which is the whole
  // point of the bias.
  if (off >= ctx_.str().size()) return Model::kNoName;
  return Model::name_encode(off);
}

std::shared_ptr<LineHeader> LineCache::header_for(const UnitHeader& unit,
                                                std::uint64_t stmt_list,
                                                const std::string& cu_name,
                                                const std::string& comp_dir) {
  const auto it = headers_.find(stmt_list);
  if (it != headers_.end()) return it->second;  // cached, possibly null

  std::shared_ptr<LineHeader> out;
  if (ctx_.sections().has_line()) {
    const LineSections sections{
        ctx_.sections().view(Sec::kLine),
        ctx_.sections().view(Sec::kLineStr),
        ctx_.str(),
    };
    auto h = std::make_shared<LineHeader>();
    std::string err;
    if (parse_line_header(sections, stmt_list, cu_name, comp_dir, unit.endian, *h, &err)) {
      out = h;
      ++parsed_headers_;
    }
  }
  headers_.emplace(stmt_list, out);
  return out;
}

std::string LineCache::linkage_name(const AttrValue& v, const UnitHeader& unit) {
  return string_of(v, str_offsets_base(unit));
}

std::uint64_t LineCache::str_offsets_base(const UnitHeader& unit) {
  const auto it = str_bases_.find(unit.offset);
  if (it != str_bases_.end()) return it->second;
  std::uint64_t base = 0;
  const AbbrevTable* ab = ctx_.abbrev_table(unit, nullptr);
  if (ab != nullptr) {
    UnitWalker w(ctx_.info(), unit, ab);
    w.reset();
    Die root;
    if (w.next(root)) {
      AttrValue r;
      if (root.attr(aat::kStrOffsetsBase, r)) base = r.u64;
    }
  }
  str_bases_.emplace(unit.offset, base);
  return base;
}

bool LineCache::resolve(const Die& die, const UnitHeader& unit, std::uint32_t cu,
                        Model& model, Provenance& prov) {
  prov = Provenance{};
  prov.cu = cu;

  AttrValue v;
  if (die.attr(aat::kDeclLine, v)) {
    prov.line = static_cast<std::uint32_t>(v.u64);
  }
  if (!die.attr(aat::kDeclFile, v)) return false;  // no file index: nothing to do

  // The CU's own attributes: DW_AT_stmt_list locates the file table, and
  // DW_AT_comp_dir is what a relative directory index resolves against.
  std::string cu_name;
  std::string comp_dir;
  std::uint64_t stmt_list = 0;
  bool have_stmt_list = false;
  // DWARF 5 puts a header on .debug_str_offsets; DWARF 4 has no such section,
  // so the base stays 0 there and is never used.
  std::uint64_t str_offsets_base = 0;
  const AbbrevTable* ab = ctx_.abbrev_table(unit, nullptr);
  if (ab != nullptr) {
    UnitWalker w(ctx_.info(), unit, ab);
    w.reset();
    Die root;
    if (w.next(root)) {
      AttrValue r;
      if (root.attr(aat::kStmtList, r)) {
        stmt_list = r.u64;
        have_stmt_list = true;
      }
      if (root.attr(aat::kStrOffsetsBase, r)) str_offsets_base = r.u64;
      if (root.attr(aat::kCompDir, r)) comp_dir = string_of(r, str_offsets_base);
      if (root.attr(aat::kName, r)) cu_name = string_of(r, str_offsets_base);
    }
  }
  if (!have_stmt_list) {
    ++no_line_section_;
    ++unresolved_;
    return false;
  }

  const std::shared_ptr<LineHeader> h = header_for(unit, stmt_list, cu_name, comp_dir);
  if (h == nullptr) {
    ++unresolved_;
    return false;
  }

  // file_path() returns "" for an index the table cannot satisfy, which covers
  // both the 1-based DWARF <= 4 range and the 0-based DWARF 5 one. An
  // unresolvable index stays id 0 rather than falling back to the CU's name.
  const std::string p = h->file_path(v.u64);
  if (p.empty()) {
    ++unresolved_;
    return false;
  }
  prov.file_id = model.path_id(p);
  return true;
}

/// True for the tags that define a node in the type graph.
bool is_type_tag(std::uint32_t t) {
  switch (t) {
    case tag::kBaseType:
    case tag::kPointerType:
    case tag::kReferenceType:
    case tag::kConstType:
    case tag::kVolatileType:
    case tag::kRestrictType:
    case tag::kAtomicType:
    case tag::kArray:
    case tag::kTypedef:
    case tag::kStructureType:
    case tag::kClass:
    case tag::kUnion:
    case tag::kEnumeration:
    case tag::kSubroutineType:
    case tag::kUnspecifiedType:
      return true;
    default:
      return false;
  }
}

TypeKind kind_of(std::uint32_t t) {
  switch (t) {
    case tag::kBaseType: return TypeKind::kBase;
    case tag::kPointerType: return TypeKind::kPointer;
    case tag::kReferenceType: return TypeKind::kLRef;
    case tag::kConstType: return TypeKind::kConst;
    case tag::kVolatileType: return TypeKind::kVolatile;
    case tag::kRestrictType: return TypeKind::kRestrict;
    case tag::kAtomicType: return TypeKind::kAtomic;
    case tag::kArray: return TypeKind::kArray;
    case tag::kTypedef: return TypeKind::kTypedef;
    case tag::kStructureType: return TypeKind::kStruct;
    case tag::kClass: return TypeKind::kClass;
    case tag::kUnion: return TypeKind::kUnion;
    case tag::kEnumeration: return TypeKind::kEnum;
    case tag::kSubroutineType: return TypeKind::kFunction;
    case tag::kUnspecifiedType: return TypeKind::kUnspecified;
    default: return TypeKind::kUnknown;
  }
}

/// Extracts a member offset from DW_AT_data_member_location.
///
/// Clang emits a plain constant for most members, but uses a location
/// expression (`DW_OP_plus_uconst`) once a base class is involved. Anything
/// that is genuinely base-relative is reported as unknown rather than guessed,
/// so the emitter can mark it instead of printing a wrong offset.
bool extract_offset(const AttrValue& v, std::uint64_t* out_offset, bool* is_static) {
  *is_static = false;
  if (v.form == form::kExprloc) {
    if (v.block.empty()) return false;
    const std::uint8_t op = v.block.data()[0];
    if (op == 0x23u /* DW_OP_plus_uconst */) {
      if (v.block.size() < 2) return false;
      std::uint64_t val = 0;
      if (util::decode_uleb128(v.block.data() + 1, v.block.data() + v.block.size(), val) == 0) {
        return false;
      }
      *out_offset = val;
      return true;
    }
    if (op == 0x22u /* DW_OP_plus */) return false;  // base-relative: unknown
    return false;
  }
  // Constant forms (udata/sdata/data1/data2/...).
  switch (v.form) {
    case form::kUdata:
    case form::kData1:
    case form::kData2:
    case form::kData4:
    case form::kData8:
    case form::kSecOffset:
      *out_offset = v.u64;
      return true;
    case form::kSdata:
      *out_offset = static_cast<std::uint64_t>(v.i64);
      return true;
    case form::kFlagPresent:
      *is_static = true;
      return true;
    default:
      return false;
  }
}

}  // namespace
namespace {

/// One open aggregate while walking a unit: a class/union whose field list is
/// still being filled, or an enum whose member list is still growing.
///
/// The DIE stream carries no explicit "end of children" marker, so the walker's
/// depth counter is what tells us an aggregate is finished.
struct Open {
  std::uint32_t depth = 0;
  std::int32_t cls = -1;    ///< index into Model::classes, -1 for enums
  std::int32_t enm = -1;    ///< index into Model::enums
  std::uint32_t first = 0;  ///< where its fields/members started
  std::uint32_t node = 0;   ///< the Type node (for array bound tracking)
};

}  // namespace

/// The model's stored handle for a DW_AT_name-style attribute.
///
/// Two shapes arrive here and they cannot be stored the same way. DW_FORM_strp
/// and the DW_FORM_strx family are offsets into a string table, so the offset is
/// encoded as-is. DW_FORM_string is the characters themselves, inline in the
/// DIE: GCC emits it for short names, so "E", "x" and "Q" arrive that way, with
/// no offset to record. Dropping those (the old behaviour) left every
/// short-named type, member and enumerator nameless -- an unnamed enum then made
/// the tree emitter refuse the whole dump -- so they are copied into the model's
/// own arena and flagged, and name() reads whichever space the flag names.
std::uint32_t name_off_of(LineCache& lines, Model& model, const AttrValue& v,
                          const UnitHeader& h) {
  if (v.form == form::kString && v.has_block) {
    if (v.block.size() == 0) return Model::kNoName;
    const std::string_view text(reinterpret_cast<const char*>(v.block.data()),
                                v.block.size());
    return Model::name_encode_arena(model.arena_add(text));
  }
  return lines.str_offset(v, h);
}

bool build_model(DwarfContext& ctx, const BuildOptions& opts, Model& model,
                 BuildStats* stats) {
  const auto t_start = diag::Clock::now();
  auto& pr = diag::progress();
  model.string_self = &ctx;
  model.string_fn = &str_thunk;

  // The counters are declared up front so the line is complete and stable from
  // the first frame rather than growing as stages are discovered.
  pr.declare("Units", 0, false);
  pr.declare("DIEs", 0, false);
  pr.declare("Types", 0, false);
  pr.declare("Fields", 0, false);
  pr.declare("Methods", 0, false);
  pr.primary("DIEs");

  BuildStats st;
  // Measured on the real target: ~3.5M type-defining DIEs. Reserving up front
  // avoids repeatedly reallocating several hundred megabytes of vectors.
  model.types.reserve(4u << 20);
  model.fields.reserve(600u << 10);
  model.methods.reserve(200u << 10);
  model.params.reserve(400u << 10);
  model.classes.reserve(600u << 10);
  model.enums.reserve(32u << 10);
  model.enum_members.reserve(64u << 10);
  model.reserve_type_slots(4u << 20);

  // DW_AT_type values that still need turning into node indices. Stored as
  // (slot, raw reference) so pass B can resolve them without re-walking.
  /// What a pending reference will be written into, so one resolve loop can
  /// serve types, fields, base classes, return types and parameters.
  enum class Slot : std::uint8_t {
    kType,       ///< model.types[i].elem
    kField,      ///< model.fields[i].type
    kClassBase,  ///< model.classes[i].base
    kMethodRet,  ///< model.methods[i].ret_type
    kParam,      ///< model.params[i].type
  };
  struct Pending {
    Slot slot;
    std::uint32_t index;     ///< index into the array named by `slot`
    std::uint32_t target;    ///< raw unit-relative DW_AT_type value
    std::uint64_t unit_off;  ///< .debug_info offset of the owning unit
  };
  std::vector<Pending> pending;
  pending.reserve(6u << 20);
  // A C++ member function appears twice: an in-class declaration carrying the
  // name and signature but no code, and an out-of-line definition that names
  // it with DW_AT_specification. The address only exists on the second, so
  // declarations are indexed by DIE offset and the definitions are applied
  // afterwards.
  std::unordered_map<std::uint64_t, std::uint32_t> decl_by_offset;
  decl_by_offset.reserve(1u << 20);
  struct SpecFix {
    std::uint64_t target = 0;   ///< absolute offset of the declaration DIE
    std::uint64_t addr = 0;
    std::uint32_t name_off = 0;
    std::uint32_t name_is_ref = 0;  ///< name came from DW_AT_linkage_name
    /// Where this concrete DIE was written, for the declaration it stands for.
    Provenance def;
    std::uint64_t size = 0;
  };
  std::vector<SpecFix> spec_fixes;
  spec_fixes.reserve(1u << 20);
  // Source provenance. One line header per unit, parsed lazily and cached.
  LineCache lines(ctx);
  model.paths.reserve(4096);
  // Mangled variable name -> declaration site, for the globals that the symbol
  // table reports later.
  std::unordered_map<std::string, Provenance> var_prov;
  var_prov.reserve(64u << 10);

  dwarf::DwarfContext::UnitIterator it(ctx);
  dwarf::UnitHeader h;
  std::string err;

  // ------------------------------------------------------------------ pass A --
  while (it.next(h, &err)) {
    if (opts.max_units != 0 && st.units >= opts.max_units) break;
    const AbbrevTable* ab = ctx.abbrev_table(h, &err);
    if (ab == nullptr) {
      ++st.units_without_abbrev;
      continue;
    }

    UnitWalker w(ctx.info(), h, ab);
    w.reset();
    Die die;
    std::vector<Open> open;
    open.reserve(32);
    // The most recent open aggregate, for the common "member directly inside a
    // class" case.
    std::int32_t cur_class = -1;
    std::int32_t cur_enum = -1;
    // Index into model.methods of the member function being assembled, and how
    // many formal parameters it has collected so far.
    std::int32_t cur_method = -1;
    std::uint32_t cur_method_first_param = 0;
    std::uint32_t method_depth = 0;

    while (w.next(die)) {
      ++st.dies;
      pr.add("DIEs");
      const unsigned depth = die.depth();
      const std::uint32_t t = die.tag();

      // Close an open member function when we return to class level.
      if (cur_method >= 0 && depth <= method_depth) {
        model.methods[static_cast<std::size_t>(cur_method)].param_count =
            static_cast<std::uint32_t>(model.params.size()) - cur_method_first_param;
        cur_method = -1;
      }

      // Close every aggregate that ends at or above this depth.
      while (!open.empty() && open.back().depth >= depth) {
        const Open& o = open.back();
        if (o.cls >= 0) {
          ClassDef& cd = model.classes[static_cast<std::size_t>(o.cls)];
          cd.field_count = static_cast<std::uint32_t>(model.fields.size()) - o.first;
        } else if (o.enm >= 0) {
          EnumDef& ed = model.enums[static_cast<std::size_t>(o.enm)];
          ed.member_count = static_cast<std::uint32_t>(model.enum_members.size()) - o.first;
        }
        open.pop_back();
      }
      cur_class = open.empty() ? -1 : open.back().cls;
      cur_enum = open.empty() ? -1 : open.back().enm;

      AttrValue v;

      if (is_type_tag(t)) {
        Type ty;
        ty.kind = kind_of(t);
        ty.transparent = (ty.kind == TypeKind::kConst || ty.kind == TypeKind::kVolatile ||
                          ty.kind == TypeKind::kRestrict || ty.kind == TypeKind::kTypedef)
                             ? 1
                             : 0;
        if (die.attr(aat::kName, v)) {
          ty.name_off = name_off_of(lines, model, v, h);
        }
        if (die.attr(aat::kByteSize, v)) ty.size = v.u64;
        if (die.attr(aat::kEncoding, v)) ty.encoding = static_cast<std::uint8_t>(v.u64);

        Open o;
        o.depth = depth;
        o.node = static_cast<std::uint32_t>(model.types.size());
        o.first = 0;
        if (ty.kind == TypeKind::kStruct || ty.kind == TypeKind::kClass ||
            ty.kind == TypeKind::kUnion) {
          ClassDef cd;
          cd.name_off = ty.name_off;
          cd.size = ty.size;
          // vtable-derived classes have no DIE and keep the zero default.
          lines.resolve(die, h, static_cast<std::uint32_t>(st.units), model, cd.prov);
          cd.kind = ty.kind == TypeKind::kClass ? 1 : (ty.kind == TypeKind::kUnion ? 2 : 0);
          cd.first_field = static_cast<std::uint32_t>(model.fields.size());
          cd.first_method = static_cast<std::uint32_t>(model.methods.size());
          o.cls = static_cast<std::int32_t>(model.classes.size());
          model.classes.push_back(cd);
          ty.def = o.cls;
          ++st.classes;
        } else if (ty.kind == TypeKind::kEnum) {
          EnumDef ed;
          ed.name_off = ty.name_off;
          ed.size = ty.size;
          lines.resolve(die, h, static_cast<std::uint32_t>(st.units), model, ed.prov);
          if (die.attr(aat::kEnumClass, v)) ed.is_enum_class = 1;
          ed.first_member = static_cast<std::uint32_t>(model.enum_members.size());
          o.enm = static_cast<std::int32_t>(model.enums.size());
          model.enums.push_back(ed);
          ty.def = o.enm;
          ++st.enums;
        }

        const std::uint32_t node = static_cast<std::uint32_t>(model.types.size());
        model.types.push_back(ty);
        ++st.type_nodes;
        pr.add("Types");
        model.index_type(static_cast<std::uint32_t>(die.offset()), node);

        if (die.attr(aat::kType, v)) {
          pending.push_back({Slot::kType, node, static_cast<std::uint32_t>(v.u64), h.offset});
        }
        if (die.has_children()) {
          o.first = (ty.kind == TypeKind::kArray)
                        ? 0
                        : (o.cls >= 0
                               ? model.classes[static_cast<std::size_t>(o.cls)].first_field
                               : (o.enm >= 0
                                      ? model.enums[static_cast<std::size_t>(o.enm)].first_member
                                      : 0));
          open.push_back(o);
          cur_class = o.cls;
          cur_enum = o.enm;
        }
        continue;
      }

      switch (t) {
        case tag::kMember: {
          if (cur_class < 0) break;
          Field f;
          if (die.attr(aat::kName, v)) {
            f.name_off = name_off_of(lines, model, v, h);
          }
          // DW_AT_data_member_location gives the instance offset; its absence
          // means the member is static.
          bool is_static = false;
          if (die.attr(aat::kDataMemberLocation, v)) {
            std::uint64_t off = 0;
            f.offset_known = extract_offset(v, &off, &is_static) ? 1 : 0;
            f.offset = off;
          } else {
            is_static = true;
          }
          // A static member's address lives in DW_AT_location as DW_OP_addr.
          if (is_static && die.attr(aat::kLocation, v) && v.has_block && !v.block.empty() &&
              v.block.data()[0] == 0x03 /* DW_OP_addr */) {
            std::uint64_t a = 0;
            util::Cursor ac(v.block.data() + 1, v.block.size() - 1, h.endian);
            if (ac.read_uint(h.address_size, a)) {
              f.offset = a;
              f.offset_known = 1;
            }
          }
          f.is_static = static_cast<std::uint8_t>(is_static ? 1 : 0);
          if (die.attr(aat::kArtificial, v)) f.is_artificial = 1;
          // Members carry a declaration site too, so tree output can print the
          // line a field came from rather than guessing it from the class.
          lines.resolve(die, h, static_cast<std::uint32_t>(st.units), model, f.prov);
          if (die.attr(aat::kBitSize, v)) {
            f.is_bitfield = 1;
            f.bit_size = v.u64;
            if (die.attr(aat::kBitOffset, v)) {
              f.bit_offset = static_cast<std::uint32_t>(v.u64);
            }
          }
          const std::uint32_t field_index = static_cast<std::uint32_t>(model.fields.size());
          model.fields.push_back(f);
          ++st.fields;
          pr.add("Fields");
          if (die.attr(aat::kType, v)) {
            pending.push_back(
                {Slot::kField, field_index, static_cast<std::uint32_t>(v.u64), h.offset});
          }
          break;
        }
        case tag::kEnumerator: {
          if (cur_enum < 0) break;
          EnumMember em;
          if (die.attr(aat::kName, v)) {
            em.name_off = name_off_of(lines, model, v, h);
          }
          if (die.attr(aat::kConstValue, v)) em.value = v.i64;
          model.enum_members.push_back(em);
          ++st.enumerators;
          break;
        }
        case tag::kInheritance: {
          if (cur_class < 0) break;
          if (die.attr(aat::kType, v)) {
            pending.push_back({Slot::kClassBase, static_cast<std::uint32_t>(cur_class),
                               static_cast<std::uint32_t>(v.u64), h.offset});
          }
          break;
        }
        case tag::kSubprogram: {
          // An out-of-line definition points back at its in-class declaration
          // with DW_AT_specification; that is where the code address lives.
          // Both attributes mean "this definition stands in for that other DIE":
          // DW_AT_specification for a plain out-of-line member function, and
          // DW_AT_abstract_origin for inlined or virtual ones.
          if ((die.attr(aat::kSpecification, v) || die.attr(aat::kAbstractOrigin, v)) &&
              dwarf::is_unit_relative_ref(v.form)) {
            SpecFix fix;
            fix.target = h.offset + v.u64;
            if (die.attr(aat::kLowPc, v)) fix.addr = lines.low_pc(v, h);
            {
              std::uint64_t high = 0;
              if (die.attr(aat::kHighPc, v) && lines.high_pc(v, h, fix.addr, high) && high > fix.addr) {
                fix.size = high - fix.addr;
              }
            }
            // The concrete DIE's own file and line: this is the out-of-line
            // definition, which lives in the .cpp while the declaration lives
            // in the header.
            lines.resolve(die, h, static_cast<std::uint32_t>(st.units), model, fix.def);
            // A strp is taken as is (even offset 0, as before); an indexed
            // string only counts when it resolved, so an unresolvable name
            // falls through to the linkage name instead of masking it.
            if (die.attr(aat::kName, v) &&
                (v.form == form::kStrp || v.form == form::kString || lines.str_offset(v, h) != 0)) {
              fix.name_off = name_off_of(lines, model, v, h);
            } else if (die.attr(aat::kLinkageName, v) &&
                       (v.form == form::kStrp || v.form == form::kString || lines.str_offset(v, h) != 0)) {
              fix.name_off = name_off_of(lines, model, v, h);
              fix.name_is_ref = 1;
            }
            if (fix.addr != 0 || fix.name_off != 0) spec_fixes.push_back(fix);
            break;
          }
          // A namespace-scope subprogram is not a class member, so it has no
          // Method to go into. It still needs recording: it is the only thing
          // that puts its declaring header (clampf in math.h) into Model::paths,
          // and the emitter needs to know whether the function exists out of
          // line or only inlined.
          if (cur_class < 0) {
            FreeFunction ff;
            if (die.attr(aat::kName, v)) ff.name_off = name_off_of(lines, model, v, h);
            if (die.attr(aat::kLinkageName, v)) ff.linkage_off = name_off_of(lines, model, v, h);
            if (die.attr(aat::kArtificial, v)) ff.is_artificial = 1;
            if (die.attr(aat::kLowPc, v)) {
              ff.addr = lines.low_pc(v, h);
              ff.has_range = 1;
              if (die.attr(aat::kHighPc, v) && v.u64 > ff.addr) ff.size = v.u64 - ff.addr;
            }
            lines.resolve(die, h, static_cast<std::uint32_t>(st.units), model, ff.decl);
            if (ff.name_off != 0 || ff.linkage_off != 0) model.free_functions.push_back(ff);
            break;
          }
          Method m;
          if (die.attr(aat::kName, v)) m.name_off = name_off_of(lines, model, v, h);
          if (die.attr(aat::kLinkageName, v)) m.linkage_off = name_off_of(lines, model, v, h);
          if (die.attr(aat::kLowPc, v)) m.addr = lines.low_pc(v, h);
          // DW_AT_high_pc is an offset from low_pc in DWARF 4 and an absolute
          // address in DWARF 5; lines.high_pc resolves which. Only a real range
          // is recorded: an inlined function has no code, and reporting that as
          // "no-range" is the honest answer.
          {
            std::uint64_t high = 0;
            if (die.attr(aat::kHighPc, v) && lines.high_pc(v, h, m.addr, high) && high > m.addr) {
              m.size = high - m.addr;
              m.has_range = 1;
            }
          }
          // Declaration site. m.def is filled in from the out-of-line definition.
          lines.resolve(die, h, static_cast<std::uint32_t>(st.units), model, m.decl);
          if (die.attr(aat::kVirtuality, v)) m.is_virtual = v.u64 != 0 ? 1 : 0;
          if (die.attr(aat::kArtificial, v)) m.is_artificial = 1;
          if (die.attr(aat::kExternal, v) && v.u64 == 0) m.is_static = 1;
          if (die.attr(aat::kAccessibility, v)) {
            m.access = static_cast<std::uint8_t>(v.u64);
          }
          const std::string_view nm = model.name(m.name_off);
          if (nm == ".ctor" || nm == "C1" || nm == "C2") m.is_ctor = 1;

          m.first_param = static_cast<std::uint32_t>(model.params.size());
          const std::int32_t mi = static_cast<std::int32_t>(model.methods.size());
          model.methods.push_back(m);
          if (die.attr(aat::kType, v)) {
            pending.push_back({Slot::kMethodRet, static_cast<std::uint32_t>(mi),
                               static_cast<std::uint32_t>(v.u64), h.offset});
          }
          model.classes[static_cast<std::size_t>(cur_class)].method_count++;
          cur_method = mi;
          cur_method_first_param = m.first_param;
          method_depth = depth;
          decl_by_offset.emplace(h.offset + die.offset(), static_cast<std::uint32_t>(mi));
          ++st.methods;
          pr.add("Methods");
          break;
        }
        case tag::kFormalParameter: {
          if (cur_method < 0) break;
          // Compiler-generated parameters (the implicit `this`, vtable
          // helpers) are not part of the source-level signature.
          if (die.attr(aat::kArtificial, v) && v.u64 != 0) break;
          Param prm;
          if (die.attr(aat::kName, v)) {
            prm.name_off = name_off_of(lines, model, v, h);
          }
          // Push first, then queue the reference against the real index:
          // computing size()-1 before the push underflows on the first param.
          const auto pi = static_cast<std::uint32_t>(model.params.size());
          model.params.push_back(prm);
          if (die.attr(aat::kType, v)) {
            pending.push_back(
                {Slot::kParam, pi, static_cast<std::uint32_t>(v.u64), h.offset});
          }
          ++st.params;
          break;
        }
        case tag::kVariable: {
          // A DWARF 5 static data member arrives as a DW_TAG_variable child of
          // the class DIE rather than as the DW_TAG_member (with no
          // DW_AT_data_member_location) that DWARF 4 emits. Recognise it by being
          // a direct child of an open aggregate, and turn it into exactly the
          // Field the DWARF 4 path builds so both dumps agree. Everything else
          // -- variables at namespace or CU scope, function locals -- keeps the
          // symbol-table join below.
          if (cur_class >= 0 && !open.empty() && open.back().depth + 1 == depth) {
            AttrValue decl_attr;
            if (die.attr(aat::kDeclaration, decl_attr)) {
              Field f;
              if (die.attr(aat::kName, v)) f.name_off = name_off_of(lines, model, v, h);
              f.is_static = 1;
              // A class-scope declaration has no DW_AT_location; only a definition
              // carries the address, so offset_known stays 0 here exactly as it
              // does for a DWARF 4 static member.
              // The DWARF 5 spelling carries the same DW_AT_artificial and the same
              // declaration site as the DWARF 4 DW_TAG_member does, so both must be
              // read here or the two versions disagree about _vtable$ and about
              // which line instances_ was declared on.
              if (die.attr(aat::kArtificial, v)) f.is_artificial = 1;
              lines.resolve(die, h, static_cast<std::uint32_t>(st.units), model, f.prov);
              const std::uint32_t field_index = static_cast<std::uint32_t>(model.fields.size());
              model.fields.push_back(f);
              ++st.fields;
              pr.add("Fields");
              if (die.attr(aat::kType, v)) {
                pending.push_back(
                    {Slot::kField, field_index, static_cast<std::uint32_t>(v.u64), h.offset});
              }
              break;
            }
          }
          // A variable that could correspond to a symbol-table global. Static
          // members are DW_TAG_member and function locals have no symbol, but
          // the depth is not fixed: a variable inside `namespace game` sits at
          // depth 2 while one at CU scope sits at depth 1, and both can own a
          // symbol. What distinguishes a joinable variable is the presence of
          // DW_AT_linkage_name, which locals and members never carry.
          AttrValue lv;
          if (!die.attr(aat::kLinkageName, lv)) break;
          // DWARF 5 spells the linkage name with DW_FORM_strx*, so the form
          // cannot be assumed to be strp; lines.string_of handles both.
          const std::string ln = lines.linkage_name(lv, h);
          if (ln.empty()) break;
          Provenance prov;
          if (!lines.resolve(die, h, static_cast<std::uint32_t>(st.units), model, prov)) {
            break;
          }
          // First definition wins: a redeclaration later in the same CU adds
          // nothing, and picking the last would make the answer depend on order.
          var_prov.emplace(ln, prov);
          ++st.variables_with_prov;
          break;
        }
        case tag::kSubrangeType: {
          // The first child of an array_type carries the element count.
          if (open.empty()) break;
          const Open& parent = open.back();
          if (parent.node >= model.types.size()) break;
          if (model.types[parent.node].kind != TypeKind::kArray) break;
          std::uint64_t count = 0;
          if (die.attr(aat::kCount, v)) {
            count = v.u64;
          } else if (die.attr(aat::kUpperBound, v)) {
            count = v.i64 >= 0 ? static_cast<std::uint64_t>(v.i64) + 1 : 0;
          }
          if (count != 0) model.types[parent.node].count = count;
          break;
        }
        default:
          break;
      }
    }

    // Close anything still open at end of unit.
    while (!open.empty()) {
      const Open& o = open.back();
      if (o.cls >= 0) {
        model.classes[static_cast<std::size_t>(o.cls)].field_count =
            static_cast<std::uint32_t>(model.fields.size()) - o.first;
      } else if (o.enm >= 0) {
        model.enums[static_cast<std::size_t>(o.enm)].member_count =
            static_cast<std::uint32_t>(model.enum_members.size()) - o.first;
      }
      open.pop_back();
    }
    ++st.units;
    pr.add("Units");
  }

  // Most member functions were inlined by the compiler, so DWARF holds only the
  // declaration and never a concrete DIE to read an address from. The mangled
  // linkage name is the join key: the linker kept a symbol for every out-of-line
  // copy, and that symbol carries the address.
  {
    std::unordered_map<std::string_view, std::uint64_t> by_name;
    for (const elf::Symbol& sym : ctx.elf().symbols()) {
      if (sym.value != 0 && !sym.name.empty()) by_name.emplace(sym.name, sym.value);
    }
    pr.declare("Methods", model.methods.size());
    pr.set("Methods", 0);
    for (Method& m : model.methods) {
      if (m.addr != 0 || m.linkage_off == 0) continue;
      // linkage_off is biased like every other name offset, so un-bias before
      // reading it as a raw .debug_str offset.
      const std::string_view mangled =
          m.linkage_off == Model::kNoName ? std::string_view()
                                          : ctx.str_at(m.linkage_off - 1);
      if (mangled.empty()) continue;
      const auto it = by_name.find(mangled);
      if (it != by_name.end()) {
        m.addr = it->second;
        ++st.methods_with_addr;
      }
    }
  }

  pr.declare("Units", st.units);
  pr.set("DIEs", st.dies);
  pr.primary("DIEs");
  pr.stage("Resolving types");
  pr.checkpoint();

  // Fold the out-of-line definitions into their declarations: this is what
  // gives every member function a code address, and a mangled name when the
  // declaration is anonymous (clang emits the linkage name on the definition).
  for (const SpecFix& fix : spec_fixes) {
    const auto it = decl_by_offset.find(fix.target);
    if (it == decl_by_offset.end()) {
      // The declaration this definition names lives in a *different* compilation
      // unit than the one whose copy of the class survived deduplication, so
      // there is no Method to fold it into. Dropping it would lose a real
      // out-of-line definition and, with it, the only proof that the .cpp exists.
      // Record it on its own instead: tree output can place it in its definition
      // file, and the flat emitter ignores this list so its output is unchanged.
      if (fix.addr != 0) {
        ir::OutOfLineDef od;
        od.name_off = fix.name_off;
        od.addr = fix.addr;
        od.size = fix.size;
        od.has_range = fix.size != 0;
        od.def = fix.def;
        model.out_of_line_defs.push_back(od);
      }
      continue;
    }
    ir::Method& m = model.methods[it->second];
    if (fix.addr != 0) m.addr = fix.addr;
    // The concrete DIE is where the code actually is, so its range is the one
    // worth reporting -- and it is only a range at all if DWARF gave one.
    if (fix.size != 0) {
      m.size = fix.size;
      m.has_range = 1;
    }
    // Only overwrite the declaration's own site when this definition resolved,
    // so an unresolvable definition leaves the header's location standing
    // rather than blanking it.
    if (fix.def.file_id != 0 || fix.def.line != 0) m.def = fix.def;
    if (fix.name_off != 0 && (m.name_off == 0 || fix.name_is_ref != 0)) {
      m.name_off = fix.name_off;
    }
    ++st.methods_with_addr;
  }

  model.total_units = st.units;
  model.total_dies = st.dies;

  // ------------------------------------------------------------------ pass B --
  // Resolve every recorded DW_AT_type into a node index. The reference is
  // relative to the start of the unit that contains it, so the unit offset is
  // added back before the offset->type lookup.
  pr.declare("Types", pending.size());
  pr.set("Types", 0);
  pr.checkpoint();
  for (const Pending& p : pending) {
    pr.add("Types");
    const auto abs = static_cast<std::uint32_t>(p.unit_off + p.target);
    const std::uint32_t node = model.lookup_type(abs);
    if (node == kNoType) {
      ++st.unresolved_refs;
      continue;
    }
    switch (p.slot) {
      case Slot::kType: model.types[p.index].elem = node; break;
      case Slot::kField: model.fields[p.index].type = node; break;
      case Slot::kClassBase: model.classes[p.index].base = node; break;
      case Slot::kMethodRet: model.methods[p.index].ret_type = node; break;
      case Slot::kParam: model.params[p.index].type = node; break;
    }
  }

  // Collapse redeclarations first: a field's type reference may land on a
  // declaration-only DIE, and dedup is what tells us the real size.
  model.deduplicate();

  // Compute every size now that the graph is complete.
  pr.stage("Deduplicating");
  pr.checkpoint();
  pr.stage("Sizing types");
  pr.declare("Types", model.types.size());
  pr.set("Types", 0);
  for (std::uint32_t i = 0; i < model.types.size(); ++i) {
    model.size_of(i);
    pr.add("Types");
  }
  for (Field& f : model.fields) {
    if (!f.offset_known && !f.is_static) ++model.fields_unknown_offset;
  }

  // A union whose DWARF byte_size is absent is as large as its widest member.
  for (ClassDef& cd : model.classes) {
    if (cd.size != 0 || cd.kind != 2) continue;
    std::uint64_t widest = 0;
    const std::uint32_t end = cd.first_field + cd.field_count;
    for (std::uint32_t i = cd.first_field; i < end && i < model.fields.size(); ++i) {
      const std::uint64_t s = model.size_of(model.fields[i].type);
      if (s > widest) widest = s;
    }
    if (widest != 0) cd.size = widest;
  }

  pr.stage("Reading symbols");
  // ---------------------------------------------------------------- symbols --
  //
  // A static data member has no DW_AT_location; its address comes from the
  // symbol table, whose Itanium encoding stores the class and member as
  // adjacent length-prefixed components ("4Vec33ZERO"). Recovering them lets the
  // emitter print a real RVA instead of a placeholder.
  {
    for (const elf::Symbol& sym : ctx.elf().symbols()) {
      if (sym.type() != static_cast<std::uint8_t>(elf::StT::kObject)) continue;
      if (sym.value == 0 || sym.name.size() < 4 || sym.name.compare(0, 3, "_ZN") != 0) continue;
      // Parse _ZN <len><name><len><name>... and keep the final two components.
      std::vector<std::string_view> parts;
      std::size_t i = 3;
      bool ok = true;
      while (i < sym.name.size() && ok) {
        std::size_t j = i;
        while (j < sym.name.size() && std::isdigit(static_cast<unsigned char>(sym.name[j]))) ++j;
        if (j == i || j - i > 4) { ok = false; break; }
        const std::size_t len = static_cast<std::size_t>(std::strtoul(sym.name.substr(i, j - i).c_str(), nullptr, 10));
        if (j + len > sym.name.size()) { ok = false; break; }
        parts.emplace_back(sym.name.data() + j, len);
        i = j + len;
        // A trailing access-specifier letter ends the symbol.
        if (i < sym.name.size() && (sym.name[i] == 'E' || sym.name[i] == 'F' ||
                                    sym.name[i] == 'A' || sym.name[i] == 'B')) {
          break;
        }
      }
      if (ok && parts.size() >= 2) {
        std::string key(parts[parts.size() - 2]);
        key.append(parts[parts.size() - 1]);
        model.static_syms.emplace(std::move(key), sym.value);
      }
    }
  }

  // Functions and globals come from the symbol table: it has authoritative
  // names, addresses and sizes, and covers objects that have no DWARF DIE of
  // their own.
  std::uint64_t gl_with_prov_total = 0;
  if (opts.symbols) {
    const auto& syms = ctx.elf().symbols();
    model.functions.reserve(syms.size() / 2);
    model.globals.reserve(syms.size() / 4);
    std::uint64_t fn = 0, gl = 0;
    for (const elf::Symbol& s : syms) {
      if (s.name.empty() || s.value == 0) continue;
      switch (static_cast<elf::StT>(s.type())) {
        case elf::StT::kFunc: {
          FunctionDef f;
          f.name_off = model.arena_add(s.name);
          f.addr = s.value;
          f.size = s.size;
          model.functions.push_back(f);
          ++fn;
          break;
        }
        case elf::StT::kObject: {
          GlobalDef g;
          g.name_off = model.arena_add(s.name);
          g.addr = s.value;
          g.size = s.size;
          // Attach the declaration site when a DWARF DIE names this symbol. The
          // symbol table is authoritative for name and address, DWARF only for
          // where it was written, so a symbol with no DIE keeps the zero default
          // rather than borrowing another object's location.
          const auto pv = var_prov.find(s.name);
          if (pv != var_prov.end()) {
            g.prov = pv->second;
            ++gl_with_prov_total;
          }
          model.globals.push_back(g);
          ++gl;
          break;
        }
        default:
          break;
      }
    }
    STELLAR_DEBUG("symbols: %llu functions, %llu globals", static_cast<unsigned long long>(fn),
              static_cast<unsigned long long>(gl));
  }

  // Count definitions that carry no DWARF name; the emitter needs to know.
  for (const ClassDef& cd : model.classes) {
    if (cd.name_off == 0) ++model.unnamed_classes;
  }

  model.methods_count = st.methods;
  model.params_count = st.params;
  for (const ClassDef& c : model.classes) {
    if (c.base != kNoType) ++model.classes_with_bases;
  }
  st.globals_with_prov = gl_with_prov_total;
  st.decl_file_unresolved = lines.unresolved();
  st.line_headers_parsed = lines.headers_parsed();
  st.seconds = diag::seconds_since(t_start);
  if (stats != nullptr) *stats = st;
  return true;
}

}  // namespace stellar::ir

namespace stellar::ir {

// ---------------------------------------------------------------------------
// Dwarfless mode
//
// A stripped binary has no DIE stream, so there is nothing to reconstruct
// types from. What it does still contain is the information the loader itself
// needs, and all of it is authoritative for a *different* question:
//
//   .eh_frame    every function's exact [start, end) range
//   .dyn/.symtab  names for whatever the toolchain exported
//   .data.rel.ro  vtable and RTTI arrays, which name classes and their method
//                 tables without any debug info
//
// Field offsets and field types are NOT recoverable this way, and this function
// does not pretend otherwise: the model is left with no field data and the
// emitter marks the result as inferred.
// ---------------------------------------------------------------------------

namespace {

/// Minimal Itanium name reader: pulls the class path out of a mangled name so a
/// vtable/typeinfo pair can be attributed to a class. Returns an empty string
/// when the name is not a recognisable `_ZN` encoding.
std::string mangled_class_path(std::string_view name) {
  // Accepts a full symbol (`_ZN7cocos2d4Vec34ZEROE`) or a vtable/typeinfo symbol
  // (`_ZTVN7cocos2d4Vec3E`), and returns the class path it encodes.
  if (name.size() >= 4 && (name.compare(0, 4, "_ZTV") == 0 ||
                           name.compare(0, 4, "_ZTI") == 0 ||
                           name.compare(0, 4, "_ZTS") == 0)) {
    name.remove_prefix(4);
  } else if (name.size() >= 3 && name.compare(0, 3, "_ZN") == 0) {
    name.remove_prefix(3);
  }
  std::size_t i = 0;
  if (i < name.size() && name[i] == 'N') ++i;  // nested-name marker

  std::string out;
  bool any = false;
  while (i < name.size()) {
    // `St` is the substitution for std:: and, unlike every other component, it
    // carries no length prefix. Without it every standard-library type fails to
    // resolve, which is most of the vtable population.
    if (i + 1 < name.size() && name[i] == 'S' && name[i + 1] == 't') {
      if (any) out += "::";
      out += "std";
      any = true;
      i += 2;
      continue;
    }
    std::size_t j = i;
    while (j < name.size() && name[j] >= '0' && name[j] <= '9') ++j;
    if (j == i || j - i > 3) break;  // not a length prefix: end of the path
    std::size_t len = 0;
    for (std::size_t k = i; k < j; ++k) len = len * 10 + static_cast<std::size_t>(name[k] - '0');
    if (len == 0 || j + len > name.size()) break;
    if (any) out += "::";
    out.append(name.substr(j, len));
    any = true;
    i = j + len;
    // A trailing access specifier, or the start of a template argument list,
    // ends the class path.
    if (i < name.size()) {
      const char c = name[i];
      if (c == 'E' || c == 'F' || c == 'A' || c == 'B' || c == 'C' || c == 'D' ||
          c == 'I') {
        break;
      }
    }
  }
  return any ? out : std::string();
}

}  // namespace

bool build_dwarfless_model(DwarfContext& ctx, Model& model, DwarflessStats* stats) {
  const auto t_start = diag::Clock::now();
  auto& pr = diag::progress();
  pr.stage("dwarfless");
  pr.declare("FDEs", 0, false);
  pr.declare("Functions", 0, false);
  pr.declare("Globals", 0, false);
  pr.declare("Classes", 0, false);
  DwarflessStats st;
  model.string_self = &ctx;
  model.string_fn = &str_thunk;
  model.inferred = true;

  const elf::ElfFile& elf = ctx.elf();

  // --- functions: .eh_frame gives every range, the symbol table names them ---
  std::unordered_map<std::uint64_t, const elf::Symbol*> by_addr;
  by_addr.reserve(elf.symbols().size() * 2);
  for (const elf::Symbol& s : elf.symbols()) {
    if (s.value == 0) continue;
    if (s.type() == static_cast<std::uint8_t>(elf::StT::kFunc) ||
        s.type() == static_cast<std::uint8_t>(elf::StT::kGnuIfunc)) {
      by_addr.emplace(s.value, &s);
    }
  }

  dwarf::EhFrameStats est;
  const std::vector<dwarf::FdeRange> fdes =
      dwarf::parse_eh_frame(ctx.sections().view(dwarf::Sec::kEhFrame),
                            ctx.sections().section_addr(dwarf::Sec::kEhFrame), &est);
  st.fdes = fdes.size();
  model.functions.reserve(fdes.size());

  pr.set("FDEs", fdes.size());
  for (const dwarf::FdeRange& f : fdes) {
    pr.add("FDEs");
    FunctionDef d;
    auto it = by_addr.find(f.start);
    if (it != by_addr.end() && !it->second->name.empty()) {
      d.name_off = model.arena_add(it->second->name);
      d.named = 1;
      ++st.functions_named;
    } else {
      // Unnamed: the address is the only stable identifier, so it becomes the
      // name. This is the `sub_<addr>` convention used by IDA and Ghidra.
      char buf[32];
      std::snprintf(buf, sizeof(buf), "sub_%llx",
                    static_cast<unsigned long long>(f.start));
      d.name_off = model.arena_add(buf);
      ++st.functions_sub_;
    }
    d.addr = f.start;
    d.size = f.size;
    model.functions.push_back(d);
  }

  // --- globals from the symbol table ---
  for (const elf::Symbol& s : elf.symbols()) {
    if (s.name.empty() || s.value == 0) continue;
    if (s.type() != static_cast<std::uint8_t>(elf::StT::kObject)) continue;
    pr.add("Globals");
    GlobalDef g;
    g.name_off = model.arena_add(s.name);
    g.addr = s.value;
    g.size = s.size;
    model.globals.push_back(g);
    ++st.globals;
  }

  // --- vtable symbols give class names and method tables ---
  // A `_ZTV<name>` symbol marks a vtable; its size divided by the pointer size
  // is the slot count, which is a real, derived fact about the class.
  const std::uint64_t ptr = 8;
  for (const elf::Symbol& s : elf.symbols()) {
    if (s.name.empty() || s.value == 0) continue;
    if (s.name.compare(0, 4, "_ZTV") != 0) continue;
    const std::string path = mangled_class_path(s.name.substr(4));
    if (path.empty() || s.size < ptr) continue;
    ClassDef cd;
    // Names live in the symbol arena, not .debug_str; record both so the
    // emitter can print either.
    cd.name_off = model.arena_add(path);
    cd.from_arena = 1;
    cd.size = s.size;
    cd.vtable_addr = s.value;
    // The first two words of a vtable are the header (offset-to-top and the
    // typeinfo pointer), not virtual functions. Excluding them is what makes
    // the count comparable with other dumpers: e.g. 205 words -> 203, of which
    // 201 are real slots once the header is removed.
    cd.vtable_words = s.size / ptr;
    cd.vtable_slots = cd.vtable_words > 2 ? cd.vtable_words - 2 : 0;
    model.classes.push_back(cd);
    ++st.classes_from_rtti;
    st.vtable_slots += cd.vtable_slots;
  }

  st.seconds = diag::seconds_since(t_start);
  if (stats != nullptr) *stats = st;
  return true;
}

}  // namespace stellar::ir
