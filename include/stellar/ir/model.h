// SPDX-License-Identifier: MIT
// The whole-program intermediate representation and its accessors.
//
// Design constraints taken from the real target: 3.5M type-defining DIEs,
// 456k struct/class/union definitions, 369k members, 728k typedefs. Anything
// pointer-heavy or per-DIE-node would be fatal, so the model is a set of flat
// vectors addressed by 32-bit indices:
//
//   * strings are stored as .debug_str offsets, never copied
//   * type graphs use u32 "elem" indices instead of pointers
//   * every hot structure is contiguous and reserve()d up front
//
// The model can therefore be emitted long after the ELF mapping is gone.
#pragma once

#include <cstdint>
#include <cstring>
#include <string>
#include <string_view>
#include <unordered_map>
#include <vector>

#include "stellar/dwarf/constants.h"

namespace stellar::ir {

/// Sentinel for "no referenced type".
inline constexpr std::uint32_t kNoType = 0xFFFFFFFFu;

enum class TypeKind : std::uint8_t {
  kUnknown = 0,
  kBase,         ///< base_type
  kPointer,      ///< pointer_type
  kLRef,         ///< reference_type
  kRRef,         ///< rvalue reference (DWARF5 0x42; folded into kLRef in DWARF4)
  kConst,        ///< const_type
  kVolatile,     ///< volatile_type
  kRestrict,     ///< restrict_type
  kAtomic,       ///< atomic_type
  kArray,        ///< array_type
  kTypedef,      ///< typedef (keeps its own name; transparent for size)
  kStruct,       ///< structure_type
  kClass,        ///< class_type
  kUnion,        ///< union_type
  kEnum,         ///< enumeration_type
  kFunction,     ///< subroutine_type
  kUnspecified,  ///< no DWARF type information available
};

/// One node of the reconstructed type graph.
struct Type {
  TypeKind kind = TypeKind::kUnknown;
  /// .debug_str offset of this type's DW_AT_name (0 when unnamed).
  std::uint32_t name_off = 0;
  /// Index of the referenced type, or kNoType.
  std::uint32_t elem = kNoType;
  /// Size in bytes; 0 means "not stated by DWARF and not inferred".
  std::uint64_t size = 0;
  /// Array element count; 0 means unspecified.
  std::uint64_t count = 0;
  /// base_type DW_AT_encoding.
  std::uint8_t encoding = 0;
  /// Index into Model::classes or Model::enums, depending on kind.
  std::int32_t def = -1;
  /// Set once size_of() has computed a size for this node.
  std::uint8_t size_done = 0;
  /// True when this node is transparent for naming (qualifiers, typedefs).
  std::uint8_t transparent = 0;
};

/// Provenance of a definition: where in the source it was declared.
///
/// `file_id` indexes Model::paths; 0 means "not stated by DWARF", never a
/// guess. `line` is DW_AT_decl_line and 0 when the attribute is absent.
/// `cu` is the index of the compilation unit the DIE belongs to, which is what
/// makes `file_id` meaningful: DW_AT_decl_file is an index into *that* unit's
/// line-header file table, and the numbering differs between DWARF versions.
struct Provenance {
  std::uint32_t file_id = 0;  ///< Model::paths index; 0 = unknown
  std::uint32_t line = 0;     ///< DW_AT_decl_line; 0 = unknown
  std::uint32_t cu = 0;       ///< compilation unit index
};

/// A data member of a struct/class/union.
struct Field {
  std::uint32_t name_off = 0;
  std::uint32_t type = kNoType;
  std::uint64_t offset = 0;
  /// False when DWARF only gives an expression (e.g. a base-relative offset).
  std::uint8_t offset_known = 0;
  /// True for a static member (no instance offset).
  std::uint8_t is_static = 0;
  /// True for a bitfield.
  std::uint8_t is_bitfield = 0;
  std::uint64_t bit_size = 0;
  std::uint32_t bit_offset = 0;
  /// DW_AT_artificial: a compiler-synthesised member such as _vptr$X. It occupies
  /// a real offset but is not source, so a source-shaped emitter must skip it.
  std::uint8_t is_artificial = 0;
  /// Where the member was declared, for a line number in tree output.
  Provenance prov;
};

/// One formal parameter of a method.
struct Param {
  std::uint32_t name_off = 0;
  std::uint32_t type = kNoType;
};

/// A method (DW_TAG_subprogram that is a member of a class).
struct Method {
  std::uint32_t name_off = 0;
  std::uint32_t ret_type = kNoType;
  std::uint32_t first_param = 0;
  std::uint32_t param_count = 0;
  /// Low PC: the function's runtime address, which the dump reports as RVA.
  std::uint64_t addr = 0;
  /// Length in bytes, from DW_AT_high_pc. Zero when the debug info gave no code
  /// range -- which is the normal case for an inlined function, and is not the
  /// same as "length zero". `has_range` tells the two apart so a caller can say
  /// "no-range" instead of disassembling zero bytes.
  std::uint64_t size = 0;
  std::uint8_t has_range = 0;
  std::uint8_t is_virtual = 0;     ///< DW_AT_virtuality != 0
  std::uint8_t is_static = 0;      ///< DW_AT_external == 0
  std::uint8_t is_ctor = 0;
  std::uint8_t is_artificial = 0;  ///< DW_AT_artificial (compiler generated)
  /// DW_AT_accessibility: 1 public, 2 protected, 3 private.
  std::uint8_t access = 1;
  /// .debug_str offset of DW_AT_linkage_name (the mangled name). Most member
  /// functions have no concrete DIE in the debug info at all -- the compiler
  /// inlined them -- so the mangled name is what ties the declaration to a real
  /// symbol, and therefore to a real address.
  std::uint32_t linkage_off = 0;
  /// Where the in-class declaration was written. `file_id` 0 and `line` 0 when
  /// DWARF does not state them.
  Provenance decl;
  /// Where the out-of-line definition was written, reached through
  /// DW_AT_specification / DW_AT_abstract_origin. Stays zero when the function
  /// has no concrete DIE (it was inlined away), which is not the same as "the
  /// definition is in the declaration's file".
  Provenance def;
};

/// A struct, class or union definition.
struct ClassDef {
  std::uint32_t name_off = 0;
  std::uint64_t size = 0;
  std::uint32_t first_field = 0;
  std::uint32_t field_count = 0;
  /// 0 = struct, 1 = class, 2 = union.
  std::uint8_t kind = 0;
  /// Index of the base-class Type, or kNoType.
  std::uint32_t base = kNoType;
  std::uint32_t first_method = 0;
  std::uint32_t method_count = 0;
  /// Set in dwarfless mode, where the name lives in the string arena and the
  /// "layout" is really a vtable's address and slot count rather than fields.
  std::uint8_t from_arena = 0;
  std::uint64_t vtable_addr = 0;
  std::uint64_t vtable_words = 0;  ///< total words, including the 2-word header
  std::uint64_t vtable_slots = 0;  ///< words - 2, i.e. real virtual entries
  /// Set by deduplicate(): a redeclaration of a type we already emitted.
  /// Indices stay valid; the emitter just skips hidden entries.
  std::uint8_t hidden = 0;
  /// Where this definition was declared. Vtable-derived entries (from_arena)
  /// have no DIE and keep the zero default.
  Provenance prov;
};

/// One enumerator.
struct EnumMember {
  std::uint32_t name_off = 0;
  std::int64_t value = 0;
};

/// An enumeration definition.
struct EnumDef {
  std::uint32_t name_off = 0;
  std::uint64_t size = 0;
  std::uint32_t first_member = 0;
  std::uint32_t member_count = 0;
  std::uint8_t hidden = 0;
  /// DW_AT_enum_class: a scoped enum. The enumerator names carry no class prefix
  /// in DWARF, so this flag is the only way to tell `Shape.kCircle` from
  /// `kCircle`.
  std::uint8_t is_enum_class = 0;
  /// Where this definition was declared.
  Provenance prov;
};

/// A function that is not a class member: a free function or a static member of
/// namespace scope. These were previously dropped by the builder, which meant
/// their declaring header (clampf in math.h) never reached Model::paths.
struct FreeFunction {
  std::uint32_t name_off = 0;
  std::uint32_t linkage_off = 0;
  std::uint64_t addr = 0;
  std::uint64_t size = 0;
  /// True when the DWARF gave a code range: the function exists out of line.
  /// False means it only ever existed inlined, which is not the same as the
  /// source being absent.
  std::uint8_t has_range = 0;
  std::uint8_t is_artificial = 0;
  Provenance decl;
};

/// An out-of-line definition whose in-class declaration could not be paired
/// with it, because the declaration's copy of the class lives in a different
/// compilation unit than the one that survived deduplication.
///
/// Kept as its own record rather than dropped: it is real code at a real
/// address, and it is frequently the only evidence that a .cpp file exists at
/// all. The flat emitter does not read this list, so adding it cannot change
/// that output.
struct OutOfLineDef {
  /// Mangled name from DW_AT_linkage_name: the declaration that should have
  /// matched is gone, so this is the only identifier DWARF gave us.
  std::uint32_t name_off = 0;
  std::uint64_t addr = 0;
  std::uint64_t size = 0;
  std::uint8_t has_range = 0;
  /// Where this definition was written.
  Provenance def;
};

/// An emitted function.
struct FunctionDef {
  std::uint32_t name_off = 0;  ///< into the model's own string arena
  std::uint64_t addr = 0;
  std::uint64_t size = 0;
  /// Name came from the symbol table, rather than being synthesised as
  /// `sub_<addr>`.
  std::uint8_t named = 0;
};

/// An emitted global variable or object.
struct GlobalDef {
  std::uint32_t name_off = 0;  ///< into the model's own string arena
  std::uint64_t addr = 0;
  std::uint64_t size = 0;
  std::uint32_t type = kNoType;
  /// Where the variable was declared. Zero when the symbol has no matching DIE,
  /// which is the normal case: globals come from the symbol table, not DWARF.
  Provenance prov;
};

/// Whole-program model. Owns every array; referents are u32 indices.
class Model {
 public:
  /// Resolves a .debug_str offset to text. Injected so the model can be emitted
  /// long after the ELF mapping is gone.
  using StringFn = std::string_view (*)(void* self, std::uint32_t off);
  void* string_self = nullptr;
  StringFn string_fn = nullptr;

  [[nodiscard]] std::string_view str(std::uint32_t off) const {
    return string_fn != nullptr ? string_fn(string_self, off) : std::string_view();
  }

  /// The encoding used by every .debug_str-backed name field in the model.
  ///
  /// A name offset of 0 used to mean "no name", which is ambiguous: a real name
  /// can legitimately sit at .debug_str offset 0, and an unnamed DIE therefore
  /// read back whatever string happened to start the section -- an unnamed
  /// parameter printed as `update(float _ZN4game4Body6updateEf)`.
  ///
  /// So offsets are stored biased by one: 0 means "no name" and a real offset N
  /// is stored as N+1. Every read goes through name() so no call site can read a
  /// name_off directly and get the wrong answer.
  inline static constexpr std::uint32_t kNoName = 0;

  /// Encodes a raw .debug_str offset for storage.
  ///
  /// The stored value is `offset + 1`, so 0 can mean "no name". That makes raw
  /// offset 0 -- a name starting at the very first byte of .debug_str, which a
  /// producer is free to emit -- representable as 1 rather than colliding with
  /// the sentinel. An offset past the encodable range is reported as absent
  /// rather than wrapping around and naming the wrong string.
  [[nodiscard]] static std::uint32_t name_encode(std::uint64_t off) noexcept {
    if (off >= kArenaName) return kNoName;  // would not fit, or collides with the flag
    return static_cast<std::uint32_t>(off + 1);
  }

  /// Marks a `name_off` that indexes the model's own arena rather than .debug_str.
  ///
  /// DW_FORM_string carries a name's characters inline in the DIE instead of an
  /// offset into .debug_str, and GCC emits it for short names -- "E", "x" -- so
  /// there is no offset to store. Those bytes are interned (arena_add) and
  /// flagged with this bit, which keeps one field able to name a string from
  /// either space. A .debug_str that large is not a thing, so the bit is free.
  inline static constexpr std::uint32_t kArenaName = 0x80000000u;

  /// Encodes an arena offset for storage in a `name_off`.
  [[nodiscard]] static std::uint32_t name_encode_arena(std::uint32_t arena_off) noexcept {
    if (arena_off >= kArenaName) return kNoName;
    return kArenaName | arena_off;
  }

  /// The name stored in a biased `name_off`, or "" when the entity is unnamed.
  [[nodiscard]] std::string_view name(std::uint32_t biased) const {
    if (biased == kNoName) return {};
    if ((biased & kArenaName) != 0) return arena(biased & ~kArenaName);
    return str(biased - 1);
  }

  /// True when a biased `name_off` denotes a name.
  [[nodiscard]] static bool has_name(std::uint32_t biased) noexcept {
    return biased != kNoName;
  }
  /// Name of a class: .debug_str in DWARF mode, the string arena in dwarfless.
  [[nodiscard]] std::string_view class_name(const ClassDef& c) const {
    return c.from_arena != 0 ? arena(c.name_off) : name(c.name_off);
  }
  /// Appends a string to the model's own arena, returning its offset. Used for
  /// symbol names, which are not in .debug_str.
  std::uint32_t arena_add(std::string_view s);
  [[nodiscard]] std::string_view arena(std::uint32_t off) const {
    if (off >= arena_.size()) return {};
    const void* nul = std::memchr(arena_.data() + off, 0, arena_.size() - off);
    return nul == nullptr
               ? std::string_view()
               : std::string_view(arena_.data() + off,
                                  static_cast<const char*>(nul) - (arena_.data() + off));
  }

  // --- type graph -----------------------------------------------------------
  std::vector<Type> types;
  std::vector<Field> fields;
  std::vector<Method> methods;
  std::vector<Param> params;
  std::vector<ClassDef> classes;
  std::vector<EnumMember> enum_members;
  std::vector<EnumDef> enums;
  std::vector<FunctionDef> functions;
  /// Free and namespace-scope functions, with their declaration site.
  std::vector<FreeFunction> free_functions;
  /// Definitions whose declaration could not be paired; see OutOfLineDef.
  std::vector<OutOfLineDef> out_of_line_defs;
  std::vector<GlobalDef> globals;

  /// "ClassName" + "MemberName" -> address, built from Itanium-mangled data
  /// symbols. A static member's address lives in the symbol table, not in
  /// DWARF, so this is how their RVAs are recovered.
  std::unordered_map<std::string, std::uint64_t> static_syms;

  // --- source paths ----------------------------------------------------------
  //
  // Interned so that the 457k classes of the real target do not each own a copy
  // of the same handful of header paths. Index 0 is reserved as "unknown": the
  // empty string, never a real path, so that a missing DW_AT_decl_file is
  // distinguishable from a file genuinely named "".
  std::vector<std::string> paths;

  /// Interns `p` and returns its id, or the existing id. An empty path interns
  /// as 0 and always returns 0.
  std::uint32_t path_id(std::string_view p);

  /// The interned path, or "" for any id that is not in the table.
  [[nodiscard]] std::string_view path(std::uint32_t id) const {
    return id != 0 && id < paths.size() ? std::string_view(paths[id]) : std::string_view();
  }

  /// Open-addressed .debug_info offset -> type index, for DW_AT_type.
  std::vector<std::uint32_t> type_slots;
  std::uint32_t type_slot_mask = 0;

  // --- accessors ------------------------------------------------------------
  [[nodiscard]] bool is_aggregate(std::uint32_t t) const {
    return t < types.size() &&
           (types[t].kind == TypeKind::kStruct || types[t].kind == TypeKind::kClass ||
            types[t].kind == TypeKind::kUnion);
  }
  [[nodiscard]] bool is_defined(std::uint32_t t) const {
    if (t == kNoType || t >= types.size() || types[t].def < 0) return false;
    switch (types[t].kind) {
      case TypeKind::kStruct:
      case TypeKind::kClass:
      case TypeKind::kUnion:
        return static_cast<std::size_t>(types[t].def) < classes.size();
      case TypeKind::kEnum:
        return static_cast<std::size_t>(types[t].def) < enums.size();
      default: return true;
    }
  }

  /// Inserts offset->type. Returns false if the table is full.
  bool index_type(std::uint32_t offset, std::uint32_t type_index);
  /// Looks up the type node for a .debug_info offset, or kNoType.
  [[nodiscard]] std::uint32_t lookup_type(std::uint32_t offset) const {
    std::uint32_t i = hash32(offset) & type_slot_mask;
    for (;;) {
      const std::uint32_t v = type_slots[i];
      if (v == 0) return kNoType;  // empty slot: key absent
      if (type_keys[i] == offset) return v - 1;
      i = (i + 1) & type_slot_mask;
    }
  }
  void reserve_type_slots(std::size_t n);

  /// Collapses redeclarations: every compilation unit re-emits the types it
  /// references, so the same class appears many times. The entry with the most
  /// fields (then the largest size) wins; the rest are marked hidden.
  void deduplicate();

  /// Byte size of a type, inferring what DWARF does not state. Memoised in the
  /// type node itself, hence the mutable `done` flag.
  std::uint64_t size_of(std::uint32_t t, unsigned depth = 0) const;

  /// Peels typedefs/qualifiers to the underlying type node.
  [[nodiscard]] std::uint32_t strip(std::uint32_t t) const {
    unsigned guard = 0;
    while (t != kNoType && t < types.size() && types[t].transparent && guard++ < 64) {
      t = types[t].elem;
    }
    return t;
  }

  /// Renders a C#-style type name: "Vec3", "char[4]", "Rule*", "Foo&".
  [[nodiscard]] std::string type_name(std::uint32_t t) const;

  // --- statistics -----------------------------------------------------------
  std::uint64_t total_dies = 0;
  std::uint64_t total_units = 0;
  std::uint64_t unnamed_classes = 0;
  std::uint64_t fields_unknown_offset = 0;
  std::uint64_t duplicate_class_names = 0;
  std::uint64_t unique_enum_names = 0;
  // Dedup diagnostics: how much information the name-based collapse discards.
  std::uint64_t dedup_shadowed_classes = 0;  ///< definitions hidden
  std::uint64_t dedup_conflicting_names = 0; ///< names whose definitions disagreed
  std::uint64_t dedup_layout_conflicts = 0;  ///< ...and disagreed on byte size
  std::uint64_t dedup_field_conflicts = 0;   ///< ...and on field count
  // Same name, but declared at a different (file_id, line): two genuinely
  // distinct C++ types that the name-only key would have collapsed into one.
  std::uint64_t dedup_distinct_sites = 0;
  // Folded into a sibling that does have a declaration site. Not a conflict:
  // a redeclaration or a vtable-derived class carries no DW_AT_decl_file.
  std::uint64_t dedup_sited_merged = 0;
  // Finer split of the above: a redeclaration with zero members is just a
  // forward declaration, and collapsing it into the real definition loses
  // nothing. Two *non-empty* layouts under one name is a genuinely ambiguous
  // situation and is counted separately.
  std::uint64_t dedup_declared_only = 0;     ///< some redeclaration had 0 fields
  std::uint64_t dedup_layout_zero = 0;       ///< some redeclaration had size 0
  std::uint64_t dedup_real_field_conflict = 0; ///< two non-empty layouts differ
  std::uint64_t dedup_real_size_conflict = 0;  ///< two non-zero sizes differ
  std::uint64_t methods_count = 0;
  /// True when the model was built without DWARF: everything in it is inferred.
  bool inferred = false;
  std::uint64_t params_count = 0;
  std::uint64_t classes_with_bases = 0;
  std::uint64_t fields_padded = 0;  ///< synthesised to fill layout gaps

  /// A same-named definition set that did not agree with itself, kept for
  /// reporting via --list-conflicts.
  struct NameConflict {
    std::string name;
    std::uint8_t kind = 0;
    std::uint32_t min_fields = 0;
    std::uint32_t max_fields = 0;
    std::uint64_t min_size = 0;
    std::uint64_t max_size = 0;
    std::uint32_t declarations = 0;
  };
  std::vector<NameConflict> conflicts;

 private:
  static std::uint32_t hash32(std::uint32_t x) noexcept {
    x ^= x >> 16;
    x *= 0x7feb352du;
    x ^= x >> 15;
    x *= 0x846ca68bu;
    x ^= x >> 16;
    return x;
  }
  std::vector<char> arena_;
  std::vector<std::uint32_t> type_keys;  ///< parallel to type_slots
  /// path text -> id in Model::paths. Owns its keys: they must not be views into
  /// `paths`, whose elements move when the vector grows.
  std::unordered_map<std::string, std::uint32_t> path_index_;
};

enum class AggregateKind : std::uint8_t { kStruct, kClass, kUnion };

}  // namespace stellar::ir
