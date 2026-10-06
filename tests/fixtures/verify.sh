#!/bin/sh
# Check every claim in EXPECTED.md against two independent sources:
#
#   1. the fixture sources themselves (sed/grep, line by line)
#   2. the compiler's own view (llvm-dwarfdump / llvm-readelf)
#
# Stellar is never invoked. A dumper cannot testify that its own output is
# correct, and EXPECTED.md exists precisely to be an authority the dumper is
# measured against.
#
# Usage:  sh tests/fixtures/verify.sh
# Exit status is 0 only when every claim passed.
set -u

HERE=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
SRC="$HERE/src"
LIB="$HERE/lib"
TERMUX_BIN="${TERMUX_BIN:-/data/data/com.termux/files/usr/bin}"

READELF="$TERMUX_BIN/llvm-readelf"
DWARFDUMP="$TERMUX_BIN/llvm-dwarfdump"

PASS=0
FAIL=0

ok() { PASS=$((PASS + 1)); printf 'PASS  %s\n' "$1"; }
no() { FAIL=$((FAIL + 1)); printf 'FAIL  %s\n' "$1"; [ $# -gt 1 ] && printf '        %s\n' "$2"; }

for tool in "$READELF" "$DWARFDUMP"; do
  if [ ! -x "$tool" ]; then
    echo "verify.sh: missing $tool" >&2
    exit 2
  fi
done

# --- source-side helpers ------------------------------------------------------

# src_line <file> <n> -- echo the 1-based line n of a fixture source.
src_line() { sed -n "${2}p" "$SRC/$1"; }

# claim_src <label> <file> <line> <regex> -- the named source line must match.
claim_src() {
  _label=$1 _file=$2 _line=$3 _re=$4
  _got=$(src_line "$_file" "$_line")
  if printf '%s' "$_got" | grep -qE "$_re"; then
    ok "$_label"
  else
    no "$_label" "src/$_file:$_line is \"$_got\", expected /$_re/"
  fi
}

# --- dwarf-side helpers -------------------------------------------------------
# Dumps are cached because llvm-dwarfdump is by far the slowest step here.
D4O0=$("$DWARFDUMP" --debug-info "$LIB/stellar-fixture-dwarf4-O0.so" 2>/dev/null)
D4O2=$("$DWARFDUMP" --debug-info "$LIB/stellar-fixture-dwarf4-O2.so" 2>/dev/null)
D5O0=$("$DWARFDUMP" --debug-info "$LIB/stellar-fixture-dwarf5-O0.so" 2>/dev/null)
D5O2=$("$DWARFDUMP" --debug-info "$LIB/stellar-fixture-dwarf5-O2.so" 2>/dev/null)

# die_of <dump> <attr> <value> -- every attribute line of the DIE that carries
# <attr> == <value>. llvm-dwarfdump prints one DIE per block starting with an
# offset line ("0x00000042:  DW_TAG_class_type"), so awk can split on those.
# Anchoring on attribute *and* value is what makes a member-offset assertion
# about that member rather than about whichever DIE happens to come first.
# The tab is built with printf because POSIX sh has no $'...'.
TAB=$(printf '\t')
# die_of <dump> <attr> <value> -- the full text of every DIE that carries
# <attr> with <value>. llvm-dwarfdump prints one DIE per block starting with an
# offset line ("0x00000042:  DW_TAG_class_type"), so awk can split on those.
# The whole block is returned because DWARF does not fix attribute order: the
# attribute a caller wants to assert on may sit before or after the one it
# anchors on, and a DIE ends at the next offset line.
# The tab is built with printf because POSIX sh has no $'...'.
TAB=$(printf '\t')
die_of() {
  printf '%s\n' "$1" | awk -v key="$2$TAB(" -v val="$3" '
    /^0x[0-9a-f]+:[[:space:]]+DW_TAG_/ {
      if (hit) printf "%s", buf
      buf = $0 "\n"; hit = 0; next
    }
    {
      buf = buf $0 "\n"
      # The attribute must appear with the wanted value. DW_AT_specification
      # prefixes its value with the offset of the DIE it points at, so the
      # value is matched as a substring rather than for equality.
      if (index($0, key) && (val == "" || index($0, val))) hit = 1
    }
    END { if (hit) printf "%s", buf }
  '
}
# Shorthand for the common DW_AT_name case.
die_name() { die_of "$1" DW_AT_name "\"$2\""; }
# The definition DIE of a subprogram is the one that owns a code range; the
# declaration DIE only has DW_AT_declaration and points at the definition via
# DW_AT_specification. Selecting on DW_AT_low_pc is what tells them apart.
# A subprogram's out-of-line definition identifies itself in one of two ways,
# depending on whether the compiler also emitted a linkage name for it:
#   * DW_AT_linkage_name ("_ZN...")      -- constructors, destructors, and
#     anything with no in-class declaration to point back at
#   * DW_AT_specification (0x.. "_ZN..") -- members defined out of line, which
#     refer to their in-class declaration instead of repeating the name
# DW_AT_low_pc is what distinguishes either of those from the declaration DIE,
# which has DW_AT_declaration and no code range. So: take whichever block names
# the symbol, then require that it owns a code range.
die_defn() {
  printf '%s\n' "$(
    die_of "$1" DW_AT_linkage_name "\"$2\""
    die_of "$1" DW_AT_specification "\"$2\""
  )" | awk '
    /^0x[0-9a-f]+:[[:space:]]+DW_TAG_/ { if (hit) printf "%s", buf; buf = $0 "\n"; hit = 0; next }
    { buf = buf $0 "\n" }
    END { if (index(buf, "DW_AT_low_pc")) printf "%s", buf }
  '
}
# Attribute order within a DIE is not fixed -- DW_AT_declaration can trail
# DW_AT_decl_line -- so a block is buffered whole and emitted only once it is
# known to be the right one.
die_block_where() {
  die_of "$1" DW_AT_linkage_name "\"$2\"" | awk -v want="$3" '
    /^0x[0-9a-f]+:[[:space:]]+DW_TAG_/ { if (hit) printf "%s", buf; buf = $0 "\n"; hit = 0; next }
    { buf = buf $0 "\n" }
    END {
      if (index(buf, want)) printf "%s", buf
    }
  '
}
# die_tag <dump> <tag> -- every attribute line of the first DIE with <tag>.
die_tag() { printf '%s\n' "$1" | grep -F "$2" -A 12; }

# claim_dwarf <label> <dump> <regex> -- the dump must contain a matching line.
claim_dwarf() {
  if printf '%s\n' "$2" | grep -qE "$3"; then
    ok "$1"
  else
    no "$1" "no line matching /$3/"
  fi
}

# claim_dwarf_absent <label> <dump> <regex> -- must NOT appear.
claim_dwarf_absent() {
  if printf '%s\n' "$2" | grep -qE "$3"; then
    no "$1" "unexpectedly matched /$3/"
  else
    ok "$1"
  fi
}

# =============================================================================
# 1. Container shape of all four libraries
# =============================================================================
echo "-- container --"
for v in dwarf4-O0 dwarf4-O2 dwarf5-O0 dwarf5-O2; do
  f="$LIB/stellar-fixture-$v.so"
  if [ -f "$f" ]; then
    ok "$v: file present"
  else
    no "$v: file present" "missing $f"
    continue
  fi

  hdr=$("$READELF" --file-header "$f")
  claim_dwarf "$v: ELF64"        "$hdr" 'Class:[[:space:]]+ELF64'
  claim_dwarf "$v: AArch64"      "$hdr" 'Machine:[[:space:]]+AArch64'
  claim_dwarf "$v: little endian" "$hdr" "Data:.*little endian"
  claim_dwarf "$v: ET_DYN"       "$hdr" 'Type:[[:space:]]+DYN'

  sec=$("$READELF" --sections "$f")
  for s in .debug_info .debug_abbrev .debug_str .debug_line; do
    claim_dwarf "$v: has $s" "$sec" "$s"
  done

  expect=4
  case $v in dwarf5-*) expect=5 ;; esac
  case $v in
    dwarf4-O0) d=$D4O0 ;; dwarf4-O2) d=$D4O2 ;;
    dwarf5-O0) d=$D5O0 ;; dwarf5-O2) d=$D5O2 ;;
  esac
  claim_dwarf "$v: .debug_info is DWARF $expect" "$d" "version = 0x000$expect"
done

# The per-version unit headers, checked against the library that must carry them.
for pair in "dwarf4-O0 4" "dwarf4-O2 4" "dwarf5-O0 5" "dwarf5-O2 5"; do
  v=${pair% *}; want=${pair#* }
  case $v in
    dwarf4-O0) d=$D4O0 ;; dwarf4-O2) d=$D4O2 ;;
    dwarf5-O0) d=$D5O0 ;; dwarf5-O2) d=$D5O2 ;;
  esac
  claim_dwarf "$v: units report version $want" "$d" "version = 0x000$want"
done

# DWARF 5 splits directory/file names into .debug_line_str; DWARF 4 does not.
for pair in "dwarf4-O0 no" "dwarf4-O2 no" "dwarf5-O0 yes" "dwarf5-O2 yes"; do
  v=${pair% *}; want=${pair#* }
  case $v in
    dwarf4-O0) f=stellar-fixture-dwarf4-O0.so ;; dwarf4-O2) f=stellar-fixture-dwarf4-O2.so ;;
    dwarf5-O0) f=stellar-fixture-dwarf5-O0.so ;; dwarf5-O2) f=stellar-fixture-dwarf5-O2.so ;;
  esac
  sec=$("$READELF" --sections "$LIB/$f")
  if [ "$want" = yes ]; then
    claim_dwarf "$v: has .debug_line_str" "$sec" '\.debug_line_str'
  else
    claim_dwarf_absent "$v: has no .debug_line_str" "$sec" '\.debug_line_str'
  fi
done

# =============================================================================
# 2. Unit order and comp_dir
# =============================================================================
echo "-- units --"
for pair in "dwarf4-O0 x" "dwarf4-O2 x" "dwarf5-O0 x" "dwarf5-O2 x"; do
  v=${pair% *}
  case $v in
    dwarf4-O0) d=$D4O0 ;; dwarf4-O2) d=$D4O2 ;;
    dwarf5-O0) d=$D5O0 ;; dwarf5-O2) d=$D5O2 ;;
  esac
  claim_dwarf "$v: unit 0 is body.cpp" "$d" 'DW_AT_name[[:space:]]+\("Classes/Player/hitboxes/body.cpp"\)'
  claim_dwarf "$v: unit 1 is player.cpp" "$d" 'DW_AT_name[[:space:]]+\("Classes/Player/player.cpp"\)'
  claim_dwarf "$v: comp_dir is /stellar-fixtures/src" "$d" 'DW_AT_comp_dir[[:space:]]+\("/stellar-fixtures/src"\)'
  # body.cpp must be the first unit name emitted, i.e. it precedes player.cpp.
  bline=$(printf '%s\n' "$d" | grep -n 'Classes/Player/hitboxes/body.cpp' | head -1 | cut -d: -f1)
  pline=$(printf '%s\n' "$d" | grep -n 'Classes/Player/player.cpp' | head -1 | cut -d: -f1)
  if [ -n "$bline" ] && [ -n "$pline" ] && [ "$bline" -lt "$pline" ]; then
    ok "$v: body.cpp precedes player.cpp"
  else
    no "$v: body.cpp precedes player.cpp" "body.cpp at line $bline, player.cpp at line $pline"
  fi
done

# =============================================================================
# 3. Types: byte sizes, member offsets, decl lines
# =============================================================================
echo "-- types --"
BH=Classes/Player/hitboxes/body.h
PH=Classes/Player/player.h

# --- declared lines, straight from the sources ---
claim_src "Entity declared at body.h:17"        "$BH" 17 '^class Entity \{'
claim_src "Entity::health_ at body.h:26"       "$BH" 26 '^  float health_ = 100\.0f;'
claim_src "Entity::update virtual at body.h:20" "$BH" 20 '^  virtual void update\(float dt\);'
claim_src "Entity::describe at body.h:23"      "$BH" 23 '^  void describe\(\) const;'
claim_src "Hitbox declared at body.h:30"       "$BH" 30 '^struct Hitbox \{'
claim_src "Hitbox::x at body.h:31"             "$BH" 31 '^  float x;'
claim_src "Hitbox::y at body.h:32"             "$BH" 32 '^  float y;'
claim_src "Hitbox::half_w at body.h:33"        "$BH" 33 '^  float half_w;'
claim_src "Hitbox::half_h at body.h:34"        "$BH" 34 '^  float half_h;'
claim_src "Body declared at body.h:38"         "$BH" 38 '^class Body : public Entity \{'
claim_src "Body::Body at body.h:40"            "$BH" 40 '^  Body\(\);'
claim_src "Body::~Body at body.h:41"           "$BH" 41 '^  ~Body\(\) override;'
claim_src "Body::update override at body.h:44" "$BH" 44 '^  void update\(float dt\) override;'
claim_src "Body::radius at body.h:47"          "$BH" 47 '^  float radius\(\) const;'
claim_src "Body::set_hitbox at body.h:49"      "$BH" 49 '^  void set_hitbox\(const Hitbox& h\);'
claim_src "Body::instances_ at body.h:52"      "$BH" 52 '^  static int instances_;'
claim_src "Body::instance_count at body.h:55"  "$BH" 55 '^  static int instance_count\(\);'
claim_src "Shape declared at body.h:57"        "$BH" 57 '^  enum class Shape \{'
claim_src "Shape::kCircle at body.h:58"        "$BH" 58 '^    kCircle,'
claim_src "Shape::kBox at body.h:59"           "$BH" 59 '^    kBox,'
claim_src "Shape::kCapsule at body.h:60"       "$BH" 60 '^    kCapsule,'
claim_src "Body::shape at body.h:63"           "$BH" 63 '^  Shape shape\(\) const;'
claim_src "Body::hitbox_ at body.h:66"         "$BH" 66 '^  Hitbox hitbox_\{\};'
claim_src "Body::shape_ at body.h:67"          "$BH" 67 '^  Shape shape_ = Shape::kCircle;'
claim_src "Player declared at player.h:18"     "$PH" 18 '^class Player \{'
claim_src "Player::Player at player.h:20"      "$PH" 20 '^  Player\(\);'
claim_src "Player::tick at player.h:22"        "$PH" 22 '^  void tick\(float dt\);'
claim_src "Player::score at player.h:24"       "$PH" 24 '^  int score\(\) const;'
claim_src "Player::body_ at player.h:27"       "$PH" 27 '^  Body body_;'
claim_src "Player::score_ at player.h:28"      "$PH" 28 '^  int score_ = 0;'

# --- the compiler's view of those same types ---
# Byte sizes are asserted per variant, since -O2 must not change them.
for pair in "dwarf4-O0 x" "dwarf4-O2 x" "dwarf5-O0 x" "dwarf5-O2 x"; do
  v=${pair% *}
  case $v in
    dwarf4-O0) d=$D4O0 ;; dwarf4-O2) d=$D4O2 ;;
    dwarf5-O0) d=$D5O0 ;; dwarf5-O2) d=$D5O2 ;;
  esac
  claim_dwarf "$v: Entity DW_AT_byte_size 0x10" \
    "$(die_name "$d" Entity)" 'DW_AT_byte_size	\(0x10\)'
  claim_dwarf "$v: Hitbox DW_AT_byte_size 0x10" \
    "$(die_name "$d" Hitbox)" 'DW_AT_byte_size	\(0x10\)'
  claim_dwarf "$v: Body DW_AT_byte_size 0x20" \
    "$(die_name "$d" Body)" 'DW_AT_byte_size	\(0x20\)'
  claim_dwarf "$v: Shape DW_AT_byte_size 0x04" \
    "$(die_name "$d" Shape)" 'DW_AT_byte_size	\(0x04\)'
  claim_dwarf "$v: Player DW_AT_byte_size 0x28" \
    "$(die_name "$d" Player)" 'DW_AT_byte_size	\(0x28\)'

  claim_dwarf "$v: Entity decl_line 17"  "$(die_name "$d" Entity)" 'DW_AT_decl_line	\(17\)'
  claim_dwarf "$v: Hitbox decl_line 30"  "$(die_name "$d" Hitbox)" 'DW_AT_decl_line	\(30\)'
  claim_dwarf "$v: Body decl_line 38"    "$(die_name "$d" Body)"   'DW_AT_decl_line	\(38\)'
  claim_dwarf "$v: Player decl_line 18"  "$(die_name "$d" Player)" 'DW_AT_decl_line	\(18\)'
  claim_dwarf "$v: Shape decl_line 57"   "$(die_name "$d" Shape)"  'DW_AT_decl_line	\(57\)'
done

# Member offsets. Each block is anchored on the member name, so the offset is
# asserted for that member specifically and not for whichever one follows it.
for pair in "dwarf4-O0 x" "dwarf4-O2 x" "dwarf5-O0 x" "dwarf5-O2 x"; do
  v=${pair% *}
  case $v in
    dwarf4-O0) d=$D4O0 ;; dwarf4-O2) d=$D4O2 ;;
    dwarf5-O0) d=$D5O0 ;; dwarf5-O2) d=$D5O2 ;;
  esac
  claim_dwarf "$v: Hitbox::x offset 0x00" "$(die_name "$d" x)"       'DW_AT_data_member_location	\(0x00\)'
  claim_dwarf "$v: Hitbox::y offset 0x04" "$(die_name "$d" y)"       'DW_AT_data_member_location	\(0x04\)'
  claim_dwarf "$v: Hitbox::half_w offset 0x08" "$(die_name "$d" half_w)"  'DW_AT_data_member_location	\(0x08\)'
  claim_dwarf "$v: Hitbox::half_h offset 0x0c" "$(die_name "$d" half_h)"  'DW_AT_data_member_location	\(0x0c\)'
  claim_dwarf "$v: Body::hitbox_ offset 0x0c" "$(die_name "$d" hitbox_)" 'DW_AT_data_member_location	\(0x0c\)'
  claim_dwarf "$v: Body::shape_ offset 0x1c" "$(die_name "$d" shape_)"  'DW_AT_data_member_location	\(0x1c\)'
  claim_dwarf "$v: Player::body_ offset 0x00" "$(die_name "$d" body_)"   'DW_AT_data_member_location	\(0x00\)'
  claim_dwarf "$v: Player::score_ offset 0x20" "$(die_name "$d" score_)"  'DW_AT_data_member_location	\(0x20\)'
  claim_dwarf "$v: Entity::health_ offset 0x08" "$(die_name "$d" health_)" 'DW_AT_data_member_location	\(0x08\)'
  claim_dwarf "$v: Body inherits Entity at 0x00" "$(die_tag "$d" DW_TAG_inheritance)"  'DW_AT_data_member_location	\(0x00\)'
  # Entity is the root: its own DIE carries no DW_TAG_inheritance child.
  claim_dwarf_absent "$v: Entity declares no inheritance" \
    "$(die_name "$d" Entity)" 'DW_TAG_inheritance'
done

# A scoped enum must still be an enumeration_type carrying DW_AT_enum_class.
for pair in "dwarf4-O0 x" "dwarf4-O2 x" "dwarf5-O0 x" "dwarf5-O2 x"; do
  v=${pair% *}
  case $v in
    dwarf4-O0) d=$D4O0 ;; dwarf4-O2) d=$D4O2 ;;
    dwarf5-O0) d=$D5O0 ;; dwarf5-O2) d=$D5O2 ;;
  esac
  claim_dwarf "$v: Shape is DW_TAG_enumeration_type" "$(die_name "$d" Shape)" 'DW_TAG_enumeration_type'
  claim_dwarf "$v: Shape has DW_AT_enum_class true"  "$(die_name "$d" Shape)" 'DW_AT_enum_class	\(true\)'
  for e in kCircle kBox kCapsule; do
    claim_dwarf "$v: enumerator $e present" "$d" "DW_AT_name[[:space:]]+\(\"$e\"\)"
  done
done

# =============================================================================
# 4. Functions: declaration lines, definition lines, virtuality
# =============================================================================
echo "-- functions --"
BC=Classes/Player/hitboxes/body.cpp
PC=Classes/Player/player.cpp

# --- out-of-line definition lines, read from the sources ---
claim_src "Entity::~Entity defined at body.cpp:10"    "$BC" 10 '^Entity::~Entity\(\) = default;'
claim_src "Entity::update defined at body.cpp:12"     "$BC" 12 '^void Entity::update\(float dt\) \{ health_ -= dt; \}$'
claim_src "Entity::describe defined at body.cpp:14"   "$BC" 14 '^void Entity::describe\(\) const \{$'
claim_src "Body::Body defined at body.cpp:19"         "$BC" 19 '^Body::Body\(\) \{$'
claim_src "Body::~Body defined at body.cpp:25"        "$BC" 25 '^Body::~Body\(\) = default;'
claim_src "Body::update defined at body.cpp:27"       "$BC" 27 '^void Body::update\(float dt\) \{$'
claim_src "Body::radius defined at body.cpp:35"       "$BC" 35 '^float Body::radius\(\) const \{ return hitbox_\.half_w \+ hitbox_\.half_h; \}$'
claim_src "Body::set_hitbox defined at body.cpp:37"   "$BC" 37 '^void Body::set_hitbox\(const Hitbox& h\) \{ hitbox_ = h; \}$'
claim_src "Body::instance_count defined at body.cpp:39" "$BC" 39 '^int Body::instance_count\(\) \{ return instances_; \}$'
claim_src "Body::shape defined at body.cpp:41"        "$BC" 41 '^Body::Shape Body::shape\(\) const \{ return shape_; \}$'
claim_src "Body::instances_ defined at body.cpp:8"    "$BC" 8 '^int Body::instances_ = 0;$'
claim_src "Player::Player defined at player.cpp:11"   "$PC" 11 '^Player::Player\(\) \{ score_ = clamp_value<int>\(0\); \}$'
claim_src "Player::tick defined at player.cpp:13"     "$PC" 13 '^void Player::tick\(float dt\) \{$'
claim_src "Player::score defined at player.cpp:18"    "$PC" 18 '^int Player::score\(\) const \{ return score_; \}$'
claim_src "player_registry_token defined at player.cpp:9" "$PC" 9 '^int player_registry_token = 0x5354454c;$'
claim_src "clampf defined at math.h:14"              Classes/Util/math.h 14 '^inline float clampf\(float v, float lo, float hi\) \{$'
claim_src "clamp_value defined at player.h:13"        "$PH" 13 '^T clamp_value\(T v\) \{$'
claim_src "template<> declared at player.h:12"        "$PH" 12 '^template <typename T>$'

# --- the definitions the DWARF must record, by linkage name ---
# Checked in dwarf4-O0, where nothing is optimised away, so a missing
# out-of-line copy is a genuine disagreement rather than an -O2 effect.
check_def() {
  _label=$1 _ln=$2 _line=$3 _file=$4
  claim_dwarf "$_label: definition DIE present" "$D4O0" \
    "DW_AT_linkage_name[[:space:]]+\(\"$_ln\"\)"
  blk=$(die_defn "$D4O0" "$_ln")
  claim_dwarf "$_label: definition DIE owns a code range" "$blk" 'DW_AT_low_pc'
  claim_dwarf "$_label: definition decl_line $_line" "$blk" "DW_AT_decl_line[[:space:]]+\($_line\)"
  claim_dwarf "$_label: definition decl_file $(basename "$_file")" "$blk" "$(basename "$_file")"
}

check_def "Entity::~Entity"  "_ZN4game6EntityD2Ev"                    10 "$BC"
check_def "Entity::update"   "_ZN4game6Entity6updateEf"               12 "$BC"
check_def "Entity::describe" "_ZNK4game6Entity8describeEv"            14 "$BC"
check_def "Body::Body"       "_ZN4game4BodyC2Ev"                      19 "$BC"
check_def "Body::~Body (D2)" "_ZN4game4BodyD2Ev"                      25 "$BC"
check_def "Body::update"     "_ZN4game4Body6updateEf"                 27 "$BC"
check_def "Body::radius"     "_ZNK4game4Body6radiusEv"                35 "$BC"
check_def "Body::set_hitbox" "_ZN4game4Body10set_hitboxERKNS_6HitboxE" 37 "$BC"
check_def "Player::Player"   "_ZN4game6PlayerC2Ev"                    11 "$PC"
check_def "Player::tick"     "_ZN4game6Player4tickEf"                 13 "$PC"
check_def "Player::score"    "_ZNK4game6Player5scoreEv"               18 "$PC"
check_def "clamp_value<int>" "_ZN4game11clamp_valueIiEET_S1_"         13 "$PH"

# The in-class declarations carry the header's line instead.
check_decl() {
  _label=$1 _ln=$2 _line=$3 _hdr=$4
  blk=$(die_block_where "$D4O0" "$_ln" "DW_AT_declaration")
  claim_dwarf "$_label: in-class decl_line $_line" "$blk" "DW_AT_decl_line[[:space:]]+\($_line\)"
  claim_dwarf "$_label: in-class decl_file $(basename "$_hdr")" "$blk" "$(basename "$_hdr")"
}
check_decl "Body::set_hitbox"     "_ZN4game4Body10set_hitboxERKNS_6HitboxE" 49 "$BH"
check_decl "Body::radius"         "_ZNK4game4Body6radiusEv"                  47 "$BH"
check_decl "Body::instance_count" "_ZN4game4Body14instance_countEv"          55 "$BH"
check_decl "Body::shape"          "_ZNK4game4Body5shapeEv"                   63 "$BH"
check_decl "Player::tick"         "_ZN4game6Player4tickEf"                   22 "$PH"
check_decl "Player::score"        "_ZNK4game6Player5scoreEv"                 24 "$PH"

# Virtual / non-virtual, and DW_AT_vtable_elem_location.
claim_dwarf "Entity::update is DW_VIRTUALITY_virtual" \
  "$(die_block_where "$D4O0" "_ZN4game6Entity6updateEf" DW_AT_declaration)" 'DW_AT_virtuality	\(DW_VIRTUALITY_virtual\)'
claim_dwarf "Body::update is DW_VIRTUALITY_virtual" \
  "$(die_block_where "$D4O0" "_ZN4game4Body6updateEf" DW_AT_declaration)" 'DW_AT_virtuality	\(DW_VIRTUALITY_virtual\)'
claim_dwarf "~Entity is DW_VIRTUALITY_virtual" \
  "$(die_name "$D4O0" "~Entity")" 'DW_AT_virtuality	\(DW_VIRTUALITY_virtual\)'
claim_dwarf "~Body is DW_VIRTUALITY_virtual" \
  "$(die_name "$D4O0" "~Body")" 'DW_AT_virtuality	\(DW_VIRTUALITY_virtual\)'
# describe and radius are non-virtual: no virtuality, no vtable slot.
claim_dwarf_absent "Entity::describe is not virtual" \
  "$(die_of "$D4O0" DW_AT_linkage_name "_ZNK4game6Entity8describeEv")" 'DW_AT_virtuality'
claim_dwarf_absent "Body::radius is not virtual" \
  "$(die_of "$D4O0" DW_AT_linkage_name "_ZNK4game4Body6radiusEv")" 'DW_AT_virtuality'

# Both vtables exist as DWARF variables and as real symbols.
for sym in _ZTVN4game6EntityE _ZTVN4game4BodyE; do
  claim_dwarf "vtable $sym described in DWARF" "$D4O0" "DW_AT_linkage_name[[:space:]]+\(\"$sym\"\)"
  if "$READELF" --symbols "$LIB/stellar-fixture-dwarf4-O0.so" 2>/dev/null | grep -q "$sym"; then
    ok "vtable $sym present in symbol table"
  else
    no "vtable $sym present in symbol table" "not found by llvm-readelf --symbols"
  fi
done

# =============================================================================
# 5. Inline semantics: the whole point of the -O0/-O2 pair
# =============================================================================
echo "-- inline semantics --"
clampf_blk_O0=$(die_of "$D4O0" DW_AT_linkage_name "_ZN4game6clampfEfff")
clampf_blk_O2=$(die_of "$D4O2" DW_AT_linkage_name "_ZN4game6clampfEfff")

# -O0: an out-of-line copy exists, so clampf has a real code range.
claim_dwarf "clampf -O0: has DW_AT_low_pc"  "$clampf_blk_O0" 'DW_AT_low_pc'
claim_dwarf "clampf -O0: has DW_AT_high_pc" "$clampf_blk_O0" 'DW_AT_high_pc'
claim_dwarf_absent "clampf -O0: no DW_AT_inline" "$clampf_blk_O0" 'DW_AT_inline'

# -O2: no code range at all, but marked inlined and referenced at the call site.
claim_dwarf_absent "clampf -O2: no DW_AT_low_pc"  "$clampf_blk_O2" 'DW_AT_low_pc'
claim_dwarf_absent "clampf -O2: no DW_AT_high_pc" "$clampf_blk_O2" 'DW_AT_high_pc'
claim_dwarf "clampf -O2: DW_AT_inline DW_INL_inlined" "$clampf_blk_O2" 'DW_AT_inline	\(DW_INL_inlined\)'
claim_dwarf "clampf -O2: inlined_subroutine at the call site" "$D4O2" 'DW_TAG_inlined_subroutine'
claim_dwarf "clampf -O2: call_line 32" "$D4O2" 'DW_AT_call_line	\(32\)'
claim_dwarf "clampf -O2: call_file body.cpp" "$D4O2" 'DW_AT_call_file.*body\.cpp'
# decl_file/decl_line are the same at both optimisation levels.
for pair in "dwarf4-O0 x" "dwarf4-O2 x" "dwarf5-O0 x" "dwarf5-O2 x"; do
  v=${pair% *}
  case $v in
    dwarf4-O0) d=$D4O0 ;; dwarf4-O2) d=$D4O2 ;;
    dwarf5-O0) d=$D5O0 ;; dwarf5-O2) d=$D5O2 ;;
  esac
  claim_dwarf "$v: clampf decl_file math.h" \
    "$(die_of "$d" DW_AT_linkage_name "_ZN4game6clampfEfff")" 'Util/math\.h'
  claim_dwarf "$v: clampf decl_line 14" \
    "$(die_of "$d" DW_AT_linkage_name "_ZN4game6clampfEfff")" 'DW_AT_decl_line	\(14\)'
done

# clamp_value<int>: present out-of-line at -O0, fully inlined away at -O2.
claim_dwarf "clamp_value<int> -O0: has DW_AT_low_pc" \
  "$(die_of "$D4O0" DW_AT_linkage_name "_ZN4game6clampfEfff")" 'DW_AT_low_pc'
claim_dwarf_absent "clamp_value<int> -O2: no out-of-line copy" "$D4O2" 'clamp_value'
for pair in "dwarf4-O0 x" "dwarf5-O0 x"; do
  v=${pair% *}
  case $v in dwarf4-O0) d=$D4O0 ;; dwarf5-O0) d=$D5O0 ;; esac
  claim_dwarf "$v: clamp_value<int> DIE name is substituted" \
    "$(die_of "$d" DW_AT_linkage_name "\"_ZN4game11clamp_valueIiEET_S1_\"")" \
    'DW_AT_name	\("clamp_value<int>"\)'
  claim_dwarf "$v: clamp_value<int> decl_line 13" \
    "$(die_of "$d" DW_AT_linkage_name "\"_ZN4game11clamp_valueIiEET_S1_\"")" 'DW_AT_decl_line	\(13\)'
done

# =============================================================================
# 6. Variables
# =============================================================================
echo "-- variables --"
tok=$(die_of "$D4O0" DW_AT_linkage_name "\"_ZN4game21player_registry_tokenE\"")
claim_dwarf "player_registry_token decl_line 9"  "$tok" 'DW_AT_decl_line	\(9\)'
claim_dwarf "player_registry_token decl_file player.cpp" "$tok" 'player\.cpp'
claim_dwarf "player_registry_token is external" "$tok" 'DW_AT_external	\(true\)'
claim_dwarf "player_registry_token has a location" "$tok" 'DW_AT_location'
# DWARF must not claim to know the initialiser value.
claim_dwarf_absent "player_registry_token has no DW_AT_const_value" "$tok" 'DW_AT_const_value'

inst=$(die_of "$D4O0" DW_AT_linkage_name "\"_ZN4game4Body10instances_E\"")
claim_dwarf "instances_ has a location" "$inst" 'DW_AT_location'
mem=$(die_name "$D4O0" "instances_")
claim_dwarf "instances_ in-class decl_line 52" "$mem" 'DW_AT_decl_line	\(52\)'
claim_dwarf "instances_ in-class decl_file body.h" "$mem" 'body\.h'
claim_dwarf "instances_ in-class is external"   "$mem" 'DW_AT_external	\(true\)'
claim_dwarf "instances_ in-class is a declaration" "$mem" 'DW_AT_declaration	\(true\)'
claim_dwarf "instances_ has DW_AT_byte_size 0x04" \
  "$(die_name "$D4O0" int)" 'DW_AT_byte_size	\(0x04\)'

# Both variables are described in all four libraries.
for pair in "dwarf4-O0 x" "dwarf4-O2 x" "dwarf5-O0 x" "dwarf5-O2 x"; do
  v=${pair% *}
  case $v in
    dwarf4-O0) d=$D4O0 ;; dwarf4-O2) d=$D4O2 ;;
    dwarf5-O0) d=$D5O0 ;; dwarf5-O2) d=$D5O2 ;;
  esac
  claim_dwarf "$v: player_registry_token described" "$d" 'player_registry_token'
  claim_dwarf "$v: instances_ described" "$d" 'instances_'
done

# The game namespace wraps the types in every library.
for pair in "dwarf4-O0 x" "dwarf4-O2 x" "dwarf5-O0 x" "dwarf5-O2 x"; do
  v=${pair% *}
  case $v in
    dwarf4-O0) d=$D4O0 ;; dwarf4-O2) d=$D4O2 ;;
    dwarf5-O0) d=$D5O0 ;; dwarf5-O2) d=$D5O2 ;;
  esac
  claim_dwarf "$v: game namespace present" "$d" 'DW_TAG_namespace'
  claim_dwarf "$v: game namespace named"   "$d" 'DW_AT_name	\("game"\)'
done

# =============================================================================
echo
echo "claims passed: $PASS"
echo "claims failed: $FAIL"
[ "$FAIL" -eq 0 ] || exit 1
exit 0
