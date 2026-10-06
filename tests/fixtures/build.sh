#!/bin/sh
# Build the four DWARF fixture libraries consumed by the Stellar tests.
#
# Two axes, four libraries:
#   -gdwarf-4 x -gdwarf-5   the two .debug_info unit formats
#   -O0       x -O2        unoptimised vs optimised
#
# The -gdwarf-4 builds are the primary fixtures: the real target binary is
# DWARF 4, so anything that breaks on 4 has to break here first.
#
# Target is fixed to aarch64-linux-android24 so the output matches the real
# input's machine (AArch64 ELF64, 8-byte pointers) regardless of the host.
set -eu

HERE=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
SRC="$HERE/src"
OUT="$HERE/lib"
CLANG="${CLANG:-clang++}"

# -ffile-prefix-map keeps DW_AT_comp_dir and the file table free of the absolute
# checkout path, so the same source produces byte-identical debug paths on every
# machine and in CI.
COMMON="--target=aarch64-linux-android24 -std=c++20 -shared -fPIC -g -Wall -I$SRC"
COMMON="$COMMON -ffile-prefix-map=$HERE=/stellar-fixtures -ffile-prefix-map=$SRC=/stellar-fixtures/src"

# Compile order is fixed so DW_AT_decl_file / the line table do not depend on
# shell globbing order.
SOURCES="Classes/Player/hitboxes/body.cpp Classes/Player/player.cpp"

mkdir -p "$OUT"

for dwarf in 4 5; do
  for opt in O0 O2; do
    name="stellar-fixture-dwarf${dwarf}-${opt}"
    # shellcheck disable=SC2086 # COMMON is a deliberately word-split flag list
    (cd "$SRC" && $CLANG $COMMON "-gdwarf-${dwarf}" "-${opt}" $SOURCES \
        -o "$OUT/$name.so")
    echo "built: $name.so"
  done
done
