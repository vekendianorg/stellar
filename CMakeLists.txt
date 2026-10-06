cmake_minimum_required(VERSION 3.20)
project(Stellar LANGUAGES CXX VERSION 1.0.0)

# ---------------------------------------------------------------------------
# Stellar -- native ELF/DWARF dumper
#
# Module layout. Each layer depends only on the ones above it, so a change to
# ELF parsing cannot ripple into type reconstruction or output.
#   util/   : byte cursors, LEB128, endianness, small helpers
#   diag/   : logging, metrics/timers, process resource reporting
#   elf/    : ELF container parsing only (no DWARF knowledge)
#   dwarf/  : DWARF abbrev/unit/DIE decoding only (no type semantics)
#   ir/     : type system intermediate representation
#   output/ : C# source generation
#   app/    : CLI front-end
# ---------------------------------------------------------------------------

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

if(NOT CMAKE_BUILD_TYPE AND NOT CMAKE_CONFIGURATION_TYPES)
  set(CMAKE_BUILD_TYPE Release CACHE STRING "Build type" FORCE)
endif()

option(STELLAR_BUILD_TESTS "Build the stellar test suite" ON)
# Capstone is optional on purpose: it is a heavy dependency, and the analysis
# core is complete without it. OFF means no Capstone symbol is referenced anywhere
# and the output is byte-identical to a build that never heard of it.
option(STELLAR_CAPSTONE "Build the vendored Capstone and allow disassembly" OFF)
option(STELLAR_WERROR "Treat warnings as errors" OFF)

# Default to -O2 even in "Debug" style builds: the hot paths (DIE walking) are
# unusably slow at -O0 for a 200 MB .debug_info, and tests are always built in
# Release-like mode here.
# Warning and optimisation flags are compiler-specific: MSVC spells them
# differently and does not accept -Wall at all.
if(MSVC)
  add_library(stellar_flags INTERFACE)
  target_compile_options(stellar_flags INTERFACE /W4 /permissive-)
  target_compile_definitions(stellar_flags INTERFACE
    _CRT_SECURE_NO_WARNINGS
    NOMINMAX
    WIN32_LEAN_AND_MEAN
  )
  if(STELLAR_WERROR)
    target_compile_options(stellar_flags INTERFACE /WX)
  endif()
else()
  add_library(stellar_flags INTERFACE)
  target_compile_options(stellar_flags INTERFACE
    $<$<CONFIG:Release>:-O2>
    $<$<CONFIG:RelWithDebInfo>:-O2>
    $<$<CXX_COMPILER_ID:GNU,Clang,AppleClang>:-fno-omit-frame-pointer>
    $<$<CXX_COMPILER_ID:GNU,Clang,AppleClang>:-Wall>
    $<$<CXX_COMPILER_ID:GNU,Clang,AppleClang>:-Wextra>
    $<$<CXX_COMPILER_ID:GNU,Clang,AppleClang>:-Wpedantic>
    $<$<AND:$<BOOL:${STELLAR_WERROR}>,$<CXX_COMPILER_ID:GNU,Clang,AppleClang>>:-Werror>
  )
endif()

# --- optional Capstone ------------------------------------------------------
#
# Built from third_party/capstone with only the four architectures Stellar can
# report on. The vendored tree is never modified; it is added as a subdirectory
# and configured through its own documented cache variables.
set(STELLAR_CAPSTONE_AVAILABLE OFF)
if(STELLAR_CAPSTONE)
  set(CAPSTONE_BUILD_SHARED OFF CACHE BOOL "" FORCE)
  set(CAPSTONE_BUILD_TESTS OFF CACHE BOOL "" FORCE)
  set(CAPSTONE_BUILD_CSTOOL OFF CACHE BOOL "" FORCE)
  # Only what ArchCaps advertises. Leaving the rest on would roughly double the
  # build for code no code path can reach.
  # third_party/capstone/CMakeLists.txt includes its own CPackConfig.txt, which
  # tests ${CMAKE_SYSTEM_PROCESSOR} unguarded. When it is empty the comparison
  # expands to `if(STREQUAL "x86_64")` and configuration fails. Supplying a value
  # is the fix that leaves the vendored tree untouched, which the task requires.
  if(NOT CMAKE_SYSTEM_PROCESSOR)
    set(CMAKE_SYSTEM_PROCESSOR "${CMAKE_HOST_SYSTEM_PROCESSOR}")
  endif()
  set(CAPSTONE_ARCHITECTURE_DEFAULT OFF CACHE BOOL "" FORCE)
  # Explicitly on the four ArchCaps advertises, then explicitly off everything
  # else. Both halves are written out on purpose: a single loop over "the rest"
  # is one typo away from silently disabling an architecture that is needed, and
  # the symptom is CS_ERR_ARCH at run time rather than a build failure.
  # Capstone names the AArch64 port ARM64, not AARCH64.
  foreach(_want X86 ARM ARM64 MIPS)
    set(CAPSTONE_${_want}_SUPPORT ON CACHE BOOL "" FORCE)
  endforeach()
  foreach(_drop BPF EVM M680X M68K MOS65XX PowerPC RISCV SH Sparc SystemZ
               TMS320C64x TriCore WASM XCore)
    set(CAPSTONE_${_drop}_SUPPORT OFF CACHE BOOL "" FORCE)
  endforeach()
  set(BUILD_SHARED_LIBS OFF CACHE BOOL "" FORCE)
  add_subdirectory(third_party/capstone EXCLUDE_FROM_ALL)
  if(TARGET capstone)
    set(STELLAR_CAPSTONE_AVAILABLE ON)
  else()
    message(WARNING "STELLAR_CAPSTONE=ON but third_party/capstone did not define a "
                    "'capstone' target; disassembly stays unavailable")
  endif()
endif()

add_library(stellar STATIC
  src/util/bytes.cpp
  src/diag/log.cpp
  src/diag/metrics.cpp
  src/diag/progress.cpp
  src/elf/mapped_file.cpp
  src/elf/elf_file.cpp
  src/elf/phdr_recovery.cpp
  src/dwarf/sections.cpp
  src/dwarf/abbrev.cpp
  src/dwarf/unit.cpp
  src/dwarf/constants.cpp
  src/dwarf/eh_frame.cpp
  src/dwarf/line.cpp
  src/dwarf/dwarf_context.cpp
  src/disasm/disasm.cpp
  src/ir/model.cpp
  src/ir/build.cpp
  src/output/emit_il2cpp.cpp
  src/output/normalize.cpp
  src/output/paths.cpp
  src/output/bodies.cpp
  src/output/emit_tree.cpp
  src/output/zip.cpp
  # tui/ : the interactive frontend. It is a frontend over the library above and
  # holds no analysis logic of its own; analysis.cpp drives the real core.
  src/tui/theme.cpp
  src/tui/logo.cpp
  src/tui/terminal.cpp
  src/tui/screen.cpp
  src/tui/analysis.cpp
  src/tui/config.cpp
  src/tui/dwarfview.cpp
  src/tui/app.cpp
)
target_include_directories(stellar PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include)

# The one definition that flips the wrapper between "really disassembles" and
# "reports capstone-not-built". Nothing else in the build refers to Capstone, so
# with the option off there is no symbol to look up.
if(STELLAR_CAPSTONE_AVAILABLE)
  target_compile_definitions(stellar PUBLIC STELLAR_WITH_CAPSTONE=1)
  target_link_libraries(stellar PRIVATE capstone)
endif()
  # Must come after add_library(stellar): the target does not exist until then,
  # and CMake rejects linking to an undefined target.
# psapi is needed for the Windows memory counters in diag/metrics.
if(WIN32)
  target_link_libraries(stellar PUBLIC psapi)
endif()

# The TUI runs the analysis on a worker thread so the interface stays
# responsive during a 30-second dump, which makes threads a real dependency
# rather than an optimisation.
set(THREADS_PREFER_PTHREAD_FLAG ON)
find_package(Threads REQUIRED)
find_package(ZLIB QUIET)
if(ZLIB_FOUND)
  target_compile_definitions(stellar PUBLIC STELLAR_HAVE_ZLIB=1)
  target_link_libraries(stellar PUBLIC ZLIB::ZLIB)
endif()
target_link_libraries(stellar PUBLIC Threads::Threads)

target_link_libraries(stellar PUBLIC stellar_flags)

add_executable(stellar-dump src/app/main.cpp)
target_link_libraries(stellar-dump PRIVATE stellar)
set_target_properties(stellar-dump PROPERTIES OUTPUT_NAME stellar)

if(STELLAR_BUILD_TESTS)
  enable_testing()
  add_subdirectory(tests)
endif()

# The version is defined once, here, and compiled in.
target_compile_definitions(stellar PUBLIC
  STELLAR_VERSION="${PROJECT_VERSION}"
  STELLAR_VERSION_MAJOR=${PROJECT_VERSION_MAJOR}
  STELLAR_VERSION_MINOR=${PROJECT_VERSION_MINOR}
  STELLAR_VERSION_PATCH=${PROJECT_VERSION_PATCH}
)

message(STATUS "Stellar ${PROJECT_VERSION}: build type=${CMAKE_BUILD_TYPE} tests=${STELLAR_BUILD_TESTS}")
