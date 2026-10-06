add_executable(stellar-tests
  main.cpp
  fixture_builder.cpp
  test_dwarf.cpp
  test_line.cpp
  test_ir_provenance.cpp
  test_ir_addrx.cpp
  test_paths.cpp
  test_real_binary.cpp
  test_ir.cpp
  test_dwarfless.cpp
  test_normalize.cpp
  test_progress.cpp
  test_emit_tree.cpp
  test_disasm.cpp
  test_tui.cpp
)
target_link_libraries(stellar-tests PRIVATE stellar)
target_include_directories(stellar-tests PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})

# The compiled AArch64 fixtures under tests/fixtures/lib are real inputs, so
# their location is baked in: they are checked in, and a test that silently
# skipped because the path moved would be worse than no test.
target_compile_definitions(stellar-tests PRIVATE
  STELLAR_FIXTURE_DIR="${CMAKE_CURRENT_SOURCE_DIR}/fixtures/lib")

add_test(NAME stellar_unit_tests COMMAND stellar-tests)

# The real 583 MB target is exercised by a separate, explicitly opted-in test
# so the default `ctest` run stays fast.
add_test(NAME stellar_real_binary
         COMMAND stellar-tests --filter=RealBinary)
set_tests_properties(stellar_real_binary PROPERTIES TIMEOUT 900)

# The fixtures are built by tests/fixtures/build.sh and committed, so this only
# reports on what is already there. Registering them separately keeps a failure
# in the line-header tests attributable.
add_test(NAME stellar_line_fixtures COMMAND stellar-tests --filter=LineFixture)
