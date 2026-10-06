// SPDX-License-Identifier: MIT
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <string>

#include "stellar/diag/log.h"
#include "test_framework.h"

int main(int argc, char** argv) {
  std::string filter;
  std::string exclude;
  bool quiet = false;
  for (int i = 1; i < argc; ++i) {
    if (std::strcmp(argv[i], "--quiet") == 0) {
      quiet = true;
    } else if (std::strncmp(argv[i], "--filter=", 9) == 0) {
      filter = argv[i] + 9;
    } else if (std::strncmp(argv[i], "--exclude=", 10) == 0) {
      exclude = argv[i] + 10;
    } else {
      filter = argv[i];
    }
  }
  // By default the real-binary tests are excluded: they open the 583 MB input,
  // which must not happen on every edit. Opt in with --include-real or by
  // passing an explicit filter that names them.
  if (exclude.empty() && filter.find("RealBinary") == std::string::npos) {
    exclude = "RealBinary";
  }
  // Tests exercise the "not found" paths on purpose; keep the noise down.
  stellar::diag::Log::set_level(stellar::diag::Level::kError);
  // Never read or write the user's real persisted config from a test: point the
  // store at a path that does not exist. Tests that exercise persistence set
  // STELLAR_CONFIG themselves to their own scratch file.
  std::error_code ec;
  std::filesystem::path tmp_base = std::filesystem::temp_directory_path(ec);
  if (ec || !std::filesystem::is_directory(tmp_base, ec)) tmp_base = "/tmp";
  const std::string missing_config = (tmp_base / "stellar-tests-no-config").string();
  stellar::test::setenv_for_test("STELLAR_CONFIG", missing_config.c_str());
  if (quiet) {
    std::freopen(nullptr, "w", stdout);
  }
  return stellar::test::run_all(filter, exclude);
}
