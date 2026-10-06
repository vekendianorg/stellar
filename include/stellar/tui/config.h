// SPDX-License-Identifier: MIT
// Persisted TUI settings.
//
// The TUI used to apply settings to the session only, which made every relaunch
// a blank slate. The store is deliberately plain: one "key = value" line per
// setting, no nesting, no shell expansion, and a path overridable via
// STELLAR_CONFIG so tests and embedded runs never touch the real file.
#pragma once

#include <cstdint>
#include <string>

namespace stellar::tui {

struct SessionConfig {
  int layout = 0;  ///< 0 = single file, 1 = tree
  int tree_format = 0;  ///< 0 = folder, 1 = zip, 2 = both
  bool include_external = false;
  bool force_overwrite = false;
  bool bodies_asm = false;
  int progress_mode = 0;  ///< 0 auto, 1 always, 2 never
  int redraw_ms = 80;
  std::uint64_t max_lines = 0;  ///< 0 = unlimited
  std::string out_dir;
  std::string strip_prefix;
  std::string external_prefix;
};

/// Where settings live: $STELLAR_CONFIG, else $XDG_CONFIG_HOME/stellar/config,
/// else ~/.config/stellar/config. Windows: %APPDATA%\stellar\config.
std::string config_path();

/// Missing or unreadable file is not an error: defaults stand. Malformed lines
/// are skipped, because a corrupted config must not break startup.
bool load_config(SessionConfig& c);
bool load_config(SessionConfig& c, const std::string& path);

/// Creates the parent directory. Returns false and fills err on failure.
bool save_config(const SessionConfig& c, std::string* err = nullptr);
bool save_config(const SessionConfig& c, const std::string& path, std::string* err = nullptr);

}  // namespace stellar::tui
