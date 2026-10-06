#include "stellar/tui/config.h"

#include <algorithm>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <sstream>
#include <system_error>

namespace stellar::tui {

std::string config_path() {
  if (const char* p = std::getenv("STELLAR_CONFIG"); p && *p) return p;
#if defined(_WIN32)
  if (const char* ad = std::getenv("APPDATA"); ad && *ad)
    return std::string(ad) + "\\stellar\\config";
#endif
  if (const char* xdg = std::getenv("XDG_CONFIG_HOME"); xdg && *xdg)
    return std::string(xdg) + "/stellar/config";
  if (const char* home = std::getenv("HOME"); home && *home)
    return std::string(home) + "/.config/stellar/config";
  return "stellar.config";
}

namespace {

std::string trim(std::string s) {
  const auto not_space = [](unsigned char c) { return c != ' ' && c != '\t' && c != '\r'; };
  const auto a = std::find_if(s.begin(), s.end(), not_space);
  const auto b = std::find_if(s.rbegin(), s.rend(), not_space).base();
  return a < b ? std::string(a, b) : std::string();
}

int parse_int(const std::string& v, int fallback) {
  try {
    return std::stoi(v);
  } catch (...) {
    return fallback;
  }
}

}  // namespace

bool load_config(SessionConfig& c) { return load_config(c, config_path()); }

bool load_config(SessionConfig& c, const std::string& path) {
  std::ifstream in(path);
  if (!in) return false;
  for (std::string line; std::getline(in, line);) {
    const std::size_t eq = line.find('=');
    if (eq == std::string::npos) continue;
    const std::string key = trim(line.substr(0, eq));
    const std::string value = trim(line.substr(eq + 1));
    if (key == "layout") c.layout = parse_int(value, c.layout);
    else if (key == "tree_format") c.tree_format = parse_int(value, c.tree_format);
    else if (key == "include_external") c.include_external = value == "1" || value == "true";
    else if (key == "force_overwrite") c.force_overwrite = value == "1" || value == "true";
    else if (key == "bodies_asm") c.bodies_asm = value == "1" || value == "true";
    else if (key == "progress_mode") c.progress_mode = parse_int(value, c.progress_mode);
    else if (key == "redraw_ms") c.redraw_ms = parse_int(value, c.redraw_ms);
    else if (key == "max_lines") {
      try {
        c.max_lines = std::stoull(value);
      } catch (...) {
      }
    } else if (key == "out_dir") c.out_dir = value;
    else if (key == "strip_prefix") c.strip_prefix = value;
    else if (key == "external_prefix") c.external_prefix = value;
    // Unknown keys are ignored: forward compatibility beats failing to start.
  }
  return true;
}

bool save_config(const SessionConfig& c, std::string* err) { return save_config(c, config_path(), err); }

bool save_config(const SessionConfig& c, const std::string& path, std::string* err) {
  std::error_code ec;
  const std::size_t slash = path.find_last_of("/\\");
  if (slash != std::string::npos) {
    std::filesystem::create_directories(path.substr(0, slash), ec);
    if (ec) {
      if (err) *err = ec.message();
      return false;
    }
  }
  std::ofstream out(path, std::ios::binary | std::ios::trunc);
  if (!out) {
    if (err) *err = "cannot open for writing";
    return false;
  }
  out << "layout = " << c.layout << "\n";
  out << "tree_format = " << c.tree_format << "\n";
  out << "include_external = " << (c.include_external ? 1 : 0) << "\n";
  out << "force_overwrite = " << (c.force_overwrite ? 1 : 0) << "\n";
  out << "bodies_asm = " << (c.bodies_asm ? 1 : 0) << "\n";
  out << "progress_mode = " << c.progress_mode << "\n";
  out << "redraw_ms = " << c.redraw_ms << "\n";
  out << "max_lines = " << c.max_lines << "\n";
  out << "out_dir = " << c.out_dir << "\n";
  out << "strip_prefix = " << c.strip_prefix << "\n";
  out << "external_prefix = " << c.external_prefix << "\n";
  if (!out) {
    if (err) *err = "write failed";
    return false;
  }
  return true;
}

}  // namespace stellar::tui
