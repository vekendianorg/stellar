// SPDX-License-Identifier: MIT
// Minimal ZIP writer for the source-tree output.
//
// Deflate when zlib is available (STELLAR_HAVE_ZLIB), stored entries otherwise:
// a zip either way, so the same file name works on both builds. No central-
// directory extra fields, no comments, 32-bit sizes -- plenty for a source dump.
#pragma once

#include <filesystem>
#include <string>

namespace stellar::output {

/// Zips the whole `src` directory into `zip_path`, names relative to `src`.
/// Returns false and fills `err` on any I/O failure.
bool write_zip(const std::filesystem::path& src, const std::filesystem::path& zip_path,
               std::string* err = nullptr);

}  // namespace stellar::output
