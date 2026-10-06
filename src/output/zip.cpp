#include "stellar/output/zip.h"

#include <cstdint>
#include <cstdio>
#include <fstream>
#include <vector>

#ifdef STELLAR_HAVE_ZLIB
#include <zlib.h>
#endif

namespace stellar::output {
namespace {

std::uint32_t crc32_of(const std::vector<char>& data) {
#ifdef STELLAR_HAVE_ZLIB
  return ::crc32(0L, reinterpret_cast<const Bytef*>(data.data()), data.size());
#else
  std::uint32_t c = 0xFFFFFFFFu;
  for (unsigned char b : data) {
    c ^= b;
    for (int k = 0; k < 8; ++k) c = (c & 1) ? (c >> 1) ^ 0xEDB88320u : c >> 1;
  }
  return c ^ 0xFFFFFFFFu;
#endif
}

std::vector<char> deflate(const std::vector<char>& in) {
#ifdef STELLAR_HAVE_ZLIB
  z_stream z{};
  if (deflateInit2(&z, Z_DEFAULT_COMPRESSION, Z_DEFLATED,
                    -MAX_WBITS, 8, Z_DEFAULT_STRATEGY) != Z_OK)
    return in;
  z.next_in = reinterpret_cast<Bytef*>(const_cast<char*>(in.data()));
  z.avail_in = static_cast<uInt>(in.size());
  std::vector<char> out(deflateBound(&z, in.size()));
  z.next_out = reinterpret_cast<Bytef*>(out.data());
  z.avail_out = static_cast<uInt>(out.size());
  deflate(&z, Z_FINISH);
  out.resize(z.total_out);
  deflateEnd(&z);
  return out;
#else
  return in;
#endif
}

void put_u16(std::vector<char>& b, std::uint16_t v) {
  b.push_back(static_cast<char>(v & 0xFF));
  b.push_back(static_cast<char>(v >> 8));
}
void put_u32(std::vector<char>& b, std::uint32_t v) {
  b.push_back(static_cast<char>(v & 0xFF));
  b.push_back(static_cast<char>((v >> 8) & 0xFF));
  b.push_back(static_cast<char>((v >> 16) & 0xFF));
  b.push_back(static_cast<char>(v >> 24));
}

}  // namespace

bool write_zip(const std::filesystem::path& src, const std::filesystem::path& zip_path,
               std::string* err) {
  namespace fs = std::filesystem;
  std::error_code ec;
  if (!fs::is_directory(src, ec)) {
    if (err) *err = "source is not a directory";
    return false;
  }

  std::vector<std::pair<fs::path, std::uint32_t>> entries;  // relative name -> crc
  struct Central {
    std::string name;
    bool deflated;
    std::uint32_t crc, comp, raw, offset;
  };
  std::vector<Central> central;
  std::vector<char> all;

  const std::string prefix = src.filename().generic_string() + "/";
  for (auto it = fs::recursive_directory_iterator(src, ec);
       !ec && it != fs::recursive_directory_iterator(); it.increment(ec)) {
    if (!it->is_regular_file(ec)) continue;
    const fs::path rel = fs::relative(it->path(), src, ec);
    if (ec) { if (err) *err = "cannot relativise path"; return false; }
    const std::string name = prefix + rel.generic_string();

    std::ifstream in(it->path(), std::ios::binary);
    if (!in) { if (err) *err = "cannot read " + name; return false; }
    std::vector<char> raw{std::istreambuf_iterator<char>(in),
                        std::istreambuf_iterator<char>()};

    const std::uint32_t crc = crc32_of(raw);
    // The uncompressed size has to be read before `raw` can be moved from, or it
    // is read back as 0: a moved-from vector is empty. Both headers then claim
    // the entry stores nothing, and every STORED entry -- any file deflate could
    // not shrink, which includes short ones -- reads `ucsize 0 <> csize N`, which
    // is what makes `unzip -t` reject the archive even though the bytes are fine.
    const std::uint32_t raw_size = static_cast<std::uint32_t>(raw.size());
    std::vector<char> packed = deflate(raw);
    bool deflated = packed.size() < raw.size();
    if (!deflated) packed = std::move(raw);

    Central c;
    c.name = name;
    c.deflated = deflated;
    c.crc = crc;
    c.comp = static_cast<std::uint32_t>(packed.size());
    c.raw = raw_size;
    c.offset = static_cast<std::uint32_t>(all.size());

    // local file header
    put_u32(all, 0x04034b50);
    put_u16(all, 20);  // version needed
    put_u16(all, 0);   // flags
    put_u16(all, deflated ? 8 : 0);
    put_u16(all, 0);   // time
    put_u16(all, 0);   // date
    put_u32(all, crc);
    put_u32(all, c.comp);
    put_u32(all, c.raw);
    put_u16(all, static_cast<std::uint16_t>(name.size()));
    put_u16(all, 0);  // extra len
    all.insert(all.end(), name.begin(), name.end());
    all.insert(all.end(), packed.begin(), packed.end());
    central.push_back(std::move(c));
  }

  const std::uint32_t cd_start = static_cast<std::uint32_t>(all.size());
  for (const auto& c : central) {
    put_u32(all, 0x02014b50);
    put_u16(all, 20);  // version made by
    put_u16(all, 20);  // version needed
    put_u16(all, 0);
    put_u16(all, c.deflated ? 8 : 0);
    put_u16(all, 0);
    put_u16(all, 0);
    put_u32(all, c.crc);
    put_u32(all, c.comp);
    put_u32(all, c.raw);
    put_u16(all, static_cast<std::uint16_t>(c.name.size()));
    put_u16(all, 0);  // extra
    put_u16(all, 0);  // comment
    put_u16(all, 0);  // disk
    put_u16(all, 0);  // internal attrs
    put_u32(all, 0);  // external attrs
    put_u32(all, c.offset);
    all.insert(all.end(), c.name.begin(), c.name.end());
  }
  const std::uint32_t cd_size = static_cast<std::uint32_t>(all.size() - cd_start);
  put_u32(all, 0x06054b50);
  put_u16(all, 0);
  put_u16(all, 0);
  put_u16(all, static_cast<std::uint16_t>(central.size()));
  put_u16(all, static_cast<std::uint16_t>(central.size()));
  put_u32(all, cd_size);
  put_u32(all, cd_start);
  put_u16(all, 0);

  std::ofstream out(zip_path, std::ios::binary);
  if (!out) { if (err) *err = "cannot open zip for writing"; return false; }
  out.write(all.data(), static_cast<std::streamsize>(all.size()));
  if (!out) { if (err) *err = "write failed"; return false; }
  return true;
}

}  // namespace stellar::output
