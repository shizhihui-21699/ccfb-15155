#include "encodings.hpp"

#include <cstring>
#include <string_view>

namespace kh {
namespace {
constexpr const char* kB64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
int b64val(uint8_t c) {
  if (c >= 'A' && c <= 'Z') return c - 'A';
  if (c >= 'a' && c <= 'z') return c - 'a' + 26;
  if (c >= '0' && c <= '9') return c - '0' + 52;
  if (c == '+') return 62;
  if (c == '/') return 63;
  return -1;
}
}  // namespace

bool base64_decode(const std::string& in, Bytes& out) {
  out.clear();
  int acc = 0, bits = 0;
  int pad = 0;
  for (size_t i = 0; i < in.size(); ++i) {
    uint8_t c = static_cast<uint8_t>(in[i]);
    if (c == '=') { ++pad; continue; }
    int v = b64val(c);
    if (v < 0) {
      if (c == '\n' || c == '\r' || c == ' ' || c == '\t') continue;
      return false;
    }
    acc = (acc << 6) | v;
    bits += 6;
    if (bits >= 8) {
      bits -= 8;
      out.push_back(static_cast<uint8_t>((acc >> bits) & 0xff));
    }
  }
  if (pad > 2) return false;
  return true;
}

std::string base64_encode(const Bytes& in) {
  std::string out;
  size_t i = 0;
  while (i + 2 < in.size()) {
    uint32_t v = (static_cast<uint32_t>(in[i]) << 16) | (static_cast<uint32_t>(in[i + 1]) << 8) | in[i + 2];
    out.push_back(kB64[(v >> 18) & 63]);
    out.push_back(kB64[(v >> 12) & 63]);
    out.push_back(kB64[(v >> 6) & 63]);
    out.push_back(kB64[v & 63]);
    i += 3;
  }
  if (i + 1 == in.size()) {
    uint32_t v = static_cast<uint32_t>(in[i]) << 16;
    out.push_back(kB64[(v >> 18) & 63]);
    out.push_back(kB64[(v >> 12) & 63]);
    out += "==";
  } else if (i + 2 == in.size()) {
    uint32_t v = (static_cast<uint32_t>(in[i]) << 16) | (static_cast<uint32_t>(in[i + 1]) << 8);
    out.push_back(kB64[(v >> 18) & 63]);
    out.push_back(kB64[(v >> 12) & 63]);
    out.push_back(kB64[(v >> 6) & 63]);
    out.push_back('=');
  }
  return out;
}

std::vector<PemBlock> find_pem_blocks(const uint8_t* data, size_t len, uint64_t abs_offset) {
  std::vector<PemBlock> out;
  static const std::string kBegin = "-----BEGIN ";
  static const std::string kEnd = "-----END ";
  size_t i = 0;
  while (i + kBegin.size() < len) {
    // Search for "-----BEGIN"
    const char* hit = nullptr;
    {
      const uint8_t* p = static_cast<const uint8_t*>(std::memchr(data + i, '-', len - i));
      while (p) {
        size_t off = static_cast<size_t>(p - data);
        if (off + 11 <= len && std::memcmp(p, "-----BEGIN ", 11) == 0) { hit = reinterpret_cast<const char*>(p); break; }
        if (off + 1 >= len) break;
        p = static_cast<const uint8_t*>(std::memchr(p + 1, '-', len - off - 1));
      }
    }
    if (!hit) break;
    size_t begin = static_cast<size_t>(hit - reinterpret_cast<const char*>(data));
    size_t lbl_start = begin + 11;
    size_t line_end = lbl_start;
    while (line_end < len && data[line_end] != '\n' && data[line_end] != '\r' && line_end - lbl_start < 64) ++line_end;
    std::string label(reinterpret_cast<const char*>(data + lbl_start), line_end - lbl_start);
    while (!label.empty() && (label.back() == '-' || label.back() == ' ')) label.pop_back();
    // find matching END line
    std::string endmark = "-----END " + label + "-----";
    size_t body_start = line_end;
    while (body_start < len && (data[body_start] == '\r' || data[body_start] == '\n')) ++body_start;
    if (label.empty() || body_start >= len) { i = begin + 1; continue; }
    // limit scan to a sane PEM size
    size_t limit = std::min<size_t>(len, body_start + (16u << 20));
    const char* eb = nullptr;
    {
      const uint8_t* q = static_cast<const uint8_t*>(std::memchr(data + body_start, '-', limit - body_start));
      while (q) {
        size_t off = static_cast<size_t>(q - data);
        if (off + endmark.size() <= limit && std::memcmp(q, endmark.data(), endmark.size()) == 0) { eb = reinterpret_cast<const char*>(q); break; }
        if (off + 1 >= limit) break;
        q = static_cast<const uint8_t*>(std::memchr(q + 1, '-', limit - off - 1));
      }
    }
    if (!eb) { i = begin + 1; continue; }
    size_t bend = static_cast<size_t>(eb - reinterpret_cast<const char*>(data));
    std::string b64(reinterpret_cast<const char*>(data + body_start), bend - body_start);
    Bytes der;
    if (base64_decode(b64, der) && !der.empty()) {
      PemBlock pb;
      pb.label = label;
      pb.der = std::move(der);
      pb.begin_off = abs_offset + begin;
      pb.end_off = abs_offset + bend + endmark.size();
      out.push_back(std::move(pb));
    }
    i = bend + endmark.size();
  }
  return out;
}

bool mostly_printable(const uint8_t* p, size_t n, double frac) {
  if (!n) return false;
  size_t good = 0;
  for (size_t i = 0; i < n; ++i) {
    uint8_t c = p[i];
    if ((c >= 0x20 && c < 0x7f) || c == '\n' || c == '\r' || c == '\t') ++good;
  }
  return static_cast<double>(good) / static_cast<double>(n) >= frac;
}

double byte_entropy(const uint8_t* p, size_t n) {
  if (!n) return 0.0;
  size_t hist[256] = {0};
  for (size_t i = 0; i < n; ++i) ++hist[p[i]];
  double e = 0.0;
  for (int i = 0; i < 256; ++i) {
    if (!hist[i]) continue;
    double pr = static_cast<double>(hist[i]) / static_cast<double>(n);
    e -= pr * std::log2(pr);
  }
  return e;
}

bool looks_hex_string(const uint8_t* p, size_t n, size_t minlen, size_t* run_len) {
  size_t run = 0;
  for (size_t i = 0; i < n; ++i) {
    uint8_t c = p[i];
    bool h = (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F');
    if (h) {
      ++run;
    } else {
      if (run >= minlen) { if (run_len) *run_len = run; return true; }
      run = 0;
    }
  }
  if (run >= minlen) { if (run_len) *run_len = run; return true; }
  return false;
}

}  // namespace kh
