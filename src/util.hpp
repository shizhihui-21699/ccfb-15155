// Small, dependency-free primitives shared by every stage of the tool.
#pragma once
#include <cstdint>
#include <cstddef>
#include <cstring>
#include <string>
#include <vector>

namespace kh {

using Bytes = std::vector<uint8_t>;

inline uint16_t rd16(const uint8_t* p) { return static_cast<uint16_t>(p[0] | (p[1] << 8)); }
inline uint32_t rd32(const uint8_t* p) {
  return static_cast<uint32_t>(p[0]) | (static_cast<uint32_t>(p[1]) << 8) |
         (static_cast<uint32_t>(p[2]) << 16) | (static_cast<uint32_t>(p[3]) << 24);
}
inline uint64_t rd64(const uint8_t* p) {
  return static_cast<uint64_t>(rd32(p)) | (static_cast<uint64_t>(rd32(p + 4)) << 32);
}
inline uint32_t rd32be(const uint8_t* p) {
  return (static_cast<uint32_t>(p[0]) << 24) | (static_cast<uint32_t>(p[1]) << 16) |
         (static_cast<uint32_t>(p[2]) << 8) | static_cast<uint32_t>(p[3]);
}

constexpr uint64_t kMaxImage = 1ull << 40;  // 1 TiB sanity ceiling

// Bit helpers on raw byte buffers, treating memory as little-endian limb arrays.
inline int bit_length(const uint8_t* be, size_t n) {
  size_t i = 0;
  while (i < n && be[i] == 0) ++i;
  if (i == n) return 0;
  int top = 0;
  for (int b = 7; b >= 0; --b)
    if (be[i] & (1u << b)) { top = b + 1; break; }
  return static_cast<int>((n - i - 1) * 8 + top);
}

inline int popcount8(uint8_t v) {
  v = static_cast<uint8_t>(v - ((v >> 1) & 0x55));
  v = static_cast<uint8_t>((v & 0x33) + ((v >> 2) & 0x33));
  return (v + (v >> 4)) & 0x0f;
}
inline int popcount32(uint32_t v) {
  v = v - ((v >> 1) & 0x55555555u);
  v = (v & 0x33333333u) + ((v >> 2) & 0x33333333u);
  v = (v + (v >> 4)) & 0x0f0f0f0fu;
  return static_cast<int>((v * 0x01010101u) >> 24);
}

inline bool constant_time_eq(const uint8_t* a, const uint8_t* b, size_t n) {
  uint8_t d = 0;
  for (size_t i = 0; i < n; ++i) d |= static_cast<uint8_t>(a[i] ^ b[i]);
  return d == 0;
}

inline std::string hex(const uint8_t* p, size_t n) {
  static const char* h = "0123456789abcdef";
  std::string s;
  s.reserve(n * 2);
  for (size_t i = 0; i < n; ++i) {
    s.push_back(h[p[i] >> 4]);
    s.push_back(h[p[i] & 15]);
  }
  return s;
}
inline std::string hex(const Bytes& b) { return hex(b.data(), b.size()); }

inline bool unhex(const std::string& s, Bytes& out) {
  out.clear();
  auto val = [](char c) -> int {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
  };
  if (s.size() % 2) return false;
  for (size_t i = 0; i < s.size(); i += 2) {
    int a = val(s[i]), b = val(s[i + 1]);
    if (a < 0 || b < 0) return false;
    out.push_back(static_cast<uint8_t>((a << 4) | b));
  }
  return true;
}

}  // namespace kh
