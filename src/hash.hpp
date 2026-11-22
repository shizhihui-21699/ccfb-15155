#pragma once
#include <array>
#include <cstdint>
#include <cstddef>

namespace kh::h {

struct Sha256 {
  uint32_t h[8];
  uint64_t len = 0;
  uint8_t buf[64];
  size_t buflen = 0;

  Sha256();
  void update(const void* data, size_t n);
  void final(uint8_t out[32]);
};

struct Sha512 {
  uint64_t h[8];
  uint64_t len = 0;
  uint8_t buf[128];
  size_t buflen = 0;

  Sha512();
  void update(const void* data, size_t n);
  void final(uint8_t out[64]);
};

struct Md5 {
  uint32_t h[4];
  uint64_t len = 0;
  uint8_t buf[64];
  size_t buflen = 0;
  Md5();
  void update(const void* data, size_t n);
  void final(uint8_t out[16]);
};

inline std::array<uint8_t, 32> sha256(const void* data, size_t n) {
  Sha256 s;
  s.update(data, n);
  std::array<uint8_t, 32> o;
  s.final(o.data());
  return o;
}
inline std::array<uint8_t, 32> sha256(const void* a, size_t na, const void* b, size_t nb) {
  Sha256 s;
  s.update(a, na);
  s.update(b, nb);
  std::array<uint8_t, 32> o;
  s.final(o.data());
  return o;
}

// HMAC-SHA256 support used by PBKDF2; kept here so KDF cracking shares code.
struct HmacSha256 {
  uint8_t k[64];
  explicit HmacSha256(const void* key, size_t n);
  void mac(const void* data, size_t n, uint8_t out[32]);
  void mac2(const void* a, size_t na, const void* b, size_t nb, uint8_t out[32]);
};

// CETI / KBKDF-ish AES-CMAC, used by some loaders; small enough to embed.
void aes_cmac_128(const uint8_t key[16], const uint8_t* msg, size_t len, uint8_t out[16]);

}  // namespace kh::h
