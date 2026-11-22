#include "fast_aes.hpp"

#include <array>
#include <cstring>

#include "aes.hpp"

namespace kh {
namespace {

// 32 KiB of tables, built once.  te0..3 implement SubBytes+ShiftRows+
// MixColumns for encryption; td0..3 the inverse for decryption.
struct Tbl {
  std::array<uint32_t, 256> te0, te1, te2, te3, td0, td1, td2, td3;
  Tbl() {
    auto xt = [](uint8_t x) -> uint8_t { return static_cast<uint8_t>((x << 1) ^ ((x & 0x80) ? 0x1b : 0)); };
    auto mul = [&](uint8_t a, uint8_t b) -> uint8_t {
      uint8_t p = 0;
      while (b) {
        if (b & 1) p ^= a;
        a = xt(a);
        b = static_cast<uint8_t>(b >> 1);
      }
      return p;
    };
    for (int i = 0; i < 256; ++i) {
      uint8_t s = kAesSbox[i];
      uint32_t e = (static_cast<uint32_t>(mul(s, 2)) << 24) | (static_cast<uint32_t>(s) << 16) |
                   (static_cast<uint32_t>(s) << 8) | mul(s, 3);
      te0[i] = e;
      te1[i] = (e >> 8) | (e << 24);
      te2[i] = (e >> 16) | (e << 16);
      te3[i] = (e >> 24) | (e << 8);
      uint8_t v = kAesInvSbox[i];
      uint32_t d = (static_cast<uint32_t>(mul(v, 14)) << 24) | (static_cast<uint32_t>(mul(v, 9)) << 16) |
                   (static_cast<uint32_t>(mul(v, 13)) << 8) | mul(v, 11);
      td0[i] = d;
      td1[i] = (d >> 8) | (d << 24);
      td2[i] = (d >> 16) | (d << 16);
      td3[i] = (d >> 24) | (d << 8);
    }
  }
};
const Tbl& tbl() {
  static Tbl t;
  return t;
}

inline void expand_enc(const uint8_t* key, int nk, uint32_t* rk) {
  for (int i = 0; i < nk; ++i)
    rk[i] = (static_cast<uint32_t>(key[4 * i]) << 24) | (static_cast<uint32_t>(key[4 * i + 1]) << 16) |
            (static_cast<uint32_t>(key[4 * i + 2]) << 8) | key[4 * i + 3];
  int nw = 4 * (nk + 7);
  for (int i = nk; i < nw; ++i) {
    uint32_t t = rk[i - 1];
    int r = i % nk;
    if (r == 0) t = aes_subword(aes_rotl8(t)) ^ (static_cast<uint32_t>(kRcon[i / nk]) << 24);
    else if (nk == 8 && r == 4) t = aes_subword(t);
    rk[i] = rk[i - nk] ^ t;
  }
}

// OpenSSL-style decryption round keys (InvMixColumns on inner rounds, blocks
// reversed) for the equivalent inverse cipher.
inline void make_dec_rk(const uint32_t* enc, int nk, uint32_t* dk) {
  int rounds = nk + 6;
  for (int j = 0; j < 4; ++j) dk[j] = enc[4 * rounds + j];
  for (int r = 1; r < rounds; ++r)
    for (int j = 0; j < 4; ++j) dk[4 * r + j] = aes_invmix_word(enc[4 * (rounds - r) + j]);
  for (int j = 0; j < 4; ++j) dk[4 * rounds + j] = enc[j];
}

inline void load_block(const uint8_t in[16], uint32_t s[4]) {
  for (int i = 0; i < 4; ++i)
    s[i] = (static_cast<uint32_t>(in[4 * i]) << 24) | (static_cast<uint32_t>(in[4 * i + 1]) << 16) |
           (static_cast<uint32_t>(in[4 * i + 2]) << 8) | in[4 * i + 3];
}

inline void store_block(const uint32_t s[4], uint8_t out[16]) {
  for (int i = 0; i < 4; ++i) {
    out[4 * i + 0] = static_cast<uint8_t>(s[i] >> 24);
    out[4 * i + 1] = static_cast<uint8_t>(s[i] >> 16);
    out[4 * i + 2] = static_cast<uint8_t>(s[i] >> 8);
    out[4 * i + 3] = static_cast<uint8_t>(s[i]);
  }
}

inline void enc_block(const uint32_t* rk, int rounds, const uint8_t in[16], uint8_t out[16]) {
  const Tbl& T = tbl();
  uint32_t st[4];
  load_block(in, st);
  uint32_t s0 = st[0] ^ rk[0], s1 = st[1] ^ rk[1], s2 = st[2] ^ rk[2], s3 = st[3] ^ rk[3];
  for (int r = 1; r < rounds; ++r) {
    uint32_t t0 = T.te0[s0 >> 24] ^ T.te1[(s1 >> 16) & 0xff] ^ T.te2[(s2 >> 8) & 0xff] ^ T.te3[s3 & 0xff] ^ rk[4 * r];
    uint32_t t1 = T.te0[s1 >> 24] ^ T.te1[(s2 >> 16) & 0xff] ^ T.te2[(s3 >> 8) & 0xff] ^ T.te3[s0 & 0xff] ^ rk[4 * r + 1];
    uint32_t t2 = T.te0[s2 >> 24] ^ T.te1[(s3 >> 16) & 0xff] ^ T.te2[(s0 >> 8) & 0xff] ^ T.te3[s1 & 0xff] ^ rk[4 * r + 2];
    uint32_t t3 = T.te0[s3 >> 24] ^ T.te1[(s0 >> 16) & 0xff] ^ T.te2[(s1 >> 8) & 0xff] ^ T.te3[s2 & 0xff] ^ rk[4 * r + 3];
    s0 = t0; s1 = t1; s2 = t2; s3 = t3;
  }
  auto fin = [&](uint32_t a, uint32_t b, uint32_t c, uint32_t d, uint32_t k) {
    return ((static_cast<uint32_t>(kAesSbox[a >> 24]) << 24) |
            (static_cast<uint32_t>(kAesSbox[(b >> 16) & 0xff]) << 16) |
            (static_cast<uint32_t>(kAesSbox[(c >> 8) & 0xff]) << 8) |
            static_cast<uint32_t>(kAesSbox[d & 0xff])) ^ k;
  };
  uint32_t o[4] = {fin(s0, s1, s2, s3, rk[4 * rounds]), fin(s1, s2, s3, s0, rk[4 * rounds + 1]),
                   fin(s2, s3, s0, s1, rk[4 * rounds + 2]), fin(s3, s0, s1, s2, rk[4 * rounds + 3])};
  store_block(o, out);
}

inline void dec_block(const uint32_t* dk, int rounds, const uint8_t in[16], uint8_t out[16]) {
  const Tbl& T = tbl();
  uint32_t st[4];
  load_block(in, st);
  uint32_t s0 = st[0] ^ dk[0], s1 = st[1] ^ dk[1], s2 = st[2] ^ dk[2], s3 = st[3] ^ dk[3];
  for (int r = 1; r < rounds; ++r) {
    uint32_t t0 = T.td0[s0 >> 24] ^ T.td1[(s3 >> 16) & 0xff] ^ T.td2[(s2 >> 8) & 0xff] ^ T.td3[s1 & 0xff] ^ dk[4 * r];
    uint32_t t1 = T.td0[s1 >> 24] ^ T.td1[(s0 >> 16) & 0xff] ^ T.td2[(s3 >> 8) & 0xff] ^ T.td3[s2 & 0xff] ^ dk[4 * r + 1];
    uint32_t t2 = T.td0[s2 >> 24] ^ T.td1[(s1 >> 16) & 0xff] ^ T.td2[(s0 >> 8) & 0xff] ^ T.td3[s3 & 0xff] ^ dk[4 * r + 2];
    uint32_t t3 = T.td0[s3 >> 24] ^ T.td1[(s2 >> 16) & 0xff] ^ T.td2[(s1 >> 8) & 0xff] ^ T.td3[s0 & 0xff] ^ dk[4 * r + 3];
    s0 = t0; s1 = t1; s2 = t2; s3 = t3;
  }
  auto fin = [&](uint32_t a, uint32_t b, uint32_t c, uint32_t d, uint32_t k) {
    return ((static_cast<uint32_t>(kAesInvSbox[a >> 24]) << 24) |
            (static_cast<uint32_t>(kAesInvSbox[(b >> 16) & 0xff]) << 16) |
            (static_cast<uint32_t>(kAesInvSbox[(c >> 8) & 0xff]) << 8) |
            static_cast<uint32_t>(kAesInvSbox[d & 0xff])) ^ k;
  };
  uint32_t o[4] = {fin(s0, s3, s2, s1, dk[4 * rounds]), fin(s1, s0, s3, s2, dk[4 * rounds + 1]),
                   fin(s2, s1, s0, s3, dk[4 * rounds + 2]), fin(s3, s2, s1, s0, dk[4 * rounds + 3])};
  store_block(o, out);
}

}  // namespace

void aes_encrypt_block(const uint8_t* key, size_t keylen, const uint8_t in[16], uint8_t out[16]) {
  int nk = aes_nk_from_len(keylen);
  if (!nk) return;
  uint32_t rk[kAesMaxWords];
  expand_enc(key, nk, rk);
  enc_block(rk, nk + 6, in, out);
}

void aes_decrypt_block(const uint8_t* key, size_t keylen, const uint8_t in[16], uint8_t out[16]) {
  int nk = aes_nk_from_len(keylen);
  if (!nk) return;
  uint32_t rk[kAesMaxWords], dk[kAesMaxWords];
  expand_enc(key, nk, rk);
  make_dec_rk(rk, nk, dk);
  dec_block(dk, nk + 6, in, out);
}

void aes_encrypt_many(const uint8_t* key, size_t keylen, const uint8_t* in, size_t n, uint8_t* out) {
  int nk = aes_nk_from_len(keylen);
  if (!nk) return;
  uint32_t rk[kAesMaxWords];
  expand_enc(key, nk, rk);
  for (size_t i = 0; i < n; ++i) enc_block(rk, nk + 6, in + 16 * i, out + 16 * i);
}

void aes_decrypt_many(const uint8_t* key, size_t keylen, const uint8_t* in, size_t n, uint8_t* out) {
  int nk = aes_nk_from_len(keylen);
  if (!nk) return;
  uint32_t rk[kAesMaxWords], dk[kAesMaxWords];
  expand_enc(key, nk, rk);
  make_dec_rk(rk, nk, dk);
  for (size_t i = 0; i < n; ++i) dec_block(dk, nk + 6, in + 16 * i, out + 16 * i);
}

void aes_mixed_many(const uint8_t* key, size_t keylen,
                    const uint8_t* const* dec_in, size_t ndec, uint8_t* dec_out,
                    const uint8_t* const* enc_in, size_t nenc, uint8_t* enc_out) {
  int nk = aes_nk_from_len(keylen);
  if (!nk) return;
  uint32_t rk[kAesMaxWords], dk[kAesMaxWords];
  expand_enc(key, nk, rk);
  if (ndec) make_dec_rk(rk, nk, dk);
  for (size_t i = 0; i < ndec; ++i) dec_block(dk, nk + 6, dec_in[i], dec_out + 16 * i);
  for (size_t i = 0; i < nenc; ++i) enc_block(rk, nk + 6, enc_in[i], enc_out + 16 * i);
}

}  // namespace kh
