// AES key-schedule modelling for memory forensics.
//
// Layout modelled
// ---------------
// The dominant in-memory artefact is a *key schedule*, not a raw key:
//   OpenSSL  AES_KEY      { uint32_t rd_key[4*(rounds+1)]; int rounds; }
//   mbedTLS  aes_encrypt_ctx { uint32_t rk[68]; ... }
//   Go       aesCipher    { enc []uint32 }   (heap slice of round keys)
//   RustCrypto aes::Aes256  round-key array
// All of them hold FIPS-197 round-key *words* as native uint32 values.
//
// Invariants (verified exhaustively against OpenSSL 4.x for nk in {4,6,8}):
//
//   Encryption schedule, with P = nk:
//     (L) free words   : w[i] == w[i-P] ^ w[i-1]
//                        for i%P in {1,2,3} and additionally
//                        i%P in {5,6,7} when P==8
//     (N0) key-schedule: w[i] == w[i-P] ^ SubWord(RotL8(w[i-1])) ^ (rc[i/P] << 24)
//                        for i%P == 0
//     (N4) 256-bit      : w[i] == w[i-P] ^ SubWord(w[i-1])   for i%P == 4
//
//   Decryption schedule (OpenSSL's InvMixColumn'd, reversed layout):
//     (D) interior blocks: d[i] == d[i+4] ^ d[i-1] for i%4 != 0, 4 <= i < nw-4
//     and block 0 holds the final enc round, the last block the raw key.
//
// (L) costs two XORs, so it is the byte-level prefilter.  (N0)/(N4) cost four
// S-box lookups and turn a hit into proof.  Both are fully invertible, so any
// surviving run of words -- even with holes -- propagates back to words 0..P-1,
// i.e. the raw key.  That is the damaged/paged-out recovery path.
#pragma once
#include <cstdint>
#include <array>
#include "util.hpp"

namespace kh {

constexpr int kAesMaxWords = 60;

extern const uint8_t kRcon[11];
extern const uint8_t kAesSbox[256];
extern const uint8_t kAesInvSbox[256];

inline uint32_t aes_subword(uint32_t x) {
  return static_cast<uint32_t>(kAesSbox[x & 0xff]) |
         (static_cast<uint32_t>(kAesSbox[(x >> 8) & 0xff]) << 8) |
         (static_cast<uint32_t>(kAesSbox[(x >> 16) & 0xff]) << 16) |
         (static_cast<uint32_t>(kAesSbox[(x >> 24) & 0xff]) << 24);
}
inline uint32_t aes_rotl8(uint32_t x) { return (x << 8) | (x >> 24); }
inline uint32_t aes_rotr8(uint32_t x) { return (x >> 8) | (x << 24); }

inline int aes_nk_from_len(size_t n) { return n == 16 ? 4 : n == 24 ? 6 : n == 32 ? 8 : 0; }
inline int aes_nwords(int nk) { return 4 * (nk + 7); }
inline int aes_rounds(int nk) { return nk + 6; }

// True when word index i of an encryption schedule is a "free" (linear) word.
inline bool aes_enc_free_word(int i, int nk) {
  int r = i % nk;
  if (r == 0) return false;
  if (nk == 8 && r == 4) return false;
  return true;
}

uint32_t aes_invmix_word(uint32_t w);
uint32_t aes_mix_word(uint32_t w);

struct AesSchedule {
  int nk = 0;
  int rounds = 0;
  int nwords = 0;
  std::array<uint32_t, kAesMaxWords> enc{};
  std::array<uint32_t, kAesMaxWords> dec{};
};

bool aes_expand(const uint8_t* key, size_t keylen, AesSchedule& out, bool want_dec = true);
bool aes_expand_words(const uint32_t* w, int nk, AesSchedule& out, bool want_dec = true);

// Canonical schedule words are BIG-ENDIAN values, which is also just a native
// load of the bytes OpenSSL writes (verified against OpenSSL 4.x).  Every byte
// permutation commutes with XOR, so the linear relation (L) holds for
// little-endian / other layouts too; only (N0)/(N4) depend on word order, which
// the verifiers handle by trying both.
inline uint32_t aes_keyword(const uint8_t* key, int i) {
  return (static_cast<uint32_t>(key[4 * i]) << 24) | (static_cast<uint32_t>(key[4 * i + 1]) << 16) |
         (static_cast<uint32_t>(key[4 * i + 2]) << 8) | static_cast<uint32_t>(key[4 * i + 3]);
}

// Recover the raw key from an encryption schedule held in canonical word order.
inline void aes_words_to_key(const uint32_t* w, int nk, uint8_t raw[32]) {
  for (int i = 0; i < nk * 4; ++i) raw[i] = static_cast<uint8_t>(w[i / 4] >> (24 - 8 * (i % 4)));
}

// Verify a window as an *encryption* schedule; returns matched word count.
int aes_verify_enc(const uint32_t* w, int nk);
// Verify a window as a *decryption* schedule; returns matched word count.
int aes_verify_dec(const uint32_t* w, int nk);
// Convert a decryption schedule to the implied encryption schedule / raw key.
bool aes_dec_to_raw(const uint32_t* dec_words, int nk, uint8_t raw[32]);

// Partial recovery: `known` is indexed by encryption-schedule word index and
// holds -1 when unknown, otherwise the low 32 bits of the word.  Propagates the
// recurrence (L)/(N0)/(N4) in both directions and reports how many of the nk
// key words became known.  Returns that count.
int aes_reconstruct_enc(std::array<int64_t, kAesMaxWords>& known, int nk);

// Byte-order variant: some implementations write schedule words big-endian.
inline uint32_t bswap32(uint32_t x) {
  return ((x & 0x000000ffu) << 24) | ((x & 0x0000ff00u) << 8) | ((x & 0x00ff0000u) >> 8) |
         ((x & 0xff000000u) >> 24);
}

}  // namespace kh
