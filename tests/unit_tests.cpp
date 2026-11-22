// Minimal self-contained test harness (no external test framework).
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <random>
#include <string>
#include <algorithm>

#include <openssl/aes.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>

#include "aes.hpp"
#include "fast_aes.hpp"
#include "keysweep.hpp"
#include "der.hpp"
#include "encodings.hpp"
#include "symmetric.hpp"
#include "scanner.hpp"
#include "hash.hpp"
#include "util.hpp"

namespace {
int g_fail = 0;
int g_pass = 0;
#define CHECK(cond)                                                          \
  do {                                                                       \
    if (cond) {                                                              \
      ++g_pass;                                                              \
    } else {                                                                 \
      ++g_fail;                                                              \
      std::printf("FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond);            \
    }                                                                        \
  } while (0)

}  // namespace

// Compare our AES expansion to OpenSSL for all key sizes and many random keys.
void test_aes_matches_openssl() {
  for (int kl : {16, 24, 32}) {
    int nk = kl / 4;
    int nw = kh::aes_nwords(nk);
    for (int t = 0; t < 300; ++t) {
      uint8_t key[32];
      RAND_bytes(key, kl);
      AES_KEY ek, dk;
      AES_set_encrypt_key(key, kl * 8, &ek);
      AES_set_decrypt_key(key, kl * 8, &dk);
      kh::AesSchedule s;
      CHECK(kh::aes_expand(key, kl, s, true));
      CHECK(std::memcmp(s.enc.data(), ek.rd_key, nw * 4) == 0);
      CHECK(std::memcmp(s.dec.data(), dk.rd_key, nw * 4) == 0);
      CHECK(kh::aes_verify_enc(s.enc.data(), nk) == nw);
      CHECK(kh::aes_verify_dec(s.dec.data(), nk) == nw);
      uint8_t raw[32];
      CHECK(kh::aes_dec_to_raw(s.dec.data(), nk, raw));
      CHECK(std::memcmp(raw, key, static_cast<size_t>(kl)) == 0);
    }
  }
}

// The schedule must be reconstructable from any surviving run, including with
// the key words themselves destroyed.
void test_aes_partial_recovery() {
  for (int kl : {16, 24, 32}) {
    int nk = kl / 4;
    int nw = kh::aes_nwords(nk);
    for (int t = 0; t < 50; ++t) {
      uint8_t key[32];
      RAND_bytes(key, kl);
      kh::AesSchedule s;
      kh::aes_expand(key, kl, s, false);

      // (a) any run of nk+1 consecutive words must pin the whole key.
      for (int start = 0; start + nk + 1 <= nw; ++start) {
        std::array<int64_t, kh::kAesMaxWords> known;
        known.fill(-1);
        for (int i = start; i < start + nk + 1; ++i) known[i] = s.enc[i];
        CHECK(kh::aes_reconstruct_enc(known, nk) == nk);
        uint32_t kw[kh::kAesMaxWords];
        for (int i = 0; i < nk; ++i) kw[i] = static_cast<uint32_t>(known[i]);
        uint8_t raw[32];
        kh::aes_words_to_key(kw, nk, raw);
        CHECK(std::memcmp(raw, key, static_cast<size_t>(kl)) == 0);
      }

      // (b) the key-word region destroyed entirely: only words [nk+2, nw)
      // survive and must still rebuild the raw key.
      std::array<int64_t, kh::kAesMaxWords> known;
      known.fill(-1);
      for (int i = nk + 2; i < nw; ++i) known[i] = s.enc[i];
      CHECK(kh::aes_reconstruct_enc(known, nk) == nk);
      uint32_t kw[kh::kAesMaxWords];
      for (int i = 0; i < nk; ++i) kw[i] = static_cast<uint32_t>(known[i]);
      uint8_t raw[32];
      kh::aes_words_to_key(kw, nk, raw);
      CHECK(std::memcmp(raw, key, static_cast<size_t>(kl)) == 0);
    }
  }
}

// FIPS-197 C.1 known answer.
void test_aes_kat() {
  uint8_t key[16] = {0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
                     0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c};
  kh::AesSchedule s;
  kh::aes_expand(key, 16, s, false);
  CHECK(s.enc[4] == 0xa0fafe17u);
  CHECK(s.enc[43] == 0xb6630ca6u);
  // Encrypt the FIPS plaintext with OpenSSL using our derived key and compare.
  uint8_t pt[16] = {0x32, 0x43, 0xf6, 0xa8, 0x88, 0x5a, 0x30, 0x8d,
                    0x31, 0x31, 0x98, 0xa2, 0xe0, 0x37, 0x07, 0x34};
  uint8_t ct[16];
  int outl = 0;
  EVP_CIPHER_CTX* c = EVP_CIPHER_CTX_new();
  EVP_EncryptInit_ex(c, EVP_aes_128_ecb(), nullptr, key, nullptr);
  EVP_CIPHER_CTX_set_padding(c, 0);
  EVP_EncryptUpdate(c, ct, &outl, pt, 16);
  EVP_CIPHER_CTX_free(c);
  const uint8_t want[16] = {0x39, 0x25, 0x84, 0x1d, 0x02, 0xdc, 0x09, 0xfb,
                            0xdc, 0x11, 0x85, 0x97, 0x19, 0x6a, 0x0b, 0x32};
  CHECK(std::memcmp(ct, want, 16) == 0);
}

void test_hash() {
  // "abc"
  auto d = kh::h::sha256("abc", 3);
  CHECK(kh::hex(d.data(), 32) ==
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
  // empty
  auto e = kh::h::sha256("", 0);
  CHECK(kh::hex(e.data(), 32) ==
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
  // sha512 abc
  kh::h::Sha512 s5;
  s5.update("abc", 3);
  uint8_t o[64];
  s5.final(o);
  CHECK(kh::hex(o, 64) ==
        "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a"
        "2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f");
  // md5 abc
  kh::h::Md5 m;
  m.update("abc", 3);
  uint8_t mo[16];
  m.final(mo);
  CHECK(kh::hex(mo, 16) == "900150983cd24fb0d6963f7d28e17f72");
}

// Fast AES must agree with OpenSSL for every key size, both directions.
void test_fast_aes() {
  for (int kl : {16, 24, 32}) {
    for (int t = 0; t < 100; ++t) {
      uint8_t key[32], pt[16], ref[16], mine[16], back[16];
      RAND_bytes(key, kl);
      RAND_bytes(pt, 16);
      AES_KEY ek, dk;
      AES_set_encrypt_key(key, kl * 8, &ek);
      AES_set_decrypt_key(key, kl * 8, &dk);
      AES_encrypt(pt, ref, &ek);
      kh::aes_encrypt_block(key, kl, pt, mine);
      CHECK(std::memcmp(ref, mine, 16) == 0);
      kh::aes_decrypt_block(key, kl, ref, back);
      CHECK(std::memcmp(back, pt, 16) == 0);
      AES_decrypt(ref, ref, &dk);
      CHECK(std::memcmp(ref, pt, 16) == 0);
    }
  }
}

// The raw-key sweep must find an embedded key and stay silent otherwise.
void test_key_sweep() {
  uint8_t key[32];
  RAND_bytes(key, 32);
  // Build a CBC-IV-prepended sample whose plaintext starts with "%PDF-1.7".
  uint8_t iv[16], p0[16] = {'%', 'P', 'D', 'F', '-', '1', '.', '7'};
  RAND_bytes(iv, 16);
  uint8_t ct0[16];
  // E(P0 xor IV) = C0  (encrypt the first block)
  uint8_t x[16];
  for (int i = 0; i < 16; ++i) x[i] = static_cast<uint8_t>(p0[i] ^ iv[i]);
  kh::aes_encrypt_block(key, 32, x, ct0);
  kh::Sample s;
  s.header.insert(s.header.end(), iv, iv + 16);
  s.header.insert(s.header.end(), ct0, ct0 + 16);
  s.header.resize(4096, 0x41);
  auto plan = kh::build_sweep_plan(s);
  CHECK(!plan.empty());
  std::vector<uint8_t> buf(8192, 0x5a);
  std::memcpy(buf.data() + 4000, key, 32);
  std::vector<kh::KeyHit> hits;
  kh::sweep_raw_keys(buf.data(), buf.size(), 0, plan, hits);
  CHECK(hits.size() == 1);
  if (!hits.empty()) {
    CHECK(hits[0].offset == 4000);
    CHECK(std::memcmp(hits[0].key, key, 32) == 0);
  }
  // Noise must not produce hits.
  std::vector<uint8_t> noise(65536);
  RAND_bytes(noise.data(), static_cast<int>(noise.size()));
  std::vector<kh::KeyHit> nh;
  kh::sweep_raw_keys(noise.data(), noise.size(), 0, plan, nh);
  CHECK(nh.empty());
}

void test_der() {
  // SEQUENCE { INTEGER 0, INTEGER n, INTEGER 65537, OCTET STRING ... }
  const uint8_t der[] = {0x30, 0x0b, 0x02, 0x01, 0x00, 0x02, 0x02, 0x12, 0x34,
                         0x02, 0x02, 0x01, 0x00, 0x00, 0x00};
  kh::Tlv t;
  CHECK(kh::der_next(der, sizeof der, 0, t, true));
  CHECK(t.tag == 0x30);
  auto kids = kh::der_children(der, sizeof der, t);
  CHECK(kids.size() == 3);
  CHECK(kids[0].tag == 0x02);
  // base64 roundtrip
  kh::Bytes in = {0, 1, 2, 3, 250, 251, 252, 253, 254, 255};
  auto enc = kh::base64_encode(in);
  kh::Bytes out;
  CHECK(kh::base64_decode(enc, out));
  CHECK(out == in);
}

// Chunk planning must cover the range with no gaps and respect the overlap.
void test_chunk_plan() {
  for (uint64_t sz : {100ull, 4096ull, 100000ull}) {
    for (uint64_t chunk : {16ull, 30ull, 1024ull}) {
      auto c = kh::plan_chunks(0, sz, chunk, 8, 1);
      CHECK(!c.empty());
      uint64_t reach = 0;
      for (const auto& x : c) {
        CHECK(x.offset <= reach);   // no gap
        reach = std::max(reach, x.offset + x.len);
      }
      CHECK(reach >= sz);
    }
  }
  // Aligned start must be honoured.
  auto c = kh::plan_chunks(5000, 9000, 1024, 0, 4096);
  CHECK(c.front().offset == 4096);
}

int run_all() {
  test_aes_kat();
  test_aes_matches_openssl();
  test_aes_partial_recovery();
  test_hash();
  test_fast_aes();
  test_key_sweep();
  test_der();
  test_chunk_plan();
  std::printf("unit: %d passed, %d failed\n", g_pass, g_fail);
  return g_fail == 0 ? 0 : 1;
}

int main() { return run_all(); }
