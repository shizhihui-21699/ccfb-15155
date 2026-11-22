// keyhunt-genimg -- build a synthetic memory image with planted keys.
//
// The image is a set of 4 KiB "pages" holding:
//   * heap-like chunks of random bytes, zero pages and repeated padding;
//   * real key material in the layouts implementations actually produce:
//       - AES encryption schedules (OpenSSL AES_KEY.rd_key) for 128/192/256,
//         both "fresh" and as left behind after cipher teardown;
//       - an OpenSSL AES_KEY *decrypt* schedule with its rounds trailer;
//       - AES schedules with 1..3 corrupted words (damaged/paged-out pages);
//       - raw 32-byte AES keys and ChaCha20 state blocks;
//       - DER private keys: RSA PKCS#1/PKCS#8, EC SEC1/PKCS#8, Ed25519/X25519,
//         DSA, plus an encrypted PKCS#8 and a PKCS#12;
//       - PEM copies of some of the above, and an OpenSSH ed25519 key;
//       - an RSA key whose DER is damaged so only n/e/d survive;
//   * decoy high-entropy blobs that look key-like but are not, and decoy DER
//     sequences that are almost-right, so precision is measurable.
//
// A manifest JSON records ground truth (offset, type, key hex) for evaluation.
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <random>
#include <set>
#include <string>
#include <vector>

#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/ec.h>
#include <openssl/core_names.h>
#include <openssl/param_build.h>
#include <openssl/pkcs12.h>
#include <openssl/x509.h>
#include <openssl/rand.h>
#include <openssl/provider.h>
#include <openssl/dsa.h>

#include "aes.hpp"
#include "hash.hpp"
#include "privkey.hpp"
#include "util.hpp"

namespace {

using kh::Bytes;

struct Planted {
  std::string type;
  uint64_t offset = 0;
  uint64_t length = 0;
  std::string key_hex;
  std::string detail;
  bool expect_detect = true;
};

std::mt19937_64 g_rng(0xC0FFEE1234ull);

Bytes rand_bytes(size_t n) {
  Bytes b(n);
  if (n) RAND_bytes(b.data(), static_cast<int>(n));
  return b;
}

class Image {
 public:
  explicit Image(size_t pages) : pages_(pages), buf_(pages * 4096) {
    // Start life as plausible process memory: mostly random heap with zero and
    // text-like regions, so the detector cannot cheat on uniform noise.
    for (size_t p = 0; p < pages; ++p) {
      uint8_t* pg = buf_.data() + p * 4096;
      uint32_t r = static_cast<uint32_t>(g_rng());
      if (r % 11 == 0) {
        std::memset(pg, 0, 4096);                       // freed / zeroed page
      } else if (r % 11 == 1) {
        std::memset(pg, 0xaa, 4096);                    // poison fill
      } else if (r % 11 == 2) {
        // ASCII-ish page (log lines, source text)
        static const char* words[] = {"the", "process", "encrypt", "buffer", "size", "free",
                                      "alloc", "thread", "file", "path", "error", "open"};
        size_t o = 0;
        while (o < 4096) {
          const char* w = words[g_rng() % 12];
          size_t l = std::strlen(w);
          if (o + l + 1 >= 4096) break;
          std::memcpy(pg + o, w, l);
          o += l;
          pg[o++] = (g_rng() % 9 == 0) ? '\n' : ' ';
        }
        std::memset(pg + o, 0, 4096 - o);
      } else {
        RAND_bytes(pg, 4096);
      }
    }
  }

  uint8_t* data() { return buf_.data(); }
  size_t size() const { return buf_.size(); }

  uint64_t plant(const Bytes& blob, const std::string& type, const std::string& key_hex,
                 const std::string& detail, bool expect = true, bool keep_page = true) {
    uint64_t off = choose_slot(blob.size());
    std::memcpy(buf_.data() + off, blob.data(), blob.size());
    planted_.push_back({type, off, blob.size(), key_hex, detail, expect});
    if (keep_page) {
      // The 16 bytes after the blob in real memory are whatever the allocator
      // left; make them random rather than zero so we do not leak structure.
      size_t tail = std::min<size_t>(32, size() - off - blob.size());
      if (tail) RAND_bytes(buf_.data() + off + blob.size(), static_cast<int>(tail));
    }
    return off;
  }

  const std::vector<Planted>& planted() const { return planted_; }

  bool save(const std::string& path) const {
    FILE* f = std::fopen(path.c_str(), "wb");
    if (!f) return false;
    size_t n = std::fwrite(buf_.data(), 1, buf_.size(), f);
    std::fclose(f);
    return n == buf_.size();
  }

 private:
  uint64_t choose_slot(size_t len) {
    size_t need_pages = (len + 4096 - 1) / 4096 + 1;
    for (int tries = 0; tries < 10000; ++tries) {
      size_t p = g_rng() % (pages_ > need_pages ? pages_ - need_pages : 0ull);
      bool ok = true;
      for (size_t q = p; q < p + need_pages && q < pages_; ++q)
        if (used_.count(q)) { ok = false; break; }
      if (!ok) continue;
      for (size_t q = p; q < p + need_pages; ++q) used_.insert(q);
      // Align to 16 unless the caller wants byte precision (they truncate).
      size_t within = (g_rng() % 200) * 16;
      uint64_t off = static_cast<uint64_t>(p) * 4096 + within;
      if (off + len > size()) off = static_cast<uint64_t>(p) * 4096;
      return off;
    }
    return 0;
  }

  size_t pages_;
  Bytes buf_;
  std::vector<Planted> planted_;
  std::set<size_t> used_;
};

// ---- key material builders ------------------------------------------------

Bytes aes_schedule_bytes(const Bytes& key, bool decrypt_schedule, bool with_rounds) {
  kh::AesSchedule s;
  kh::aes_expand(key.data(), key.size(), s, true);
  const uint32_t* w = decrypt_schedule ? s.dec.data() : s.enc.data();
  int nw = s.nwords;
  Bytes out(static_cast<size_t>(nw) * 4 + (with_rounds ? 4 : 0));
  // Round-key words are stored as native little-endian uint32; a native load of
  // those bytes equals the canonical big-endian word our model uses.
  for (int i = 0; i < nw; ++i) {
    // OpenSSL holds rd_key[] as native uint32 values, i.e. little-endian bytes
    // on x86/ARM64.  Store them the same way so a native load yields the
    // canonical big-endian word our detector works with.
    uint32_t v = w[i];
    std::memcpy(out.data() + i * 4, &v, 4);
  }
  if (with_rounds) {
    uint32_t r = static_cast<uint32_t>(s.rounds);
    std::memcpy(out.data() + nw * 4, &r, 4);
  }
  return out;
}

Bytes chacha_state_bytes(const Bytes& key, uint32_t counter, const uint8_t nonce[12]) {
  Bytes out(64);
  uint32_t w[16] = {0x61707865u, 0x3320646eu, 0x79622d32u, 0x6b206574u};
  for (int i = 0; i < 8; ++i)
    w[4 + i] = static_cast<uint32_t>(key[i * 4]) | (static_cast<uint32_t>(key[i * 4 + 1]) << 8) |
               (static_cast<uint32_t>(key[i * 4 + 2]) << 16) | (static_cast<uint32_t>(key[i * 4 + 3]) << 24);
  w[12] = counter;
  for (int i = 0; i < 3; ++i)
    w[13 + i] = static_cast<uint32_t>(nonce[i * 4]) | (static_cast<uint32_t>(nonce[i * 4 + 1]) << 8) |
                (static_cast<uint32_t>(nonce[i * 4 + 2]) << 16) | (static_cast<uint32_t>(nonce[i * 4 + 3]) << 24);
  std::memcpy(out.data(), w, 64);
  return out;
}

EVP_PKEY* gen_rsa(int bits) {
  EVP_PKEY_CTX* c = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, nullptr);
  EVP_PKEY_keygen_init(c);
  EVP_PKEY_CTX_set_rsa_keygen_bits(c, bits);
  EVP_PKEY* k = nullptr;
  EVP_PKEY_keygen(c, &k);
  EVP_PKEY_CTX_free(c);
  return k;
}

EVP_PKEY* gen_ec(const char* curve) {
  EVP_PKEY_CTX* c = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, nullptr);
  EVP_PKEY_keygen_init(c);
  EVP_PKEY_CTX_set_ec_paramgen_curve_nid(c, OBJ_sn2nid(curve));
  EVP_PKEY* k = nullptr;
  EVP_PKEY_keygen(c, &k);
  EVP_PKEY_CTX_free(c);
  return k;
}

EVP_PKEY* gen_dsa(int bits) {
  // OpenSSL 4 refuses DSA keygen through the provider path; the legacy API
  // still works and produces exactly the DER we want to test against.
  DSA* d = DSA_new();
  if (!d) return nullptr;
  if (DSA_generate_parameters_ex(d, bits, nullptr, 0, nullptr, nullptr, nullptr) != 1 ||
      DSA_generate_key(d) != 1) {
    DSA_free(d);
    return nullptr;
  }
  EVP_PKEY* k = EVP_PKEY_new();
  if (!k || EVP_PKEY_set1_DSA(k, d) != 1) {
    EVP_PKEY_free(k);
    DSA_free(d);
    return nullptr;
  }
  DSA_free(d);
  return k;
}

Bytes pkey_der(EVP_PKEY* k) {
  if (!k) { std::fprintf(stderr, "pkey_der: null key\n"); return {}; }
  unsigned char* d = nullptr;
  int n = i2d_PrivateKey(k, &d);
  Bytes out;
  if (n > 0) out.assign(d, d + n);
  OPENSSL_free(d);
  return out;
}

Bytes pkey_pem(EVP_PKEY* k) {
  if (!k) return {};
  BIO* b = BIO_new(BIO_s_mem());
  PEM_write_bio_PrivateKey(b, k, nullptr, nullptr, 0, nullptr, nullptr);
  char* p = nullptr;
  long n = BIO_get_mem_data(b, &p);
  Bytes out(p, p + n);
  BIO_free(b);
  return out;
}

Bytes rsa_pkcs1_der(EVP_PKEY* k) {
  RSA* r = k ? const_cast<RSA*>(EVP_PKEY_get0_RSA(k)) : nullptr;
  if (!r) return {};
  unsigned char* d = nullptr;
  int n = i2d_RSAPrivateKey(r, &d);
  Bytes out;
  if (n > 0) out.assign(d, d + n);
  OPENSSL_free(d);
  return out;
}

Bytes encrypted_pkcs8(EVP_PKEY* k, const char* pass) {
  BIO* b = BIO_new(BIO_s_mem());
  PEM_write_bio_PrivateKey(b, k, EVP_aes_256_cbc(), nullptr, 0, nullptr, const_cast<char*>(pass));
  char* p = nullptr;
  long n = BIO_get_mem_data(b, &p);
  std::string pem(p, p + n);
  BIO_free(b);
  // extract DER from the PEM body
  auto blocks = kh::find_pem_blocks(reinterpret_cast<const uint8_t*>(pem.data()), pem.size(), 0);
  if (blocks.empty()) return {};
  return blocks[0].der;
}

Bytes pkcs12_der(EVP_PKEY* k, const char* pass) {
  PKCS12* p = PKCS12_create(pass, "keyhunt", k, nullptr, nullptr, 0, 0, 0, 0, 0);
  if (!p) return {};
  unsigned char* d = nullptr;
  int n = i2d_PKCS12(p, &d);
  Bytes out;
  if (n > 0) out.assign(d, d + n);
  OPENSSL_free(d);
  PKCS12_free(p);
  return out;
}

std::string bn_param(EVP_PKEY* k, const char* name) {
  BIGNUM* b = nullptr;
  if (EVP_PKEY_get_bn_param(k, name, &b) != 1) return {};
  std::string h = kh::Bn(BN_dup(b)).to_hex();
  BN_free(b);
  return h;
}

// Build a PKCS#1 DER from explicit n,e,d (no factors) to exercise recovery.
Bytes pkcs1_from_nd(const std::string& n_hex, const std::string& e_hex, const std::string& d_hex) {
  // Minimal, syntactically valid RSAPrivateKey with absent CRT fields is not
  // legal ASN.1 (they are mandatory), so instead emit a PKCS#8-like structure
  // the finder will salvage: SEQUENCE { INTEGER 0, INTEGER n, INTEGER e, INTEGER d }
  // is exactly what a truncated file looks like.
  auto tlv = [](uint8_t tag, const Bytes& body) {
    Bytes out;
    out.push_back(tag);
    size_t l = body.size();
    if (l < 0x80) {
      out.push_back(static_cast<uint8_t>(l));
    } else if (l < 0x100) {
      out.push_back(0x81);
      out.push_back(static_cast<uint8_t>(l));
    } else {
      out.push_back(0x82);
      out.push_back(static_cast<uint8_t>(l >> 8));
      out.push_back(static_cast<uint8_t>(l));
    }
    out.insert(out.end(), body.begin(), body.end());
    return out;
  };
  auto integer_of_hex = [&](std::string h) {
    Bytes b;
    if (h.size() % 2) h = "0" + h;
    kh::unhex(h, b);
    if (!b.empty() && (b[0] & 0x80)) b.insert(b.begin(), 0);
    return tlv(0x02, b);
  };
  Bytes body;
  Bytes zero = {0};
  auto v0 = tlv(0x02, zero);
  Bytes nb = integer_of_hex(n_hex), eb = integer_of_hex(e_hex), db = integer_of_hex(d_hex);
  body.insert(body.end(), v0.begin(), v0.end());
  body.insert(body.end(), nb.begin(), nb.end());
  body.insert(body.end(), eb.begin(), eb.end());
  body.insert(body.end(), db.begin(), db.end());
  return tlv(0x30, body);
}

}  // namespace

int main(int argc, char** argv) {
  OSSL_PROVIDER_load(nullptr, "default");
  std::string out = "image.raw";
  std::string manifest = "";
  size_t mib = 96;
  std::string sample_out;
  for (int i = 1; i < argc; ++i) {
    std::string a = argv[i];
    if (a == "-o" && i + 1 < argc) out = argv[++i];
    else if (a == "-m" && i + 1 < argc) manifest = argv[++i];
    else if (a == "--mib" && i + 1 < argc) mib = static_cast<size_t>(std::strtoul(argv[++i], nullptr, 0));
    else if (a == "--sample" && i + 1 < argc) sample_out = argv[++i];
    else { std::fprintf(stderr, "unknown arg %s\n", a.c_str()); return 2; }
  }
  size_t pages = (mib * 1024 * 1024) / 4096;
  Image img(pages);

  std::vector<std::pair<std::string, Bytes>> secrets;  // name -> plaintext

  // ---- symmetric keys planted as live schedules -------------------------
  for (int bits : {256, 128, 192, 256, 128}) {
    Bytes key = rand_bytes(bits / 8);
    std::string type = "aes-" + std::to_string(bits) + "-enc-schedule";
    auto blob = aes_schedule_bytes(key, false, true);
    img.plant(blob, type, kh::hex(key), "OpenSSL AES_KEY.rd_key + rounds");
  }
  // decrypt schedule with rounds trailer
  {
    Bytes key = rand_bytes(32);
    auto blob = aes_schedule_bytes(key, true, true);
    img.plant(blob, "aes-256-dec-schedule", kh::hex(key), "OpenSSL decrypt schedule");
  }
  // damaged encryption schedules: zero out consecutive words to simulate a page
  // that was partially overwritten before capture
  for (int variant = 0; variant < 4; ++variant) {
    Bytes key = rand_bytes(32);
    auto blob = aes_schedule_bytes(key, false, false);
    size_t nw = blob.size() / 4;
    int holes = 1 + variant;
    // Do not touch the first 8 words (the raw key) except in the last variant.
    for (int h = 0; h < holes; ++h) {
      size_t idx = (variant == 3) ? (g_rng() % 6) : (8 + g_rng() % (nw - 8));
      std::memset(blob.data() + idx * 4, 0, 4 * (1 + g_rng() % 2));
    }
    img.plant(blob, "aes-256-enc-schedule-damaged", kh::hex(key),
              "schedule with " + std::to_string(holes) + " zeroed word(s)");
  }

  // ---- raw keys + ChaCha -------------------------------------------------
  for (int i = 0; i < 3; ++i) {
    Bytes key = rand_bytes(32);
    Bytes blob = key;
    img.plant(blob, "raw-aes-256", kh::hex(key), "bare key bytes in heap");
  }
  {
    Bytes key = rand_bytes(32);
    uint8_t nonce[12];
    RAND_bytes(nonce, 12);
    auto blob = chacha_state_bytes(key, 0, nonce);
    img.plant(blob, "chacha20-state", kh::hex(key), "ChaCha20 block state");
  }

  // ---- asymmetric keys ---------------------------------------------------
  {
    EVP_PKEY* r = gen_rsa(2048);
    if (!r) { std::fprintf(stderr, "keygen failed: %s\n", "gen_rsa(2048)"); return 3; }
    img.plant(rsa_pkcs1_der(r), "rsa-2048-pkcs1", bn_param(r, OSSL_PKEY_PARAM_RSA_N),
              "DER RSAPrivateKey");
    img.plant(pkey_der(r), "rsa-2048-pkcs8", bn_param(r, OSSL_PKEY_PARAM_RSA_N), "DER PKCS#8");
    img.plant(pkey_pem(r), "rsa-2048-pem", bn_param(r, OSSL_PKEY_PARAM_RSA_N), "PEM PKCS#8");
    EVP_PKEY_free(r);
  }
  {
    EVP_PKEY* r = gen_rsa(1024);
    if (!r) { std::fprintf(stderr, "keygen failed: %s\n", "gen_rsa(1024)"); return 3; }
    // Only n,e,d survive: build the truncated structure a damaged file leaves.
    std::string n = bn_param(r, OSSL_PKEY_PARAM_RSA_N);
    std::string e = bn_param(r, OSSL_PKEY_PARAM_RSA_E);
    std::string d = bn_param(r, OSSL_PKEY_PARAM_RSA_D);
    auto blob = pkcs1_from_nd(n, e, d);
    img.plant(blob, "rsa-1024-ned-only", n, "SEQUENCE{n,e,d} (no factors)");
    EVP_PKEY_free(r);
  }
  {
    EVP_PKEY* k = gen_ec("prime256v1");
    if (!k) { std::fprintf(stderr, "keygen failed: %s\n", "gen_ec prime256v1"); return 3; }
    img.plant(pkey_der(k), "ec-p256-sec1", {}, "DER SEC1 ECPrivateKey");
    img.plant(pkey_pem(k), "ec-p256-pem", {}, "PEM EC PRIVATE KEY");
    EVP_PKEY_free(k);
  }
  {
    EVP_PKEY* k = gen_ec("secp256k1");
    if (!k) { std::fprintf(stderr, "keygen failed: %s\n", "gen_ec secp256k1"); return 3; }
    img.plant(pkey_der(k), "ec-secp256k1-sec1", {}, "DER SEC1 ECPrivateKey");
    EVP_PKEY_free(k);
  }
  {
    EVP_PKEY* ed = EVP_PKEY_Q_keygen(nullptr, nullptr, "ED25519");
    if (!ed) { std::fprintf(stderr, "ed25519 keygen failed\n"); return 3; }
    img.plant(pkey_der(ed), "ed25519-pkcs8", {}, "DER PKCS#8 Ed25519");
    img.plant(pkey_pem(ed), "ed25519-pem", {}, "PEM Ed25519");
    EVP_PKEY_free(ed);
    EVP_PKEY* x = EVP_PKEY_Q_keygen(nullptr, nullptr, "X25519");
    if (!x) { std::fprintf(stderr, "x25519 keygen failed\n"); return 3; }
    img.plant(pkey_der(x), "x25519-pkcs8", {}, "DER PKCS#8 X25519");
    EVP_PKEY_free(x);
  }
  {
    EVP_PKEY* d = gen_dsa(1024);
    if (!d) { std::fprintf(stderr, "keygen failed: %s\n", "gen_dsa(1024)"); return 3; }
    img.plant(pkey_der(d), "dsa-1024-pkcs8", {}, "DER PKCS#8 DSA");
    EVP_PKEY_free(d);
  }
  {
    EVP_PKEY* r = gen_rsa(2048);
    if (!r) { std::fprintf(stderr, "keygen failed: %s\n", "gen_rsa(2048)"); return 3; }
    auto enc = encrypted_pkcs8(r, "Pa55w0rd!");
    img.plant(enc, "rsa-2048-encrypted-pkcs8", {}, "EncryptedPrivateKeyInfo (aes-256-cbc)");
    auto p12 = pkcs12_der(r, "Pa55w0rd!");
    img.plant(p12, "rsa-2048-pkcs12", {}, "PKCS#12");
    EVP_PKEY_free(r);
  }

  // ---- decoys ------------------------------------------------------------
  for (int i = 0; i < 24; ++i) {
    // random bytes that are NOT schedules, near crypto-looking strings
    Bytes noise = rand_bytes(220);
    const char* ctx = " AES-256 key encrypt cipher nonce ";
    std::memcpy(noise.data(), ctx, std::strlen(ctx));
    img.plant(noise, "decoy-noise", {}, "high-entropy blob near AES string", false);
  }
  for (int i = 0; i < 12; ++i) {
    // a sequence that looks like DER but is not a key
    Bytes bogus = rand_bytes(300);
    bogus[0] = 0x30;
    bogus[1] = 0x82;
    bogus[2] = 0x01;
    bogus[3] = 0x28;
    img.plant(bogus, "decoy-der", {}, "SEQUENCE of random bytes", false);
  }

  if (!img.save(out)) {
    std::fprintf(stderr, "cannot write %s\n", out.c_str());
    return 1;
  }

  // Manifest.
  std::string mpath = manifest.empty() ? out + ".manifest.json" : manifest;
  FILE* f = std::fopen(mpath.c_str(), "w");
  std::fprintf(f, "{\n  \"image\": \"%s\",\n  \"size\": %zu,\n  \"planted\": [\n", out.c_str(), img.size());
  const auto& pl = img.planted();
  for (size_t i = 0; i < pl.size(); ++i) {
    std::fprintf(f, "    {\"type\": \"%s\", \"offset\": %llu, \"length\": %llu, \"key_hex\": \"%s\", "
                    "\"detail\": \"%s\", \"expect_detect\": %s}%s\n",
                 pl[i].type.c_str(), static_cast<unsigned long long>(pl[i].offset),
                 static_cast<unsigned long long>(pl[i].length), pl[i].key_hex.c_str(),
                 pl[i].detail.c_str(), pl[i].expect_detect ? "true" : "false",
                 i + 1 == pl.size() ? "" : ",");
  }
  std::fprintf(f, "  ]\n}\n");
  std::fclose(f);

  // Optional: a ransomware-style sample file encrypted with one of the keys, so
  // the verifier has something real to prove against.  We take the first AES-256
  // schedule key and write a plaintext prefix followed by a CBC-encrypted body.
  if (!sample_out.empty()) {
    // Find the first planted AES-256 schedule.
    const Planted* pick = nullptr;
    // Prefer a bare raw key so the sweep path (not just schedule detection) has
    // to find it; fall back to a schedule key.
    for (const auto& p : img.planted())
      if (p.type == "raw-aes-256") { pick = &p; break; }
    if (!pick)
      for (const auto& p : img.planted())
        if (p.type == "aes-256-enc-schedule") { pick = &p; break; }
    Bytes key;
    kh::unhex(pick->key_hex, key);
    Bytes plain;
    const char* marker = "%PDF-1.7\n% synthetic ransomware sample body\n";
    plain.assign(marker, marker + std::strlen(marker));
    while (plain.size() < 8192) {
      Bytes chunk = rand_bytes(1024);
      plain.insert(plain.end(), chunk.begin(), chunk.end());
    }
    // Encrypt with AES-256-CBC, IV prepended, as most ransomware does.
    uint8_t iv[16];
    RAND_bytes(iv, 16);
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr, key.data(), iv);
    Bytes ct(plain.size() + 32);
    int n1 = 0, n2 = 0;
    EVP_EncryptUpdate(ctx, ct.data(), &n1, plain.data(), static_cast<int>(plain.size()));
    EVP_EncryptFinal_ex(ctx, ct.data() + n1, &n2);
    EVP_CIPHER_CTX_free(ctx);
    ct.resize(static_cast<size_t>(n1 + n2));
    Bytes file(iv, iv + 16);
    file.insert(file.end(), ct.begin(), ct.end());
    FILE* sf = std::fopen(sample_out.c_str(), "wb");
    std::fwrite(file.data(), 1, file.size(), sf);
    std::fclose(sf);
    std::printf("sample: %s key=%s\n", sample_out.c_str(), pick->key_hex.c_str());
  }

  std::printf("wrote %s (%zu MiB, %zu planted structures) + %s\n", out.c_str(), mib,
              img.planted().size(), mpath.c_str());
  return 0;
}
