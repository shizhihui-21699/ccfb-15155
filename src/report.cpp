#include "report.hpp"

#include <cstdio>
#include <cstring>
#include <ctime>
#include <string>

#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/core_names.h>
#include <openssl/param_build.h>
#include <openssl/x509.h>

#include <sys/stat.h>

#include "aes.hpp"
#include "hash.hpp"

namespace kh {
namespace {

std::string jstr(const std::string& s) {
  std::string o = "\"";
  for (char c : s) {
    switch (c) {
      case '"': o += "\\\""; break;
      case '\\': o += "\\\\"; break;
      case '\n': o += "\\n"; break;
      case '\r': o += "\\r"; break;
      case '\t': o += "\\t"; break;
      default:
        if (static_cast<unsigned char>(c) < 0x20) {
          char b[8];
          std::snprintf(b, sizeof b, "\\u%04x", c);
          o += b;
        } else {
          o += c;
        }
    }
  }
  o += "\"";
  return o;
}

const char* source_name(KeyHit::Source s) {
  switch (s) {
    case KeyHit::Source::AesEncSchedule: return "aes-enc-schedule";
    case KeyHit::Source::AesDecSchedule: return "aes-dec-schedule";
    case KeyHit::Source::AesRawKey: return "aes-raw-key";
    case KeyHit::Source::ChaCha20State: return "chacha20-state";
    case KeyHit::Source::ChaCha20Key: return "chacha20-key";
    case KeyHit::Source::DesSchedule: return "des-schedule";
    case KeyHit::Source::Sm4Schedule: return "sm4-schedule";
    case KeyHit::Source::CamelliaSchedule: return "camellia-schedule";
    case KeyHit::Source::BlowfishSchedule: return "blowfish-schedule";
    case KeyHit::Source::RawCandidate: return "raw-candidate";
    case KeyHit::Source::DerivedFromSchedule: return "derived";
  }
  return "?";
}

std::string key_hex(const KeyHit& h) { return hex(h.key, h.key_len); }

std::string key_fingerprint(const KeyHit& h) {
  auto d = h::sha256(h.key, h.key_len);
  return hex(d.data(), 6);
}

bool write_file(const std::string& path, const void* p, size_t n, mode_t mode) {
  FILE* f = std::fopen(path.c_str(), "wb");
  if (!f) return false;
  ::chmod(path.c_str(), mode);
  size_t w = std::fwrite(p, 1, n, f);
  std::fclose(f);
  return w == n;
}

std::string dirname_join(const std::string& a, const std::string& b) {
  if (a.empty()) return b;
  if (a.back() == '/') return a + b;
  return a + "/" + b;
}

// Convert an AsymCandidate into an EVP_PKEY / PEM when complete.
bool asym_to_pkey(const AsymCandidate& c, EVP_PKEY*& out) {
  out = nullptr;
  if (c.kind == AsymKind::Rsa && !c.rsa.n.empty() && !c.rsa.e.empty()) {
    RsaParts k = c.rsa;
    std::string why;
    rsa_validate_and_complete(k, why);
    OSSL_PARAM_BLD* bld = OSSL_PARAM_BLD_new();
    BIGNUM* n = BN_bin2bn(k.n.data(), static_cast<int>(k.n.size()), nullptr);
    BIGNUM* e = BN_bin2bn(k.e.data(), static_cast<int>(k.e.size()), nullptr);
    auto add = [&](const char* name, const Bytes& v) -> BIGNUM* {
      if (v.empty()) return nullptr;
      BIGNUM* b = BN_bin2bn(v.data(), static_cast<int>(v.size()), nullptr);
      OSSL_PARAM_BLD_push_BN(bld, name, b);
      return b;
    };
    OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_RSA_N, n);
    OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_RSA_E, e);
    BIGNUM* d = add(OSSL_PKEY_PARAM_RSA_D, k.d);
    BIGNUM* p = add(OSSL_PKEY_PARAM_RSA_FACTOR1, k.p);
    BIGNUM* q = add(OSSL_PKEY_PARAM_RSA_FACTOR2, k.q);
    BIGNUM* dp = add(OSSL_PKEY_PARAM_RSA_EXPONENT1, k.dp);
    BIGNUM* dq = add(OSSL_PKEY_PARAM_RSA_EXPONENT2, k.dq);
    BIGNUM* qi = add(OSSL_PKEY_PARAM_RSA_COEFFICIENT1, k.qi);
    OSSL_PARAM* ps = OSSL_PARAM_BLD_to_param(bld);
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_from_name(nullptr, "RSA", nullptr);
    EVP_PKEY* key = nullptr;
    if (ctx && EVP_PKEY_fromdata_init(ctx) > 0)
      EVP_PKEY_fromdata(ctx, &key, EVP_PKEY_KEYPAIR, ps);
    out = key;
    OSSL_PARAM_free(ps);
    OSSL_PARAM_BLD_free(bld);
    EVP_PKEY_CTX_free(ctx);
    BN_free(n); BN_free(e); BN_free(d); BN_free(p); BN_free(q);
    BN_free(dp); BN_free(dq); BN_free(qi);
    return out != nullptr;
  }
  if ((c.kind == AsymKind::Ed25519 || c.kind == AsymKind::X25519) && c.priv.size() == 32) {
    out = EVP_PKEY_new_raw_private_key(
        c.kind == AsymKind::Ed25519 ? EVP_PKEY_ED25519 : EVP_PKEY_X25519, nullptr, c.priv.data(), 32);
    return out != nullptr;
  }
  return false;
}

}  // namespace

void write_jsonl(const std::string& path, const ScanSummary& sum, const std::vector<SymFinding>& sym,
                 const std::vector<AsymFinding>& asym, bool include_unverified) {
  FILE* f = std::fopen(path.c_str(), "w");
  if (!f) return;
  std::fprintf(f, "{\"type\":\"summary\",\"image\":%s,\"size\":%llu,\"bytes_scanned\":%llu,"
                  "\"seconds\":%.2f,\"symmetric\":%zu,\"asymmetric\":%zu,\"verified\":%zu}\n",
               jstr(sum.image).c_str(), static_cast<unsigned long long>(sum.image_size),
               static_cast<unsigned long long>(sum.bytes_scanned), sum.seconds, sum.symmetric_hits,
               sum.asym_hits, sum.verified);
  for (const auto& sf : sym) {
    if (!include_unverified && !sf.verdict.valid) continue;
    const auto& h = sf.hit;
    std::fprintf(f,
                 "{\"type\":\"symmetric\",\"offset\":%llu,\"source\":%s,\"cipher\":%s,"
                 "\"key_len\":%u,\"key\":%s,\"fingerprint\":%s,\"recovered\":%s,"
                 "\"matched_words\":%u,\"total_words\":%u,\"note\":%s,"
                 "\"verified\":%s,\"verify_cipher\":%s,\"verify_how\":%s,"
                 "\"plaintext_sha256\":%s,\"confidence\":%d}\n",
                 static_cast<unsigned long long>(h.offset), jstr(source_name(h.source)).c_str(),
                 jstr(h.cipher).c_str(), h.key_len, jstr(key_hex(h)).c_str(),
                 jstr(key_fingerprint(h)).c_str(), h.recovered ? "true" : "false", h.matched_words,
                 h.total_words, jstr(h.note).c_str(), sf.verdict.valid ? "true" : "false",
                 jstr(sf.verdict.cipher).c_str(), jstr(sf.verdict.how).c_str(),
                 jstr(sf.verdict.plaintext_sha256).c_str(),
                 sf.verdict.valid ? sf.verdict.confidence : 0);
  }
  for (const auto& af : asym) {
    if (!include_unverified && !af.verdict.valid) continue;
    const auto& c = af.cand;
    std::fprintf(f, "{\"type\":\"asymmetric\",\"offset\":%llu,\"kind\":%d,\"container\":%d,"
                    "\"curve\":%s,\"bits\":%d,\"confidence\":%d,\"encrypted\":%s,"
                    "\"note\":%s,\"verified\":%s,\"verify_how\":%s}\n",
                 static_cast<unsigned long long>(c.offset), static_cast<int>(c.kind),
                 static_cast<int>(c.container), jstr(c.curve).c_str(), c.bits, c.confidence,
                 c.encrypted ? "true" : "false", jstr(c.note).c_str(),
                 af.verdict.valid ? "true" : "false", jstr(af.verdict.how).c_str());
  }
  std::fclose(f);
}

void write_report(const std::string& path, const ScanSummary& sum, const std::vector<SymFinding>& sym,
                  const std::vector<AsymFinding>& asym, bool include_unverified) {
  FILE* f = path.empty() ? stdout : std::fopen(path.c_str(), "w");
  if (!f) return;
  std::fprintf(f, "== keyhunt report ==\n");
  std::fprintf(f, "image         : %s (%llu bytes)\n", sum.image.c_str(),
               static_cast<unsigned long long>(sum.image_size));
  std::fprintf(f, "scanned       : %llu bytes in %.2fs\n",
               static_cast<unsigned long long>(sum.bytes_scanned), sum.seconds);
  std::fprintf(f, "symmetric hits: %zu  (recovered/partial: %zu)\n", sum.symmetric_hits, sum.recovered);
  std::fprintf(f, "asymmetric    : %zu\n", sum.asym_hits);
  std::fprintf(f, "verified      : %zu\n\n", sum.verified);

  bool header = false;
  auto print_hdr = [&]() {
    if (header) return;
    header = true;
    std::fprintf(f, "%-6s %-16s %-13s %-12s %-8s %s\n", "conf", "offset", "source", "cipher",
                 "fingerprint", "detail");
    std::fprintf(f, "--------------------------------------------------------------------------------"
                    "----------\n");
  };

  for (const auto& sf : sym) {
    if (!include_unverified && !sf.verdict.valid) continue;
    print_hdr();
    std::fprintf(f, "%-6d 0x%-14llx %-13s %-12s %-8s %s\n",
                 sf.verdict.valid ? sf.verdict.confidence : 20,
                 static_cast<unsigned long long>(sf.hit.offset),
                 source_name(sf.hit.source), sf.hit.cipher.c_str(),
                 key_fingerprint(sf.hit).c_str(),
                 sf.verdict.valid ? ("VERIFIED: " + sf.verdict.how).c_str() : sf.hit.note.c_str());
    if (sf.verdict.valid) {
      std::fprintf(f, "       key %s len=%u  plaintext-sha256=%s\n", key_hex(sf.hit).c_str(),
                   sf.hit.key_len, sf.verdict.plaintext_sha256.c_str());
    }
  }
  bool ahdr = false;
  for (const auto& af : asym) {
    if (!include_unverified && !af.verdict.valid) continue;
    if (!ahdr) {
      ahdr = true;
      std::fprintf(f, "\n%-6s %-16s %-24s %-12s %s\n", "conf", "offset", "container", "kind",
                   "detail");
      std::fprintf(f, "--------------------------------------------------------------------------------"
                      "----------\n");
    }
    const auto& c = af.cand;
    std::fprintf(f, "%-6d 0x%-14llx %-24s %-12s %s\n",
                 af.verdict.valid ? af.verdict.confidence : std::max(5, c.confidence),
                 static_cast<unsigned long long>(c.offset), c.container_describe().c_str(),
                 c.kind_name().c_str(),
                 af.verdict.valid ? ("VERIFIED: " + af.verdict.how).c_str() : c.note.c_str());
  }
  if (f != stdout) std::fclose(f);
}

size_t export_keys(const std::string& outdir, const std::vector<SymFinding>& sym,
                   const std::vector<AsymFinding>& asym) {
  std::string kd = dirname_join(outdir, "keys");
  ::mkdir(outdir.c_str(), 0700);
  ::mkdir(kd.c_str(), 0700);
  size_t n = 0;
  for (const auto& sf : sym) {
    if (!sf.verdict.valid) continue;
    const auto& h = sf.hit;
    char name[256];
    std::snprintf(name, sizeof name, "%02zu_sym_%s_%llx_%s", n, h.cipher.c_str(),
                  static_cast<unsigned long long>(h.offset), key_fingerprint(h).c_str());
    std::string base = dirname_join(kd, name);
    write_file(base + ".key", h.key, h.key_len, 0600);
    std::string hx = key_hex(h) + "\n";
    write_file(base + ".hex", hx.data(), hx.size(), 0600);
    std::string meta = std::string("{\n  \"offset\": ") + std::to_string(h.offset) +
                       ",\n  \"cipher\": \"" + sf.verdict.cipher + "\",\n  \"key_hex\": \"" + key_hex(h) +
                       "\",\n  \"plaintext_sha256\": \"" + sf.verdict.plaintext_sha256 +
                       "\",\n  \"note\": \"" + h.note + "\"\n}\n";
    write_file(base + ".json", meta.data(), meta.size(), 0600);
    ++n;
  }
  for (const auto& af : asym) {
    if (!af.verdict.valid) continue;
    EVP_PKEY* key = nullptr;
    if (!asym_to_pkey(af.cand, key)) continue;
    char name[256];
    std::snprintf(name, sizeof name, "%02zu_asym_%s_%llx", n, af.cand.kind_name().c_str(),
                  static_cast<unsigned long long>(af.cand.offset));
    std::string base = dirname_join(kd, name);
    FILE* f = std::fopen((base + ".pem").c_str(), "w");
    if (f) {
      ::chmod((base + ".pem").c_str(), 0600);
      PEM_write_PrivateKey(f, key, nullptr, nullptr, 0, nullptr, nullptr);
      std::fclose(f);
      ++n;
    }
    EVP_PKEY_free(key);
  }
  return n;
}

}  // namespace kh
