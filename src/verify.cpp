#include "verify.hpp"

#include <algorithm>
#include <cstring>

#include <openssl/evp.h>
#include <openssl/err.h>

#include "aes.hpp"
#include "hash.hpp"
#include "privkey.hpp"

namespace kh {
namespace {

const EVP_CIPHER* cipher_for(const std::string& name, size_t keylen) {
  std::string n = name;
  for (auto& c : n) c = static_cast<char>(std::toupper(static_cast<unsigned char>(c)));
  if (keylen == 16) return EVP_get_cipherbyname(("AES-128-" + n).c_str());
  if (keylen == 24) return EVP_get_cipherbyname(("AES-192-" + n).c_str());
  if (keylen == 32) return EVP_get_cipherbyname(("AES-256-" + n).c_str());
  return nullptr;
}

// Decrypt `ct` under one trial and judge whether the result is plausible.
bool try_decrypt(const uint8_t* key, size_t keylen, const Trial& t, const Sample& s,
                 Bytes& pt_out, std::string& reason) {
  size_t need = t.data_offset;
  if (s.header.size() < need + 1) return false;
  if (s.header.size() < t.iv_offset + t.iv_len) return false;
  const EVP_CIPHER* c = cipher_for(t.cipher, keylen);
  if (!c) return false;
  Bytes iv(t.iv_len, 0);
  if (t.iv_len) std::memcpy(iv.data(), s.header.data() + t.iv_offset, t.iv_len);
  EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
  if (!ctx) return false;
  bool ok = false;
  do {
    if (EVP_DecryptInit_ex(ctx, c, nullptr, nullptr, nullptr) != 1) break;
    // Only the CBC/ECB family has meaningful padding.  For stream modes the
    // block check below rejects wrong keys on its own, and preset padding is
    // harmless there; keep it off for GCM/CTR/CFB/OFB to avoid surprises.
    int mode = EVP_CIPHER_get_mode(c);
    bool block_padded = (mode == EVP_CIPH_CBC_MODE || mode == EVP_CIPH_ECB_MODE);
    EVP_CIPHER_CTX_set_padding(ctx, block_padded ? 1 : 0);
    if (mode == EVP_CIPH_GCM_MODE && t.iv_len &&
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, static_cast<int>(t.iv_len), nullptr) != 1)
      break;
    if (EVP_DecryptInit_ex(ctx, nullptr, nullptr, key, t.iv_len ? iv.data() : nullptr) != 1) break;
    Bytes out(s.header.size() + 64);
    int outl = 0;
    size_t produced = 0;
    if (EVP_DecryptUpdate(ctx, out.data(), &outl, s.header.data() + t.data_offset,
                          static_cast<int>(s.header.size() - t.data_offset)) != 1)
      break;
    produced += static_cast<size_t>(outl);
    int fin = 0;
    // Padding is only meaningful when the whole ciphertext was buffered; a
    // truncated sample header will make EVP_DecryptFinal fail even for the right
    // key, so treat a plaintext-magic hit after Update as success.  For CBC we
    // cannot use Update's output unless the IV was right, which is what we test.
    bool final_ok = EVP_DecryptFinal_ex(ctx, out.data() + produced, &fin) == 1;
    if (final_ok) produced += static_cast<size_t>(fin);
    out.resize(produced);
    std::string kind;
    if (!out.empty() && looks_like_known_plaintext(out.data(), out.size(), &kind)) {
      pt_out = std::move(out);
      reason = "plaintext magic: " + kind;
      ok = true;
    } else if (final_ok && out.size() > 16) {
      double e = byte_entropy(out.data(), std::min<size_t>(out.size(), 4096));
      if (e < 7.2) {
        pt_out = std::move(out);
        reason = "low-entropy plaintext";
        ok = true;
      }
    }
  } while (false);
  EVP_CIPHER_CTX_free(ctx);
  ERR_clear_error();
  return ok;
}

struct Magic {
  const char* kind;
  const char* bytes;
  size_t len;
  size_t off;
};
const Magic kMagics[] = {
    {"PDF", "%PDF-", 5, 0},
    {"ZIP/DOCX/JAR (PK)", "PK\x03\x04", 4, 0},
    {"Office/OLE (D0CF11E0)", "\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1", 8, 0},
    {"GZIP", "\x1f\x8b\x08", 3, 0},
    {"PNG", "\x89PNG\r\n\x1a\n", 8, 0},
    {"JPEG", "\xff\xd8\xff", 3, 0},
    {"ELF", "\x7f" "ELF", 4, 0},
    {"PE (MZ)", "MZ", 2, 0},
    {"SQLite", "SQLite format 3", 15, 0},
    {"RIFF", "RIFF", 4, 0},
    {"TAR", "ustar", 5, 257},
    {"7z", "7z\xbc\xaf\x27\x1c", 6, 0},
    {"RAR", "Rar!\x1a\x07", 6, 0},
    {"XML", "<?xml", 5, 0},
    {"UTF-16 text", "\xff\xfe", 2, 0},
};

}  // namespace

bool looks_like_known_plaintext(const uint8_t* p, size_t n, std::string* kind) {
  for (const auto& m : kMagics) {
    if (n < m.off + m.len) continue;
    if (std::memcmp(p + m.off, m.bytes, m.len) == 0) {
      if (kind) *kind = m.kind;
      return true;
    }
  }
  // Heuristic: a long run of printable text is also strong evidence.
  if (n >= 512) {
    size_t printable = 0;
    for (size_t i = 0; i < 512; ++i) {
      uint8_t c = p[i];
      if ((c >= 0x20 && c < 0x7f) || c == '\n' || c == '\r' || c == '\t') ++printable;
    }
    if (printable > 460) {
      if (kind) *kind = "plain text";
      return true;
    }
  }
  return false;
}

Verdict verify_symmetric(const KeyHit& hit, const std::vector<Sample>& samples) {
  Verdict v;
  if (hit.key_len != 16 && hit.key_len != 24 && hit.key_len != 32) return v;
  if (hit.key_complete == false) return v;

  std::vector<Trial> trials;
  // Ransomware's usual shapes: whole-file CBC/CTR with either a prepended IV or
  // a fixed zero IV; AES-CBC over the first block is enough to test.
  for (size_t kl : {size_t{32}, size_t{16}, size_t{24}}) {
    if (hit.key_len && kl != hit.key_len) continue;
    size_t block = 16;
    trials.push_back({"CBC", "AES-CBC IV-prepended", kl, block, 0, block});
    trials.push_back({"CBC", "AES-CBC zero-IV", kl, block, 0, 0});
    trials.push_back({"CTR", "AES-CTR IV-prepended", kl, block, 0, block});
    trials.push_back({"CTR", "AES-CTR zero-IV", kl, block, 0, 0});
    trials.push_back({"ECB", "AES-ECB", kl, 0, 0, 0});
    trials.push_back({"CFB", "AES-CFB IV-prepended", kl, block, 0, block});
    trials.push_back({"OFB", "AES-OFB IV-prepended", kl, block, 0, block});
  }
  // ChaCha20 trials (24-byte nonce layout & IETF 12-byte nonce).
  if (hit.cipher.find("chacha") != std::string::npos) {
    trials.push_back({"CHACHA20", "ChaCha20 IETF (nonce after)", 32, 12, 0, 12});
    trials.push_back({"CHACHA20", "ChaCha20 IETF (nonce at -12)", 32, 12, 0, 12});
  }

  for (const auto& s : samples) {
    if (s.header.empty()) continue;
    for (const auto& t : trials) {
      Bytes pt;
      std::string reason;
      if (try_decrypt(hit.key, hit.key_len, t, s, pt, reason)) {
        v.valid = true;
        v.cipher = t.mode_name;
        v.how = reason + " in " + s.path;
        auto d = h::sha256(pt.data(), pt.size());
        v.plaintext_sha256 = hex(d.data(), d.size());
        v.confidence = 98;
        return v;
      }
    }
  }
  return v;
}

Verdict verify_asym(const AsymCandidate& cand) {
  Verdict v;
  switch (cand.kind) {
    case AsymKind::Rsa: {
      RsaParts k = cand.rsa;
      std::string why;
      int conf = rsa_validate_and_complete(k, why);
      if (conf >= 80) {
        v.valid = true;
        v.how = why;
        v.confidence = conf;
        v.cipher = "RSA-" + std::to_string(k.bits());
      }
      break;
    }
    case AsymKind::Ed25519: {
      if (cand.priv.size() != 32) break;
      uint8_t pub[32];
      if (!ed25519_pubkey(cand.priv.data(), pub)) break;
      v.valid = true;
      v.confidence = cand.pub.empty() ? 60 : 0;
      if (!cand.pub.empty()) {
        // SSH public blob is "type(11) ed25519(7) key(32)"; compare trailing 32.
        if (cand.pub.size() >= 32 &&
            std::memcmp(cand.pub.data() + cand.pub.size() - 32, pub, 32) == 0)
          v.confidence = 99;
        else
          v.confidence = 0;
        if (v.confidence == 0) break;
      }
      v.how = "ed25519 seed -> public key derives";
      v.cipher = "ed25519";
      v.valid = v.confidence > 0;
      break;
    }
    case AsymKind::X25519: {
      if (cand.priv.size() != 32) break;
      uint8_t pub[32];
      if (!x25519_pubkey(cand.priv.data(), pub)) break;
      v.valid = true;
      v.confidence = 60;
      v.how = "x25519 scalar -> public key derives";
      v.cipher = "x25519";
      break;
    }
    case AsymKind::Ec: {
      // Validate the scalar is in range for the named curve.
      if (cand.priv.empty() || cand.curve.empty()) break;
      int bits = cand.bits ? cand.bits : static_cast<int>(cand.priv.size()) * 8;
      Bn d;
      d.set_bytes(cand.priv.data(), cand.priv.size());
      if (d.bits() == 0) break;
      if (d.bits() <= bits) {
        v.valid = true;
        v.confidence = 55;
        v.how = "EC scalar in range for " + cand.curve;
        v.cipher = "ecdsa/" + cand.curve;
      }
      break;
    }
    case AsymKind::Dsa:
      if (!cand.dsa_x.empty()) {
        v.valid = true;
        v.confidence = 50;
        v.how = "DSA x present";
        v.cipher = "dsa";
      }
      break;
    default:
      break;
  }
  return v;
}

}  // namespace kh
