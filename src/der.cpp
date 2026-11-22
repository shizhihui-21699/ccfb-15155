#include "der.hpp"

#include <cstring>

namespace kh {

const char* kOidRsaEncryption = "1.2.840.113549.1.1.1";
const char* kOidRsaPss = "1.2.840.113549.1.1.10";
const char* kOidEcPublicKey = "1.2.840.10045.2.1";
const char* kOidEd25519 = "1.3.101.112";
const char* kOidX25519 = "1.3.101.110";
const char* kOidEd448 = "1.3.101.113";
const char* kOidDsa = "1.2.840.10040.4.1";

namespace {
struct Curve {
  const char* name;
  const char* oid;
  int bits;
};
const Curve kCurves[] = {
    {"secp256r1", "1.2.840.10045.3.1.7", 256}, {"prime256v1", "1.2.840.10045.3.1.7", 256},
    {"secp384r1", "1.3.132.0.34", 384},        {"secp521r1", "1.3.132.0.35", 521},
    {"secp256k1", "1.3.132.0.10", 256},        {"secp224r1", "1.3.132.0.33", 224},
    {"brainpoolP256r1", "1.3.36.3.3.2.8.1.1.7", 256},
    {"brainpoolP384r1", "1.3.36.3.3.2.8.1.1.11", 384},
    {"brainpoolP512r1", "1.3.36.3.3.2.8.1.1.13", 512},
    {"SM2", "1.2.156.10197.1.301", 256},
    {"curve25519", "1.3.101.110", 255},
    {"curve448", "1.3.101.111", 448},
    {"ed25519", "1.3.101.112", 255},
    {"ed448", "1.3.101.113", 448},
};
}  // namespace

bool oid_is_curve(const std::string& oid, std::string* name, int* bits) {
  for (const auto& c : kCurves) {
    if (oid == c.oid) {
      if (name) *name = c.name;
      if (bits) *bits = c.bits;
      return true;
    }
  }
  return false;
}

bool der_next(const uint8_t* data, size_t len, size_t off, Tlv& out, bool allow_ber) {
  if (off + 2 > len) return false;
  size_t p = off;
  uint8_t tag = data[p++];
  // High-tag-number form is irrelevant for the structures we care about.
  if ((tag & 0x1f) == 0x1f) return false;
  uint8_t lb = data[p++];
  size_t l = 0;
  bool indef = false;
  if (lb < 0x80) {
    l = lb;
  } else if (lb == 0x80) {
    if (!allow_ber) return false;
    indef = true;
    l = 0;
  } else {
    int nb = lb & 0x7f;
    if (nb > 4) return false;
    if (p + static_cast<size_t>(nb) > len) return false;
    for (int i = 0; i < nb; ++i) l = (l << 8) | data[p++];
  }
  out.tag = tag;
  out.hdr_len = p - off;
  out.len = l;
  out.indefinite = indef;
  out.off = off;
  out.content = data + p;
  if (!indef && (p + l > len)) {
    // Length runs past the buffer.  Report what is available; caller decides.
    out.len = len - p;
    return false;
  }
  return true;
}

std::vector<Tlv> der_children(const uint8_t* data, size_t len, const Tlv& parent, bool allow_ber) {
  std::vector<Tlv> out;
  if (!parent.content) return out;
  size_t base = static_cast<size_t>(parent.content - data);
  size_t limit = parent.indefinite ? len : std::min(len, base + parent.len);
  size_t p = base;
  while (p < limit) {
    if (parent.indefinite && p + 1 < limit && data[p] == 0 && data[p + 1] == 0) break;
    Tlv t;
    if (!der_next(data, len, p, t, allow_ber)) {
      if (t.hdr_len == 0) break;
    }
    if (t.hdr_len == 0) break;
    out.push_back(t);
    if (limit < len && t.off + t.total() > limit) break;
    p = t.off + t.total();
  }
  return out;
}

bool der_oid_to_string(const Tlv& tlv, std::string& out) {
  if (tlv.tag != static_cast<uint8_t>(Tag::Oid) || tlv.len == 0) return false;
  const uint8_t* p = tlv.content;
  size_t n = tlv.len;
  char buf[16];
  uint32_t v = 0;
  size_t i = 0;
  // first byte: 40*x + y
  if (n == 0) return false;
  uint32_t first = p[i++];
  std::snprintf(buf, sizeof buf, "%u.%u", first / 40, first % 40);
  out = buf;
  v = 0;
  bool have = false;
  for (; i < n; ++i) {
    v = (v << 7) | (p[i] & 0x7f);
    have = true;
    if (!(p[i] & 0x80)) {
      std::snprintf(buf, sizeof buf, ".%u", v);
      out += buf;
      v = 0;
      have = false;
    }
  }
  if (have) return false;  // truncated
  return true;
}

bool der_integer_positive(const Tlv& tlv) {
  if (tlv.tag != static_cast<uint8_t>(Tag::Integer) || tlv.len == 0) return false;
  return !(tlv.content[0] & 0x80);
}

void der_integer_bytes(const Tlv& tlv, const uint8_t*& p, size_t& n) {
  p = tlv.content;
  n = tlv.len;
  while (n > 1 && *p == 0) { ++p; --n; }
}

std::string KeyStructure::describe() const {
  static const char* names[] = {
      "unknown",   "RSA-PKCS#1", "RSA-PKCS#8", "EC-SEC1",   "EC-PKCS#8", "Ed25519", "X25519",
      "DSA-PKCS#8", "Encrypted-PKCS#8", "PKCS#12", "PKCS#7", "X509-cert", "OpenSSH-key"};
  int idx = static_cast<int>(kind);
  std::string s = (idx >= 0 && idx < 13) ? names[idx] : "unknown";
  if (bits > 0) s += "(" + std::to_string(bits) + "-bit)";
  if (!algorithm_oid.empty()) s += " oid=" + algorithm_oid;
  if (!complete) s += " [truncated]";
  return s;
}

namespace {

// Read a SEQUENCE at off, tolerating a wrong length (salvage mode).
bool open_seq(const uint8_t* data, size_t len, size_t off, Tlv& seq, bool salvage) {
  if (!der_next(data, len, off, seq, true)) {
    if (!salvage) return false;
    // Re-derive: treat as sequence with the rest of the buffer.
    if (off + 2 > len) return false;
    seq.tag = data[off];
    if (seq.tag != 0x30) return false;
    size_t p = off + 2;
    if (data[off + 1] & 0x80) {
      int nb = data[off + 1] & 0x7f;
      if (nb > 4 || off + 2 + nb > len) return false;
      p = off + 2 + nb;
    }
    seq.hdr_len = p - off;
    seq.off = off;
    seq.len = len - p;
    seq.content = data + p;
    seq.indefinite = false;
  }
  return seq.tag == 0x30;
}

}  // namespace

// The children helper above needs the original buffer; classify with access to
// it and simple inline child walking to avoid storing fat structures.
KeyStructure parse_key_structure(const uint8_t* data, size_t len, size_t off, bool salvage) {
  KeyStructure ks;
  ks.off = off;
  if (off >= len) return ks;
  Tlv seq;
  if (!open_seq(data, len, off, seq, salvage)) return ks;
  ks.total_len = seq.total();
  if (!seq.indefinite && seq.off + seq.total() > len) ks.complete = false;

  auto kids = der_children(data, len, seq);
  auto need = [&](size_t i) { return i < kids.size(); };
  auto setint = [&](size_t i, KeyStructure::Field& f) {
    if (!need(i)) return;
    const Tlv& t = kids[i];
    if (t.tag != static_cast<uint8_t>(Tag::Integer)) return;
    const uint8_t* p;
    size_t n;
    der_integer_bytes(t, p, n);
    f.p = p;
    f.n = n;
  };

  // ---- DSA private key (SEQUENCE {version,p,q,g,y,x}) -------------------
  // Must be tested before the PKCS#8/SEC1 branches because its shape starts
  // with an INTEGER version followed by more INTEGERs, which those branches can
  // misread.
  if (need(5) && kids[0].tag == 0x02 && kids[0].len <= 4 && kids[1].tag == 0x02 &&
      kids[2].tag == 0x02 && kids[3].tag == 0x02 && kids[4].tag == 0x02 && kids[5].tag == 0x02) {
    bool allint = true;
    for (size_t i = 0; i < 6 && i < kids.size(); ++i)
      if (kids[i].tag != 0x02) { allint = false; break; }
    // x is small relative to p, and p is large; a 9+ integer sequence is RSA.
    if (allint && kids.size() <= 7 && kids[1].len >= 20 && kids[5].len >= 20) {
      ks.kind = KeyStructure::Kind::DsaPkcs8;
      setint(1, ks.dsa_p);   // p
      setint(2, ks.dsa_q);   // q
      setint(3, ks.dsa_g);   // g
      setint(5, ks.priv);    // x
      ks.bits = static_cast<int>(kids[1].len) * 8;
      return ks;
    }
  }

  // ---- PKCS#1 RSAPrivateKey --------------------------------------------
  if (need(0) && kids[0].tag == 0x02 && kids[0].len <= 4 && need(8) && kids[1].tag == 0x02 &&
      kids[2].tag == 0x02 && kids.size() >= 9) {
    bool looks_rsa = true;
    for (size_t i = 1; i <= 8 && i < kids.size(); ++i)
      if (kids[i].tag != 0x02) { looks_rsa = false; break; }
    if (looks_rsa && kids[1].len >= 64 && kids[1].len <= 1024) {
      ks.kind = KeyStructure::Kind::RsaPkcs1;
      ks.bits = static_cast<int>(kids[1].len) * 8;
      setint(1, ks.n);
      setint(2, ks.e);
      setint(3, ks.d);
      setint(4, ks.p);
      setint(5, ks.q);
      setint(6, ks.dp);
      setint(7, ks.dq);
      setint(8, ks.qinv);
      return ks;
    }
  }

  // ---- PKCS#12 PFX: SEQUENCE { INTEGER version, ContentInfo, MacData }
  // MacData is optional but when present is a SEQUENCE; the authSafe is a
  // ContentInfo named "data" (1.2.840.113549.1.7.1).
  if (need(1) && kids[0].tag == 0x02 && kids[0].len <= 4 && kids[1].tag == 0x30) {
    auto ci = der_children(data, len, kids[1]);
    std::string oid;
    if (!ci.empty() && ci[0].tag == 0x06 && der_oid_to_string(ci[0], oid) &&
        oid == "1.2.840.113549.1.7.1") {
      ks.kind = KeyStructure::Kind::Pkcs12;
      ks.algorithm_oid = oid;
      return ks;
    }
  }

  // ---- EncryptedPrivateKeyInfo (versionless) ---------------------------
  // SEQUENCE { AlgorithmIdentifier, OCTET STRING }.  Check this before the
  // generic PKCS#8 branch so PBES2/PBKDF2 containers are labelled correctly.
  if (need(1) && kids[0].tag == 0x30 && kids[1].tag == 0x04) {
    auto alg = der_children(data, len, kids[0]);
    std::string oid;
    if (!alg.empty() && der_oid_to_string(alg[0], oid)) {
      ks.algorithm_oid = oid;
      bool enc = oid.rfind("1.2.840.113549.1.5", 0) == 0 ||   // PBES1/PBES2
                 oid.rfind("1.2.840.113549.1.12.1", 0) == 0 ||  // PBKDF2-based
                 oid.rfind("1.3.6.1.4.1.11591.4", 0) == 0;      // scrypt
      if (enc) {
        ks.kind = KeyStructure::Kind::EncryptedPkcs8;
        return ks;
      }
    }
  }

  // ---- PKCS#8 PrivateKeyInfo -------------------------------------------
  if (need(0) && kids[0].tag == 0x02 && kids[0].len <= 4 && kids.size() >= 3) {
    if (kids[1].tag == 0x30) {  // AlgorithmIdentifier
      auto alg = der_children(data, len, kids[1]);
      std::string oid;
      if (!alg.empty() && der_oid_to_string(alg[0], oid)) {
        ks.algorithm_oid = oid;
        if (kids[2].tag == 0x04) {  // privateKey OCTET STRING
          const uint8_t* inner = kids[2].content;
          size_t inner_len = kids[2].len;
          if (oid == kOidRsaEncryption) {
            ks.kind = KeyStructure::Kind::RsaPkcs8;
            // parse inner RSAPrivateKey
            Tlv iseq;
            if (open_seq(inner, inner_len, 0, iseq, salvage)) {
              auto ik = der_children(inner, inner_len, iseq);
              if (ik.size() >= 9) {
                auto gi = [&](size_t i, KeyStructure::Field& f) {
                  if (i >= ik.size() || ik[i].tag != 0x02) return;
                  const uint8_t* p;
                  size_t n;
                  der_integer_bytes(ik[i], p, n);
                  f.p = p;
                  f.n = n;
                };
                gi(1, ks.n); gi(2, ks.e); gi(3, ks.d); gi(4, ks.p); gi(5, ks.q);
                gi(6, ks.dp); gi(7, ks.dq); gi(8, ks.qinv);
                ks.bits = static_cast<int>(ik[1].len) * 8;
              }
            }
            return ks;
          }
          if (oid == kOidEcPublicKey) {
            std::string cname;
            int cbits = 0;
            if (alg.size() > 1 && alg[1].tag == 0x06) {
              std::string coid;
              if (der_oid_to_string(alg[1], coid)) { oid_is_curve(coid, &cname, &cbits); }
            }
            Tlv eseq;
            if (open_seq(inner, inner_len, 0, eseq, salvage)) {
              auto ek = der_children(inner, inner_len, eseq);
              ks.kind = KeyStructure::Kind::EcPkcs8;
              ks.bits = cbits;
              for (auto& t : ek) {
                if (t.tag == 0x04 && ks.priv.n == 0) { ks.priv.p = t.content; ks.priv.n = t.len; }
              }
            } else {
              ks.kind = KeyStructure::Kind::EcPkcs8;
              ks.bits = cbits;
              ks.priv.p = inner;
              ks.priv.n = inner_len;
            }
            return ks;
          }
          if (oid == kOidEd25519) {
            ks.kind = KeyStructure::Kind::Ed25519Pkcs8;
            ks.priv.p = inner;
            ks.priv.n = inner_len;
            ks.bits = 255;
            // DER: OCTET STRING(0x04,32) inside
            if (inner_len >= 2 && inner[0] == 0x04) { ks.priv.p = inner + 2; ks.priv.n = inner_len - 2; }
            return ks;
          }
          if (oid == kOidX25519) {
            ks.kind = KeyStructure::Kind::X25519Pkcs8;
            ks.priv.p = inner;
            ks.priv.n = inner_len;
            ks.bits = 255;
            if (inner_len >= 2 && inner[0] == 0x04) { ks.priv.p = inner + 2; ks.priv.n = inner_len - 2; }
            return ks;
          }
          if (oid == kOidDsa) {
            ks.kind = KeyStructure::Kind::DsaPkcs8;
            ks.priv.p = inner;
            ks.priv.n = inner_len;
            return ks;
          }
        }
      }
    } else if (kids[1].tag == 0x30 && kids.size() >= 2) {
      // EncryptedPrivateKeyInfo: SEQ { AlgorithmIdentifier, OCTET STRING }
      auto alg = der_children(data, len, kids[1]);
      std::string oid;
      if (!alg.empty() && der_oid_to_string(alg[0], oid)) {
        ks.algorithm_oid = oid;
        if (oid.rfind("1.2.840.113549.1.5", 0) == 0 || oid.rfind("1.2.840.113549.1.12.1", 0) == 0) {
          ks.kind = KeyStructure::Kind::EncryptedPkcs8;
          return ks;
        }
      }
    }
  }

  // ---- SEC1 ECPrivateKey ------------------------------------------------
  if (need(0) && kids[0].tag == 0x02 && kids[0].len <= 4 && need(1) && kids[1].tag == 0x04) {
    ks.kind = KeyStructure::Kind::EcSec1;
    ks.priv.p = kids[1].content;
    ks.priv.n = kids[1].len;
    ks.bits = static_cast<int>(kids[1].len) * 8;
    if (kids.size() >= 3 && kids[2].tag == 0xa0) {
      auto ctx = der_children(data, len, kids[2]);
      std::string coid;
      if (!ctx.empty() && ctx[0].tag == 0x06 && der_oid_to_string(ctx[0], coid)) {
        ks.algorithm_oid = coid;
        std::string n;
        int b = 0;
        if (oid_is_curve(coid, &n, &b)) ks.bits = b;
      }
    }
    return ks;
  }

  // ---- X.509 Certificate ------------------------------------------------
  if (need(0) && kids[0].tag == 0x30 && need(1) && kids[1].tag == 0x30 && kids.size() >= 3 &&
      kids[2].tag == 0x03) {
    ks.kind = KeyStructure::Kind::Certificate;
    return ks;
  }

  // ---- PKCS#7 / CMS SignedData or PKCS#12 PFX ---------------------------
  if (need(0) && kids[0].tag == 0x06 && need(1) && kids[1].tag == 0xa0) {
    std::string oid;
    if (der_oid_to_string(kids[0], oid)) {
      ks.algorithm_oid = oid;
      if (oid == "1.2.840.113549.1.7.2") ks.kind = KeyStructure::Kind::Pkcs7;       // signedData
      else if (oid == "1.2.840.113549.1.7.1") ks.kind = KeyStructure::Kind::Pkcs7;  // data
      else if (oid == "1.2.840.113549.1.12.10.1.1") ks.kind = KeyStructure::Kind::Pkcs12;  // keyBag
    }
    return ks;
  }
  if (need(0) && kids[0].tag == 0x02 && kids[0].len <= 4 && need(1) && kids[1].tag == 0x30 &&
      need(2) && kids[2].tag == 0x04 && kids.size() >= 3) {
    // PFX ::= SEQUENCE { version, authSafe ContentInfo, macData }
    ks.kind = KeyStructure::Kind::Pkcs12;
    return ks;
  }

  return ks;
}

}  // namespace kh
