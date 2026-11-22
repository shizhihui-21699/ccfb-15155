#include "privkey.hpp"

#include <cstring>

#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/x509.h>

#include "encodings.hpp"
#include "symmetric.hpp"

namespace kh {
namespace {

void fill_rsa(const KeyStructure& ks, AsymCandidate& c) {
  auto put = [](Bytes& dst, const KeyStructure::Field& f) {
    if (f.p && f.n) dst.assign(f.p, f.p + f.n);
  };
  put(c.rsa.n, ks.n);
  put(c.rsa.e, ks.e);
  put(c.rsa.d, ks.d);
  put(c.rsa.p, ks.p);
  put(c.rsa.q, ks.q);
  put(c.rsa.dp, ks.dp);
  put(c.rsa.dq, ks.dq);
  put(c.rsa.qi, ks.qinv);
  c.bits = c.rsa.bits();
}

bool parse_dsa_inner(const uint8_t* p, size_t n, AsymCandidate& c) {
  // DSA PKCS#8 privateKey is INTEGER x.
  Tlv t;
  if (!der_next(p, n, 0, t, true)) return false;
  if (t.tag == 0x02) {
    const uint8_t* q;
    size_t qn;
    der_integer_bytes(t, q, qn);
    c.dsa_x.assign(q, q + qn);
    return true;
  }
  // Some encoders embed a full SEQUENCE {p,q,g,y,x}.
  if (t.tag == 0x30) {
    auto k = der_children(p, n, t);
    if (k.size() >= 2 && k.back().tag == 0x02) {
      const uint8_t* q;
      size_t qn;
      der_integer_bytes(k.back(), q, qn);
      c.dsa_x.assign(q, q + qn);
      return true;
    }
  }
  return false;
}

}  // namespace

bool ed25519_pubkey(const uint8_t seed[32], uint8_t pub[32]) {
  EVP_PKEY* k = EVP_PKEY_new_raw_private_key(EVP_PKEY_ED25519, nullptr, seed, 32);
  if (!k) return false;
  size_t l = 32;
  bool ok = EVP_PKEY_get_raw_public_key(k, pub, &l) == 1 && l == 32;
  EVP_PKEY_free(k);
  return ok;
}

bool x25519_pubkey(const uint8_t scalar[32], uint8_t pub[32]) {
  EVP_PKEY* k = EVP_PKEY_new_raw_private_key(EVP_PKEY_X25519, nullptr, scalar, 32);
  if (!k) return false;
  size_t l = 32;
  bool ok = EVP_PKEY_get_raw_public_key(k, pub, &l) == 1 && l == 32;
  EVP_PKEY_free(k);
  return ok;
}

bool candidate_from_pem(const PemBlock& pb, uint64_t base, AsymCandidate& out) {
  const std::string& lbl = pb.label;
  out.offset = pb.begin_off;
  out.length = pb.end_off - pb.begin_off;
  out.encrypted = lbl.find("ENCRYPTED") != std::string::npos;
  KeyStructure ks = parse_key_structure(pb.der.data(), pb.der.size(), 0, true);
  out.bits = ks.bits;
  out.confidence = 90;

  if (lbl == "RSAPRIVATE KEY" || lbl == "RSA PRIVATE KEY") {
    out.kind = AsymKind::Rsa;
    out.container = KeyStructure::Kind::RsaPkcs1;
    if (ks.kind != KeyStructure::Kind::RsaPkcs1) ks = parse_key_structure(pb.der.data(), pb.der.size(), 0, true);
    fill_rsa(ks, out);
    return true;
  }
  if (lbl == "PRIVATE KEY") {
    out.container = ks.kind;
    out.kind = ks.kind == KeyStructure::Kind::RsaPkcs8 ? AsymKind::Rsa
               : ks.kind == KeyStructure::Kind::EcPkcs8 ? AsymKind::Ec
               : ks.kind == KeyStructure::Kind::Ed25519Pkcs8 ? AsymKind::Ed25519
               : ks.kind == KeyStructure::Kind::X25519Pkcs8 ? AsymKind::X25519
               : ks.kind == KeyStructure::Kind::DsaPkcs8 ? AsymKind::Dsa
                                                          : AsymKind::Unknown;
    if (out.kind == AsymKind::Rsa) fill_rsa(ks, out);
    else if (out.kind == AsymKind::Ec || out.kind == AsymKind::Ed25519 || out.kind == AsymKind::X25519) {
      if (ks.priv.p) out.priv.assign(ks.priv.p, ks.priv.p + ks.priv.n);
    } else if (out.kind == AsymKind::Dsa && ks.priv.p) {
      parse_dsa_inner(ks.priv.p, ks.priv.n, out);
    }
    return out.kind != AsymKind::Unknown;
  }
  if (lbl == "EC PRIVATE KEY") {
    out.kind = AsymKind::Ec;
    out.container = KeyStructure::Kind::EcSec1;
    if (ks.priv.p) out.priv.assign(ks.priv.p, ks.priv.p + ks.priv.n);
    // SEC1 carries the curve as a [0] context tag inside the DER, which
    // parse_key_structure already resolves into algorithm_oid.
    out.curve = ks.algorithm_oid;
    std::string cname;
    int cbits = 0;
    if (!ks.algorithm_oid.empty() && oid_is_curve(ks.algorithm_oid, &cname, &cbits)) {
      out.curve = cname;
      out.bits = cbits;
    }
    return true;
  }
  if (lbl == "OPENSSH PRIVATE KEY") {
    out.kind = AsymKind::Unknown;  // handled by dedicated parser
    out.container = KeyStructure::Kind::OpenSshPrivate;
    return false;
  }
  if (lbl.find("ENCRYPTED PRIVATE KEY") != std::string::npos) {
    out.encrypted = true;
    out.encryption_oid = ks.algorithm_oid;
    return true;
  }
  return false;
}

bool candidate_from_der(const uint8_t* data, size_t len, size_t off, uint64_t base,
                        bool salvage, AsymCandidate& out) {
  if (off >= len || data[off] != 0x30) return false;
  KeyStructure ks = parse_key_structure(data, len, off, salvage);
  if (ks.kind == KeyStructure::Kind::Unknown) return false;
  out.offset = base + off;
  out.length = ks.total_len;
  out.container = ks.kind;
  out.bits = ks.bits;
  out.confidence = ks.complete ? 85 : 60;
  switch (ks.kind) {
    case KeyStructure::Kind::RsaPkcs1:
    case KeyStructure::Kind::RsaPkcs8:
      out.kind = AsymKind::Rsa;
      fill_rsa(ks, out);
      return !out.rsa.n.empty();
    case KeyStructure::Kind::EcSec1:
    case KeyStructure::Kind::EcPkcs8:
      out.kind = AsymKind::Ec;
      if (ks.priv.p) out.priv.assign(ks.priv.p, ks.priv.p + ks.priv.n);
      out.curve = ks.algorithm_oid;
      {
        std::string cname;
        int cbits = 0;
        if (!ks.algorithm_oid.empty() && oid_is_curve(ks.algorithm_oid, &cname, &cbits)) {
          out.curve = cname;
          out.bits = cbits;
        }
      }
      return !out.priv.empty();
    case KeyStructure::Kind::Ed25519Pkcs8:
      out.kind = AsymKind::Ed25519;
      if (ks.priv.p) out.priv.assign(ks.priv.p, ks.priv.p + ks.priv.n);
      return out.priv.size() == 32;
    case KeyStructure::Kind::X25519Pkcs8:
      out.kind = AsymKind::X25519;
      if (ks.priv.p) out.priv.assign(ks.priv.p, ks.priv.p + ks.priv.n);
      return out.priv.size() == 32;
    case KeyStructure::Kind::DsaPkcs8:
      out.kind = AsymKind::Dsa;
      if (ks.priv.p) {
        // Bare OpenSSL DSA already stores raw x in ks.priv; a PKCS#8-wrapped DSA
        // stores a TLV in ks.priv that parse_dsa_inner must unwrap.
        Tlv probe;
        if (der_next(ks.priv.p, ks.priv.n, 0, probe, true) && probe.tag == 0x02 &&
            probe.len == ks.priv.n - probe.hdr_len) {
          const uint8_t* qp;
          size_t qn;
          der_integer_bytes(probe, qp, qn);
          out.dsa_x.assign(qp, qp + qn);
        } else if (!parse_dsa_inner(ks.priv.p, ks.priv.n, out)) {
          out.dsa_x.assign(ks.priv.p, ks.priv.p + ks.priv.n);
        }
      }
      if (ks.dsa_p.p) out.dsa_p.assign(ks.dsa_p.p, ks.dsa_p.p + ks.dsa_p.n);
      if (ks.dsa_q.p) out.dsa_q.assign(ks.dsa_q.p, ks.dsa_q.p + ks.dsa_q.n);
      if (ks.dsa_g.p) out.dsa_g.assign(ks.dsa_g.p, ks.dsa_g.p + ks.dsa_g.n);
      out.bits = ks.bits;
      return !out.dsa_x.empty();
    case KeyStructure::Kind::EncryptedPkcs8:
      out.encrypted = true;
      out.encryption_oid = ks.algorithm_oid;
      out.kind = AsymKind::Unknown;
      return true;
    case KeyStructure::Kind::Pkcs12:
      out.encrypted = true;
      out.kind = AsymKind::Unknown;
      return true;
    default:
      return false;
  }
}

namespace {
// SSH string: uint32 big-endian length followed by bytes.
bool ssh_str(const uint8_t* p, size_t n, size_t& off, Bytes& out) {
  if (off + 4 > n) return false;
  uint32_t l = rd32be(p + off);
  off += 4;
  if (l > n - off || l > (1u << 20)) return false;
  out.assign(p + off, p + off + l);
  off += l;
  return true;
}
uint32_t ssh_u32(const uint8_t* p, size_t n, size_t& off, bool& ok) {
  if (off + 4 > n) { ok = false; return 0; }
  uint32_t v = rd32be(p + off);
  off += 4;
  return v;
}
}  // namespace

void find_openssh_keys(const uint8_t* data, size_t len, uint64_t base,
                       std::vector<AsymCandidate>& out) {
  static const char kMagic[] = "openssh-key-v1";
  const size_t magic_len = 15;  // without trailing NUL
  for (size_t i = 0; i + magic_len + 1 < len; ++i) {
    if (std::memcmp(data + i, kMagic, magic_len) != 0) continue;
    size_t off = i + magic_len + 1;  // skip NUL
    Bytes cipher, kdf, kdfopts;
    if (!ssh_str(data, len, off, cipher)) continue;
    if (!ssh_str(data, len, off, kdf)) continue;
    if (!ssh_str(data, len, off, kdfopts)) continue;
    bool ok = true;
    uint32_t nkeys = ssh_u32(data, len, off, ok);
    if (!ok || nkeys == 0 || nkeys > 8) continue;
    if (std::memcmp(cipher.data(), "none", 4) != 0 && cipher.size() >= 4) continue;
    // skip public keys
    for (uint32_t k = 0; k < nkeys; ++k) {
      Bytes pk;
      if (!ssh_str(data, len, off, pk)) { ok = false; break; }
    }
    if (!ok) continue;
    Bytes priv;
    if (!ssh_str(data, len, off, priv)) continue;
    if (priv.size() < 8) continue;
    // decrypted private block: check1 == check2
    if (rd32be(priv.data()) != rd32be(priv.data() + 4)) continue;
    size_t p = 8;
    Bytes type;
    if (!ssh_str(priv.data(), priv.size(), p, type)) continue;
    std::string t(type.begin(), type.end());
    AsymCandidate c;
    c.offset = base + i;
    c.length = off - i;
    c.container = KeyStructure::Kind::OpenSshPrivate;
    c.confidence = 92;
    c.note = "openssh-key-v1 " + t;
    if (t == "ssh-ed25519") {
      Bytes pub, sk;
      if (!ssh_str(priv.data(), priv.size(), p, pub)) continue;
      if (!ssh_str(priv.data(), priv.size(), p, sk)) continue;
      if (sk.size() != 64) continue;  // pub||priv seed
      c.kind = AsymKind::Ed25519;
      c.priv.assign(sk.begin(), sk.begin() + 32);
      c.pub = pub;
      out.push_back(std::move(c));
    } else if (t == "ssh-rsa") {
      Bytes n, e, d, iqmp, p_, q_;
      if (!ssh_str(priv.data(), priv.size(), p, n)) continue;
      if (!ssh_str(priv.data(), priv.size(), p, e)) continue;
      if (!ssh_str(priv.data(), priv.size(), p, d)) continue;
      if (!ssh_str(priv.data(), priv.size(), p, iqmp)) continue;
      if (!ssh_str(priv.data(), priv.size(), p, p_)) continue;
      if (!ssh_str(priv.data(), priv.size(), p, q_)) continue;
      c.kind = AsymKind::Rsa;
      c.rsa.n = n; c.rsa.e = e; c.rsa.d = d; c.rsa.qi = iqmp; c.rsa.p = p_; c.rsa.q = q_;
      c.bits = static_cast<int>(n.size()) * 8;
      out.push_back(std::move(c));
    } else if (t == "ecdsa-sha2-nistp256" || t == "ecdsa-sha2-nistp384" || t == "ecdsa-sha2-nistp521") {
      Bytes curve, pub, sk;
      if (!ssh_str(priv.data(), priv.size(), p, curve)) continue;
      if (!ssh_str(priv.data(), priv.size(), p, pub)) continue;
      if (!ssh_str(priv.data(), priv.size(), p, sk)) continue;
      c.kind = AsymKind::Ec;
      c.priv = sk;
      c.pub = pub;
      c.curve = std::string(curve.begin(), curve.end());
      out.push_back(std::move(c));
    }
  }
}

void find_raw_curve25519(const uint8_t* data, size_t len, uint64_t base,
                         std::vector<AsymCandidate>& out) {
  // We cannot distinguish a random 32-byte scalar from noise structurally, so
  // only look within a small window of a curve-adjacent marker.
  static const char* kMarkers[] = {"ed25519", "Ed25519", "ED25519", "x25519", "X25519",
                                   "curve25519", "curve448", "ssh-ed25519", "age-encryption",
                                   "wireguard", "noise_", "Noise_"};
  for (size_t i = 0; i + 4 < len; ++i) {
    for (const char* m : kMarkers) {
      size_t ml = std::strlen(m);
      if (i + ml > len || std::memcmp(data + i, m, ml) != 0) continue;
      size_t lo = i > 256 ? i - 256 : 0;
      size_t hi = std::min(len, i + ml + 256);
      for (size_t o = lo; o + 32 <= hi; o += 4) {
        if (!plausible_secret_scalar(data + o)) continue;
        AsymCandidate c;
        c.kind = AsymKind::Ed25519;
        c.container = KeyStructure::Kind::Unknown;
        c.offset = base + o;
        c.length = 32;
        c.priv.assign(data + o, data + o + 32);
        c.confidence = 35;
        c.note = "raw 32-byte scalar near '" + std::string(m) + "'";
        out.push_back(std::move(c));
      }
      break;
    }
  }
}

bool plausible_secret_scalar(const uint8_t* p) {
  int distinct = 0;
  int seen[256] = {0};
  for (int i = 0; i < 32; ++i)
    if (!seen[p[i]]++) ++distinct;
  if (distinct < 20) return false;
  // Reject byte patterns that are clearly text or counters.
  if (mostly_printable(p, 32, 0.9)) return false;
  return true;
}

void find_asym_candidates(const uint8_t* data, size_t len, uint64_t base,
                          std::vector<AsymCandidate>& out) {
  // PEM blocks first.
  auto pems = find_pem_blocks(data, len, base);
  for (const auto& pb : pems) {
    AsymCandidate c;
    if (candidate_from_pem(pb, base, c)) out.push_back(std::move(c));
  }
  find_openssh_keys(data, len, base, out);

  // DER blobs: every SEQUENCE tag is a candidate start.  Cheap length sanity
  // check keeps this linear-ish; the parse itself is bounded.
  for (size_t i = 0; i + 4 < len; ++i) {
    if (data[i] != 0x30) continue;
    uint8_t lb = data[i + 1];
    size_t l;
    if (lb < 0x80) l = lb;
    else if (lb == 0x81) l = data[i + 2];
    else if (lb == 0x82) l = (static_cast<size_t>(data[i + 2]) << 8) | data[i + 3];
    else continue;
    if (l < 32) continue;
    // Avoid re-parsing inside a PEM body we already handled.
    bool in_pem = false;
    for (const auto& pb : pems) {
      uint64_t abs = base + i;
      if (abs >= pb.begin_off && abs < pb.end_off) { in_pem = true; break; }
    }
    if (in_pem) continue;
    AsymCandidate c;
    if (candidate_from_der(data, len, i, base, false, c)) out.push_back(std::move(c));
  }
  find_raw_curve25519(data, len, base, out);
}

std::string AsymCandidate::container_describe() const {
  KeyStructure ks;
  ks.kind = container;
  std::string d = ks.describe();
  if (encrypted) d += " [encrypted]";
  return d;
}

std::string AsymCandidate::kind_name() const {
  switch (kind) {
    case AsymKind::Rsa: return "rsa";
    case AsymKind::Ec: return "ec";
    case AsymKind::Dsa: return "dsa";
    case AsymKind::Ed25519: return "ed25519";
    case AsymKind::X25519: return "x25519";
    default: return "unknown";
  }
}

}  // namespace kh
