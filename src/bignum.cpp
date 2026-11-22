#include "bignum.hpp"

#include <cstring>

#include <openssl/bn.h>
#include <openssl/crypto.h>
#include <openssl/err.h>

namespace kh {

bool Bn::set_le_limbs(const uint8_t* p, size_t nbytes) {
  // Reverse to big-endian, then import.
  Bytes be(nbytes);
  for (size_t i = 0; i < nbytes; ++i) be[i] = p[nbytes - 1 - i];
  return BN_bin2bn(be.data(), static_cast<int>(be.size()), b_) != nullptr;
}

std::string Bn::to_hex() const {
  char* h = BN_bn2hex(b_);
  if (!h) return {};
  std::string s(h);
  OPENSSL_free(h);
  // BN_bn2hex emits uppercase with a leading '-' for negatives; strip to lower.
  if (!s.empty() && s[0] == '-') s = s.substr(1);
  for (auto& c : s) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
  return s;
}

Bytes Bn::to_bytes() const {
  Bytes out(static_cast<size_t>(BN_num_bytes(b_)));
  if (!out.empty()) BN_bn2bin(b_, out.data());
  return out;
}

Bytes Bn::to_bytes_padded(size_t n) const {
  Bytes out(n, 0);
  size_t have = static_cast<size_t>(BN_num_bytes(b_));
  if (have > n) return to_bytes();
  BN_bn2bin(b_, out.data() + (n - have));
  return out;
}

bool bn_is_probable_prime(const Bn& x, int checks) {
  if (!x.valid() || x.bits() < 2) return false;
  (void)checks;  // BN_check_prime always runs a strong Miller-Rabin battery
  return BN_check_prime(x.get(), nullptr, nullptr) == 1;
}

bool bn_is_one(const Bn& x) { return BN_is_one(x.get()) == 1; }
bool bn_is_zero(const Bn& x) { return BN_is_zero(x.get()) == 1; }
bool bn_eq(const Bn& a, const Bn& b) { return BN_cmp(a.get(), b.get()) == 0; }

namespace {

Bytes bn_bytes(const BIGNUM* b) {
  Bytes out(static_cast<size_t>(BN_num_bytes(b)));
  if (!out.empty()) BN_bn2bin(b, out.data());
  return out;
}

Bn bytes_bn(const Bytes& b) {
  Bn r;
  if (!b.empty()) r.set_bytes(b.data(), b.size());
  return r;
}

// lcm(a,b)
void bn_lcm(BIGNUM* out, const BIGNUM* a, const BIGNUM* b, BN_CTX* ctx) {
  BIGNUM* g = BN_new();
  BIGNUM* t = BN_new();
  BN_gcd(g, a, b, ctx);
  BN_mul(t, a, b, ctx);
  BN_div(out, nullptr, t, g, ctx);
  BN_free(g);
  BN_free(t);
}

}  // namespace

bool rsa_factor_from_ed(const Bn& n, const Bn& e, const Bn& d, Bn& p, Bn& q) {
  // Algorithm: k = e*d - 1 = 2^t * r.  For random g, squaring g^r until it hits
  // 1 yields a square root of 1 mod n other than +/-1 with good probability,
  // giving a factor via gcd(x-1, n).
  BN_CTX* ctx = BN_CTX_new();
  BIGNUM* k = BN_new();
  BIGNUM* r = BN_new();
  BIGNUM* g = BN_new();
  BIGNUM* x = BN_new();
  BIGNUM* y = BN_new();
  BIGNUM* diff = BN_new();
  BIGNUM* pm = BN_new();
  BIGNUM* qm = BN_new();
  BN_mul(k, e.get(), d.get(), ctx);
  BN_sub_word(k, 1);
  int t = 0;
  BN_copy(r, k);
  while (!BN_is_odd(r)) { BN_rshift1(r, r); ++t; }
  bool ok = false;
  unsigned seed = 0x9e3779b9u;
  for (int iter = 0; iter < 100 && !ok; ++iter) {
    // deterministic pseudo-random g in [2, n-1]
    BIGNUM* range = BN_dup(n.get());
    BN_sub_word(range, 3);
    seed = seed * 1103515245u + 12345u;
    BN_set_word(g, (seed % 0xfffffffeu) + 2);
    BN_free(range);
    if (BN_cmp(g, n.get()) >= 0) BN_set_word(g, 2);
    BN_mod_exp(x, g, r, n.get(), ctx);
    if (BN_is_one(x) || BN_cmp(x, n.get()) == 0) continue;
    for (int j = 1; j < t && !ok; ++j) {
      BN_mod_exp(y, x, BN_value_one(), n.get(), ctx);  // placeholder
      BN_mod_sqr(y, x, n.get(), ctx);
      if (BN_is_one(y)) {
        // x is a nontrivial square root of 1
        BN_sub_word(x, 1);
        BN_gcd(pm, x, n.get(), ctx);
        if (BN_is_one(pm) || BN_cmp(pm, n.get()) == 0) { BN_add_word(x, 1); continue; }
        BN_div(qm, nullptr, n.get(), pm, ctx);
        p = Bn(BN_dup(pm));
        q = Bn(BN_dup(qm));
        ok = true;
        break;
      }
      if (BN_cmp(y, n.get()) == 0) break;
      BN_copy(x, y);
    }
  }
  BN_free(k); BN_free(r); BN_free(g); BN_free(x); BN_free(y);
  BN_free(diff); BN_free(pm); BN_free(qm);
  BN_CTX_free(ctx);
  return ok;
}

bool rsa_match_factors(const Bn& n, const std::vector<Bn*>& candidates, Bn& p, Bn& q) {
  int nb = n.bits();
  for (size_t i = 0; i < candidates.size(); ++i) {
    for (size_t j = i + 1; j < candidates.size(); ++j) {
      if (std::abs(candidates[i]->bits() - candidates[j]->bits()) > 2) continue;
      if (candidates[i]->bits() + candidates[j]->bits() < nb - 1) continue;
      BN_CTX* ctx = BN_CTX_new();
      BIGNUM* prod = BN_new();
      BN_mul(prod, candidates[i]->get(), candidates[j]->get(), ctx);
      bool eq = BN_cmp(prod, n.get()) == 0;
      BN_free(prod);
      BN_CTX_free(ctx);
      if (eq) {
        p = Bn(BN_dup(candidates[i]->get()));
        q = Bn(BN_dup(candidates[j]->get()));
        return true;
      }
    }
  }
  return false;
}

int rsa_validate_and_complete(RsaParts& k, std::string& why) {
  auto toBn = [](const Bytes& b) { return bytes_bn(b); };
  if (k.n.empty() || k.e.empty()) { why = "missing n or e"; return 0; }
  Bn n = toBn(k.n), e = toBn(k.e);
  if (n.bits() < 512 || n.bits() > 16384) { why = "n size implausible"; return 0; }
  if (e.bits() > 64 || bn_is_zero(e)) { why = "e implausible"; return 10; }
  int conf = 40;
  BN_CTX* ctx = BN_CTX_new();

  // If we have p and q, the strongest check is n == p*q.
  if (!k.p.empty() && !k.q.empty()) {
    Bn p = toBn(k.p), q = toBn(k.q);
    BIGNUM* prod = BN_new();
    BN_mul(prod, p.get(), q.get(), ctx);
    bool eq = BN_cmp(prod, n.get()) == 0;
    BN_free(prod);
    if (!eq) {
      // Maybe p and q are actually the two prime factors of n but swapped or
      // padded; try n divisible by each.
      if (BN_div(nullptr, nullptr, n.get(), p.get(), ctx) == 1 ||
          BN_mod_word(n.get(), 2) == 0) {
        /* fall through */
      }
      BIGNUM* rem = BN_new();
      BN_div(nullptr, rem, n.get(), p.get(), ctx);
      if (!BN_is_zero(rem)) { BN_free(rem); BN_CTX_free(ctx); why = "p*q != n"; return 5; }
      BN_free(rem);
      BN_div(q.get(), nullptr, n.get(), p.get(), ctx);
      k.q = bn_bytes(q.get());
    }
    conf = 85;
    if (bn_is_probable_prime(p) && bn_is_probable_prime(q)) conf = 95;
  } else if (!k.d.empty()) {
    conf = 65;
  }

  // Derive n from p*q when only the factors survived.
  if (k.n.empty() && !k.p.empty() && !k.q.empty()) {
    Bn p = toBn(k.p), q = toBn(k.q);
    BIGNUM* prod = BN_new();
    BN_mul(prod, p.get(), q.get(), ctx);
    k.n = bn_bytes(prod);
    BN_free(prod);
    conf = 80;
  }

  // If we have d but no factors, factor n to rebuild them, or at least check
  // e*d consistency modulo lambda (which needs factors, so factor).
  if (!k.d.empty() && (k.p.empty() || k.q.empty())) {
    Bn d = toBn(k.d);
    Bn p2, q2;
    if (rsa_factor_from_ed(n, e, d, p2, q2)) {
      k.p = p2.to_bytes();
      k.q = q2.to_bytes();
      conf = std::max(conf, 90);
    } else {
      why = "could not factor n from (n,e,d)";
      conf = std::min(conf, 60);
    }
  }

  // Rebuild CRT parameters when factors exist.
  if (!k.p.empty() && !k.q.empty()) {
    Bn p = toBn(k.p), q = toBn(k.q);
    if (k.d.empty() && !k.e.empty()) {
      BIGNUM* phi = BN_new();
      BIGNUM* p1 = BN_dup(p.get());
      BIGNUM* q1 = BN_dup(q.get());
      BN_sub_word(p1, 1);
      BN_sub_word(q1, 1);
      bn_lcm(phi, p1, q1, ctx);
      BIGNUM* d = BN_new();
      if (BN_mod_inverse(d, e.get(), phi, ctx)) {
        k.d = bn_bytes(d);
        conf = std::max(conf, 88);
      }
      BN_free(phi); BN_free(p1); BN_free(q1); BN_free(d);
    }
    if (k.dp.empty() || k.dq.empty() || k.qi.empty()) {
      Bn d = k.d.empty() ? Bn() : toBn(k.d);
      if (d.valid()) {
        BIGNUM* dp = BN_new();
        BIGNUM* dq = BN_new();
        BIGNUM* qi = BN_new();
        BIGNUM* p1 = BN_dup(p.get());
        BIGNUM* q1 = BN_dup(q.get());
        BN_sub_word(p1, 1);
        BN_sub_word(q1, 1);
        BN_mod(dp, d.get(), p1, ctx);
        BN_mod(dq, d.get(), q1, ctx);
        BN_mod_inverse(qi, q.get(), p.get(), ctx);
        if (k.dp.empty()) k.dp = bn_bytes(dp);
        if (k.dq.empty()) k.dq = bn_bytes(dq);
        if (k.qi.empty() && qi) k.qi = bn_bytes(qi);
        BN_free(dp); BN_free(dq); BN_free(qi); BN_free(p1); BN_free(q1);
      }
    }
    if (k.d.empty()) conf = std::max(conf, 70);
  }

  if (k.d.empty() && (k.p.empty() || k.q.empty())) conf = std::min(conf, 55);
  BN_CTX_free(ctx);
  if (conf >= 85) why = "consistent RSA key";
  else if (why.empty()) why = "partial RSA key";
  return conf;
}

bool rsa_salvage_pkcs1(const uint8_t* data, size_t len, RsaParts& out, std::string& why) {
  // Find INTEGER TLVs in the region, accept those with plausible lengths for
  // n,e,d,p,q,dp,dq,qi and try to assemble a consistent key.  This tolerates a
  // damaged SEQUENCE header or one corrupt field.
  struct Item {
    size_t off;
    size_t len;
    const uint8_t* p;
  };
  std::vector<Item> ints;
  for (size_t i = 0; i + 4 < len; ++i) {
    if (data[i] != 0x02) continue;
    uint8_t lb = data[i + 1];
    size_t l = 0, hdr = 2;
    if (lb < 0x80) {
      l = lb;
    } else if (lb == 0x81) {
      if (i + 2 >= len) continue;
      l = data[i + 2];
      hdr = 3;
    } else if (lb == 0x82) {
      if (i + 3 >= len) continue;
      l = (static_cast<size_t>(data[i + 2]) << 8) | data[i + 3];
      hdr = 4;
    } else {
      continue;
    }
    if (l == 0 || i + hdr + l > len) continue;
    ints.push_back({i, l, data + i + hdr});
  }
  if (ints.size() < 2) return false;

  // Look for n: the largest integer that is 64..1024 bytes.
  int ni = -1;
  for (size_t i = 0; i < ints.size(); ++i) {
    if (ints[i].len >= 64 && ints[i].len <= 1024) {
      if (ni < 0 || ints[i].len > ints[ni].len) ni = static_cast<int>(i);
    }
  }
  if (ni < 0) { why = "no n-sized integer found"; return false; }
  out.n.assign(ints[ni].p, ints[ni].p + ints[ni].len);
  while (out.n.size() > 1 && out.n[0] == 0) out.n.erase(out.n.begin());

  // e: small integer, usually 65537 (3 bytes) but accept up to 8.
  for (size_t i = 0; i < ints.size(); ++i) {
    if (ints[i].len <= 8 && ints[i].len >= 1 && static_cast<int>(i) != ni) {
      Bytes v(ints[i].p, ints[i].p + ints[i].len);
      while (v.size() > 1 && v[0] == 0) v.erase(v.begin());
      Bn b;
      b.set_bytes(v.data(), v.size());
      if (b.bits() >= 2 && b.bits() <= 33) { out.e = v; break; }
    }
  }

  // d: comparable to n in size (usually slightly smaller).
  for (size_t i = 0; i < ints.size(); ++i) {
    if (static_cast<int>(i) == ni) continue;
    if (ints[i].len >= out.n.size() - 4 && ints[i].len <= out.n.size() + 1) {
      Bytes v(ints[i].p, ints[i].p + ints[i].len);
      while (v.size() > 1 && v[0] == 0) v.erase(v.begin());
      if (!out.d.empty()) break;
      out.d = v;
    }
  }

  // p, q: half-size primes.
  {
    std::vector<Bn*> cands;
    std::vector<size_t> idx;
    for (size_t i = 0; i < ints.size(); ++i) {
      if (static_cast<int>(i) == ni) continue;
      if (ints[i].len >= out.n.size() / 2 - 4 && ints[i].len <= out.n.size() / 2 + 4) {
        Bn* b = new Bn();
        const uint8_t* p = ints[i].p;
        size_t n = ints[i].len;
        while (n > 1 && *p == 0) { ++p; --n; }
        b->set_bytes(p, n);
        cands.push_back(b);
        idx.push_back(i);
      }
    }
    Bn nbn = bytes_bn(out.n);
    Bn pb, qb;
    if (cands.size() >= 2 && rsa_match_factors(nbn, cands, pb, qb)) {
      out.p = pb.to_bytes();
      out.q = qb.to_bytes();
    }
    for (auto* b : cands) delete b;
  }

  std::string vwhy;
  int conf = rsa_validate_and_complete(out, vwhy);
  why = vwhy;
  return conf >= 60 && !out.n.empty();
}

}  // namespace kh
