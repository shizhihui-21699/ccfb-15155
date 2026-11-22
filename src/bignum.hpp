// Big-integer helpers for key validation and recovery.  Wraps OpenSSL BIGNUM
// (constant quality, asm-accelerated modpow) and adds the forensic operations
// that matter here:
//
//   * converting between image-resident little-endian limb arrays and BIGNUMs;
//   * RSA consistency checks (n == p*q, e*d == 1 mod lambda);
//   * factoring n from (n, e, d) -- the classic probabilistic algorithm, used
//     to rebuild p and q when only the private exponent survived;
//   * recovering an RSA key from a damaged DER blob by re-anchoring on INTEGER
//     boundaries and validating each candidate field arithmetically.
#pragma once
#include <cstdint>
#include <string>
#include <vector>

#include <openssl/bn.h>

#include "util.hpp"

namespace kh {

class Bn {
 public:
  Bn() : b_(BN_new()) {}
  explicit Bn(BIGNUM* b) : b_(b) {}
  Bn(const Bn&) = delete;
  Bn& operator=(const Bn&) = delete;
  Bn(Bn&& o) noexcept : b_(o.b_) { o.b_ = nullptr; }
  Bn& operator=(Bn&& o) noexcept {
    if (this != &o) { BN_free(b_); b_ = o.b_; o.b_ = nullptr; }
    return *this;
  }
  ~Bn() { BN_free(b_); }

  BIGNUM* get() const { return b_; }
  BIGNUM* release() { BIGNUM* r = b_; b_ = nullptr; return r; }
  bool valid() const { return b_ != nullptr; }

  int bits() const { return b_ ? BN_num_bits(b_) : 0; }
  int bytes() const { return b_ ? BN_num_bytes(b_) : 0; }

  bool set_hex(const std::string& h) { return BN_hex2bn(&b_, h.c_str()) > 0; }
  bool set_dec(const std::string& d) { return BN_dec2bn(&b_, d.c_str()) > 0; }
  bool set_bytes(const uint8_t* p, size_t n) { return BN_bin2bn(p, static_cast<int>(n), b_) != nullptr; }
  bool set_u64(uint64_t v) { return BN_set_word(b_, static_cast<BN_ULONG>(v)) == 1; }
  // Little-endian limb array as stored in OpenSSL's BIGNUM.d.
  bool set_le_limbs(const uint8_t* p, size_t nbytes);

  std::string to_hex() const;
  Bytes to_bytes() const;           // minimal big-endian, no leading zero
  Bytes to_bytes_padded(size_t n) const;  // left-padded with zeros to n bytes

 private:
  BIGNUM* b_ = nullptr;
};

// ---- structural / arithmetic validation --------------------------------
bool bn_is_probable_prime(const Bn& x, int checks = 24);
bool bn_is_one(const Bn& x);
bool bn_is_zero(const Bn& x);
bool bn_eq(const Bn& a, const Bn& b);

struct RsaParts {
  Bytes n, e, d, p, q, dp, dq, qi;  // big-endian, minimal; empty => unknown
  bool has(const Bytes& x) const { return !x.empty(); }
  int bits() const { return static_cast<int>(n.size()) * 8; }
};

// Validate a full or partial RSA key.  Fills in missing fields where possible
// (p, q from n,e,d; dp,dq,qi from p,q,d; n from p,q).  Returns a confidence
// 0..100 and sets `why` to a human-readable reason.
int rsa_validate_and_complete(RsaParts& k, std::string& why);

// Factor n given the private exponent.  Returns false if it fails.
bool rsa_factor_from_ed(const Bn& n, const Bn& e, const Bn& d, Bn& p, Bn& q);

// Recover an RSA key from a raw byte region that may be a slightly damaged
// PKCS#1 RSAPrivateKey.  Returns true when a consistent key was assembled.
bool rsa_salvage_pkcs1(const uint8_t* data, size_t len, RsaParts& out, std::string& why);

// Given ordered candidate integers of plausible sizes, find a pair p,q with
// p*q == n (uses bit-length bucketing first).
bool rsa_match_factors(const Bn& n, const std::vector<Bn*>& candidates, Bn& p, Bn& q);

}  // namespace kh
