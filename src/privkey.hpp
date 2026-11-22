// Recognition of asymmetric private-key containers in memory: DER blobs, PEM
// armour, OpenSSH "openssh-key-v1" envelopes, and raw Ed25519/X25519 scalars.
// Produces structured candidates that the verifier later exercises.
#pragma once
#include <cstdint>
#include <string>
#include <vector>

#include "bignum.hpp"
#include "der.hpp"
#include "encodings.hpp"
#include "util.hpp"

namespace kh {

enum class AsymKind {
  Rsa,
  Ec,
  Dsa,
  Ed25519,
  X25519,
  Unknown,
};

struct AsymCandidate {
  AsymKind kind = AsymKind::Unknown;
  KeyStructure::Kind container = KeyStructure::Kind::Unknown;
  uint64_t offset = 0;
  uint64_t length = 0;
  std::string curve;
  int bits = 0;
  int confidence = 0;
  std::string note;

  RsaParts rsa;           // for RSA
  Bytes priv;             // EC/Ed/X scalar (big-endian, minimal)
  Bytes pub;              // public point / key when available
  Bytes dsa_p, dsa_q, dsa_g, dsa_x;

  bool encrypted = false;  // EncryptedPrivateKeyInfo / PKCS#12
  std::string encryption_oid;

  std::string container_describe() const;
  std::string kind_name() const;
};

// Scan a buffer for key containers.  PEM is detected first so its base64 body
// is not double-reported by the DER scanner.
void find_asym_candidates(const uint8_t* data, size_t len, uint64_t base,
                          std::vector<AsymCandidate>& out);

// Parse a single PEM block into a candidate.
bool candidate_from_pem(const PemBlock& pb, uint64_t base, AsymCandidate& out);

// Parse a plausible DER region (called at SEQUENCE tag positions).
bool candidate_from_der(const uint8_t* data, size_t len, size_t off, uint64_t base,
                        bool salvage, AsymCandidate& out);

// OpenSSH private key blob scan ("openssh-key-v1\0").
void find_openssh_keys(const uint8_t* data, size_t len, uint64_t base,
                       std::vector<AsymCandidate>& out);

// Raw 32-byte curve25519/448 scalar heuristics near crypto-adjacent strings.
void find_raw_curve25519(const uint8_t* data, size_t len, uint64_t base,
                         std::vector<AsymCandidate>& out);

// Ed25519: derive public key from 32-byte seed using OpenSSL; used by verifier
// and by the generator.  Returns false if OpenSSL refuses the scalar.
bool ed25519_pubkey(const uint8_t seed[32], uint8_t pub[32]);
// Reject byte patterns that cannot be a random curve scalar (text, counters).
bool plausible_secret_scalar(const uint8_t* p);
bool x25519_pubkey(const uint8_t scalar[32], uint8_t pub[32]);

}  // namespace kh
