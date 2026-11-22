// Passphrase search for encrypted key containers, and KDF recognition of the
// structures that survive in memory (PBKDF2 state, scrypt/bcrypt blobs).
#pragma once
#include <cstdint>
#include <string>
#include <vector>

#include "util.hpp"

namespace kh {

struct KdfProfile {
  enum class Kind { Pbkdf2HmacSha1, Pbkdf2HmacSha256, Pbkdf2HmacSha512, Scrypt, BcryptPbkdf, Unknown };
  Kind kind = Kind::Unknown;
  Bytes salt;
  uint64_t iterations = 0;
  uint32_t keylen = 0;
  uint32_t blocksize = 0;
  uint32_t parallelism = 0;  // scrypt p
  uint32_t cost = 0;         // bcrypt cost / scrypt N exponent
};

// Try to decrypt PKCS#8 EncryptedPrivateKeyInfo with a passphrase.  On success
// `out_der` holds the plaintext PrivateKeyInfo DER.
bool decrypt_pkcs8_with_pass(const Bytes& encrypted_der, const std::string& pass, Bytes& out_der);

// Try every passphrase in `dict`; returns index of the first that works, or -1.
int crack_pkcs8(const Bytes& encrypted_der, const std::vector<std::string>& dict);

// Try PKCS#12 MAC verification / decryption with a passphrase.
bool decrypt_pkcs12_with_pass(const Bytes& p12_der, const std::string& pass, Bytes& out_der);

// Parse the AlgorithmIdentifier of an EncryptedPrivateKeyInfo and describe it.
bool describe_encryption(const Bytes& der, std::string& algo, KdfProfile& kdf);

}  // namespace kh
