#include "kdf.hpp"

#include <cstring>

#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/pkcs12.h>
#include <openssl/x509.h>

#include "der.hpp"
#include "encodings.hpp"

namespace kh {

// Feed a raw DER blob to OpenSSL by wrapping it in PEM armour, then let
// PEM_read_bio_PrivateKey do the KDF + decryption.
static EVP_PKEY* pkcs8_pem_try(const Bytes& der, const std::string& pass) {
  std::string b64 = base64_encode(der);
  std::string pem = "-----BEGIN ENCRYPTED PRIVATE KEY-----\n" + b64 + "\n-----END ENCRYPTED PRIVATE KEY-----\n";
  BIO* b = BIO_new_mem_buf(pem.data(), static_cast<int>(pem.size()));
  if (!b) return nullptr;
  EVP_PKEY* k = PEM_read_bio_PrivateKey(b, nullptr, nullptr, const_cast<char*>(pass.c_str()));
  BIO_free(b);
  return k;
}

bool decrypt_pkcs8_with_pass(const Bytes& encrypted_der, const std::string& pass, Bytes& out_der) {
  EVP_PKEY* k = pkcs8_pem_try(encrypted_der, pass);
  if (!k) { ERR_clear_error(); return false; }
  unsigned char* der = nullptr;
  // Re-encode as plain PKCS#8: i2d_PrivateKey gives the algorithm-specific DER
  // (PKCS#1 for RSA, SEC1 for EC), which is what callers want.
  int len = i2d_PrivateKey(k, &der);
  if (len > 0) out_der.assign(der, der + len);
  OPENSSL_free(der);
  EVP_PKEY_free(k);
  return len > 0;
}

int crack_pkcs8(const Bytes& encrypted_der, const std::vector<std::string>& dict) {
  for (size_t i = 0; i < dict.size(); ++i) {
    Bytes tmp;
    if (decrypt_pkcs8_with_pass(encrypted_der, dict[i], tmp)) return static_cast<int>(i);
  }
  return -1;
}

bool decrypt_pkcs12_with_pass(const Bytes& p12_der, const std::string& pass, Bytes& out_der) {
  const unsigned char* p = p12_der.data();
  PKCS12* p12 = d2i_PKCS12(nullptr, &p, static_cast<long>(p12_der.size()));
  if (!p12) { ERR_clear_error(); return false; }
  EVP_PKEY* key = nullptr;
  X509* cert = nullptr;
  STACK_OF(X509)* ca = nullptr;
  int ok = PKCS12_parse(p12, pass.c_str(), &key, &cert, &ca);
  bool good = false;
  if (ok && key) {
    unsigned char* der = nullptr;
    int len = i2d_PrivateKey(key, &der);
    if (len > 0) { out_der.assign(der, der + len); good = true; }
    OPENSSL_free(der);
  }
  if (key) EVP_PKEY_free(key);
  if (cert) X509_free(cert);
  if (ca) sk_X509_pop_free(ca, X509_free);
  PKCS12_free(p12);
  ERR_clear_error();
  return good;
}

bool describe_encryption(const Bytes& der, std::string& algo, KdfProfile& kdf) {
  KeyStructure ks = parse_key_structure(der.data(), der.size(), 0, true);
  if (ks.kind != KeyStructure::Kind::EncryptedPkcs8) return false;
  algo = ks.algorithm_oid;
  // Re-walk to fetch KDF parameters.
  Tlv seq;
  if (!der_next(der.data(), der.size(), 0, seq, true)) return false;
  auto kids = der_children(der.data(), der.size(), seq);
  if (kids.size() < 2) return false;
  auto alg = der_children(der.data(), der.size(), kids[0]);
  if (alg.size() < 2) return false;
  Tlv params = alg[1];
  auto ps = der_children(der.data(), der.size(), params);
  for (auto& t : ps) {
    if (t.tag == 0x04 && kdf.salt.empty()) kdf.salt.assign(t.content, t.content + t.len);
    if (t.tag == 0x02) {
      // iteration count or key length: decide by size/position later.
      if (t.len <= 4) {
        uint64_t v = 0;
        for (size_t i = 0; i < t.len; ++i) v = (v << 8) | t.content[i];
        if (v > 1000) kdf.iterations = v;
        else if (v > 0 && kdf.keylen == 0) kdf.keylen = static_cast<uint32_t>(v);
      }
    }
  }
  return true;
}

}  // namespace kh
