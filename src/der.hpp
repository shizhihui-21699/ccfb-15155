// Minimal, hardened DER/BER walker.  Enough ASN.1 to recognise the PKCS#1/#8,
// SEC1, PKCS#7 and X.509 shapes that carry private keys, and to keep going when
// a length or tag is damaged (memory images are not clean files).
#pragma once
#include <cstdint>
#include <string>
#include <vector>
#include "util.hpp"

namespace kh {

enum class Tag : uint8_t {
  Boolean = 0x01,
  Integer = 0x02,
  BitString = 0x03,
  OctetString = 0x04,
  Null = 0x05,
  Oid = 0x06,
  Utf8String = 0x0c,
  PrintableString = 0x13,
  IA5String = 0x16,
  UtcTime = 0x17,
  GeneralizedTime = 0x18,
  Sequence = 0x30,
  Set = 0x31,
};

struct Tlv {
  uint8_t tag = 0;
  size_t hdr_len = 0;   // header bytes (tag + length)
  size_t len = 0;       // content length (0 when indefinite/unknown)
  bool indefinite = false;
  size_t off = 0;       // offset of the tag byte relative to the parse base
  const uint8_t* content = nullptr;

  size_t total() const { return hdr_len + len; }
};

// Strict-ish parser.  Returns false and fills `err` when the TLV at `off` is
// not decodable.  `allow_ber` permits indefinite-length and constructed strings.
bool der_next(const uint8_t* data, size_t len, size_t off, Tlv& out, bool allow_ber = true);

// Iterate the children of a constructed TLV; tolerant of trailing junk.
std::vector<Tlv> der_children(const uint8_t* data, size_t len, const Tlv& parent, bool allow_ber = true);

bool der_oid_to_string(const Tlv& tlv, std::string& out);
bool der_integer_positive(const Tlv& tlv);
// Strip leading zero padding from an INTEGER's content.
void der_integer_bytes(const Tlv& tlv, const uint8_t*& p, size_t& n);

// A "parse report" from attempting to interpret a region as a private key.
struct KeyStructure {
  enum class Kind {
    Unknown,
    RsaPkcs1,       // RSAPrivateKey ::= SEQUENCE {version,n,e,d,p,q,...}
    RsaPkcs8,       // PrivateKeyInfo wrapping rsaEncryption
    EcSec1,         // ECPrivateKey ::= SEQUENCE {1, privateKey OCTET STRING, ...}
    EcPkcs8,        // PrivateKeyInfo wrapping id-ecPublicKey
    Ed25519Pkcs8,   // PrivateKeyInfo wrapping Ed25519 (CurvePrivateKey)
    X25519Pkcs8,
    DsaPkcs8,
    EncryptedPkcs8, // EncryptedPrivateKeyInfo -- needs a passphrase
    Pkcs12,
    Pkcs7,
    Certificate,    // X.509, not a key but useful for hunting cert structure
    OpenSshPrivate, // "openssh-key-v1" envelope
  };
  Kind kind = Kind::Unknown;
  size_t off = 0;        // offset of the outer SEQUENCE
  size_t total_len = 0;
  bool complete = true;  // false when length ran past available bytes
  std::string algorithm_oid;
  int bits = 0;
  // Field offsets (relative to parse base) for the key material, filled where
  // applicable so callers can hand exact byte ranges to the verifier.
  struct Field {
    const uint8_t* p = nullptr;
    size_t n = 0;
  } n, e, d, p, q, dp, dq, qinv, priv, pub;
  Field dsa_p, dsa_q, dsa_g;

  std::string describe() const;
};

// Attempt to classify a region starting exactly at `off`.  `salvage` keeps
// parsing damaged structures (used by the candidate path, not the scan path).
KeyStructure parse_key_structure(const uint8_t* data, size_t len, size_t off, bool salvage);

// Famous OID strings.
extern const char* kOidRsaEncryption;   // 1.2.840.113549.1.1.1
extern const char* kOidRsaPss;          // 1.2.840.113549.1.1.10
extern const char* kOidEcPublicKey;     // 1.2.840.10045.2.1
extern const char* kOidEd25519;         // 1.3.101.112
extern const char* kOidX25519;          // 1.3.101.110
extern const char* kOidEd448;           // 1.3.101.113
extern const char* kOidDsa;             // 1.2.840.10040.4.1
extern const char* kOidNamedCurves[];   // null-terminated pairs name/oid
bool oid_is_curve(const std::string& oid, std::string* name, int* bits);

}  // namespace kh
