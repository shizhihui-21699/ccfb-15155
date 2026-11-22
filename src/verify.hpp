// Verification: turn a candidate key into evidence by actually using it.
//
// For symmetric keys we try the cipher/mode combinations a ransomware sample is
// likely to use, against one or more sample blobs, and report which combination
// produced a hit and the resulting plaintext hash.  For asymmetric keys we
// check mathematical consistency and, when a key was recovered, exercise a
// private operation.
#pragma once
#include <cstdint>
#include <string>
#include <vector>

#include "privkey.hpp"
#include "symmetric.hpp"
#include "util.hpp"

namespace kh {

struct Sample {
  std::string path;
  Bytes header;     // first N bytes of the sample
  uint64_t size = 0;
  bool has_plain_magic = false;
};

// A decryption trial definition.
struct Trial {
  std::string cipher;     // EVP name, e.g. "AES-256-CBC"
  std::string mode_name;  // human label
  size_t key_len = 0;
  size_t iv_len = 0;
  uint64_t iv_offset = 0;   // where the IV is taken from in the sample
  uint64_t data_offset = 0;
};

struct Verdict {
  bool valid = false;
  std::string how;
  std::string cipher;
  std::string plaintext_sha256;
  int confidence = 0;
  Bytes sample_id;  // SHA-256 of the file carved from the image (when available)
};

// Try a symmetric key against a set of samples under a set of trials.
Verdict verify_symmetric(const KeyHit& hit, const std::vector<Sample>& samples);

// Try an asymmetric key's private operation.  Returns confidence and reason.
Verdict verify_asym(const AsymCandidate& cand);

// Predict what plaintext look like: known file magics by prefix.
bool looks_like_known_plaintext(const uint8_t* p, size_t n, std::string* kind);

}  // namespace kh
