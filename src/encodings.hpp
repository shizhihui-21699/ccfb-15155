// Text encodings found inside memory images: PEM armour, hex, base64 and the
// printable-run heuristic used to spot serialized keys stored as strings.
#pragma once
#include <cstdint>
#include <string>
#include "util.hpp"

namespace kh {

bool base64_decode(const std::string& in, Bytes& out);
std::string base64_encode(const Bytes& in);

struct PemBlock {
  std::string label;
  Bytes der;
  size_t begin_off = 0;  // offset of "-----BEGIN"
  size_t end_off = 0;
};

// Scans a byte range for valid PEM armour.  Returns blocks found.  `abs_offset`
// is added to the reported offsets.
std::vector<PemBlock> find_pem_blocks(const uint8_t* data, size_t len, uint64_t abs_offset);

// True when more than `frac` of bytes in [p,p+n) are printable ASCII/whitespace.
bool mostly_printable(const uint8_t* p, size_t n, double frac = 0.95);

// Heuristic entropy estimate in bits/byte over a buffer (byte histogram).
double byte_entropy(const uint8_t* p, size_t n);

// Does the buffer look like ASCII hex of at least `minlen` characters?
bool looks_hex_string(const uint8_t* p, size_t n, size_t minlen, size_t* run_len);

}  // namespace kh
