// Sample-driven raw-key sweep.
//
// Rationale
// ---------
// A bare key in memory has no structure to recognise, so the only honest
// detector is the ciphertext.  When the operator supplies a locked sample and
// the plaintext's first bytes are guessable (file magic), a candidate 32-byte
// key K is *proven* by one block operation:
//
//   CBC, IV prepended : D_K(C[16..32]) == P0 xor IV
//   CBC, zero IV      : D_K(C[0..16])  == P0
//   CTR, IV prepended : E_K(IV)        == P0 xor C0
//   CTR, zero IV      : E_K(0)         == P0 xor C0
//   ECB               : D_K(C[0..16])  == P0
//
// With >= 8 known plaintext bytes a false positive has probability ~2^-64, so a
// sweep over every aligned window of a huge image stays silent unless a real
// key is present.  To keep the sweep affordable, the key expansion is done once
// per window and reused across every test, and instead of N tests we evaluate
// 4 probe blocks and match their outputs against the few expected values.
#pragma once
#include <cstdint>
#include <string>
#include <vector>

#include "symmetric.hpp"
#include "verify.hpp"
#include "util.hpp"

namespace kh {


// One probe: an input block plus the set of plaintext prefixes that would make
// each output a hit.  `dec` selects decrypt-block vs encrypt-block.
struct Probe {
  uint8_t input[16] = {0};
  bool dec = true;
  std::string mode;  // human label
};

struct Expect {
  uint8_t bytes[16] = {0};
  int known = 0;     // how many prefix bytes are compared
  int probe = 0;     // index into probes
  std::string kind;  // file type guessed
};

struct KeySweepPlan {
  std::vector<Probe> probes;
  std::vector<Expect> expects;   // prefix candidates (probe index resolved)
  size_t key_len = 32;
  bool empty() const { return expects.empty(); }
};

// Build the probe/expect plan from a sample.
KeySweepPlan build_sweep_plan(const Sample& s);

// Sweep every 4-byte-aligned window as a key.  Each window is tried as the raw
// key verbatim and as a run of OpenSSL-style (byte-swapped) round-key words.
void sweep_raw_keys(const uint8_t* data, size_t len, uint64_t base, const KeySweepPlan& plan,
                    std::vector<KeyHit>& out, size_t max_hits = 64);

}  // namespace kh
