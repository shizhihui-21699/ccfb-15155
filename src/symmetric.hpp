// Detection of symmetric key schedules and raw keys that survive in memory,
// plus the "other side" of the schedule: non-AES block ciphers (3DES, SM4,
// Camellia, Blowfish, ChaCha20) and raw high-entropy key material that is only
// a candidate until the verifier proves it.
#pragma once
#include <cstdint>
#include <string>
#include <vector>
#include "util.hpp"

namespace kh {

// One detection: where it was found and what the implied key material is.
struct KeyHit {
  enum class Source {
    AesEncSchedule,
    AesDecSchedule,
    AesRawKey,
    ChaCha20State,
    ChaCha20Key,
    DesSchedule,
    Sm4Schedule,
    CamelliaSchedule,
    BlowfishSchedule,
    RawCandidate,
    DerivedFromSchedule,
  };
  Source source = Source::RawCandidate;
  uint64_t offset = 0;
  uint32_t key_len = 0;
  uint8_t key[32] = {0};
  std::string cipher;        // "aes-256", "chacha20", "3des", ...
  std::string note;          // provenance, e.g. "enc schedule nk=8 100%"
  uint32_t matched_words = 0;
  uint32_t total_words = 0;
  bool recovered = false;     // key was reconstructed from a damaged schedule
  bool key_complete = true;   // all key bytes are known
};

struct ScanLimits {
  // Cap the number of kept raw-entropy candidates to avoid quadratic growth on
  // huge images; schedules and structured keys are always kept.
  size_t max_raw_candidates = 4096;
  size_t max_hits = 200000;
  // Minimum run length (in words) for an AES schedule to be considered when the
  // full schedule is not present.
  int min_partial_words = 8;
};

class SymmetricDetector {
 public:
  explicit SymmetricDetector(const ScanLimits& lim = {}) : lim_(lim) {}

  // Scan a whole buffer.  `base` is the buffer's absolute offset in the image.
  void scan(const uint8_t* data, size_t len, uint64_t base, std::vector<KeyHit>& out);

  struct Stats {
    std::vector<uint64_t> aes_enc_scanned;
    std::vector<uint64_t> aes_dec_scanned;
    std::vector<uint64_t> raw_windows;
  } stats;

 private:
  void scan_aes(const uint8_t* data, size_t len, uint64_t base, std::vector<KeyHit>& out);
  void scan_dec_schedules(const uint8_t* data, size_t len, uint64_t base, std::vector<KeyHit>& out);
  void scan_chacha(const uint8_t* data, size_t len, uint64_t base, std::vector<KeyHit>& out);
  void scan_raw(const uint8_t* data, size_t len, uint64_t base, std::vector<KeyHit>& out);
  void emit_schedule(std::vector<KeyHit>& out, uint64_t off, const uint32_t* key_words, int nk,
                     uint32_t matched, bool partial, const char* what);

  ScanLimits lim_;
  size_t raw_kept_ = 0;
  size_t hits_ = 0;
};

// Test a candidate raw key against "is this plausible AES key material":
// high entropy, not a repeated pattern, not mostly zero.
bool plausible_raw_key(const uint8_t* p, size_t n);

// ChaCha20: state layout is
//   constants[0..3], key[0..7], counter, nonce[0..2]   (all LE uint32)
// Accept native-LE words.  Returns true if the 16-word block is a valid state.
bool looks_like_chacha20_state(const uint32_t* w, Bytes& key_out);
// Recover the 32-byte key from a state whose key words survive partially; the
// surviving words are given as a mask.  Returns number of known key words.
int chacha20_partial_recover(const uint32_t* w, uint32_t known_mask, uint8_t key_out[32]);

}  // namespace kh
