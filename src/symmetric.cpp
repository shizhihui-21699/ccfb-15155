#include "symmetric.hpp"

#include <algorithm>
#include <cstring>
#include <unordered_set>

#include "aes.hpp"
#include "encodings.hpp"

namespace kh {
namespace {

inline uint32_t ld(const uint8_t* p) { return rd32(p); }

// Collect candidate AES schedule starts from the linear recurrence
//   w[q] == w[q-nk] ^ w[q-1]
// A true match at q implies the schedule starts at s = q - nk - t for some
// t in [1, nk-1] (t = (q-s) mod nk, which is never 0 for a free word).  In
// random data this predicate fires with probability 2^-32 per word, so the
// candidate list stays nearly empty even on multi-GB images.
template <typename F>
void for_each_schedule_start(const uint8_t* data, size_t len, int nk, F&& fn) {
  const size_t nwords = len / 4;
  if (nwords < static_cast<size_t>(nk + 2)) return;
  std::unordered_set<uint32_t> tested;
  tested.reserve(64);
  auto w = [&](size_t i) { return ld(data + 4 * i); };
  for (size_t q = static_cast<size_t>(nk); q < nwords; ++q) {
    if (w(q) != (w(q - nk) ^ w(q - 1))) continue;
    for (int t = 1; t < nk; ++t) {
      long long s_ll = static_cast<long long>(q) - nk - t;
      if (s_ll < 0) continue;
      size_t s = static_cast<size_t>(s_ll);
      if (s + nk > nwords) continue;
      if (tested.size() < 4096 && !tested.insert(static_cast<uint32_t>(s)).second) continue;
      if (!fn(s, nwords)) return;
    }
  }
}

}  // namespace

bool plausible_raw_key(const uint8_t* p, size_t n) {
  if (n != 16 && n != 24 && n != 32) return false;
  int seen[256] = {0};
  int distinct = 0;
  int zeros = 0;
  for (size_t i = 0; i < n; ++i) {
    if (!seen[p[i]]++) ++distinct;
    if (p[i] == 0) ++zeros;
  }
  if (distinct < static_cast<int>(n * 0.55)) return false;
  if (zeros > static_cast<int>(n / 4)) return false;
  int run = 1;
  for (size_t i = 1; i < n; ++i) {
    run = (p[i] == p[i - 1]) ? run + 1 : 1;
    if (run >= 8) return false;
  }
  return true;
}

bool looks_like_chacha20_state(const uint32_t* w, Bytes& key_out) {
  static const uint32_t k32[4] = {0x61707865u, 0x3320646eu, 0x79622d32u, 0x6b206574u};
  static const uint32_t k16[4] = {0x61707865u, 0x3120646eu, 0x79622d36u, 0x6b206574u};
  bool m32 = true, m16 = true;
  for (int i = 0; i < 4; ++i) {
    if (w[i] != k32[i]) m32 = false;
    if (w[i] != k16[i]) m16 = false;
  }
  if (!m32 && !m16) return false;
  key_out.resize(32);
  for (int i = 0; i < 8; ++i) {
    key_out[i * 4 + 0] = static_cast<uint8_t>(w[4 + i]);
    key_out[i * 4 + 1] = static_cast<uint8_t>(w[4 + i] >> 8);
    key_out[i * 4 + 2] = static_cast<uint8_t>(w[4 + i] >> 16);
    key_out[i * 4 + 3] = static_cast<uint8_t>(w[4 + i] >> 24);
  }
  return true;
}

int chacha20_partial_recover(const uint32_t* w, uint32_t known_mask, uint8_t key_out[32]) {
  int got = 0;
  for (int i = 0; i < 8; ++i) {
    bool k = (known_mask >> i) & 1;
    uint32_t v = k ? w[4 + i] : 0;
    if (k) ++got;
    key_out[i * 4 + 0] = static_cast<uint8_t>(v);
    key_out[i * 4 + 1] = static_cast<uint8_t>(v >> 8);
    key_out[i * 4 + 2] = static_cast<uint8_t>(v >> 16);
    key_out[i * 4 + 3] = static_cast<uint8_t>(v >> 24);
  }
  return got;
}

// ---------------------------------------------------------------------------
// AES schedule detection.
// ---------------------------------------------------------------------------
void SymmetricDetector::scan_aes(const uint8_t* data, size_t len, uint64_t base,
                                 std::vector<KeyHit>& out) {
  for (int nk : {8, 6, 4}) {
    const int nw = aes_nwords(nk);
    for_each_schedule_start(data, len, nk, [&](size_t s, size_t nwords) -> bool {
      size_t avail = std::min(static_cast<size_t>(nw), nwords - s);
      if (avail < static_cast<size_t>(nk + 2)) return true;
      uint32_t words[kAesMaxWords];
      for (size_t i = 0; i < avail; ++i) words[i] = ld(data + 4 * (s + i));

      // Path 1: every surviving word is genuine -> plain expansion check.
      {
        AesSchedule sc;
        if (aes_expand_words(words, nk, sc, false)) {
          size_t match = 0;
          for (size_t i = 0; i < avail; ++i)
            if (words[i] == sc.enc[i]) ++match;
          if (match == avail) {
            emit_schedule(out, base + 4 * s, sc.enc.data(), nk, static_cast<uint32_t>(match),
                          avail < static_cast<size_t>(nw), "enc schedule");
            stats.aes_enc_scanned.push_back(base + 4 * s);
            return true;
          }
        }
      }
      // Path 2: damaged schedule -> reconstruct the key, then verify against
      // memory words ONLY at indices >= nk.  Words below nk are the seeds the
      // expansion was built from and would match trivially; and a window that
      // is a *shifted* view of a real schedule satisfies the linear recurrence
      // but its expansion disagrees with memory beyond the seed region, so this
      // test is what separates a true partial schedule from a shifted one.
      std::array<int64_t, kAesMaxWords> known;
      known.fill(-1);
      size_t seeds = 0;
      for (size_t i = 0; i < avail; ++i) {
        if (words[i] != 0) {
          known[i] = static_cast<int64_t>(words[i]);
          ++seeds;
        }
      }
      if (seeds < static_cast<size_t>(nk + 3)) return true;
      if (aes_reconstruct_enc(known, nk) < nk) return true;
      uint32_t keyw[kAesMaxWords];
      for (int i = 0; i < nk; ++i) keyw[i] = static_cast<uint32_t>(known[i]);
      AesSchedule sc;
      if (!aes_expand_words(keyw, nk, sc, false)) return true;
      size_t beyond = 0, beyond_match = 0;
      for (size_t i = static_cast<size_t>(nk); i < avail; ++i) {
        if (words[i] == 0) continue;  // damaged/missing word: no evidence either way
        ++beyond;
        if (words[i] == sc.enc[i]) ++beyond_match;
      }
      // Demand a solid derived region, not just a couple of coincidences.
      if (beyond >= static_cast<size_t>(nk + 2) && beyond_match >= static_cast<size_t>(nk + 2) &&
          beyond_match * 100 >= beyond * 90) {
        emit_schedule(out, base + 4 * s, sc.enc.data(), nk,
                      static_cast<uint32_t>(beyond_match + nk), true, "salvaged enc schedule");
        stats.aes_enc_scanned.push_back(base + 4 * s);
        return true;
      }
      return true;
    });
  }
}

void SymmetricDetector::emit_schedule(std::vector<KeyHit>& out, uint64_t off, const uint32_t* key_words,
                                      int nk, uint32_t matched, bool partial, const char* what) {
  KeyHit h;
  h.source = KeyHit::Source::AesEncSchedule;
  h.offset = off;
  h.key_len = static_cast<uint32_t>(nk * 4);
  aes_words_to_key(key_words, nk, h.key);
  h.cipher = "aes-" + std::to_string(nk * 32);
  h.matched_words = matched;
  h.total_words = static_cast<uint32_t>(aes_nwords(nk));
  h.recovered = partial;
  h.note = std::string(what) + " " + std::to_string(matched) + "/" + std::to_string(h.total_words) +
           " words";
  out.push_back(h);
  ++hits_;
}

// ---------------------------------------------------------------------------
// Decryption schedules.  Two independent anchors:
//   * the round count OpenSSL stores right after rd_key[];
//   * runs of d[i] == d[i+4] ^ d[i-1] within the interior of the reversed
//     IntegerMixColumn'd blocks (covers layouts without a rounds field).
// ---------------------------------------------------------------------------
void SymmetricDetector::scan_dec_schedules(const uint8_t* data, size_t len, uint64_t base,
                                           std::vector<KeyHit>& out) {
  const size_t nwords = len / 4;

  auto try_at = [&](size_t s, int nk) {
    int nw = aes_nwords(nk);
    if (s + static_cast<size_t>(nw) > nwords) return;
    uint32_t words[kAesMaxWords];
    for (int i = 0; i < nw; ++i) words[i] = ld(data + 4 * (s + i));
    if (aes_verify_dec(words, nk) != nw) return;
    uint8_t raw[32];
    if (!aes_dec_to_raw(words, nk, raw)) return;
    KeyHit h;
    h.source = KeyHit::Source::AesDecSchedule;
    h.offset = base + 4 * s;
    h.key_len = static_cast<uint32_t>(nk * 4);
    std::memcpy(h.key, raw, h.key_len);
    h.cipher = "aes-" + std::to_string(nk * 32);
    h.matched_words = static_cast<uint32_t>(nw);
    h.total_words = static_cast<uint32_t>(nw);
    h.note = "dec schedule";
    out.push_back(h);
    ++hits_;
    stats.aes_dec_scanned.push_back(h.offset);
  };

  // Anchor A: rounds word == 10/12/14 immediately after the schedule.
  for (size_t q = 0; q < nwords; ++q) {
    uint32_t v = ld(data + 4 * q);
    if (v != 10 && v != 12 && v != 14) continue;
    int nk = static_cast<int>(v) - 6;
    int nw = aes_nwords(nk);
    if (q < static_cast<size_t>(nw)) continue;
    try_at(q - nw, nk);
  }

  // Anchor B: runs of the reversed-block recurrence theorem.
  for (size_t q = 1; q + 4 < nwords; ++q) {
    if (q % 4 == 0) continue;
    if (ld(data + 4 * q) != (ld(data + 4 * (q + 4)) ^ ld(data + 4 * (q - 1)))) continue;
    // A recurrence match at word q forces the schedule start to be congruent
    // to q mod 4 with s <= q-4; only s = q-4 is closest, attempt it.
    for (int nk : {4, 6, 8}) {
      int nw = aes_nwords(nk);
      size_t s = q - 4;
      if (s + static_cast<size_t>(nw) > nwords) continue;
      try_at(s, nk);
    }
  }
}

void SymmetricDetector::scan_chacha(const uint8_t* data, size_t len, uint64_t base,
                                    std::vector<KeyHit>& out) {
  static const char kConst[] = "expand 32-byte k";
  static const char kConst16[] = "expand 16-byte k";
  for (size_t i = 0; i + 64 <= len; ++i) {
    if (std::memcmp(data + i, kConst, 16) != 0 && std::memcmp(data + i, kConst16, 16) != 0) continue;
    uint32_t w[16];
    for (int k = 0; k < 16; ++k) w[k] = ld(data + i + 4 * k);
    Bytes key;
    if (!looks_like_chacha20_state(w, key)) continue;
    KeyHit h;
    h.source = KeyHit::Source::ChaCha20State;
    h.offset = base + i;
    h.key_len = 32;
    std::memcpy(h.key, key.data(), 32);
    h.cipher = "chacha20";
    h.matched_words = 4;
    h.total_words = 16;
    h.note = "chacha20 state (constants intact)";
    out.push_back(h);
    ++hits_;
  }
}

void SymmetricDetector::scan_raw(const uint8_t* data, size_t len, uint64_t base,
                                 std::vector<KeyHit>& out) {
  static const char* kContext[] = {"AES", "aes", "ChaCha", "chacha", "Rijndael", "encrypt",
                                   "Encrypt", "cipher", "Cipher", "salsa", "Salsa", "nonce",
                                   "secret", "locked", "ransom", "RANSOM", "filekey", "FileKey"};
  const size_t kPage = 4096;
  for (size_t pg = 0; pg < len; pg += kPage) {
    if (raw_kept_ >= lim_.max_raw_candidates) return;
    size_t plen = std::min(kPage, len - pg);
    if (byte_entropy(data + pg, plen) < 7.0) continue;
    bool ctx = false;
    size_t lo = pg > 2048 ? pg - 2048 : 0;
    size_t hi = std::min(len, pg + plen + 2048);
    for (const char* kw : kContext) {
      size_t kl = std::strlen(kw);
      if (kl > hi - lo) continue;
      for (size_t j = lo; j + kl <= hi; ++j)
        if (std::memcmp(data + j, kw, kl) == 0) { ctx = true; break; }
      if (ctx) break;
    }
    if (!ctx) continue;
    for (size_t o = pg; o + 16 <= pg + plen; o += 4) {
      if (raw_kept_ >= lim_.max_raw_candidates) return;
      for (size_t kl : {size_t{32}, size_t{16}, size_t{24}}) {
        if (o + kl > pg + plen) continue;
        if (!plausible_raw_key(data + o, kl)) continue;
        KeyHit h;
        h.source = KeyHit::Source::RawCandidate;
        h.offset = base + o;
        h.key_len = static_cast<uint32_t>(kl);
        std::memcpy(h.key, data + o, kl);
        h.cipher = "unknown";
        h.note = "raw " + std::to_string(kl) + "-byte entropy near crypto strings";
        out.push_back(h);
        ++raw_kept_;
      }
    }
  }
  stats.raw_windows.push_back(base);
}

void SymmetricDetector::scan(const uint8_t* data, size_t len, uint64_t base,
                             std::vector<KeyHit>& out) {
  if (len < 64) return;
  scan_aes(data, len, base, out);
  scan_dec_schedules(data, len, base, out);
  scan_chacha(data, len, base, out);
  if (lim_.max_raw_candidates) scan_raw(data, len, base, out);
  if (out.size() >= lim_.max_hits) out.resize(lim_.max_hits);
}

}  // namespace kh
