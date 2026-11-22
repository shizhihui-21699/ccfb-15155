#include "keysweep.hpp"

#include <cstring>

#include "fast_aes.hpp"
#include "verify.hpp"

namespace kh {
namespace {

struct Prefix {
  const char* kind;
  const char* bytes;
  size_t len;  // length derived from the literal; never declared by hand
};

// Prefixes worth guessing; only >= 8 bytes can be compared without inflating
// the false-positive rate.  The length is deduced from the array size, so a
// wrong hand-written count can never over-read the literal.
#define KH_PREFIX(k, lit) Prefix{k, lit, sizeof(lit) - 1}
const Prefix kPrefixes[] = {
    KH_PREFIX("PDF", "%PDF-1.7"),
    KH_PREFIX("PDF", "%PDF-1.6"),
    KH_PREFIX("PDF", "%PDF-1.5"),
    KH_PREFIX("PDF", "%PDF-1.4"),
    KH_PREFIX("PDF", "%PDF-1.3"),
    KH_PREFIX("ZIP/OOXML", "PK\x03\x04\x14\x00\x06\x00\x08\x00"),
    KH_PREFIX("ZIP/OOXML", "PK\x03\x04\x14\x00\x00\x00\x08\x00"),
    KH_PREFIX("Office/OLE", "\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"),
    KH_PREFIX("PNG", "\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR"),
    KH_PREFIX("SQLite", "SQLite format 3\x00"),
    KH_PREFIX("ELF", "\x7f" "ELF\x02\x01\x01\x00"),
    KH_PREFIX("JPEG", "\xff\xd8\xff\xe0\x00\x10JFIF\x00"),
    KH_PREFIX("GZIP", "\x1f\x8b\x08\x08\x00\x00\x00\x00"),
    KH_PREFIX("7z", "7z\xbc\xaf\x27\x1c\x00\x04"),
    KH_PREFIX("RAR", "Rar!\x1a\x07\x01\x00"),
    KH_PREFIX("XML", "<?xml version="),
};
#undef KH_PREFIX

Bytes pad(const char* p, size_t n) {
  Bytes b(16, 0);
  std::memcpy(b.data(), p, n < 16 ? n : 16);
  return b;
}

}  // namespace

KeySweepPlan build_sweep_plan(const Sample& s) {
  KeySweepPlan plan;
  const Bytes& h = s.header;
  if (h.size() < 48) return plan;
  plan.key_len = 32;
  // Probe blocks: 0 = C0, 1 = C16, 2 = zero, 3 = IV(=C0).
  // Decrypt probes are C0 and C16; encrypt probes are zero and IV.
  auto add_probe = [&](const uint8_t* in, bool dec, const char* mode) -> int {
    Probe p;
    std::memcpy(p.input, in, 16);
    p.dec = dec;
    p.mode = mode;
    plan.probes.push_back(p);
    return static_cast<int>(plan.probes.size() - 1);
  };
  uint8_t zero[16] = {0};
  int p_c0_dec = add_probe(h.data(), true, "AES-CBC zero-IV");
  int p_c16_dec = add_probe(h.data() + 16, true, "AES-CBC IV-prepended");
  int p_ecb = p_c0_dec;  // ECB uses the same probe as CBC zero-IV
  (void)p_ecb;
  int p_zero_enc = add_probe(zero, false, "AES-CTR zero-IV");
  int p_iv_enc = add_probe(h.data(), false, "AES-CTR IV-prepended");

  for (const auto& pfx : kPrefixes) {
    Bytes pp = pad(pfx.bytes, pfx.len);
    int known = static_cast<int>(pfx.len < 16 ? pfx.len : 16);
    // CBC zero-IV: D(C0) == P0
    {
      Expect e;
      std::memcpy(e.bytes, pp.data(), 16);
      e.known = known;
      e.probe = p_c0_dec;
      e.kind = pfx.kind;
      plan.expects.push_back(e);
    }
    // CBC IV-prepended: D(C16) == P0 xor IV
    {
      Expect e;
      for (int i = 0; i < 16; ++i) e.bytes[i] = static_cast<uint8_t>(pp[i] ^ h[i]);
      e.known = known;
      e.probe = p_c16_dec;
      e.kind = pfx.kind;
      plan.expects.push_back(e);
    }
    // CTR zero-IV: E(0) == P0 xor C0
    {
      Expect e;
      for (int i = 0; i < 16; ++i) e.bytes[i] = static_cast<uint8_t>(pp[i] ^ h[i]);
      e.known = known;
      e.probe = p_zero_enc;
      e.kind = pfx.kind;
      plan.expects.push_back(e);
    }
    // CTR IV-prepended: E(IV) == P0 xor C16
    {
      Expect e;
      for (int i = 0; i < 16; ++i) e.bytes[i] = static_cast<uint8_t>(pp[i] ^ h[16 + i]);
      e.known = known;
      e.probe = p_iv_enc;
      e.kind = pfx.kind;
      plan.expects.push_back(e);
    }
  }
  return plan;
}

void sweep_raw_keys(const uint8_t* data, size_t len, uint64_t base, const KeySweepPlan& plan,
                    std::vector<KeyHit>& out, size_t max_hits) {
  size_t key_len = plan.key_len;
  if (plan.empty() || len < key_len) return;
  // Bucket expectations by probe so each probe result is compared against only
  // the prefixes that apply to it.
  std::vector<std::vector<const Expect*>> by_probe(plan.probes.size());
  for (const auto& e : plan.expects) by_probe[static_cast<size_t>(e.probe)].push_back(&e);

  // Bare keys are stored verbatim in memory; round-key schedules (whose bytes
  // are word-swapped relative to the key) are already handled by scan_aes, so no
  // byte-order variant is needed here.
  // Precompute the probe batching once; the inner loop is hot.
  const size_t nprobes = plan.probes.size();
  const uint8_t* din[8] = {nullptr};
  const uint8_t* ein[8] = {nullptr};
  int dslot[8], eslot[8];
  size_t ndec = 0, nenc = 0;
  for (size_t pi = 0; pi < nprobes; ++pi) {
    dslot[pi] = eslot[pi] = -1;
    if (by_probe[pi].empty()) continue;
    if (plan.probes[pi].dec) { dslot[pi] = static_cast<int>(ndec); din[ndec++] = plan.probes[pi].input; }
    else { eslot[pi] = static_cast<int>(nenc); ein[nenc++] = plan.probes[pi].input; }
  }

  for (size_t o = 0; o + key_len <= len; o += 4) {
    const uint8_t* keybuf = data + o;
    uint8_t dout[8][16], eout[8][16];
    aes_mixed_many(keybuf, key_len, din, ndec, &dout[0][0], ein, nenc, &eout[0][0]);
    bool hit = false;
    {
      for (size_t pi = 0; pi < nprobes && !hit; ++pi) {
        if (by_probe[pi].empty()) continue;
        const uint8_t* res = plan.probes[pi].dec ? dout[dslot[pi]] : eout[eslot[pi]];
        for (const Expect* ex : by_probe[pi]) {
          if (std::memcmp(res, ex->bytes, static_cast<size_t>(ex->known)) != 0) continue;
          KeyHit h;
          h.source = KeyHit::Source::AesRawKey;
          h.offset = base + o;
          h.key_len = static_cast<uint32_t>(key_len);
          std::memcpy(h.key, keybuf, key_len);
          h.cipher = "aes-256";
          h.matched_words = static_cast<uint32_t>(ex->known);
          h.total_words = 16;
          h.note = "raw key proven by " + plan.probes[pi].mode + " (" + ex->kind + ")";
          out.push_back(h);
          hit = true;
          break;
        }
      }
      if (hit && out.size() >= max_hits) return;
    }
  }
}

}  // namespace kh
