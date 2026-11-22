#include "pipeline.hpp"

#include <algorithm>
#include <chrono>
#include <cmath>
#include <cstdio>
#include <cstring>
#include <fstream>
#include <mutex>
#include <set>
#include <sstream>
#include <thread>
#include <unordered_set>

#include "aes.hpp"
#include "bignum.hpp"
#include "encodings.hpp"
#include "kdf.hpp"
#include "keysweep.hpp"
#include "privkey.hpp"
#include "scanner.hpp"
#include "symmetric.hpp"
#include "verify.hpp"

namespace kh {
namespace {

struct RawKeySpec {
  std::string cipher;
  Bytes key;
};

bool parse_raw_key(const std::string& s, RawKeySpec& out) {
  std::string spec = s;
  std::string cipher;
  size_t colon = spec.find(':');
  if (colon != std::string::npos) {
    cipher = spec.substr(0, colon);
    spec = spec.substr(colon + 1);
  }
  if (!unhex(spec, out.key)) return false;
  out.cipher = cipher;
  return true;
}

// Load verification samples once.  We keep the first 4 KiB; enough for several
// block/mode trials without holding whole files in memory.
std::vector<Sample> load_samples(const std::vector<std::string>& paths) {
  std::vector<Sample> out;
  for (const auto& p : paths) {
    std::ifstream f(p, std::ios::binary);
    if (!f) {
      std::fprintf(stderr, "warning: cannot open sample %s\n", p.c_str());
      continue;
    }
    Sample s;
    s.path = p;
    f.seekg(0, std::ios::end);
    s.size = static_cast<uint64_t>(f.tellg());
    f.seekg(0);
    s.header.resize(4096);
    f.read(reinterpret_cast<char*>(s.header.data()), static_cast<std::streamsize>(s.header.size()));
    s.header.resize(static_cast<size_t>(f.gcount()));
    out.push_back(std::move(s));
  }
  return out;
}

std::mutex g_print_mu;

void progress_line(const ScanProgress& p, bool done) {
  double pct = p.bytes_total ? 100.0 * static_cast<double>(p.bytes_done.load()) / p.bytes_total : 0;
  std::fprintf(stderr, "\r[scan] %6.2f%%  %.2f/%.2f GiB  chunks %llu/%llu  candidates %llu   ", pct,
               p.bytes_done.load() / 1073741824.0, p.bytes_total / 1073741824.0,
               static_cast<unsigned long long>(p.chunks_done.load()),
               static_cast<unsigned long long>(p.chunks_total),
               static_cast<unsigned long long>(p.discoveries.load()));
  if (done) std::fprintf(stderr, "\n");
  std::fflush(stderr);
}

// Deduplicate findings across overlapping chunks by (type, offset, key bytes).
struct Dedup {
  std::set<std::string> seen;
  std::mutex mu;
  // Returns true if new.
  bool add(const std::string& k) {
    std::lock_guard<std::mutex> lk(mu);
    return seen.insert(k).second;
  }
};

std::string sym_key(const KeyHit& h) {
  return "s:" + std::to_string(h.offset) + ":" + std::to_string(h.key_len) + ":" + hex(h.key, h.key_len);
}
std::string asym_key(const AsymCandidate& c) {
  return "a:" + std::to_string(c.offset) + ":" + std::to_string(static_cast<int>(c.container));
}

// Localise a structure that may have been found in the overlap region: report
// the offset only from the chunk that "owns" it (first chunk whose aligned
// start <= offset).
bool owned_by_chunk(uint64_t off, const Chunk& c, uint64_t chunk_step) {
  return off >= c.offset && off < c.offset + chunk_step;
}

bool parse_range(const std::string& s, uint64_t& start, uint64_t& end) {
  std::string t = s;
  size_t sep = t.find('-');
  bool plus = false;
  if (sep == std::string::npos) {
    sep = t.find('+');
    plus = true;
  }
  if (sep == std::string::npos) return false;
  std::string a = t.substr(0, sep), b = t.substr(sep + 1);
  auto parse_num = [](const std::string& x, uint64_t& v) -> bool {
    try {
      size_t idx = 0;
      v = std::stoull(x, &idx, 0);
      return idx == x.size();
    } catch (...) {
      return false;
    }
  };
  uint64_t x = 0, y = 0;
  if (!parse_num(a, x) || !parse_num(b, y)) return false;
  start = x;
  end = plus ? x + y : y;
  return true;
}

}  // namespace

namespace {
// Samples are identical for every thread; load them once per distinct path set.
const std::vector<Sample>& shared_samples(const std::vector<std::string>& paths) {
  static std::mutex mu;
  static std::string key;
  static std::vector<Sample> cached;
  std::string k;
  for (const auto& p : paths) { k += p; k += '\0'; }
  std::lock_guard<std::mutex> lk(mu);
  if (k != key) {
    cached = load_samples(paths);
    key = k;
  }
  return cached;
}
}  // namespace

void analyse_buffer(const uint8_t* data, size_t len, uint64_t base, const PipelineConfig& cfg,
                    std::vector<SymFinding>& sym, std::vector<AsymFinding>& asym,
                    ScanProgress* progress) {
  static thread_local ScanLimits limits;
  if (!cfg.raw_scan) limits.max_raw_candidates = 0;
  SymmetricDetector det(limits);
  std::vector<KeyHit> hits;
  det.scan(data, len, base, hits);

  const std::vector<Sample>& samples = shared_samples(cfg.samples);

  // Known keys supplied by the operator are always tested against samples; they
  // are reported alongside discovered keys.
  for (const auto& ks : cfg.keys) {
    RawKeySpec rk;
    if (!parse_raw_key(ks, rk)) continue;
    KeyHit h;
    h.source = KeyHit::Source::AesRawKey;
    h.offset = 0;
    h.key_len = static_cast<uint32_t>(rk.key.size());
    std::memcpy(h.key, rk.key.data(), std::min<size_t>(32, rk.key.size()));
    h.cipher = rk.cipher.empty() ? ("aes-" + std::to_string(rk.key.size() * 8)) : rk.cipher;
    h.note = "operator-supplied";
    hits.push_back(h);
  }

  // Sample-driven sweep: finds bare 32-byte keys with no structural signature
  // by testing whether they decrypt the known plaintext prefix.  This is the
  // only false-positive-free way to recover keys that only exist as raw bytes.
  static thread_local KeySweepPlan sweep_plan;
  static thread_local size_t plan_for = static_cast<size_t>(-1);
  if (plan_for != samples.size()) {
    sweep_plan = KeySweepPlan{};
    for (const auto& s : samples) {
      auto p = build_sweep_plan(s);
      if (!p.empty()) { sweep_plan = p; break; }
    }
    plan_for = samples.size();
  }
  if (!sweep_plan.empty()) {
    std::vector<KeyHit> swept;
    sweep_raw_keys(data, len, base, sweep_plan, swept);
    for (auto& h : swept) {
      // Re-run the full trial set so the reported mode and plaintext hash come
      // from the real decryption path, not just the block check.
      SymFinding f;
      f.hit = h;
      f.verdict = verify_symmetric(h, samples);
      if (f.verdict.valid) sym.push_back(std::move(f));
    }
  }

  for (auto& h : hits) {
    SymFinding f;
    f.hit = h;
    f.verdict = verify_symmetric(h, samples);
    sym.push_back(std::move(f));
  }

  if (cfg.asym_scan) {
    std::vector<AsymCandidate> cands;
    find_asym_candidates(data, len, base, cands);
    // Embedded encrypted containers: try to crack with the dictionary.
    for (auto& c : cands) {
      if (c.encrypted && !cfg.dict.empty()) {
        Bytes der;
        if (c.container == KeyStructure::Kind::EncryptedPkcs8) {
          // Re-extract the DER from the image region for the cracker.
          size_t off = static_cast<size_t>(c.offset - base);
          if (off + c.length <= len) {
            Bytes enc(data + off, data + off + c.length);
            for (const auto& pass : cfg.dict) {
              if (decrypt_pkcs8_with_pass(enc, pass, der)) {
                c.note += " (passphrase '" + pass + "' decrypts)";
                c.encrypted = false;
                c.confidence = 95;
                break;
              }
            }
          }
        }
      }
      AsymFinding f;
      f.cand = c;
      f.verdict = verify_asym(c);
      asym.push_back(std::move(f));
    }
  }
  if (progress) progress->discoveries.fetch_add(sym.size() + asym.size());
}

int run_pipeline(const PipelineConfig& cfg) {
  using clock = std::chrono::steady_clock;
  auto t0 = clock::now();

  MappedFile mf;
  std::string err;
  if (!mf.open(cfg.image_path, err)) {
    std::fprintf(stderr, "error: %s\n", err.c_str());
    return 2;
  }

  std::vector<std::pair<uint64_t, uint64_t>> ranges;
  if (cfg.ranges.empty()) {
    ranges.push_back({0, mf.size()});
  } else {
    for (const auto& r : cfg.ranges) {
      uint64_t s, e;
      if (!parse_range(r, s, e) || s >= e || e > mf.size()) {
        std::fprintf(stderr, "error: bad range '%s' (image is %llu bytes)\n", r.c_str(),
                     static_cast<unsigned long long>(mf.size()));
        return 2;
      }
      ranges.push_back({s, e});
    }
  }

  unsigned threads = cfg.threads;
  if (!threads) {
    unsigned hw = std::thread::hardware_concurrency();
    threads = hw > 2 ? hw - 1 : 2;
  }

  std::vector<SymFinding> sym;
  std::vector<AsymFinding> asym;
  Dedup dedup;
  std::mutex out_mu;
  ScanProgress progress;
  uint64_t chunk_step = cfg.chunk_bytes;

  auto on_chunk = [&](const Chunk& c, size_t) {
    std::vector<SymFinding> ls;
    std::vector<AsymFinding> la;
    analyse_buffer(mf.data() + c.offset, c.len, c.offset, cfg, ls, la);
    std::lock_guard<std::mutex> lk(out_mu);
    for (auto& f : ls) {
      if (!owned_by_chunk(f.hit.offset, c, chunk_step) && f.hit.offset != 0) continue;
      if (!dedup.add(sym_key(f.hit))) continue;
      sym.push_back(std::move(f));
    }
    for (auto& f : la) {
      if (!owned_by_chunk(f.cand.offset, c, chunk_step)) continue;
      if (!dedup.add(asym_key(f.cand))) continue;
      asym.push_back(std::move(f));
    }
    progress.discoveries.store(sym.size() + asym.size());
  };

  auto last = clock::now();
  for (const auto& [s, e] : ranges) {
    auto chunks = plan_chunks(s, e, cfg.chunk_bytes, cfg.overlap, mf.page_size());
    run_chunks(mf, chunks, threads, on_chunk, progress);
    auto now = clock::now();
    if (cfg.progress_interval_ms &&
        std::chrono::duration<double>(now - last).count() > cfg.progress_interval_ms / 1000.0) {
      progress_line(progress, false);
      last = now;
    }
  }
  if (cfg.progress_interval_ms) progress_line(progress, true);

  // Final verification pass: findings that were cut off by chunk boundaries and
  // therefore not yet verified get another try against every sample.
  std::vector<Sample> samples = load_samples(cfg.samples);
  for (auto& f : sym)
    if (!f.verdict.valid) f.verdict = verify_symmetric(f.hit, samples);

  auto t1 = clock::now();
  ScanSummary sum;
  sum.image = cfg.image_path;
  sum.image_size = mf.size();
  sum.bytes_scanned = progress.bytes_done.load();
  sum.seconds = std::chrono::duration<double>(t1 - t0).count();
  sum.symmetric_hits = sym.size();
  sum.asym_hits = asym.size();
  for (const auto& f : sym) {
    if (f.verdict.valid) ++sum.verified;
    if (f.hit.recovered) ++sum.recovered;
  }
  for (const auto& f : asym)
    if (f.verdict.valid) ++sum.verified;

  // Sort by verified-then-offset so the useful result is at the top.
  std::sort(sym.begin(), sym.end(), [](const SymFinding& a, const SymFinding& b) {
    if (a.verdict.valid != b.verdict.valid) return a.verdict.valid;
    return a.hit.offset < b.hit.offset;
  });
  std::sort(asym.begin(), asym.end(), [](const AsymFinding& a, const AsymFinding& b) {
    if (a.verdict.valid != b.verdict.valid) return a.verdict.valid;
    return a.cand.offset < b.cand.offset;
  });

  write_report(cfg.report_path, sum, sym, asym, cfg.include_unverified);
  if (!cfg.jsonl_path.empty()) write_jsonl(cfg.jsonl_path, sum, sym, asym, cfg.include_unverified);
  if (cfg.export_keys && !cfg.outdir.empty()) {
    size_t n = export_keys(cfg.outdir, sym, asym);
    std::fprintf(stderr, "[scan] exported %zu key file(s) to %s/keys\n", n, cfg.outdir.c_str());
  }
  return 0;
}

}  // namespace kh
