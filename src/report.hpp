// Result model and output formats (human report, JSONL, key material export).
#pragma once
#include <cstdint>
#include <string>
#include <vector>

#include "privkey.hpp"
#include "symmetric.hpp"
#include "verify.hpp"

namespace kh {

struct SymFinding {
  KeyHit hit;
  Verdict verdict;
};

struct AsymFinding {
  AsymCandidate cand;
  Verdict verdict;
};

struct ScanSummary {
  std::string image;
  uint64_t image_size = 0;
  uint64_t ranges_scanned = 0;
  uint64_t bytes_scanned = 0;
  double seconds = 0;
  size_t symmetric_hits = 0;
  size_t asym_hits = 0;
  size_t verified = 0;
  size_t recovered = 0;
};

// Write machine-readable results.  One JSON object per line keeps huge result
// sets streamable and diff-friendly.
void write_jsonl(const std::string& path, const ScanSummary& sum,
                 const std::vector<SymFinding>& sym, const std::vector<AsymFinding>& asym,
                 bool include_unverified);

// Human report to stdout / file.
void write_report(const std::string& path, const ScanSummary& sum,
                  const std::vector<SymFinding>& sym, const std::vector<AsymFinding>& asym,
                  bool include_unverified);

// Write recovered keys in a directly usable form:
//   <outdir>/keys/<index>_<cipher>_<offset>_<hash>.{key,hex,pem,json}
// Keys are written with 0600 and the directory with 0700.
size_t export_keys(const std::string& outdir, const std::vector<SymFinding>& sym,
                   const std::vector<AsymFinding>& asym);

}  // namespace kh
