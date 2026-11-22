#pragma once
#include <cstdint>
#include <string>
#include <vector>

#include "report.hpp"
#include "scanner.hpp"

namespace kh {

struct PipelineConfig {
  std::string image_path;
  std::vector<std::string> ranges;      // "start-end" or "start+len", hex or decimal
  std::vector<std::string> samples;     // sample files to verify against
  std::vector<std::string> keys;        // known keys ("hex" or "aes-256:hex") to try
  std::vector<std::string> dict;        // passphrase dictionary for encrypted keys
  std::string outdir;
  std::string report_path;              // "" => stdout
  std::string jsonl_path;
  unsigned threads = 0;
  uint64_t chunk_bytes = 64ull << 20;
  uint64_t overlap = 1ull << 20;
  bool include_unverified = false;
  bool export_keys = false;
  bool asym_scan = true;
  bool raw_scan = false;   // entropy heuristic candidates (noisy; off by default)
  bool verbose = false;
  uint64_t progress_interval_ms = 2000;
};

int run_pipeline(const PipelineConfig& cfg);

// Exposed for tests: scan an in-memory buffer end to end.
void analyse_buffer(const uint8_t* data, size_t len, uint64_t base, const PipelineConfig& cfg,
                    std::vector<SymFinding>& sym, std::vector<AsymFinding>& asym,
                    ScanProgress* progress = nullptr);

}  // namespace kh
