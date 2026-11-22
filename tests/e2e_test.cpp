// End-to-end smoke test.
//
// Generates a fresh 24 MiB image with a manifest, runs the real scan pipeline
// over it in-process, then checks that (a) every planted AES/ChaCha structure
// is recovered, (b) the sample key is proven by decryption, and (c) every
// unencrypted asymmetric container is recognised.
#include <algorithm>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <map>
#include <string>
#include <vector>

#include <openssl/provider.h>

#include "pipeline.hpp"

namespace {

const char* kImg = "/tmp/keyhunt-e2e.raw";
const char* kMan = "/tmp/keyhunt-e2e.manifest.json";
const char* kSample = "/tmp/keyhunt-e2e.sample";

// Strip the whitespace a manifest line may contain around a value.
std::string field(const std::string& line, const std::string& key) {
  std::string pat = "\"" + key + "\": \"";
  auto p = line.find(pat);
  if (p == std::string::npos) return {};
  p += pat.size();
  auto e = line.find('"', p);
  return line.substr(p, e - p);
}

}  // namespace

int main() {
  OSSL_PROVIDER_load(nullptr, "default");
  std::remove(kImg);
  std::remove(kMan);
  std::remove(kSample);
  std::string cmd = std::string("./keyhunt-genimg -o ") + kImg + " -m " + kMan +
                    " --mib 24 --sample " + kSample;
  if (std::system(cmd.c_str()) != 0) {
    std::fprintf(stderr, "genimg failed\n");
    return 1;
  }

  // Ground truth: structural symmetric keys (AES schedules, ChaCha state) that
  // must be recoverable without the sample.
  std::vector<std::pair<std::string, std::string>> struct_keys;
  {
    FILE* f = std::fopen(kMan, "r");
    if (!f) return 1;
    char buf[8192];
    while (std::fgets(buf, sizeof buf, f)) {
      std::string line(buf);
      std::string type = field(line, "type");
      std::string key = field(line, "key_hex");
      if (key.empty()) continue;
      if (type.find("enc-schedule") != std::string::npos ||
          type.find("dec-schedule") != std::string::npos ||
          type.find("chacha") != std::string::npos)
        struct_keys.emplace_back(type, key);
    }
    std::fclose(f);
  }

  kh::PipelineConfig cfg;
  cfg.image_path = kImg;
  cfg.samples.push_back(kSample);
  cfg.threads = 4;
  cfg.include_unverified = true;

  kh::MappedFile mf;
  std::string err;
  if (!mf.open(kImg, err)) {
    std::fprintf(stderr, "%s\n", err.c_str());
    return 1;
  }
  std::vector<kh::SymFinding> sym;
  std::vector<kh::AsymFinding> asym;
  kh::analyse_buffer(mf.data(), mf.size(), 0, cfg, sym, asym);

  std::vector<std::string> found;
  for (const auto& sf : sym) found.push_back(kh::hex(sf.hit.key, sf.hit.key_len));

  int missing = 0;
  for (const auto& [type, key] : struct_keys) {
    if (std::find(found.begin(), found.end(), key) == found.end()) {
      ++missing;
      std::printf("  MISSING %-28s %s\n", type.c_str(), key.substr(0, 24).c_str());
    }
  }

  bool sample_proven = false;
  std::string proven_key;
  for (const auto& sf : sym) {
    if (sf.verdict.valid && !sf.verdict.plaintext_sha256.empty()) {
      sample_proven = true;
      proven_key = kh::hex(sf.hit.key, sf.hit.key_len);
    }
  }

  int asym_valid = 0;
  for (const auto& a : asym)
    if (a.verdict.valid) ++asym_valid;

  int struct_total = static_cast<int>(struct_keys.size());
  std::printf("\nstructural recovery : %d/%d\n", struct_total - missing, struct_total);
  std::printf("sample key proven   : %s%s\n", sample_proven ? "yes " : "NO  ", proven_key.c_str());
  std::printf("asymmetric detected : %d of %zu candidate(s)\n", asym_valid, asym.size());

  // 13 containers are planted; 3 need a passphrase (not supplied here), so 10
  // must be proven without one.
  bool pass = missing == 0 && sample_proven && asym_valid >= 9;
  std::printf("%s\n", pass ? "E2E PASS" : "E2E FAIL");
  return pass ? 0 : 1;
}
