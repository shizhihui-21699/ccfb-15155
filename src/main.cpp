// keyhunt -- recover cryptographic keys from a memory image and prove them by
// decrypting sample files.
//
//   keyhunt scan image.raw --sample locked.docx --jsonl out.jsonl --outdir out/
//   keyhunt scan image.raw --range 0x1a000000-0x2a000000 -t 8
//   keyhunt try  image.raw --key aes-256:<hex> --sample locked.docx
//   keyhunt verify --key <hex> --sample locked.docx
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>

#include "pipeline.hpp"
#include "util.hpp"
#include "verify.hpp"

namespace {

void usage() {
  std::fprintf(stderr,
               "keyhunt -- memory-image key recovery\n\n"
               "usage:\n"
               "  keyhunt scan   <image> [options]\n"
               "  keyhunt verify --key <hex|cipher:hex> --sample <file> [...]\n\n"
               "scan options:\n"
               "  --range <start-end>     scan only this byte range (hex or dec, repeatable)\n"
               "  --sample <file>         ciphertext sample to verify keys against (repeatable)\n"
               "  --key <cipher:hex>      test an operator-supplied key too (repeatable)\n"
               "  --dict <file>           passphrase list for encrypted private keys\n"
               "  --outdir <dir>          write recovered keys (mode 0600) below <dir>/keys\n"
               "  --jsonl <file>          machine-readable one-object-per-line output\n"
               "  --report <file>         human report (default stdout)\n"
               "  -t, --threads <n>       worker threads (default: cores-1)\n"
               "  --chunk <bytes>         chunk size (default 64 MiB)\n"
               "  --all                   include unverified candidates in output\n"
               "  --no-asym              skip asymmetric key detection\n"
               "  -q, --quiet             suppress progress on stderr\n"
               "  -h, --help\n\n"
               "verify options:\n"
               "  --key <cipher:hex>      key to test (repeatable)\n"
               "  --sample <file>         ciphertext sample (repeatable)\n"
               "  --raw-offset <n>        skip this many leading bytes of each sample\n");
}

uint64_t parse_size(const std::string& s) {
  char* end = nullptr;
  double v = std::strtod(s.c_str(), &end);
  uint64_t mul = 1;
  if (end && *end) {
    switch (std::tolower(static_cast<unsigned char>(*end))) {
      case 'k': mul = 1024ull; break;
      case 'm': mul = 1024ull * 1024; break;
      case 'g': mul = 1024ull * 1024 * 1024; break;
      case 't': mul = 1024ull * 1024 * 1024 * 1024; break;
      default: mul = 1; break;
    }
  }
  return static_cast<uint64_t>(v * static_cast<double>(mul));
}

std::vector<std::string> read_dict(const std::string& path) {
  std::vector<std::string> out;
  FILE* f = std::fopen(path.c_str(), "r");
  if (!f) return out;
  char buf[1024];
  while (std::fgets(buf, sizeof buf, f)) {
    size_t n = std::strlen(buf);
    while (n && (buf[n - 1] == '\n' || buf[n - 1] == '\r')) buf[--n] = 0;
    if (n) out.emplace_back(buf, n);
  }
  std::fclose(f);
  return out;
}

int cmd_verify(int argc, char** argv) {
  std::vector<std::string> keys, samples;
  size_t raw_offset = 0;
  for (int i = 0; i < argc; ++i) {
    std::string a = argv[i];
    if ((a == "--key" || a == "-k") && i + 1 < argc) keys.emplace_back(argv[++i]);
    else if (a == "--sample" && i + 1 < argc) samples.emplace_back(argv[++i]);
    else if (a == "--raw-offset" && i + 1 < argc) raw_offset = std::strtoull(argv[++i], nullptr, 0);
    else { std::fprintf(stderr, "unknown argument: %s\n", a.c_str()); return 2; }
  }
  if (keys.empty() || samples.empty()) {
    std::fprintf(stderr, "verify needs --key and --sample\n");
    return 2;
  }
  std::vector<kh::Sample> ss;
  for (const auto& p : samples) {
    kh::Sample s;
    s.path = p;
    FILE* f = std::fopen(p.c_str(), "rb");
    if (!f) { std::fprintf(stderr, "cannot open %s\n", p.c_str()); continue; }
    s.header.resize(65536);
    s.header.resize(std::fread(s.header.data(), 1, s.header.size(), f));
    std::fclose(f);
    if (raw_offset) s.header.erase(s.header.begin(), s.header.begin() + static_cast<long>(raw_offset));
    ss.push_back(std::move(s));
  }
  int found = 0;
  for (const auto& k : keys) {
    kh::KeyHit h;
    std::string spec = k, cipher;
    size_t colon = spec.find(':');
    if (colon != std::string::npos) { cipher = spec.substr(0, colon); spec = spec.substr(colon + 1); }
    kh::Bytes kb;
    if (!kh::unhex(spec, kb)) { std::fprintf(stderr, "bad key hex: %s\n", k.c_str()); continue; }
    h.key_len = static_cast<uint32_t>(kb.size());
    std::memcpy(h.key, kb.data(), std::min<size_t>(32, kb.size()));
    h.cipher = cipher;
    auto v = kh::verify_symmetric(h, ss);
    if (v.valid) {
      ++found;
      std::printf("VALID  %s  %s  plaintext-sha256=%s\n", k.c_str(), v.how.c_str(),
                  v.plaintext_sha256.c_str());
    } else {
      std::printf("no     %s\n", k.c_str());
    }
  }
  return found ? 0 : 1;
}

}  // namespace

int main(int argc, char** argv) {
  if (argc < 2) { usage(); return 2; }
  std::string cmd = argv[1];
  if (cmd == "-h" || cmd == "--help" || cmd == "help") { usage(); return 0; }
  if (cmd == "verify") return cmd_verify(argc - 2, argv + 2);
  if (cmd != "scan") { usage(); return 2; }

  kh::PipelineConfig cfg;
  for (int i = 2; i < argc; ++i) {
    std::string a = argv[i];
    auto next = [&](const char* what) -> std::string {
      if (i + 1 >= argc) { std::fprintf(stderr, "%s needs a value\n", what); std::exit(2); }
      return argv[++i];
    };
    if (a == "-h" || a == "--help") { usage(); return 0; }
    else if (a == "--range") cfg.ranges.push_back(next("--range"));
    else if (a == "--sample") cfg.samples.push_back(next("--sample"));
    else if (a == "--key" || a == "-k") cfg.keys.push_back(next("--key"));
    else if (a == "--dict") cfg.dict = read_dict(next("--dict"));
    else if (a == "--outdir") cfg.outdir = next("--outdir");
    else if (a == "--jsonl") cfg.jsonl_path = next("--jsonl");
    else if (a == "--report") cfg.report_path = next("--report");
    else if (a == "-t" || a == "--threads") cfg.threads = static_cast<unsigned>(std::strtoul(next("-t").c_str(), nullptr, 0));
    else if (a == "--chunk") cfg.chunk_bytes = parse_size(next("--chunk"));
    else if (a == "--all") cfg.include_unverified = true;
    else if (a == "--export") cfg.export_keys = true;
    else if (a == "--no-asym") cfg.asym_scan = false;
    else if (a == "--raw") cfg.raw_scan = true;
    else if (a == "-q" || a == "--quiet") cfg.progress_interval_ms = 0;
    else if (a[0] == '-') { std::fprintf(stderr, "unknown option: %s\n", a.c_str()); return 2; }
    else if (cfg.image_path.empty()) cfg.image_path = a;
    else { std::fprintf(stderr, "unexpected argument: %s\n", a.c_str()); return 2; }
  }
  if (cfg.image_path.empty()) { usage(); return 2; }
  if (!cfg.outdir.empty() && !cfg.export_keys) cfg.export_keys = true;
  return kh::run_pipeline(cfg);
}
