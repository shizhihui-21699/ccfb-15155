// Streaming scanner: maps the image, slices it into overlapping chunks, and
// runs detection over them with a thread pool.  Overlap ensures a structure is
// never missed because it straddles a chunk boundary; a small LRU of recent
// detections removes the resulting duplicates.
#pragma once
#include <atomic>
#include <cstdint>
#include <functional>
#include <string>
#include <vector>

#include "util.hpp"

namespace kh {

class MappedFile {
 public:
  MappedFile() = default;
  ~MappedFile();
  MappedFile(const MappedFile&) = delete;
  MappedFile& operator=(const MappedFile&) = delete;

  bool open(const std::string& path, std::string& err);
  void close();
  const uint8_t* data() const { return data_; }
  uint64_t size() const { return size_; }
  uint64_t page_size() const { return page_; }

 private:
  int fd_ = -1;
  const uint8_t* data_ = nullptr;
  uint64_t size_ = 0;
  uint64_t page_ = 4096;
};

struct Chunk {
  uint64_t offset;
  uint64_t len;
};

// Splits an aligned range into chunks, overlapping by `overlap` bytes.
std::vector<Chunk> plan_chunks(uint64_t begin, uint64_t end, uint64_t chunk, uint64_t overlap,
                               uint64_t alignment);

struct ScanProgress {
  std::atomic<uint64_t> bytes_done{0};
  std::atomic<uint64_t> chunks_done{0};
  std::atomic<uint64_t> discoveries{0};
  uint64_t bytes_total = 0;
  uint64_t chunks_total = 0;
};

// Runs `work(chunk)` across `threads` workers.  `work` must be thread-safe or
// the caller must serialise its own output.
void run_chunks(const MappedFile& mf, const std::vector<Chunk>& chunks, unsigned threads,
                const std::function<void(const Chunk&, size_t chunk_index)>& work,
                ScanProgress& progress);

}  // namespace kh
