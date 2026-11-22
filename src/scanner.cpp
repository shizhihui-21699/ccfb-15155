#include "scanner.hpp"

#include <algorithm>
#include <cerrno>
#include <cstdio>
#include <cstring>
#include <thread>

#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

namespace kh {

MappedFile::~MappedFile() { close(); }

bool MappedFile::open(const std::string& path, std::string& err) {
  close();
  fd_ = ::open(path.c_str(), O_RDONLY);
  if (fd_ < 0) {
    err = "open(" + path + "): " + std::strerror(errno);
    return false;
  }
  struct stat st {};
  if (fstat(fd_, &st) != 0) {
    err = "fstat: " + std::string(std::strerror(errno));
    ::close(fd_);
    fd_ = -1;
    return false;
  }
  if (!S_ISREG(st.st_mode)) {
    err = path + " is not a regular file (try `dd` from the block device)";
    ::close(fd_);
    fd_ = -1;
    return false;
  }
  size_ = static_cast<uint64_t>(st.st_size);
  long ps = ::sysconf(_SC_PAGESIZE);
  page_ = ps > 0 ? static_cast<uint64_t>(ps) : 4096;
  if (size_ == 0) {
    err = path + " is empty";
    ::close(fd_);
    fd_ = -1;
    return false;
  }
  void* p = ::mmap(nullptr, size_, PROT_READ, MAP_PRIVATE, fd_, 0);
  if (p == MAP_FAILED) {
    err = "mmap: " + std::string(std::strerror(errno));
    ::close(fd_);
    fd_ = -1;
    return false;
  }
  data_ = static_cast<const uint8_t*>(p);
  // Advise the kernel the access pattern is a forward sweep.  This is a hint
  // and is skipped on platforms where MADV_SEQUENTIAL means something else.
#if defined(MADV_SEQUENTIAL) && defined(__linux__)
  ::madvise(const_cast<void*>(static_cast<const void*>(p)), size_, MADV_SEQUENTIAL);
#endif
  return true;
}

void MappedFile::close() {
  if (data_) {
    ::munmap(const_cast<uint8_t*>(data_), size_);
    data_ = nullptr;
  }
  if (fd_ >= 0) {
    ::close(fd_);
    fd_ = -1;
  }
  size_ = 0;
}

std::vector<Chunk> plan_chunks(uint64_t begin, uint64_t end, uint64_t chunk, uint64_t overlap,
                               uint64_t alignment) {
  std::vector<Chunk> out;
  if (end <= begin) return out;
  if (alignment == 0) alignment = 1;
  begin -= begin % alignment;
  if (chunk == 0) chunk = end - begin;
  if (overlap >= chunk) overlap = chunk / 2;
  uint64_t pos = begin;
  while (pos < end) {
    uint64_t stop = std::min(end, pos + chunk);
    uint64_t real_end = std::min(end, stop + overlap);
    out.push_back({pos, real_end - pos});
    if (stop >= end) break;
    pos = stop;
  }
  return out;
}

void run_chunks(const MappedFile& mf, const std::vector<Chunk>& chunks, unsigned threads,
                const std::function<void(const Chunk&, size_t)>& work, ScanProgress& progress) {
  progress.bytes_total = 0;
  for (const auto& c : chunks) progress.bytes_total += c.len;
  progress.chunks_total = chunks.size();
  std::atomic<size_t> next{0};
  auto worker = [&]() {
    for (;;) {
      size_t i = next.fetch_add(1);
      if (i >= chunks.size()) break;
      work(chunks[i], i);
      progress.bytes_done.fetch_add(chunks[i].len);
      progress.chunks_done.fetch_add(1);
    }
  };
  unsigned n = std::max(1u, threads);
  n = std::min<unsigned>(n, static_cast<unsigned>(chunks.size()));
  if (n <= 1) {
    worker();
    return;
  }
  std::vector<std::thread> pool;
  pool.reserve(n);
  for (unsigned i = 0; i < n; ++i) pool.emplace_back(worker);
  for (auto& t : pool) t.join();
}

}  // namespace kh
