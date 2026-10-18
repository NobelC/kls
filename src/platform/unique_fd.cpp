#include "kls/platform/unique_fd.hpp"
#include <unistd.h>
#include <utility>

namespace kls::platform {

// ARCHITECTURAL NOTE: RAII guarantees.
// Constructors and destructors must be noexcept to prevent std::terminate 
// during stack unwinding or object initialization.
UniqueFd::UniqueFd(int fd) noexcept : fd_{fd} {}

UniqueFd::~UniqueFd() noexcept {
  reset();
}

// Move constructor transfers ownership safely.
// other.release() ensures the source object is left in a valid, empty state (-1),
// preventing double-close vulnerabilities.
UniqueFd::UniqueFd(UniqueFd&& other) noexcept : fd_{other.release()} {}

// Move assignment. The self-assignment check avoids an unnecessary syscall,
// though std::exchange would handle it safely regardless.
UniqueFd& UniqueFd::operator=(UniqueFd&& other) noexcept {
  if (this != &other) {
    reset(other.release());
  }
  return *this;
}

// Releases ownership without closing the descriptor.
// std::exchange guarantees the internal state is updated atomically.
int UniqueFd::release() noexcept {
  return std::exchange(fd_, -1);
}

// Replaces the managed descriptor.
// Closes the old descriptor if valid, strictly preventing file descriptor leaks.
void UniqueFd::reset(int new_fd) noexcept {
  if (new_fd == fd_) {
    return;
  }

  const int old_fd = std::exchange(fd_, new_fd);

  if (old_fd >= 0) {
    // ARCHITECTURAL NOTE: Explicitly ignore close() return value.
    // Handling or throwing errors during RAII cleanup is unsafe. 
    // We prioritize preventing resource leaks over reporting close failures.
    static_cast<void>(::close(old_fd));
  }
}

} // namespace kls::platform
