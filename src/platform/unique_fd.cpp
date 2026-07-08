#include "../../include/kls/platform/unique_fd.hpp"
#include <unistd.h>
#include <utility>

namespace kls::platform {

UniqueFd::UniqueFd(int fd) noexcept
    : fd_{fd} {}

UniqueFd::~UniqueFd() noexcept {
  reset();
}

UniqueFd::UniqueFd(UniqueFd&& other) noexcept
    : fd_{other.release()} {}

UniqueFd& UniqueFd::operator=(UniqueFd&& other) noexcept {
  if (this != &other) {
    reset(other.release());
  }

  return *this;
}

int UniqueFd::release() noexcept {
  return std::exchange(fd_, -1);
}

void UniqueFd::reset(int new_fd) noexcept {
  if (new_fd == fd_) {
    return;
  }

  const int old_fd = std::exchange(fd_, new_fd);

  if (old_fd >= 0) {
    static_cast<void>(::close(old_fd));
  }
}

} // namespace kls::platform
