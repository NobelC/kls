#pragma once

namespace kls::platform {

class UniqueFd final {
public:
  constexpr UniqueFd() noexcept = default;
  explicit UniqueFd(int fd) noexcept;

  ~UniqueFd() noexcept;

  UniqueFd(const UniqueFd&) = delete;
  UniqueFd& operator=(const UniqueFd&) = delete;

  UniqueFd(UniqueFd&& other) noexcept;
  UniqueFd& operator=(UniqueFd&& other) noexcept;

  [[nodiscard]] constexpr explicit operator bool() const noexcept {
    return fd_ >= 0;
  }

  [[nodiscard]] int release() noexcept;
  void reset(int new_fd = -1) noexcept;
  
  [[nodiscard]] constexpr int get() const noexcept{
    return fd_;
  }

private:
  int fd_{-1};
};

} // namespace kls::platform
