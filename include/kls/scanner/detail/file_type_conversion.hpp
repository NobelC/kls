#pragma once
#include "../../filesystem/file_type.hpp"
#include <sys/types.h>
#include <sys/wait.h>

namespace scanner::detail  {
  [[nodiscard]] kls::filesystem::FileType type_from_mode(const mode_t& if_type ) noexcept;
  [[nodiscard]] kls::filesystem::FileType type_from_dirent(const unsigned char& dt_type ) noexcept;
}
