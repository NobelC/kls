#pragma once
#include <cstdint>
namespace kls::filesystem {
  enum class FileType : uint8_t{
    regular = 8,
    directory = 4,
    symlink = 10,
    character_device = 2,
    block_device = 6,
    named_pipe = 1,
    unix_domain_socket = 12,
    unknown = 0,
  };
}
