#pragma once

#include <cstdint>
#include <ctime>
#include <optional>
#include <string>
#include <sys/types.h>
#include "../filesystem/file_type.hpp"

namespace kls::audit {

struct AuditEntry {
  ino_t inode = 0;
  std::uint64_t size = 0;
  mode_t mode = 0;
  nlink_t nlinks = 0;
  uid_t uid = 0;
  gid_t gid = 0;

  filesystem::FileType type = filesystem::FileType::unknown;


  time_t mtime = 0;
  time_t btime = 0;

  std::string name;
  std::string full_path;
  std::optional<std::string> symlink_target = std::nullopt;
  std::string extension;
};

}
