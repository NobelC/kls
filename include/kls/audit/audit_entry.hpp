#pragma once

#include "kls/filesystem/file_type.hpp"
#include <cstdint>
#include <ctime>
#include <optional>
#include <string>
#include <sys/types.h>

namespace kls::auditor {

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

  // Mount identity for cross-filesystem tracking.
  //  stx_dev_major and stx_dev_minor identify the device.
  //  mount_id (Linux 5.8+) identifies the specific mount point.
  std::uint32_t dev_major = 0;
  std::uint32_t dev_minor = 0;
  std::optional<std::uint64_t> mount_id = std::nullopt;
};

} // namespace kls::auditor
