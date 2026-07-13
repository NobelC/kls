#pragma once

#include <cstdint>
#include <ctime>
#include <string>
#include <sys/types.h>
#include <vector>

#include "../findings/health_flags.hpp"

namespace kls::audit {

struct AuditEntry {
  ino_t inode = 0;
  std::uint64_t size = 0;
  mode_t mode = 0;
  nlink_t nlinks = 0;
  uid_t uid = 0;
  gid_t gid = 0;

  bool is_directory : 1 = false;
  bool is_symlink : 1 = false;
  bool symlink_broken : 1 = false;
  bool has_capabilities : 1 = false;
  bool correct_state : 1 = false;

  time_t mtime = 0;
  time_t btime = 0;

  std::string name;
  std::string path;
  std::string symlink_target;
  std::string extension;

  std::vector<kls::findings::HealthFlags> health;
  std::vector<kls::findings::HealthFlags> capabilities;

  AuditEntry() = default;

  void clear() noexcept {
    inode = 0;
    size = 0;
    mode = 0;
    nlinks = 0;
    uid = 0;
    gid = 0;

    is_directory = false;
    is_symlink = false;
    symlink_broken = false;
    has_capabilities = false;
    correct_state = false;

    mtime = 0;
    btime = 0;

    name.clear();
    path.clear();
    symlink_target.clear();
    extension.clear();
    health.clear();
    capabilities.clear();
  }
};

}
