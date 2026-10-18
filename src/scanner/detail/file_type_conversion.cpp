#include "kls/detail/file_type_conversion.hpp"
#include "kls/filesystem/file_type.hpp"
#include <dirent.h>
#include <fcntl.h>
#include <sys/stat.h>

namespace kls::detail {

// ARCHITECTURAL NOTE: Authoritative type resolution.
// Uses the mode bitmask (from stat/statx), which is always reliable.
// This is the fallback when dirent->d_type returns DT_UNKNOWN on certain filesystems.
[[nodiscard]] kls::filesystem::FileType type_from_mode(const mode_t &mode) noexcept {
  switch (mode & S_IFMT) {
    case S_IFREG: {
      return kls::filesystem::FileType::regular;
    }
    case S_IFDIR: {
      return kls::filesystem::FileType::directory;
    }
    case S_IFLNK: {
      return kls::filesystem::FileType::symlink;
    }
    case S_IFCHR: {
      return kls::filesystem::FileType::character_device;
    }
    case S_IFBLK: {
      return kls::filesystem::FileType::block_device;
    }
    case S_IFIFO: {
      return kls::filesystem::FileType::named_pipe;
    }
    case S_IFSOCK: {
      return kls::filesystem::FileType::unix_domain_socket;
    }
    default: {
      return kls::filesystem::FileType::unknown;
    }
  }
}

// ARCHITECTURAL NOTE: Fast-path type resolution.
// Reads the d_type field directly from readdir(3). This avoids an extra statx syscall, 
// optimizing traversal performance. Callers must fallback to type_from_mode() 
// if this function returns FileType::unknown (equivalent to DT_UNKNOWN).
[[nodiscard]] kls::filesystem::FileType type_from_dirent(const unsigned char &dt_type) noexcept {
  switch (dt_type) {
    case DT_REG: {
      return kls::filesystem::FileType::regular;
    }
    case DT_DIR: {
      return kls::filesystem::FileType::directory;
    }
    case DT_LNK: {
      return kls::filesystem::FileType::symlink;
    }
    case DT_CHR: {
      return kls::filesystem::FileType::character_device;
    }
    case DT_BLK: {
      return kls::filesystem::FileType::block_device;
    }
    case DT_FIFO: {
      return kls::filesystem::FileType::named_pipe;
    }
    case DT_SOCK: {
      return kls::filesystem::FileType::unix_domain_socket;
    }
    default: {
      return kls::filesystem::FileType::unknown;
    }
  }
}

} // namespace kls::detail
