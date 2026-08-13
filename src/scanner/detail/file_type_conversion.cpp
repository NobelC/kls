#include "kls/detail/file_type_conversion.hpp"
#include "kls/filesystem/file_type.hpp"
#include <dirent.h>
#include <fcntl.h>
#include <sys/stat.h>

namespace detail  {
  [[nodiscard]] kls::filesystem::FileType type_from_mode(const mode_t& mode ) noexcept {
    switch (mode & S_IFMT) {
      case S_IFREG:
        return kls::filesystem::FileType::regular;
        break;
      case S_IFDIR:
        return kls::filesystem::FileType::directory;
        break;
      case S_IFLNK:
        return kls::filesystem::FileType::symlink;
        break;
      case S_IFCHR:
        return kls::filesystem::FileType::character_device;
        break;
      case S_IFBLK:
        return kls::filesystem::FileType::block_device;
        break;
      case S_IFIFO:
        return kls::filesystem::FileType::named_pipe;
        break;
      case S_IFSOCK:
        return kls::filesystem::FileType::unix_domain_socket;
        break;
      default:
         return kls::filesystem::FileType::unknown;
    }
  } 
  
  [[nodiscard]] kls::filesystem::FileType type_from_dirent(const unsigned char& dt_type ) noexcept {
    switch (dt_type) {
      case DT_REG:
        return kls::filesystem::FileType::regular;
        break;
      case DT_DIR:
        return kls::filesystem::FileType::directory;
        break;
      case DT_LNK:
        return kls::filesystem::FileType::symlink;
        break;
      case DT_CHR:
        return kls::filesystem::FileType::character_device;
        break;
      case DT_BLK:
        return kls::filesystem::FileType::block_device;
        break;
      case DT_FIFO:
        return kls::filesystem::FileType::named_pipe;
        break;
      case DT_SOCK:
        return kls::filesystem::FileType::unix_domain_socket;
        break;
      default:
         return kls::filesystem::FileType::unknown;
    }
  }
}
