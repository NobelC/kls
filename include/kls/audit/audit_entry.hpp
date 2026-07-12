#pragma once
#include <cstdint>
#include <sys/types.h>
#include <string>
#include "../findings/health_flags.hpp"
#include <vector>
#include <ctime>

namespace kls::audit {

  struct AuditEntry {
  
  ino_t inode = 0;  
  uint64_t size = 0;  
  mode_t mode = 0;    
  nlink_t nlinks = 0; 
  uid_t uid = 0;      
  gid_t gid = 0;   

  
  bool is_directory : 1 = false;
  bool is_symlink : 1 = false;

 
  time_t mtime = 0;
  time_t btime = 0; 

  std::string full_path;
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
    mtime = 0;
    btime = 0;
    full_path.clear();
    symlink_target.clear();
    extension.clear();
    health.clear();
    capabilities.clear();
  }
};

}
