#include <kls/cli/option/option-raw-metadata.hpp>

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
  bool symlink_broken : 1 = false;
  bool has_capabilities : 1 = false;
  bool correct_state : 1 = false;

 
  time_t mtime = 0;
  time_t btime = 0; 

  std::string name;
  std::string path;
  std::string symlink_target;
  std::string extension;
  std::vector<HealthFlag> health;
  std::vector<HealthFlag> capabilities;

  AuditEntry() noexcept
  {
    name.reserve(256);
    path.reserve(256);
    symlink_target.reserve(256);
    extension.reserve(256);
    //health.reserve(2);
  }


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
    mtime = 0;
    btime = 0;
    correct_state = false;
    name.clear();
    path.clear();
    symlink_target.clear();
    extension.clear();
    health.clear();
  }
};

}
