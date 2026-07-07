#include <kls/analyzers/health_analyzer.hpp>
#include "../../src/SUID-SGID-register/health-register.hpp"
#include <fcntl.h>
#include <sys/stat.h>
#include <linux/fs.h>
#include <sys/ioctl.h>
#include <sys/xattr.h>
#include <grp.h>
#include <pwd.h>
#include <unistd.h>
#include <array>

constexpr static int TOLERANCE_TIME = 1000;

void kls::analyzer::analyze_health(kls::audit::AuditEntry &fe, std::string_view full_path, const struct statx &stx,const time_t& TIME_NOW) noexcept {
      auto AddFlag = [&](ID id) {
        const HealthFlag* flag = GetHealthFlag(id);
        if (flag) { fe.health.emplace_back(*flag); }
    };

    const bool is_suid = (stx.stx_mode & S_ISUID) != 0;
    const bool is_sgid = (stx.stx_mode & S_ISGID) != 0;
    const bool is_reg  = S_ISREG(stx.stx_mode);
    const bool is_dir  = S_ISDIR(stx.stx_mode);
    const bool is_lnk  = S_ISLNK(stx.stx_mode);

    if (fe.mtime > (TIME_NOW + TOLERANCE_TIME)) {
      AddFlag(ID("SU13"));
    }

    if ((stx.stx_mask & STATX_BTIME) && fe.btime > 0 && is_reg && 
        (stx.stx_mode & (S_IXUSR | S_IXGRP | S_IXOTH)) && (fe.mtime < (fe.btime - TOLERANCE_TIME))) {
        AddFlag(ID("SU14")); 
    }

    if ((S_ISCHR(stx.stx_mode) || S_ISBLK(stx.stx_mode)) && !full_path.starts_with("/dev/")) {
        AddFlag(ID("HWBD")); 
    }

    if (is_dir && (stx.stx_mode & S_IWOTH) && !(stx.stx_mode & S_ISVTX)) {
        AddFlag(ID("SG02")); 
    }
    {
      long initial_buffer = sysconf(_SC_GETGR_R_SIZE_MAX);
      if(initial_buffer == -1){
        initial_buffer = 1024;
      }

      struct passwd pwd;
      struct passwd* result = nullptr;
      std::vector<char> buffer(static_cast<unsigned long>(initial_buffer));
      
      while((getpwuid_r(fe.uid,&pwd,buffer.data(),buffer.size(),&result)) == ERANGE){
        buffer.resize(buffer.size() * 2);
      }

      if(result == nullptr){
        AddFlag(ID{"SU11"});
      }

    }
    
    {
      
      long initial_buffer = sysconf(_SC_GETGR_R_SIZE_MAX) ;
      if (initial_buffer == -1){
        initial_buffer = 1024;
      }
      
      struct group gp;
      struct group* result = nullptr;
      std::vector<char> buffer(static_cast<unsigned long>(  initial_buffer));
      while((getgrgid_r(fe.gid,&gp,buffer.data(),buffer.size(),&result)) == ERANGE){
        buffer.resize(buffer.size() * 2);
      }

      if (result == nullptr) {
        AddFlag(ID("SG05"));
      }

    }
    
    

    if (is_reg) {
        if (stx.stx_mode & S_ISVTX) {
          AddFlag(ID("SU22"));
        }
        
        bool has_exec = (stx.stx_mode & (S_IXUSR | S_IXGRP | S_IXOTH)) != 0;
        if (has_exec && (stx.stx_mode & (S_IWGRP | S_IWOTH))) {
          AddFlag(ID("SU08"));
        }
        int fd = open(std::string(full_path).c_str(), O_RDONLY | O_NONBLOCK);
        if (fd != -1) {
            int flags = 0;
            if (ioctl(fd, FS_IOC_GETFLAGS, &flags) != -1) {
                if (flags & FS_IMMUTABLE_FL) {
                  AddFlag(ID("IMMU"));
                }
                if (flags & FS_APPEND_FL) {
                  AddFlag(ID("APND"));
                }
            }
            close(fd);
        }
    }

    if (is_lnk && is_suid) {
      AddFlag(ID("SU09"));
    }

    if (is_suid) {
        AddFlag(ID("SU01"));

        if (stx.stx_mode & S_IWOTH) {
          AddFlag(ID("SU02"));
        }
        
        if (stx.stx_mode & S_IXOTH) {
          AddFlag(ID("SU07"));
        }
        if (is_dir) {
          AddFlag(ID("SU10"));
        }
        if (!(stx.stx_mode & (S_IXUSR | S_IXGRP | S_IXOTH))) {
          AddFlag(ID("SU03"));
        }
        
        if (!(stx.stx_mode & (S_IXUSR | S_IXGRP | S_IXOTH)) && (stx.stx_mode & (S_IRUSR | S_IRGRP | S_IROTH))) {
            AddFlag(ID("SU18"));
        }

        if (!is_dir && fe.nlinks > 1) {
          AddFlag(ID("SU17"));
        }
        if (fe.uid != 0) {
          AddFlag(ID("SU05"));
        }
        if (!IsKnowPath(full_path)) {
          AddFlag(ID("SU04"));
        }
        if (full_path.starts_with("/tmp") || full_path.starts_with("/var")) {
          AddFlag(ID("SU20"));
        }
        if (full_path.starts_with("/home")) {
          AddFlag(ID("SU21"));
        }

        constexpr time_t ONE_DAY_IN_SECONDS = 86400;
        if (fe.uid == 0 && std::abs(TIME_NOW - fe.mtime) < ONE_DAY_IN_SECONDS) {
            AddFlag(ID("SU12"));
        }

        if (getxattr(std::string(full_path).c_str(), "security.capability", nullptr, 0) > 0) {
            AddFlag(ID("SU19"));
        }

        if (is_reg) {
            int fd = open(std::string(full_path).c_str(), O_RDONLY);
            if (fd != -1) {
              std::array<char, 4> buffer = {0};
                ssize_t n = read(fd, buffer.data(), 4);
                close(fd);

                if (n >= 2) {
                    bool is_script = (buffer[0] == '#' && buffer[1] == '!');
                    bool is_elf = (n == 4 && buffer[0] == 0x7f && buffer[1] == 'E' && buffer[2] == 'L' && buffer[3] == 'F');
                    
                    if (is_script) {
                        AddFlag(ID("SU06")); 
                    } else if (!is_elf) {
                        AddFlag(ID("SU16")); 
                    }
                } else {
                    AddFlag(ID("SU16"));                 
                }
            }
        }
    }

    if (is_sgid) {
        AddFlag(ID("SG01"));
        if (stx.stx_mode & S_IWOTH) {
          AddFlag(ID("SG03"));
        }
        if (stx.stx_mode & S_IWGRP) {
          AddFlag(ID("SG04"));
        }
        if (!is_dir && !(stx.stx_mode & (S_IXUSR | S_IXGRP | S_IXOTH))) {
            AddFlag(ID("SU03")); 
        }
    }

}
