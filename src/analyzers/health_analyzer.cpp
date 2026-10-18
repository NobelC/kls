#include "kls/analyzers/health_analyzer.hpp"
#include "kls/findings/finding_registry.hpp"
#include "kls/findings/whitelist.hpp"
#include "kls/platform/unique_fd.hpp"
#include <array>
#include <cmath>
#include <fcntl.h>
#include <grp.h>
#include <linux/fs.h>
#include <pwd.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/xattr.h>
#include <unistd.h>
#include <vector>

namespace kls::analyzer {

// Clock skew tolerance. NTP syncs, VM snapshots, or dual-boot setups 
// can cause minor time drift. 1000s prevents false positives on recent files.
constexpr static int TOLERANCE_TIME = 1000;

std::vector<kls::detail::ID> analyze_health(const kls::auditor::AuditEntry &fe,
                                            const time_t &TIME_NOW) {
  std::vector<kls::detail::ID> finding_entry = {};
  
  auto AddFlag = [&](kls::detail::ID id) {
    const kls::findings::Finding *flag = kls::findings::get_finding(id);
    if (flag) {
      finding_entry.emplace_back(id);
    }
  };

  const bool is_suid = (fe.mode & S_ISUID) != 0;
  const bool is_sgid = (fe.mode & S_ISGID) != 0;
  const bool is_reg = S_ISREG(fe.mode);
  const bool is_dir = S_ISDIR(fe.mode);
  const bool is_lnk = S_ISLNK(fe.mode);

  // Anti-forensics & Time Manipulation: Files shouldn't be modified in the future.
  if (fe.mtime > (TIME_NOW + TOLERANCE_TIME)) {
    AddFlag(kls::detail::ID("SU13"));
  }

  // Detects backdated files. If birth time is newer than modification time, 
  // the timestamp was explicitly manipulated to hide recent changes.
  if (fe.btime > 0 && is_reg && (fe.mode & (S_IXUSR | S_IXGRP | S_IXOTH)) &&
      (fe.mtime < (fe.btime - TOLERANCE_TIME))) {
    AddFlag(kls::detail::ID("SU14"));
  }

  // Device nodes outside /dev are a classic rootkit/backdoor technique 
  // to access raw hardware, memory (/dev/mem), or bypass filesystem permissions.
  if ((S_ISCHR(fe.mode) || S_ISBLK(fe.mode)) &&
      !fe.full_path.starts_with("/dev/")) {
    AddFlag(kls::detail::ID("HWBD"));
  }

  // World-writable directory without sticky bit. Allows any user to 
  // delete or rename other users' files (e.g., a misconfigured /tmp).
  if (is_dir && (fe.mode & S_IWOTH) && !(fe.mode & S_ISVTX)) {
    AddFlag(kls::detail::ID("SG02"));
  }

  // Orphaned UID: The file is owned by a user that no longer exists.
  // If the UID is later reassigned, the new user inherits ownership of this file.
  {
    long initial_buffer = sysconf(_SC_GETGR_R_SIZE_MAX);
    if (initial_buffer == -1) {initial_buffer = 1024;}
    
    struct passwd pwd;
    struct passwd *result = nullptr;
    std::vector<char> buffer(static_cast<unsigned long>(initial_buffer));
    
    while ((getpwuid_r(fe.uid, &pwd, buffer.data(), buffer.size(), &result)) == ERANGE) {
      buffer.resize(buffer.size() * 2);
    }
    if (result == nullptr) {AddFlag(kls::detail::ID("SU11"));}
  }

  // Orphaned GID: Same risk as orphaned UID, but for group ownership.
  {
    long initial_buffer = sysconf(_SC_GETGR_R_SIZE_MAX);
    if (initial_buffer == -1) {initial_buffer = 1024;}
    
    struct group gp;
    struct group *result = nullptr;
    std::vector<char> buffer(static_cast<unsigned long>(initial_buffer));
    
    while ((getgrgid_r(fe.gid, &gp, buffer.data(), buffer.size(), &result)) == ERANGE) {
      buffer.resize(buffer.size() * 2);
    }
    if (result == nullptr) {AddFlag(kls::detail::ID("SG05"));}
  }

  if (is_reg) {
    // Sticky bit on a regular file is anomalous and usually a misconfiguration.
    if (fe.mode & S_ISVTX) {AddFlag(kls::detail::ID("SU22"));}

    // Executable file that is also group- or world-writable. 
    // Any user in the group or system can inject malicious code into it.
    bool has_exec = (fe.mode & (S_IXUSR | S_IXGRP | S_IXOTH)) != 0;
    if (has_exec && (fe.mode & (S_IWGRP | S_IWOTH))) {
      AddFlag(kls::detail::ID("SU08"));
    }

    // NOTE: Uses absolute path. ARCHITECTURE.md targets descriptor-relative ops.
    // Kept as-is for now to unblock baseline, but requires migration to openat().
    kls::platform::UniqueFd fd{::open(std::string(fe.full_path).c_str(),
                                      O_RDONLY | O_NONBLOCK | O_CLOEXEC)};
    if (fd) {
      int flags = 0;
      if (::ioctl(fd.get(), FS_IOC_GETFLAGS, &flags) != -1) {
        // Immutable/Append-only flags can be used legitimately by admins, 
        // but are heavily abused by malware for persistence.
        if (flags & FS_IMMUTABLE_FL) {AddFlag(kls::detail::ID("IMMU"));}
        if (flags & FS_APPEND_FL) {AddFlag(kls::detail::ID("APND"));}
      }
    }
  }

  // Linux ignores SUID on symlinks, but its presence indicates filesystem 
  // tampering, a broken restore, or an attempt to exploit a vulnerable kernel.
  if (is_lnk && is_suid) {AddFlag(kls::detail::ID("SU09"));}

  if (is_suid) {
    AddFlag(kls::detail::ID("SU01"));
    
    if (fe.mode & S_IWOTH) {AddFlag(kls::detail::ID("SU02"));}
    if (fe.mode & S_IXOTH) {AddFlag(kls::detail::ID("SU07"));}
    if (is_dir) {AddFlag(kls::detail::ID("SU10"));}
    
    if (!(fe.mode & (S_IXUSR | S_IXGRP | S_IXOTH))) {
      AddFlag(kls::detail::ID("SU03"));
      if (fe.mode & (S_IRUSR | S_IRGRP | S_IROTH)) {AddFlag(kls::detail::ID("SU18"));}
    }
    
    // Hardlinks to SUID binaries can be exploited to bypass path-based restrictions 
    // or cause quota exhaustion if the binary is modified via the link.
    if (!is_dir && fe.nlinks > 1) {AddFlag(kls::detail::ID("SU17"));}
    
    // SUID binary not owned by root. Highly suspicious, often indicates a trap.
    if (fe.uid != 0) {AddFlag(kls::detail::ID("SU05"));}
    
    // SUID binaries outside standard system paths are a primary privilege escalation vector.
    if (!kls::findings::is_known_path(fe.full_path)) {AddFlag(kls::detail::ID("SU04"));}
    
    // SUID binaries in user-writable directories (/tmp, /var, /home) can be 
    // replaced or modified by any user with write access to those paths.
    if (fe.full_path.starts_with("/tmp") || fe.full_path.starts_with("/var")) {AddFlag(kls::detail::ID("SU20"));}
    if (fe.full_path.starts_with("/home")) {AddFlag(kls::detail::ID("SU21"));}
    
    // Recently modified SUID binaries. Attackers often drop or modify these during an exploit.
    constexpr time_t ONE_DAY_IN_SECONDS = 86400;
    if (fe.uid == 0 && std::abs(TIME_NOW - fe.mtime) < ONE_DAY_IN_SECONDS) {
      AddFlag(kls::detail::ID("SU12"));
    }
    
    // SUID binary that also has file capabilities. Redundant and increases the attack surface.
    if (getxattr(std::string(fe.full_path).c_str(), "security.capability", nullptr, 0) > 0) {
      AddFlag(kls::detail::ID("SU19"));
    }
    
    if (is_reg) {
      kls::platform::UniqueFd fd{::open(std::string(fe.full_path).c_str(), O_RDONLY | O_CLOEXEC)};
      if (fd) {
        std::array<char, 4> buffer = {0};
        ssize_t n = read(fd.get(), buffer.data(), 4);
        if (n >= 2) {
          bool is_script = (buffer[0] == '#' && buffer[1] == '!');
          bool is_elf = (n == 4 && buffer[0] == 0x7f && buffer[1] == 'E' &&
                         buffer[2] == 'L' && buffer[3] == 'F');
          
          // Kernel ignores SUID on scripts, but if executed via an interpreter, 
          // it can lead to privilege escalation.
          if (is_script) {
            AddFlag(kls::detail::ID("SU06"));
          } 
          // A SUID file that is neither a valid ELF nor a script is highly anomalous.
          else if (!is_elf) {
            AddFlag(kls::detail::ID("SU16"));
          }
        } else {
          AddFlag(kls::detail::ID("SU16"));
        }
      }
    }
  }

  if (is_sgid) {
    AddFlag(kls::detail::ID("SG01"));
    if (fe.mode & S_IWOTH) {AddFlag(kls::detail::ID("SG03"));}
    
    // SGID binary writable by its own group. Group members can inject code 
    // and execute it with the group's privileges.
    if (fe.mode & S_IWGRP) {AddFlag(kls::detail::ID("SG04"));}
    
    if (!is_dir && !(fe.mode & (S_IXUSR | S_IXGRP | S_IXOTH))) {
      AddFlag(kls::detail::ID("SU03"));
    }
  }

  return finding_entry;
}

} // namespace kls::analyzer
