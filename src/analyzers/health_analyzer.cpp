#include "kls/analyzers/health_analyzer.hpp"
#include "kls/findings/finding_registry.hpp"
#include "kls/findings/whitelist.hpp"
#include "kls/platform/unique_fd.hpp"
#include <fcntl.h>
#include <sys/stat.h>
#include <linux/fs.h>
#include <sys/ioctl.h>
#include <sys/xattr.h>
#include <grp.h>
#include <pwd.h>
#include <unistd.h>
#include <array>
#include <vector>
#include <cmath>

namespace kls::analyzer {

constexpr static int TOLERANCE_TIME = 1000;

std::vector<ID> analyze_health(const kls::auditor::AuditEntry& fe, const time_t& TIME_NOW) {
    std::vector<ID> finding_entry = {};
    
    auto AddFlag = [&](ID id) {
        const kls::findings::Finding* flag = kls::findings::get_health_flag(id);
        if (flag) {
            finding_entry.emplace_back(id);
        }
    };

    const bool is_suid = (fe.mode & S_ISUID) != 0;
    const bool is_sgid = (fe.mode & S_ISGID) != 0;
    const bool is_reg = S_ISREG(fe.mode);
    const bool is_dir = S_ISDIR(fe.mode);
    const bool is_lnk = S_ISLNK(fe.mode);

    if (fe.mtime > (TIME_NOW + TOLERANCE_TIME)) {
        AddFlag(ID("SU13"));
    }

    if (fe.btime > 0 && is_reg &&
        (fe.mode & (S_IXUSR | S_IXGRP | S_IXOTH)) && (fe.mtime < (fe.btime - TOLERANCE_TIME))) {
        AddFlag(ID("SU14"));
    }

    if ((S_ISCHR(fe.mode) || S_ISBLK(fe.mode)) && !fe.full_path.starts_with("/dev/")) {
        AddFlag(ID("HWBD"));
    }

    if (is_dir && (fe.mode & S_IWOTH) && !(fe.mode & S_ISVTX)) {
        AddFlag(ID("SG02"));
    }
    
    {
        long initial_buffer = sysconf(_SC_GETGR_R_SIZE_MAX);
        if (initial_buffer == -1) {
            initial_buffer = 1024;
        }

        struct passwd pwd;
        struct passwd* result = nullptr;
        std::vector<char> buffer(static_cast<unsigned long>(initial_buffer));

        while ((getpwuid_r(fe.uid, &pwd, buffer.data(), buffer.size(), &result)) == ERANGE) {
            buffer.resize(buffer.size() * 2);
        }

        if (result == nullptr) {
            AddFlag(ID("SU11"));
        }
    }

    {
        long initial_buffer = sysconf(_SC_GETGR_R_SIZE_MAX);
        if (initial_buffer == -1) {
            initial_buffer = 1024;
        }

        struct group gp;
        struct group* result = nullptr;
        std::vector<char> buffer(static_cast<unsigned long>(initial_buffer));
        while ((getgrgid_r(fe.gid, &gp, buffer.data(), buffer.size(), &result)) == ERANGE) {
            buffer.resize(buffer.size() * 2);
        }

        if (result == nullptr) {
            AddFlag(ID("SG05"));
        }
    }

    if (is_reg) {
        if (fe.mode & S_ISVTX) {
            AddFlag(ID("SU22"));
        }

        bool has_exec = (fe.mode & (S_IXUSR | S_IXGRP | S_IXOTH)) != 0;
        if (has_exec && (fe.mode & (S_IWGRP | S_IWOTH))) {
            AddFlag(ID("SU08"));
        }
        
        kls::platform::UniqueFd fd{::open(std::string(fe.full_path).c_str(), O_RDONLY | O_NONBLOCK | O_CLOEXEC)};
        if (fd) {
            int flags = 0;
            if (::ioctl(fd.get(), FS_IOC_GETFLAGS, &flags) != -1) {
                if (flags & FS_IMMUTABLE_FL) {
                    AddFlag(ID("IMMU"));
                }
                if (flags & FS_APPEND_FL) {
                    AddFlag(ID("APND"));
                }
            }
        }
    }

    if (is_lnk && is_suid) {
        AddFlag(ID("SU09"));
    }

    if (is_suid) {
        AddFlag(ID("SU01"));

        if (fe.mode & S_IWOTH) {
            AddFlag(ID("SU02"));
        }

        if (fe.mode & S_IXOTH) {
            AddFlag(ID("SU07"));
        }
        if (is_dir) {
            AddFlag(ID("SU10"));
        }
        if (!(fe.mode & (S_IXUSR | S_IXGRP | S_IXOTH))) {
            AddFlag(ID("SU03"));
        }

        if (!(fe.mode & (S_IXUSR | S_IXGRP | S_IXOTH)) && (fe.mode & (S_IRUSR | S_IRGRP | S_IROTH))) {
            AddFlag(ID("SU18"));
        }

        if (!is_dir && fe.nlinks > 1) {
            AddFlag(ID("SU17"));
        }
        if (fe.uid != 0) {
            AddFlag(ID("SU05"));
        }
        if (!kls::findings::is_known_path(fe.full_path)) {
            AddFlag(ID("SU04"));
        }
        if (fe.full_path.starts_with("/tmp") || fe.full_path.starts_with("/var")) {
            AddFlag(ID("SU20"));
        }
        if (fe.full_path.starts_with("/home")) {
            AddFlag(ID("SU21"));
        }

        constexpr time_t ONE_DAY_IN_SECONDS = 86400;
        if (fe.uid == 0 && std::abs(TIME_NOW - fe.mtime) < ONE_DAY_IN_SECONDS) {
            AddFlag(ID("SU12"));
        }

        if (getxattr(std::string(fe.full_path).c_str(), "security.capability", nullptr, 0) > 0) {
            AddFlag(ID("SU19"));
        }

        if (is_reg) {
            kls::platform::UniqueFd fd{::open(std::string(fe.full_path).c_str(), O_RDONLY | O_CLOEXEC)};
            if (fd) {
                std::array<char, 4> buffer = {0};
                ssize_t n = read(fd.get(), buffer.data(), 4);

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
        if (fe.mode & S_IWOTH) {
            AddFlag(ID("SG03"));
        }
        if (fe.mode & S_IWGRP) {
            AddFlag(ID("SG04"));
        }
        if (!is_dir && !(fe.mode & (S_IXUSR | S_IXGRP | S_IXOTH))) {
            AddFlag(ID("SU03"));
        }
    }
    
    return finding_entry;
}

} // namespace kls::analyzer
