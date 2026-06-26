#include "../../include/option/option-implementation.hpp"
#include "../../include/option/option-raw-metadata.hpp"
#include "../../include/token/group-token.hpp"
#include "../../include/token/token-raw-metadata.hpp"
#include "../SUID-SGID-register/health-register.hpp"
#include "../white-list-routes/white-list-routes.hpp"
#include "../CAPABILITIES-register/capabilities-register.hpp"
#include <algorithm>
#include <array>
#include <cerrno>
#include <condition_variable>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <dirent.h>
#include <fcntl.h>
#include <filesystem>
#include <format>
#include <grp.h>
#include <iostream>
#include <iterator>
#include <limits>
#include <linux/limits.h>
#include <linux/stat.h>
#include <memory>
#include <numeric>
#include <pthread.h>
#include <pwd.h>
#include <queue>
#include <mutex>
#include <pthread.h>
#include <string>
#include <string_view>
#include <sys/stat.h>
#include <sys/types.h>
#include <type_traits>
#include <unordered_map>
#include <unordered_set>
#include <variant>
#include <ctime>
#include <sys/ioctl.h>
#include <linux/fs.h>
#include <fcntl.h>
#include <unistd.h>
#include <condition_variable>
#include <sys/xattr.h>
#include <linux/xattr.h>
#include <linux/capability.h>

#ifndef VFS_CAP_REVISION_MASK
#define VFS_CAP_REVISION_MASK 0xff000000
#endif

namespace {

struct Option {
  bool recursive : 1;
  bool all : 1;
  bool long_format : 1;
  bool no_header_format : 1;
  bool follow_symlink : 1;
  bool capabilities : 1;
  bool no_health : 1;
  bool stats : 1;
  bool explain : 1;
  bool only_capability : 1;
};

constexpr unsigned int MAX_LENGTH = 30;
time_t TIME_NOW = time(nullptr);
constexpr static int TOLERANCE_TIME = 1000; 

struct PendingDir {
  std::string path;
  int depth;
};

struct RecolectionShared{
  std::string name;
  std::string full_path;
  std::string current_path;
};

struct DirDelete{
  void operator()(DIR* dir) const noexcept{
    if(dir){
      closedir(dir);
    }
  }
};

using DirPtr = std::unique_ptr<DIR, DirDelete>;

void PerformHealthChecks(FileEntry &fe, std::string_view full_path, const struct statx &stx) {
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

void PerformCapabilities(FileEntry &fe, std::string_view full_path){
  auto AddCapability = [&](ID id) {
        const HealthFlag* flag = GetCapabilityFlag(id);
        if (flag) { fe.capabilities.emplace_back(*flag); }
  };
  std::array<uint8_t,64> buffer;
  std::memset(buffer.data(), 0, sizeof(buffer));
  ssize_t size = getxattr(std::string(full_path).c_str(), XATTR_NAME_CAPS ,buffer.data(), sizeof(buffer));

  if(size == -1){
    return ;
  }

  if(size > 0 ){
    AddCapability(ID("CA01"));
  }
  auto* cap_struct = reinterpret_cast<struct vfs_cap_data*>(buffer.data());
  uint32_t magic_etc = cap_struct->magic_etc;
  uint32_t version = magic_etc & VFS_CAP_REVISION_MASK;

  if(version != VFS_CAP_REVISION_1 && version != VFS_CAP_REVISION_2 && version != VFS_CAP_REVISION_3){
    AddCapability(ID{"CA28"});
    return ;
  }

  uint64_t permitted = ((uint64_t)cap_struct->data[1].permitted << 32) | cap_struct->data[0].permitted;
  uint64_t inheritable = ((uint64_t)cap_struct->data[1].inheritable << 32) | cap_struct->data[0].inheritable;

  if(permitted == 0 && inheritable == 0){
    AddCapability(ID{"CA35"});
  }
  if(inheritable != 0){
    AddCapability(ID{"CA36"});
  }
  if(permitted & ((1ULL << 21) | (1ULL << 19) | (1ULL << 16))){
    AddCapability(ID{"CA25"});
  }
  if(permitted & ((1ULL << 7) | (1ULL << 6) | (1ULL << 0))){
    AddCapability(ID{"CA26"});
  }
  if(permitted & ((1ULL << 13) | (1Ull <<12))){
    AddCapability(ID{"CA27"});
  }
  if(permitted & ((1ULL << 1) | (1Ull << 2))){
    AddCapability(ID{"CA30"});
  }
  if(permitted & ((1ULL << 3) | (1ULL << 4))){
    AddCapability(ID{"CA31"});
  }
  if(permitted & ((1ULL << 18))){
    AddCapability(ID{"CA32"});
  }
  if(permitted & ((1ULL << 17))){
    AddCapability(ID{"CA33"});
  }
  if(permitted & ((1ULL << 29) | (1ULL << 30))){
    AddCapability(ID{"CA34"});
  }

}

void ProcessGeneralRecolection(FileEntry &fe, const std::string &full_path,
                     std::string_view name, std::string_view current_path, const Option& health) {
    fe.inode = 0;
    fe.size = 0;
    fe.mode = 0;
    fe.nlinks = 0;
    fe.uid = 0;
    fe.gid = 0;
    fe.is_directory = false;
    fe.is_symlink = false;
    fe.symlink_broken = false;
    fe.has_capabilities = false;
    fe.mtime = 0;
    fe.btime = 0;
    fe.name = name;
    fe.path = current_path;
    fe.symlink_target.clear();
    fe.extension.clear();
    if (!fe.health.empty()) {
        fe.health.clear();
    }

    struct statx stx;
    unsigned int mask = STATX_BASIC_STATS | STATX_BTIME;

    if (statx(AT_FDCWD, full_path.c_str(),
              AT_SYMLINK_NOFOLLOW | AT_STATX_DONT_SYNC, mask, &stx) == 0) {
        
        fe.inode = stx.stx_ino;
        fe.size = stx.stx_size;
        fe.nlinks = stx.stx_nlink;
        fe.mode = stx.stx_mode;
        fe.mtime = stx.stx_mtime.tv_sec;
        fe.uid = stx.stx_uid;
        fe.gid = stx.stx_gid;
        fe.btime = (stx.stx_mask & STATX_BTIME) ? stx.stx_btime.tv_sec : 0;

        fe.is_directory = S_ISDIR(stx.stx_mode);
        fe.is_symlink = S_ISLNK(stx.stx_mode);

        std::string_view name_view(fe.name);
        if (size_t dot_pos = name_view.find_last_of('.');
            dot_pos != std::string_view::npos && dot_pos > 0) {
            fe.extension = std::string(name_view.substr(dot_pos));
        }

        if(!health.no_health && health.only_capability){
          PerformCapabilities(fe, full_path);
          return ;
        }

        if (!health.no_health) {
            PerformHealthChecks(fe, full_path, stx);
            PerformCapabilities(fe, full_path);
        }
    }
}

void ProcessPrinter(std::vector<FileEntry> &entries, const Option& option_bool,
                    std::unordered_map<uid_t, std::string>& cache_owner, std::unordered_map<uid_t, std::string>& cache_group) {
  if (entries.empty()) {
    return;
  }

  if(option_bool.no_header_format ){

  }
  else if(option_bool.no_health){
      std::cout << std::format("{:<5} {:<10} {:<3} {:<8} {:<8} {:<10} {:<12} {:<30} \n",
                           "TYPE","PERMS", "LNK", "OWNER", "GROUP", "SIZE", "MODIFIED",
                           "NAME");
  }
  else{
      std::cout << std::format("{:<5} {:<10} {:<3} {:<8} {:<8} {:<10} {:<12} {:<30} {:<30}\n",
                           "TYPE","PERMS", "LNK", "OWNER", "GROUP", "SIZE", "MODIFIED",
                           "NAME", "ALERTS");
  }
  std::cout << std::string(120, '-') << "\n";

  for (auto &e : entries) {
    auto AddFlag = [&](ID id) {
        const HealthFlag* flag = GetHealthFlag(id);
        if (flag) { e.health.emplace_back(*flag); }
    };

    // 1. Perms (Mode)
    std::string perms;
    perms += (e.mode & S_IRUSR) ? "r" : "-";
    perms += (e.mode & S_IWUSR) ? "w" : "-";
    perms += (e.mode & S_IXUSR) ? "x" : "-";
    
    perms += (e.mode & S_IRGRP) ? "r" : "-";
    perms += (e.mode & S_IWGRP) ? "w" : "-";
    perms += (e.mode & S_IXGRP) ? "x" : "-";

    perms += (e.mode & S_IROTH) ? "r" : "-";
    perms += (e.mode & S_IWOTH) ? "w" : "-";
    perms += (e.mode & S_IXOTH) ? "x" : "-";
    

    
    std::string owner;
    {
      if(cache_owner.contains(e.uid)){
        owner = cache_owner.at(e.uid);
      }
      else{
        errno = 0;
        const passwd* pw = getpwuid(e.uid);
        if(pw){
          cache_owner[e.uid] = pw->pw_name;
          owner = pw->pw_name;
        }
        else{
          cache_owner[e.uid] = std::to_string(e.uid);
          if(!option_bool.no_health){ 
            if(errno == 0 || errno == ENOENT){
              AddFlag(ID("SU23"));
            }
          }
        }
      }
    }
    std::string group_str;
    {
      if(cache_group.contains(e.gid)){
        group_str = cache_group.at(e.gid);
      }
      else{
        errno = 0;
        const group* gp = getgrgid(e.gid);
        if(gp){
          cache_group[e.gid] = gp->gr_name;
          group_str = gp->gr_name;
        }
        else{
          cache_group[e.gid] = std::to_string(e.gid);
          if(!option_bool.no_health){
            if(errno == 0 || errno == ENOENT){
              AddFlag(ID("SU24"));
            }
          }
        }
      }
    }
    

    // 3. Time
    std::array<char, std::size("yyyy-mm-dd")> str_time;
    std::strftime(str_time.data(), str_time.size(), "%F", std::gmtime(&e.mtime));
    // 4. Size
    std::string size_str;
    auto size_final = static_cast<double>(e.size);
    if((e.size < 1024)){
      size_str = std::format("{:.2f} B",size_final);
    }
    else if(e.size < 1048576){
      size_final /= 1024.0;
      size_str = std::format("{:.2f} KB",size_final);
    }
    else if(e.size < 1073741824){
      size_final /= 1048576.0;
      size_str = std::format("{:.2f} MB",size_final);
    }
    else if(e.size < 1099511627776){
      size_final /= 1073741824.0;
      size_str = std::format("{:.2f} GB",size_final);
    }
    else{
      size_final /=  1099511627776.0;
      size_str = std::format("{:.2f} TB",size_final);   
    }
    
    std::string type;
    type.reserve(3);

    std::string display_name = e.name;
    if(MAX_LENGTH < display_name.size()){
      display_name.resize(MAX_LENGTH -3);
      display_name.append("...");
    }
    
    auto pading_size = MAX_LENGTH - static_cast<unsigned int>(display_name.size());
    std::string padding = pading_size > 0 ? std::string(pading_size, ' ') : "" ;

    std::string formatted_name;
    formatted_name.reserve(display_name.size());
    // Color for directory name
    if(e.is_directory){
      formatted_name.append(display_name).append(padding);
      type = "DIR";
    } 
    else{
      formatted_name.append(display_name);
      type = e.is_symlink ? "SYM" : "FIL";
    }

    // Final Render
    if(option_bool.no_health){
      std::cout << std::format("{:<5} {:<10} {:<3} {:<8} {:<8} {:<10} {:<12} {:<30} \n",type, perms,
                             e.nlinks, owner, group_str, size_str, std::string_view(str_time.data(), str_time.size()), formatted_name);
    }
    else{
      auto join_alert = std::accumulate(e.health.begin(), e.health.end(), std::string{},
        [](const std::string& acc, const HealthFlag& s){
          return acc.empty() ? s.id.to_string() : acc + " | " + s.id.to_string(); 
        });
      if (join_alert.empty()){
        join_alert = "-----------";
      }
      std::cout << std::format("{:<5} {:<10} {:<3} {:<8} {:<8} {:<10} {:<12} {:<30} {:<30}\n", type, perms,
                             e.nlinks, owner, group_str, size_str, std::string_view(str_time.data(), str_time.size()), formatted_name, join_alert);
    }
    formatted_name.clear();
    display_name.clear();
  }
}

[[nodiscard]] constexpr std::string_view get_param_option_value(const std::vector<Token>& params, std::string_view target_name) noexcept {
  auto it = std::ranges::find(params, target_name, &Token::name);
  if(it != params.end()) [[likely]] {
    return it->value;
  }
  return {};
}



}// namespace

void LIST_HANDLER(const GroupToken &token_group) {
  CreatedHealthFlags();
  CreatedCapabilityFlags();

  std::mutex mutex_queue;
  std::condition_variable condition_queue;
  bool finished_recolection = false;

  std::vector<FileEntry> file_entry;
  std::queue<PendingDir> pending_dirs;

  std::unordered_map<uid_t, std::string> cache_owner;
  std::unordered_map<gid_t, std::string> cache_group;

  const Option option_bool = {
      .recursive = std::ranges::any_of(
          token_group.options,
          [](const auto &t) { return t.name == "--recursive"; }),
      .all = std::ranges::any_of(
          token_group.options, [](const auto &t) { return t.name == "--all"; }),
      .long_format =
          std::ranges::any_of(token_group.options,
                              [](const auto &t) { return t.name == "--long"; }),
      .no_header_format = std::ranges::any_of(
          token_group.options,
          [](const auto &t) { return t.name == "--no-header"; }),
      .follow_symlink = std::ranges::any_of(
          token_group.options,
          [](const auto &t) { return t.name == "--follow-symlink"; }),
      .capabilities =
          std::ranges::any_of(token_group.options, [](const auto &t) {
            return t.name == "--capabilities";
          }),
  .no_health = std::ranges::any_of(token_group.options, [](const auto&t){
        return t.name == "--no-health"; 
      }), 
  .stats = std::ranges::any_of(token_group.options, [](const auto&t){
        return t.name == "--stats";
      }),
  .explain = std::ranges::any_of(token_group.options, [](const auto& t){
      return t.name == "--explain-code";
      }),
  .only_capability = std::ranges::any_of(token_group.options, [](const auto& t){
      return t.name == "--only-capability";
      })
  };


  int depth_limit = 0;
  auto it = std::ranges::find_if(
      token_group.options, [](const auto &t) { return t.name == "--depth"; });
  
  if (it != token_group.options.end()) {
    if (!it->value.empty()) {
      depth_limit = std::stoi(std::string(it->value));
    }
  }

  if (option_bool.recursive && it == token_group.options.end()) {
    depth_limit = std::numeric_limits<int>::max();
  }

  std::string start_path =
      token_group.positional.empty()
          ? "."
          : std::string(token_group.positional.front().name);

  if (!std::filesystem::exists(start_path)) {
    std::cerr << std::format("ERROR: {} NO EXISTE\n", start_path);
    return;
  }

  if(option_bool.explain){
    auto code = get_param_option_value(token_group.options,"--explain-code");
    std::vector<std::string_view> result_process;
    size_t count_element = static_cast<size_t>(std::count(code.begin(), code.end(), ','));
    result_process.reserve(count_element + 1);

    size_t pos = 0;
    while((pos = code.find(',')) != std::string_view::npos){
      result_process.push_back(code.substr(0,pos));
      code.remove_prefix(pos + 1);
    }
    result_process.push_back(code);

    for(const auto& flag : result_process){
      PrintHealthFlags(ID{flag});
    }
    return ;
  }

//================================================================================================================================================================
//Process of Recolection 

  pending_dirs.push({.path = start_path, .depth = 0});
  std::string full_path; full_path.reserve(PATH_MAX);

  std::queue<std::vector<RecolectionShared>> queue_shared; 
  std::vector<RecolectionShared> batch;
  batch.reserve(512);

    auto thread_work = [&](){
    FileEntry fe;
    while(true){
      std::vector<RecolectionShared> local_lote;
      {
        std::unique_lock<std::mutex> lock_guard(mutex_queue);
        condition_queue.wait(lock_guard, [&]{
            return !queue_shared.empty()  || finished_recolection;
        });

        if(queue_shared.empty() && finished_recolection){
          break;
        }

        local_lote = std::move(queue_shared.front());
        queue_shared.pop();
      }
      for(const auto& entry : local_lote){
        ProcessGeneralRecolection(fe,entry.full_path,entry.name,entry.current_path,option_bool);
        file_entry.emplace_back(std::move(fe));
        fe.clear();
      }
    }

  };

  std::thread thread_consumer(thread_work);


  while(!pending_dirs.empty()){
    
    PendingDir current = std::move(pending_dirs.front());
    pending_dirs.pop();

    DirPtr dir_ptr(opendir(current.path.c_str()));
    struct dirent *entry;
    if(!dir_ptr){continue;}
    
    
    full_path.append(current.path);
    if(full_path.back() != '/'){
      full_path.append("/");
    }
    size_t base_len = full_path.size(); 

    while((entry = readdir(dir_ptr.get())) != nullptr){
      std::string_view name(entry->d_name);
      if(name == "." || name == ".."){
        continue;
      }
      if(!option_bool.all && name.starts_with(".")){
        continue;
      }
      full_path.append(name);

      batch.push_back({
          .name = entry->d_name,
          .full_path = full_path,
          .current_path = current.path,
          });
      
      
      bool dir_entry = entry->d_type == DT_UNKNOWN ? std::filesystem::is_directory(full_path) : (entry->d_type == DT_DIR ? true : false); 

      if (dir_entry && option_bool.recursive && current.depth < depth_limit) {  
        pending_dirs.push({
            .path = full_path, .depth = current.depth + 1,
        });
      }
      full_path.resize(base_len);

      if(batch.size() >= 512){
        {
          std::lock_guard<std::mutex> lock(mutex_queue);
          queue_shared.push(std::move(batch));
          condition_queue.notify_one();
        }
        batch.clear();
      }
    }

    full_path.clear();
  }

  if(!batch.empty()){
    {
        std::lock_guard<std::mutex> lock(mutex_queue);
        queue_shared.push(std::move(batch));
        condition_queue.notify_one();
      }
    }

  {
    std::lock_guard<std::mutex> lock(mutex_queue);
    finished_recolection = true;
    condition_queue.notify_all();
  }

  thread_consumer.join();

  //==================================================================================================================================================================

  //-----------------------------------------------------------------------------------------
  auto run_pipeline = [&](OptionCategory target_cat) {
    for (const auto &opt : token_group.options) {
      auto metadata = GetOptionData(opt.name);
      if (metadata && metadata->category == target_cat) {
        FilterStruct fs{.entries = file_entry, .context = opt.value};
        std::visit(
            [&](const auto &handler) {
              if constexpr (std::is_same_v<std::decay_t<decltype(handler)>,
                                           FilteringProcess>) {
                handler(fs);
              }
           },
            metadata->handler);
      }
    }
  };

  run_pipeline(OptionCategory::FILTERING);
  run_pipeline(OptionCategory::SORTING);

  ProcessPrinter(file_entry, option_bool, cache_owner, cache_group);
}
