#include "../../../../include/option/option-implementation.hpp"
#include "../../../../include/option/option-raw-metadata.hpp"
#include "../../../../include/token/group-token.hpp"
#include "../../../../include/token/token-raw-metadata.hpp"
#include <algorithm>
#include <atomic>
#include <cerrno>
#include <condition_variable>
#include <cstdio>
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
#include <mutex>
#include <numeric>
#include <pwd.h>
#include <queue>
#include <string>
#include <string_view>
#include <sys/stat.h>
#include <sys/types.h>
#include <thread>
#include <type_traits>
#include <unordered_map>
#include <variant>
#include <ctime>

namespace {
constexpr unsigned int MAX_THREAD = 10;
constexpr unsigned int MAX_LENGTH = 30;
time_t TIME_NOW = time(nullptr);
static std::unordered_map<uid_t, std::string> cache_owner;
static std::unordered_map<gid_t, std::string> cache_group;

struct Option {
  bool recursive : 1;
  bool all : 1;
  bool long_format : 1;
  bool no_header_format : 1;
  bool follow_symlink : 1;
  bool capabilities : 1;
  bool needs_metadata : 1;
  bool healt : 1;
};

struct PendingDir {
  std::string path;
  int depth;
};

void LongRecolection(FileEntry &fe, const std::string &full_path,
                     const dirent *entry, std::string_view current_path, const Option& health) {
  // Inicialización de seguridad para evitar valores basura en bitfields y metadatos
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
  fe.name = entry->d_name;
  fe.path = current_path;
  fe.symlink_target.clear();
  fe.extension.clear();
  if (!fe.health.empty()) {
    fe.health.clear();
  }

  struct statx stx;
  unsigned int mask = STATX_BASIC_STATS | STATX_BTIME;

  // full_path ya viene construido del loop principal para evitar doble format
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

    // Usar S_ISDIR y S_ISLNK de statx garantiza corrección sin depender de d_type del dirent (que puede ser DT_UNKNOWN)
    fe.is_directory = S_ISDIR(stx.stx_mode);
    fe.is_symlink = S_ISLNK(stx.stx_mode);

    std::string_view name_view(fe.name);
    if (size_t dot_pos = name_view.find_last_of('.');
        dot_pos != std::string_view::npos && dot_pos > 0) {
      fe.extension = std::string(name_view.substr(dot_pos));
    }
    if(health.healt){
      if(stx.stx_mode & S_ISUID){
        fe.health.emplace_back(HealthFlag{
            .code = "SUID bit set — executes as file owner",
            .level = 3,
            });
      }
      if(stx.stx_mode & S_ISGID){
        fe.health.emplace_back(HealthFlag{
            .code = "SGID bit set — executes as file group",
            .level = 3,
            });
      }
      if(stx.stx_mode & S_IWOTH){
        fe.health.emplace_back(HealthFlag{
            .code = "world-writable — any user can modify this file",
            .level = 3,
            });
      }
      if(fe.is_symlink){
        struct statx stx_target;
        if(statx(AT_FDCWD, full_path.c_str(), 0, STATX_TYPE, &stx_target) == -1){
          if(errno == ENOENT || errno == ENOTDIR || errno == ELOOP){
            fe.health.emplace_back(HealthFlag{
                .code = "broken symlink — target does not exist",
                .level = 3,
            }); 
            fe.symlink_broken = true;
          }
        }
      }
      if(S_ISREG(stx.stx_mode)){
        bool has_exec = (stx.stx_mode & (S_IXUSR | S_IXGRP | S_IXOTH)) != 0;
        bool has_no_read = (stx.stx_mode & (S_IRUSR | S_IRGRP | S_IROTH)) == 0;

        if(has_exec && has_no_read){
          fe.health.emplace_back(HealthFlag{
            .code = "executable without read bit — suspicious permission",
            .level = 3,
          });
        }
      }
      if(!cache_owner.contains(fe.uid)){
        errno = 0;
        passwd *pw = getpwuid(fe.uid);
        if(pw){
          cache_owner[fe.uid] = cache_owner[fe.uid] = pw->pw_name;
        }
        } else {
          cache_owner[fe.uid] = std::to_string(fe.uid);
          if (errno == 0 || errno == ENOENT) {
            fe.health.emplace_back(HealthFlag{
              .code = "orphan uid — user no longer exists",
              .level = 3,
            });
          }
        }
      }

      if(!cache_group.contains(fe.gid)){
        errno = 0;
        group *gp = getgrgid(fe.gid);
        if(gp){
          cache_group[fe.gid] = cache_group[fe.gid] = gp->gr_name;
        }
        } else {
          cache_group[fe.gid] = std::to_string(fe.gid);
          if (errno == 0 || errno == ENOENT) {
            fe.health.emplace_back(HealthFlag{
              .code = "orphan uid — user no longer exists",
              .level = 3,
            });
          }
        }
      }
      if(fe.mtime > TIME_NOW){
        fe.health.emplace_back(HealthFlag{
            .code = "future timestamp — mtime is ahead of system clock",
            .level = 3,
            });
      }
    }
  }


void LongPrinter(const std::vector<FileEntry> &entries) {
  if (entries.empty()) {
    return;
  }

  // Encabezado (si no se activó --no-header)
  std::cout << std::format("{:<10} {:<3} {:<8} {:<8} {:<10} {:<12} {:<30} {:<30}\n",
                           "PERMS", "LNK", "OWNER", "GROUP", "SIZE", "MODIFIED",
                           "NAME", "ALERTS");
  std::cout << std::string(120, '-') << "\n";

  for (const auto &e : entries) {
    // 1. Permisos (Modo)
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
    std::string group_str;
    if (cache_owner.contains(e.uid)) {
      owner = cache_owner.at(e.uid);
    } else {
      passwd *pw = getpwuid(e.uid);
      owner = pw ? pw->pw_name : "UNKNOWN";
      cache_owner[e.uid] = owner;
    }

    if (cache_group.contains(e.gid)) {
      group_str = cache_group.at(e.gid);
    } else {
      group *gp = getgrgid(e.gid);
      group_str = gp ? gp->gr_name : "UNKNOWN";
      cache_group[e.gid] = group_str;
    }

    // 3. Tiempo
    std::string time_str = std::format("{:%b %d %H:%M}", std::chrono::system_clock::from_time_t(e.mtime));
    // 4. Tamaño (Manejo del valor centinela MAX que definimos)
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
    
    auto join_alert = std::accumulate(e.health.begin(), e.health.end(), std::string{},
        [](const std::string& acc, const HealthFlag& s){
          return acc.empty() ? s.code : acc + " | " + s.code; 
        });
    if (join_alert.empty()){
      join_alert = "-----------";
    }
   
    std::string display_name = e.name;
    if(MAX_LENGTH < display_name.size()){
      display_name.resize(0,MAX_LENGTH -3);
      display_name.append("...");
    }
    
    auto pading_size = MAX_LENGTH - static_cast<unsigned int>(display_name.size());
    std::string padding = pading_size > 0 ? std::string(pading_size, ' ') : "" ;


    std::string one_str = "\033[1;34m";
    std::string last_str = "\033[0m";
    std::string formatted_name;
    formatted_name.reserve(display_name.size() + one_str.size() + last_str.size());
    // Color para el nombre si es directorio
    if(e.is_directory){
      formatted_name.append(one_str).append(display_name).append(last_str).append(padding);
    } 
    else{
      formatted_name = display_name;
    }
    // Renderizado Final
    std::cout << std::format("{:<10} {:<3} {:<8} {:<8} {:<10} {:<12} {:<30} {:<30}\n", perms,
                             e.nlinks, owner, group_str, size_str, time_str, formatted_name, join_alert);
  }
} // namespace

void LIST_HANDLER(const GroupToken &token_group) {
  std::vector<FileEntry> file_entry;
  std::queue<PendingDir> pending_dirs;

  Option options_bool = {
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
      .needs_metadata = false,
      .healt = std::ranges::any_of(token_group.options, [](const auto& t){
          return t.name == "--health";
          })};

  options_bool.needs_metadata =
      options_bool.long_format ||
      std::ranges::any_of(token_group.options, [](const auto &opt) {
        return opt.name == "--modified-before" ||
               opt.name == "--modified-after" ||
               (opt.name == "--sort" &&
                (opt.value == "modified" || opt.value == "size" ||
                 opt.value == "type" || opt.value == "extension" ||
                 opt.value == "ext"));
      });

  int depth_limit = 0;
  auto it = std::ranges::find_if(
      token_group.options, [](const auto &t) { return t.name == "--depth"; });
  if (it != token_group.options.end()) {
    if (!it->value.empty()) {
      depth_limit = std::stoi(std::string(it->value));
    }
  }
  if (options_bool.recursive && it == token_group.options.end()) {
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

  pending_dirs.push({.path = start_path, .depth = 0});

  unsigned int used_thread = std::min(std::thread::hardware_concurrency() == 0
                                          ? 1
                                          : std::thread::hardware_concurrency(),
                                      MAX_THREAD);
  std::mutex write_dirs_queue;
  std::mutex write_dirs_vector;
  std::vector<std::thread> threads;
  std::condition_variable condition;
  std::atomic<int> working_threads = 0;
  std::atomic<bool> root_submitted = false;

  threads.reserve(used_thread);
  for (size_t i = 0; i < used_thread; i++) {
    threads.emplace_back([&, options_bool, depth_limit]() {
      std::vector<FileEntry> file_entry_temp;
      std::vector<PendingDir> temp_pending_dir;

      std::string full_path;
      full_path.reserve(PATH_MAX);

      while (true) {
        PendingDir current;
        {
          std::unique_lock<std::mutex> lock(write_dirs_queue);
          condition.wait(lock, [&] {
            return !pending_dirs.empty() ||
                   (root_submitted && working_threads == 0);
          });

          if (working_threads == 0 && pending_dirs.empty()) {
            return;
          }
          if (pending_dirs.empty()) {
            continue;
          }

          current = std::move(pending_dirs.front());
          pending_dirs.pop();
          working_threads++;
        }

        DIR *dir_ptr = opendir(current.path.c_str());
        if (!dir_ptr) {
          working_threads--;
          condition.notify_all();
          continue;
        }

        struct dirent *entry;
        while ((entry = readdir(dir_ptr)) != nullptr) {
          std::string_view name(entry->d_name);
          if (name == "." || name == "..") {
            continue;
          }
          if (!options_bool.all && name.starts_with('.')) {
            continue;
          }

          full_path = current.path;
          if (full_path.back() != '/') {
            full_path += "/";
          }
          full_path += name;

          FileEntry entry_data;
          LongRecolection(entry_data, full_path, entry, current.path, options_bool);

          if (entry_data.is_directory && options_bool.recursive &&
              current.depth < depth_limit) {
            temp_pending_dir.push_back(
                {.path = full_path, .depth = current.depth + 1});
          }

          file_entry_temp.push_back(std::move(entry_data));
        }
        closedir(dir_ptr);

        // Transferencia masiva a cola global
        if (!temp_pending_dir.empty()) {
          std::lock_guard<std::mutex> lock(write_dirs_queue);
          for (auto &d : temp_pending_dir) {
            pending_dirs.push(d);
          }
          temp_pending_dir.clear();
        }

        // Transferencia masiva a vector global
        if (!file_entry_temp.empty()) {
          std::lock_guard<std::mutex> lock(write_dirs_vector);
          file_entry.insert(file_entry.end(),
                            std::make_move_iterator(file_entry_temp.begin()),
                            std::make_move_iterator(file_entry_temp.end()));
          file_entry_temp.clear();
        }

        working_threads--;
        condition.notify_all();
      }
    });
  }

  root_submitted = true;
  condition.notify_all();
  for (auto &t : threads) {
    if (t.joinable()) {
      t.join();
    }
  }
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
            metadata->hanlder);
      }
    }
  };

  run_pipeline(OptionCategory::FILTERING);
  run_pipeline(OptionCategory::SORTING);

  LongPrinter(file_entry);
}
