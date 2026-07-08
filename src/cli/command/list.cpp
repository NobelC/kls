#include "../../include/kls/cli/option/option-implementation.hpp"
#include "../../include/kls/cli/option/option-raw-metadata.hpp"
#include "../../include/kls/cli/token/group-token.hpp"
#include "../../include/kls/cli/token/token-raw-metadata.hpp"

//============================= NEW IMPLEMENTATIONS
#include "../../include/kls/audit/audit_entry.hpp"
#include "../../include/kls/analyzers/health_analyzer.hpp"
#include "../../include/kls/analyzers/capability_analyzer.hpp"
#include "../../include/kls/report/render_report.hpp"
//=============================
#include "../../SUID-SGID-register/health-register.hpp"
#include "../../CAPABILITIES-register/capabilities-register.hpp"
#include <algorithm>
#include <array>
#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <dirent.h>
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
#include <pwd.h>
#include <queue>
#include <mutex>
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

time_t TIME_NOW = time(nullptr);

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


void ProcessGeneralRecolection(kls::audit::AuditEntry &fe, const std::string &full_path,
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
          kls::analyzer::analyze_capability(fe, full_path);
          return ;
        }

        if (!health.no_health) {
          kls::analyzer::analyze_health(fe, full_path, stx, TIME_NOW);
          kls::analyzer::analyze_capability(fe, full_path);
        }
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

  std::vector<kls::audit::AuditEntry> file_entry;
  std::queue<PendingDir> pending_dirs;



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
    kls::audit::AuditEntry fe;
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

  kls::report::RenderOptions render_options{};
  render_options.show_headers = !option_bool.no_header_format;
  render_options.show_findings = !option_bool.no_health;

  kls::report::render_report(
    std::cout, std::span<const kls::audit::AuditEntry>(file_entry),render_options
    );
}
