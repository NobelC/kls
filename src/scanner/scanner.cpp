#include "../../include/kls/scanner/scanner.hpp"
#include "../../include/kls/filesystem/file_type.hpp"
#include "../../include/kls/detail/file_type_conversion.hpp"
#include <array>
#include <cerrno>
#include <cstdint>
#include <linux/limits.h>
#include <linux/stat.h>
#include <optional>
#include <queue>
#include <sys/types.h>
#include <dirent.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <utility>
#include <memory>


namespace kls::scanner {

  struct DirDelete{
    void operator()(DIR* dir) const noexcept{
      if(dir){
        closedir(dir);
      }
    }
  };

  using DirPtr = std::unique_ptr<DIR, DirDelete>;

  struct DirectoryRecord{
    std::string path;
    std::size_t depth;
  };

  kls::scanner::DiscoveryResult discover_entries(const std::string& root, const ScanOptions& options){
    //================================= Scanner Process =====================================
    DiscoveredOutput scan_discovered_candidates;
    std::queue<DirectoryRecord> pending_directories;
    std::string full_path; full_path.reserve(PATH_MAX);

    pending_directories.push(DirectoryRecord{
        .path = root,
        .depth = 0,
    });

    auto add_issue = [&](ScanIssueCode issues,const  std::string& actual_path, int open_error){
      scan_discovered_candidates.issues.emplace_back(ScanIssue{
              .code = issues,
              .path = actual_path,
              .system_error = {open_error, std::generic_category()}
      });
    };

    while(!pending_directories.empty()){
      auto actual_entry = std::move(pending_directories.front());
      pending_directories.pop();
      errno = 0;
      DirPtr dir_ptr(::opendir(actual_entry.path.c_str()));
      int open_error = dir_ptr == nullptr ? errno : 0;
      //============================= ERROR ROOT ==================
      if(dir_ptr == nullptr && actual_entry.depth == 0){
        if(open_error == ENOENT){
          return kls::scanner::DiscoveryResult{
            kls::Failure{
              kls::scanner::ScanError{
                .code = kls::scanner::ScanErrorCode::root_not_found,
                .path = root,
                .system_error = std::error_code{open_error, std::generic_category()}
              }
            }
          };
        }

        if(open_error == ENOTDIR){
          return kls::scanner::DiscoveryResult{
            kls::Failure{
              ScanError{
                .code = ScanErrorCode::root_not_directory,
                .path = root,
                .system_error = {open_error, std::generic_category()},
              }
            }
          };
        }

        if(open_error == EACCES){
          return kls::scanner::DiscoveryResult{
            kls::Failure{
              ScanError{
                .code = ScanErrorCode::root_permission_denied,
                .path = root,
                .system_error = {open_error, std::generic_category()},
              }
            }
          };
        }

        if(open_error != 0){
          return kls::scanner::DiscoveryResult{
            kls::Failure{
              ScanError{
                .code = ScanErrorCode::root_open_failed,
                .path = root,
                .system_error = {open_error, std::generic_category()}
              }
            }
          };
        }

      }

      //=================== Issues in sub-directory

      if(!dir_ptr){

        if(open_error == EACCES){
          add_issue(ScanIssueCode::directory_permission_denied, actual_entry.path, open_error);
        }
        else if(open_error == ENOENT){
          add_issue(ScanIssueCode::entry_disappeared, actual_entry.path, open_error);
        }

        else if(open_error == ENOTDIR){
          add_issue(ScanIssueCode::entry_type_changed, actual_entry.path, open_error);
        }

        else if(open_error == EMFILE){
          add_issue(ScanIssueCode::descriptor_limited, actual_entry.path, open_error);
        }

        else if(open_error == ENFILE){
          add_issue(ScanIssueCode::global_limited, actual_entry.path, open_error);
        }

        else if(open_error == EIO){
          add_issue(ScanIssueCode::io_error, actual_entry.path, open_error);
        }

        else{
          add_issue(ScanIssueCode::directory_open_failed, actual_entry.path, open_error);
        }

        continue;
      }

     //===================== Recolection in entry ===================== 

      full_path.append(actual_entry.path);
      if( full_path.empty() ||full_path.back() != '/'){
        full_path.append("/");
      }
      size_t base_len = full_path.size();
      auto directory_id = scan_discovered_candidates.directory_paths.size();
      scan_discovered_candidates.directory_paths.emplace_back(full_path);

      while(true){
        errno = 0;
        struct dirent* entry = readdir(dir_ptr.get());
        open_error = errno;

        if(entry == nullptr){
          if (open_error != 0){
            add_issue(ScanIssueCode::directory_read_failed, actual_entry.path,open_error);
          }
          break;
        }


        std::string temp_name(entry->d_name);

        if(temp_name == "." || temp_name == ".."){
          continue;
        }
        if(!options.include_hidden && temp_name.starts_with(".")){
          continue;
        }

        filesystem::FileType type_correct = filesystem::FileType::unknown;
        type_correct = detail::type_from_dirent(entry->d_type);

        if(type_correct == filesystem::FileType::unknown){
          errno = 0;
          struct statx stx {};
          const int result_statx = statx(::dirfd(dir_ptr.get()) , entry->d_name,AT_SYMLINK_NOFOLLOW, STATX_TYPE, &stx );

          if(result_statx == -1){
            open_error = errno;
            full_path.append(temp_name);
            add_issue(ScanIssueCode::entry_type_detection_failed, full_path,open_error);
            full_path.resize(base_len);
            continue;
          }
          if((stx.stx_mask & STATX_TYPE) == 0){
            full_path.append(temp_name);
            add_issue(ScanIssueCode::entry_type_detection_failed,full_path,0);
            full_path.resize(base_len);
            continue;
          }

          mode_t type_result = stx.stx_mode;
          type_correct = detail::type_from_mode(type_result);
          if(type_correct == filesystem::FileType::unknown){
            full_path.append(temp_name);
            add_issue(ScanIssueCode::entry_type_detection_failed, full_path,0 );
            full_path.resize(base_len);
            continue;
          }

        }
        full_path.append(temp_name);

        if(type_correct ==   filesystem::FileType::directory && options.recursive && actual_entry.depth < options.maximum_depth){
          pending_directories.push({
              .path = full_path,
              .depth = actual_entry.depth + 1,
          });
        }

        // ===================================================== read symlink
        std::optional<std::size_t> target_id = std::nullopt;
        if(type_correct ==   filesystem::FileType::symlink && options.symlink_status == SymlinkMode::read){
          errno = 0;
          std::array<char,PATH_MAX> buffer;
          ssize_t resolve_symlink = readlinkat(::dirfd(dir_ptr.get()),entry->d_name, buffer.data(), sizeof(buffer));
          open_error = resolve_symlink == -1 ? errno : 0;

          if(open_error != 0 || resolve_symlink == -1){
            add_issue(ScanIssueCode::symlink_error_resolve,full_path,open_error);
          }
          else if(static_cast<std::size_t>(resolve_symlink) == buffer.size()){
            add_issue(ScanIssueCode::symlink_target_truncated, full_path, open_error);
          }
          else{
            auto index_target = scan_discovered_candidates.target_symlink.size();
            scan_discovered_candidates.target_symlink.emplace_back(buffer.data(), static_cast<std::size_t>(resolve_symlink));
            target_id = index_target;
          }
        }
        //=============================================================================
        scan_discovered_candidates.candidates.emplace_back(CandidateEntry{
            .name = std::move(temp_name),
            .parent = directory_id,
            .discovered_inode = entry->d_ino == 0 ? std::nullopt : std::optional<std::uint64_t>(entry->d_ino) ,
            .discovered_type = type_correct,
            .target_symlink_id = target_id
            });
        full_path.resize(base_len);
      }
      full_path.clear();
    }

    return kls::scanner::DiscoveryResult{
      kls::Success<kls::scanner::DiscoveredOutput>{
        std::move(scan_discovered_candidates)
      }
    };

  }
}
