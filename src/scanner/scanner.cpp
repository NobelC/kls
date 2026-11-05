#include "kls/scanner/scanner.hpp"
#include "kls/detail/file_type_conversion.hpp"
#include "kls/filesystem/file_type.hpp"
#include "kls/platform/unique_fd.hpp"
#include <array>
#include <cerrno>
#include <cstdint>
#include <dirent.h>
#include <fcntl.h>
#include <linux/limits.h>
#include <linux/stat.h>
#include <memory>
#include <optional>
#include <queue>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <utility>

namespace kls::scanner {

constexpr std::array<std::string_view, 4> EXCLUDED_PREFIXES = {
    {"/dev/", "/proc/", "/run/", "/sys/"}};

[[nodiscard]] constexpr bool
is_excluded_pseudo_filesystem(std::string_view path) noexcept {
  for (const auto &prefix : EXCLUDED_PREFIXES) {
    if (path.starts_with(prefix)) {
      return true;
    }
  }
  return false;
}

// RAII wrapper for DIR*. Prevents file descriptor leaks on early returns.
struct DirDelete {
  void operator()(DIR *dir) const noexcept {
    if (dir) {
      ::closedir(dir);
    }
  }
};
using DirPtr = std::unique_ptr<DIR, DirDelete>;

// Descriptor-relative traversal.
// DirectoryRecord holds the display path (for reports) and an index into
// DiscoveredOutput::directory_fds (for relative operations).
struct DirectoryRecord {
  std::string display_path;
  std::size_t dir_fds_index = 0;
  std::size_t depth = 0;
};

kls::scanner::DiscoveryResult discover_entries(const std::string &root,
                                               const ScanOptions &options) {
  DiscoveredOutput scan_discovered_candidates;
  std::queue<DirectoryRecord> pending_directories;

  // Acquire root directory descriptor once.
  // Use O_DIRECTORY to ensure we're opening a directory, not a file.
  // Use O_CLOEXEC to prevent descriptor leaks to child processes.
  int root_fd = ::open(root.c_str(), O_RDONLY | O_DIRECTORY | O_CLOEXEC);
  if (root_fd < 0) {
    int err = errno;
    if (err == ENOENT) {
      return kls::Failure{kls::scanner::ScanError{
          .code = ScanErrorCode::root_not_found,
          .path = root,
          .system_error = {err, std::generic_category()}}};
    }
    if (err == ENOTDIR) {
      return kls::Failure{
          ScanError{.code = ScanErrorCode::root_not_directory,
                    .path = root,
                    .system_error = {err, std::generic_category()}}};
    }
    if (err == EACCES) {
      return kls::Failure{
          ScanError{.code = ScanErrorCode::root_permission_denied,
                    .path = root,
                    .system_error = {err, std::generic_category()}}};
    }
    return kls::Failure{
        ScanError{.code = ScanErrorCode::root_open_failed,
                  .path = root,
                  .system_error = {err, std::generic_category()}}};
  }

  // Register root in directory_fds (index 0)
  scan_discovered_candidates.directory_paths.emplace_back(root);
  scan_discovered_candidates.directory_fds.emplace_back(
      kls::platform::UniqueFd(root_fd));

  pending_directories.push(
      DirectoryRecord{.display_path = root, .dir_fds_index = 0, .depth = 0});

  auto add_issue = [&](ScanIssueCode issues, const std::string &actual_path,
                       int open_error) {
    scan_discovered_candidates.issues.emplace_back(
        ScanIssue{.code = issues,
                  .path = actual_path,
                  .system_error = {open_error, std::generic_category()}});
  };

  // BFS via std::queue. Prevents stack overflow on deep trees.
  while (!pending_directories.empty()) {
    auto actual_entry = std::move(pending_directories.front());
    pending_directories.pop();

    // Retrieve parent directory descriptor.
    int parent_fd =
        scan_discovered_candidates.directory_fds[actual_entry.dir_fds_index]
            .get();

    // Use fdopendir for readdir.
    //  We dup() the fd because fdopendir takes ownership.
    int dup_fd = ::dup(parent_fd);
    if (dup_fd < 0) {
      add_issue(ScanIssueCode::directory_open_failed, actual_entry.display_path,
                errno);
      continue;
    }

    DirPtr dir_ptr(::fdopendir(dup_fd));
    if (!dir_ptr) {
      ::close(dup_fd); // fdopendir failed, close manually
      add_issue(ScanIssueCode::directory_open_failed, actual_entry.display_path,
                errno);
      continue;
    }

    scan_discovered_candidates.visited_count++;

    // Build display path for reports (not used as object handle)
    std::string full_path = actual_entry.display_path;
    if (full_path.empty() || full_path.back() != '/') {
      full_path.append("/");
    }
    size_t base_len = full_path.size();

    while (true) {
      errno = 0;
      struct dirent *entry = readdir(dir_ptr.get());
      int open_error = errno;

      if (entry == nullptr) {
        if (open_error != 0) {
          add_issue(ScanIssueCode::directory_read_failed,
                    actual_entry.display_path, open_error);
        }
        break;
      }

      std::string temp_name(entry->d_name);
      if (temp_name == "." || temp_name == "..") {
        continue;
      }
      if (!options.include_hidden && temp_name.starts_with('.')) {
        continue;
      }

      scan_discovered_candidates.discovered_count++;

      // Fast-path type resolution from dirent
      filesystem::FileType type_correct =
          detail::type_from_dirent(entry->d_type);

      // Descriptor-relative statx.
      // Use parent_fd + entry->d_name instead of absolute path.
      // AT_SYMLINK_NOFOLLOW ensures we inspect the symlink itself.
      struct statx stx{};
      bool need_statx = (type_correct == filesystem::FileType::unknown);

      // For directories, we always need statx for mount crossing detection
      // and to verify it's not a symlink (O_NOFOLLOW safety)
      if (type_correct == filesystem::FileType::directory || need_statx) {
        errno = 0;
        const int result_statx =
            ::statx(parent_fd, entry->d_name, AT_SYMLINK_NOFOLLOW,
                    STATX_BASIC_STATS | STATX_MNT_ID, &stx);

        if (result_statx == -1) {
          open_error = errno;
          full_path.append(temp_name);
          add_issue(ScanIssueCode::entry_type_detection_failed, full_path,
                    open_error);
          full_path.resize(base_len);
          continue;
        }

        if ((stx.stx_mask & STATX_TYPE) == 0) {
          full_path.append(temp_name);
          add_issue(ScanIssueCode::entry_type_detection_failed, full_path, 0);
          full_path.resize(base_len);
          continue;
        }

        type_correct = detail::type_from_mode(stx.stx_mode);
        if (type_correct == filesystem::FileType::unknown) {
          full_path.append(temp_name);
          add_issue(ScanIssueCode::entry_type_detection_failed, full_path, 0);
          full_path.resize(base_len);
          continue;
        }
        need_statx = false;
      }

      full_path.append(temp_name);

      std::uint32_t dev_major = 0;
      std::uint32_t dev_minor = 0;

      if (type_correct == filesystem::FileType::directory &&
          options.recursive && actual_entry.depth < options.maximum_depth) {
        // Exclude pseudo-filesystems by default
        if (is_excluded_pseudo_filesystem(full_path)) {
          scan_discovered_candidates.excluded_count++;
          add_issue(ScanIssueCode::pseudo_filesystem_excluded, full_path, 0);
          full_path.resize(base_len);
          continue;
        }

        // Open subdirectory relative to parent.
        // O_NOFOLLOW prevents following symlinks to directories.
        // O_DIRECTORY ensures we only open directories.
        int child_fd =
            ::openat(parent_fd, entry->d_name,
                     O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
        if (child_fd < 0) {
          open_error = errno;
          if (open_error == EACCES) {
            add_issue(ScanIssueCode::directory_permission_denied, full_path,
                      open_error);
          } else if (open_error == ENOENT) {
            add_issue(ScanIssueCode::entry_disappeared, full_path, open_error);
          } else if (open_error == ENOTDIR) {
            add_issue(ScanIssueCode::entry_type_changed, full_path, open_error);
          } else if (open_error == EMFILE) {
            add_issue(ScanIssueCode::descriptor_limited, full_path, open_error);
          } else if (open_error == ENFILE) {
            add_issue(ScanIssueCode::global_limited, full_path, open_error);
          } else if (open_error == EIO) {
            add_issue(ScanIssueCode::io_error, full_path, open_error);
          } else {
            add_issue(ScanIssueCode::directory_open_failed, full_path,
                      open_error);
          }
          full_path.resize(base_len);
          continue;
        }

        // Capture device identity for mount crossing detection
        if (!need_statx) {
          dev_major = stx.stx_dev_major;
          dev_minor = stx.stx_dev_minor;
        }

        // Register subdirectory in directory_fds
        auto child_dir_id = scan_discovered_candidates.directory_fds.size();
        scan_discovered_candidates.directory_paths.emplace_back(full_path);
        scan_discovered_candidates.directory_fds.emplace_back(
            kls::platform::UniqueFd(child_fd));

        pending_directories.push(
            DirectoryRecord{.display_path = full_path,
                            .dir_fds_index = child_dir_id,
                            .depth = actual_entry.depth + 1});
      }

      // Directory-relative symlink resolution
      std::optional<std::size_t> target_id = std::nullopt;
      if (type_correct == filesystem::FileType::symlink &&
          options.symlink_status == SymlinkMode::read) {
        errno = 0;
        std::array<char, PATH_MAX> buffer;
        ssize_t resolve_symlink =
            readlinkat(parent_fd, entry->d_name, buffer.data(), sizeof(buffer));
        open_error = resolve_symlink == -1 ? errno : 0;

        if (open_error != 0 || resolve_symlink == -1) {
          add_issue(ScanIssueCode::symlink_error_resolve, full_path,
                    open_error);
        } else if (static_cast<std::size_t>(resolve_symlink) == buffer.size()) {
          add_issue(ScanIssueCode::symlink_target_truncated, full_path,
                    open_error);
        } else {
          auto index_target = scan_discovered_candidates.target_symlink.size();
          scan_discovered_candidates.target_symlink.emplace_back(
              buffer.data(), static_cast<std::size_t>(resolve_symlink));
          target_id = index_target;
        }
      }

      // Capture inode from statx if available, otherwise from dirent
      std::optional<std::uint64_t> discovered_inode = std::nullopt;
      if (!need_statx && (stx.stx_mask & STATX_INO)) {
        discovered_inode = stx.stx_ino;
      } else if (entry->d_ino != 0) {
        discovered_inode = entry->d_ino;
      }

      scan_discovered_candidates.candidates.emplace_back(
          CandidateEntry{.name = std::move(temp_name),
                         .parent = actual_entry.dir_fds_index,
                         .discovered_inode = discovered_inode,
                         .discovered_type = type_correct,
                         .target_symlink_id = target_id,
                         .discovered_dev_major = dev_major,
                         .discovered_dev_minor = dev_minor});

      full_path.resize(base_len);
    }
  }

  return kls::Success<kls::scanner::DiscoveredOutput>{
      std::move(scan_discovered_candidates)};
}

} // namespace kls::scanner
