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
#include <string_view>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <utility>

namespace kls::scanner {

// ============================================================================
// Pseudo-filesystem exclusion list.
// These dynamic filesystems can cause side effects (automounts, slow reads,
// unpredictable behavior). Excluded by default per THREAT-MODEL.md.
// ============================================================================
namespace {
constexpr std::array<std::string_view, 4> EXCLUDED_PREFIXES = {{
    "/dev/",
    "/proc/",
    "/run/",
    "/sys/",
}};

[[nodiscard]] constexpr bool
is_excluded_pseudo_filesystem(std::string_view path) noexcept {
  for (const auto &prefix : EXCLUDED_PREFIXES) {
    if (path.starts_with(prefix)) {
      return true;
    }
  }
  return false;
}
} // namespace

// RAII wrapper for DIR*. Prevents file descriptor leaks on early returns.
struct DirDelete {
  void operator()(DIR *dir) const noexcept {
    if (dir) {
      ::closedir(dir);
    }
  }
};
using DirPtr = std::unique_ptr<DIR, DirDelete>;

// ============================================================================
// Descriptor-relative traversal.
// DirectoryRecord holds the display path (for reports) and an index into
// DiscoveredOutput::directory_fds (for relative operations).
// Absolute paths are presentation data, NOT object handles.
// ============================================================================
struct DirectoryRecord {
  std::string display_path;
  std::size_t dir_fds_index = 0;
  std::size_t depth = 0;
};

kls::scanner::DiscoveryResult discover_entries(const std::string &root,
                                               const ScanOptions &options) {
  DiscoveredOutput scan_discovered_candidates;
  std::queue<DirectoryRecord> pending_directories;

  // ========================================================================
  // Acquire root directory descriptor once.
  // O_DIRECTORY ensures we open a directory, not a file.
  // O_CLOEXEC prevents descriptor leaks to child processes.
  // ========================================================================
  int root_fd = ::open(root.c_str(), O_RDONLY | O_DIRECTORY | O_CLOEXEC);
  if (root_fd < 0) {
    const int err = errno;
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

  // Register root in directory_fds (index 0) and directory_paths.
  scan_discovered_candidates.directory_paths.emplace_back(root);
  scan_discovered_candidates.directory_fds.emplace_back(
      kls::platform::UniqueFd(root_fd));

  pending_directories.push(
      DirectoryRecord{.display_path = root, .dir_fds_index = 0, .depth = 0});

  auto add_issue = [&](ScanIssueCode code, const std::string &path,
                       int error_code) {
    scan_discovered_candidates.issues.emplace_back(
        ScanIssue{.code = code,
                  .path = path,
                  .system_error = {error_code, std::generic_category()}});
  };

  // ========================================================================
  // ARCHITECTURAL NOTE: BFS via std::queue.
  // Prevents stack overflow on maliciously deep directory trees, ensuring
  // predictable memory usage and bounded traversal.
  // ========================================================================
  while (!pending_directories.empty()) {
    auto actual_entry = std::move(pending_directories.front());
    pending_directories.pop();

    // BASELINE C-07: Retrieve parent directory descriptor.
    const int parent_fd =
        scan_discovered_candidates.directory_fds[actual_entry.dir_fds_index]
            .get();

    // Use fdopendir for readdir.
    // We dup() the fd because fdopendir takes ownership of the descriptor.
    // The original fd remains in directory_fds for collect_metadata.
    int dup_fd = ::dup(parent_fd);
    if (dup_fd < 0) {
      add_issue(ScanIssueCode::directory_open_failed, actual_entry.display_path,
                errno);
      continue;
    }

    DirPtr dir_ptr(::fdopendir(dup_fd));
    if (!dir_ptr) {
      const int open_error = errno;
      ::close(dup_fd); // fdopendir failed, close manually
      add_issue(ScanIssueCode::directory_open_failed, actual_entry.display_path,
                open_error);
      continue;
    }

    scan_discovered_candidates.visited_count++;

    // Build display path for reports (NOT used as object handle).
    std::string full_path = actual_entry.display_path;
    if (full_path.empty() || full_path.back() != '/') {
      full_path.push_back('/');
    }
    const std::size_t base_len = full_path.size();

    while (true) {
      errno = 0;
      struct dirent *entry = readdir(dir_ptr.get());
      const int open_error = errno;

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

      // ====================================================================
      // Single-pass metadata collection.
      // Perform statx once during discovery to capture ALL metadata,
      // eliminating the need for a second pass in collect_metadata.
      //
      // Descriptor-relative statx.
      // Use parent_fd + entry->d_name instead of AT_FDCWD + full_path.
      // AT_SYMLINK_NOFOLLOW ensures we inspect the symlink itself,
      // preventing accidental traversal outside the audit root.
      // ====================================================================
      struct statx stx{};
      errno = 0;
      const int statx_result =
          ::statx(parent_fd, entry->d_name, AT_SYMLINK_NOFOLLOW,
                  STATX_BASIC_STATS | STATX_BTIME
#ifdef STATX_MNT_ID
                      | STATX_MNT_ID
#endif
                  ,
                  &stx);

      if (statx_result == -1) {
        const int statx_error = errno;
        full_path.append(temp_name);
        if (statx_error == ENOENT) {
          add_issue(ScanIssueCode::entry_disappeared, full_path, statx_error);
        } else {
          add_issue(ScanIssueCode::metadata_failed, full_path, statx_error);
        }
        full_path.resize(base_len);
        continue;
      }

      // Filesystem robustness: Network or exotic filesystems may omit fields.
      // We explicitly check the mask rather than trusting uninitialized memory.
      constexpr unsigned int required_mask =
          STATX_TYPE | STATX_MODE | STATX_INO | STATX_SIZE | STATX_NLINK |
          STATX_UID | STATX_GID | STATX_MTIME;
      if ((stx.stx_mask & required_mask) != required_mask) {
        full_path.append(temp_name);
        add_issue(ScanIssueCode::metadata_incomplete, full_path, 0);
        full_path.resize(base_len);
        continue;
      }

      const auto type_correct = detail::type_from_mode(stx.stx_mode);
      if (type_correct == filesystem::FileType::unknown) {
        full_path.append(temp_name);
        add_issue(ScanIssueCode::entry_type_detection_failed, full_path, 0);
        full_path.resize(base_len);
        continue;
      }

      full_path.append(temp_name);

      // ====================================================================
      // Exclude pseudo-filesystems by default.
      // Check before enqueuing to prevent traversal into dynamic filesystems.
      // ====================================================================
      if (type_correct == filesystem::FileType::directory &&
          options.recursive && actual_entry.depth < options.maximum_depth) {
        if (is_excluded_pseudo_filesystem(full_path)) {
          scan_discovered_candidates.excluded_count++;
          add_issue(ScanIssueCode::pseudo_filesystem_excluded, full_path, 0);
          full_path.resize(base_len);
          continue;
        }

        // ==================================================================
        // Open subdirectory relative to parent.
        // O_NOFOLLOW prevents following symlinks to directories.
        // O_DIRECTORY ensures we only open directories.
        // O_CLOEXEC prevents descriptor leaks to child processes.
        // ==================================================================
        const int child_fd =
            ::openat(parent_fd, entry->d_name,
                     O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
        if (child_fd < 0) {
          const int child_error = errno;
          if (child_error == EACCES) {
            add_issue(ScanIssueCode::directory_permission_denied, full_path,
                      child_error);
          } else if (child_error == ENOENT) {
            add_issue(ScanIssueCode::entry_disappeared, full_path, child_error);
          } else if (child_error == ENOTDIR) {
            add_issue(ScanIssueCode::entry_type_changed, full_path,
                      child_error);
          } else if (child_error == EMFILE) {
            add_issue(ScanIssueCode::descriptor_limited, full_path,
                      child_error);
          } else if (child_error == ENFILE) {
            add_issue(ScanIssueCode::global_limited, full_path, child_error);
          } else if (child_error == EIO) {
            add_issue(ScanIssueCode::io_error, full_path, child_error);
          } else {
            add_issue(ScanIssueCode::directory_open_failed, full_path,
                      child_error);
          }
          full_path.resize(base_len);
          continue;
        }

        // Register subdirectory in directory_fds and directory_paths.
        const auto child_dir_id =
            scan_discovered_candidates.directory_fds.size();
        scan_discovered_candidates.directory_paths.emplace_back(full_path);
        scan_discovered_candidates.directory_fds.emplace_back(
            kls::platform::UniqueFd(child_fd));

        pending_directories.push(
            DirectoryRecord{.display_path = full_path,
                            .dir_fds_index = child_dir_id,
                            .depth = actual_entry.depth + 1});
      }

      // ====================================================================
      // Directory-relative symlink resolution.
      // readlinkat with parent_fd ensures we resolve the link exactly where
      // it was found, avoiding race conditions if the parent directory is
      // swapped mid-scan.
      // ====================================================================
      std::optional<std::string> symlink_target = std::nullopt;
      if (type_correct == filesystem::FileType::symlink &&
          options.symlink_status == SymlinkMode::read) {
        errno = 0;
        std::array<char, PATH_MAX> buffer;
        const ssize_t resolve_symlink = ::readlinkat(
            parent_fd, entry->d_name, buffer.data(), buffer.size());
        const int link_error = (resolve_symlink == -1) ? errno : 0;

        if (link_error != 0 || resolve_symlink == -1) {
          add_issue(ScanIssueCode::symlink_error_resolve, full_path,
                    link_error);
        } else if (static_cast<std::size_t>(resolve_symlink) == buffer.size()) {
          add_issue(ScanIssueCode::symlink_target_truncated, full_path, 0);
        } else {
          symlink_target = std::string(
              buffer.data(), static_cast<std::size_t>(resolve_symlink));
        }
      }

      // Extract extension efficiently.
      std::string extension;
      if (const std::size_t dot_position = temp_name.find_last_of('.');
          dot_position != std::string::npos && dot_position > 0) {
        extension = temp_name.substr(dot_position);
      }

      // ====================================================================
      // Store ALL metadata in CandidateEntry.
      // This eliminates the need for a second statx pass in collect_metadata.
      //
      // Capture mount identity for cross-filesystem tracking.
      // ====================================================================
      scan_discovered_candidates.candidates.emplace_back(CandidateEntry{
          .name = std::move(temp_name),
          .parent = actual_entry.dir_fds_index,
          .full_path = full_path,
          .inode = stx.stx_ino,
          .size = stx.stx_size,
          .mode = stx.stx_mode,
          .nlinks = stx.stx_nlink,
          .uid = stx.stx_uid,
          .gid = stx.stx_gid,
          .mtime = stx.stx_mtime.tv_sec,
          .btime = (stx.stx_mask & STATX_BTIME) ? stx.stx_btime.tv_sec : 0,
          .type = type_correct,
          .extension = std::move(extension),
          .symlink_target = std::move(symlink_target),
          .dev_major = stx.stx_dev_major,
          .dev_minor = stx.stx_dev_minor,
#ifdef STATX_MNT_ID
          .mount_id = (stx.stx_mask & STATX_MNT_ID)
                          ? std::optional<std::uint64_t>(stx.stx_mnt_id)
                          : std::nullopt
#else
          .mount_id = std::nullopt
#endif
      });

      full_path.resize(base_len);
    }
  }

  return kls::Success<kls::scanner::DiscoveredOutput>{
      std::move(scan_discovered_candidates)};
}

} // namespace kls::scanner
