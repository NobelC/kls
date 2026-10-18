#include "kls/scanner/collect_metadata.hpp"
#include "kls/audit/audit_entry.hpp"
#include "kls/scanner/scanner.hpp"
#include "kls/detail/file_type_conversion.hpp"
#include <cstddef>
#include <fcntl.h>
#include <linux/limits.h>
#include <linux/stat.h>
#include <optional>
#include <string>
#include <sys/stat.h>
#include <system_error>
#include <cerrno>

namespace kls::scanner {

[[nodiscard]]
kls::scanner::ScanOutput collect_metadata(
    const kls::scanner::DiscoveredOutput& discovered_output
) {
  ScanOutput final_output;
  final_output.items.reserve(discovered_output.candidates.size());

  // Request birth time (btime) alongside basic stats. 
  // Legacy `stat` cannot provide reliable creation time.
  constexpr unsigned int requested_mask = STATX_BASIC_STATS | STATX_BTIME;

  // These fields are mandatory for security analysis. 
  // If the filesystem omits them, the entry is flagged as incomplete, not assumed safe.
  constexpr unsigned int required_mask =
      STATX_TYPE | STATX_MODE | STATX_INO | STATX_SIZE |
      STATX_NLINK | STATX_UID | STATX_GID | STATX_MTIME;

  std::string full_path;
  full_path.reserve(PATH_MAX);

  for (const auto& candidate : discovered_output.candidates) {
    // Sanity check: Prevent out-of-bounds access on malformed discovery state.
    if (candidate.parent >= discovered_output.directory_paths.size()) {
      final_output.issues.emplace_back(ScanIssue{
          .code = ScanIssueCode::invalid_discovery_reference,
          .path = candidate.name,
          .system_error = {},
      });
      continue;
    }

    const std::string& parent_path = discovered_output.directory_paths[candidate.parent];
    full_path.clear();
    full_path.append(parent_path);
    if (!parent_path.empty() && !parent_path.ends_with('/')) {
      full_path.push_back('/');
    }
    full_path.append(candidate.name);

    kls::auditor::AuditEntry result_entry;
    result_entry.name = candidate.name;
    result_entry.full_path = full_path;

    if (candidate.target_symlink_id) {
      const std::size_t target_id = *candidate.target_symlink_id;
      if (target_id >= discovered_output.target_symlink.size()) {
        final_output.issues.emplace_back(ScanIssue{
            .code = ScanIssueCode::invalid_discovery_reference,
            .path = full_path,
            .system_error = {},
        });
        continue;
      }
      result_entry.symlink_target = discovered_output.target_symlink[target_id];
    }

    struct statx stx {};
    errno = 0;

    // ARCHITECTURAL NOTE: AT_SYMLINK_NOFOLLOW is mandatory.
    // We must inspect the symlink itself, not its target, to prevent 
    // accidental traversal outside the audit root or triggering side effects.
    // TODO: Migrate to `dirfd` + `entry->d_name` instead of `AT_FDCWD` + `full_path` 
    // to fully satisfy the descriptor-relative scanner requirement in ARCHITECTURE.md.
    const int statx_result = ::statx(
        AT_FDCWD,
        full_path.c_str(),
        AT_SYMLINK_NOFOLLOW,
        requested_mask,
        &stx
    );

    if (statx_result == -1) {
      const int statx_error = errno;
      final_output.issues.emplace_back(ScanIssue{
          .code = statx_error == ENOENT ? ScanIssueCode::entry_disappeared : ScanIssueCode::metadata_failed,
          .path = full_path,
          .system_error = {statx_error, std::generic_category()},
      });
      continue;
    }

    // Filesystem robustness: Network or exotic filesystems may omit fields.
    // We explicitly check the mask rather than trusting uninitialized memory.
    if ((stx.stx_mask & required_mask) != required_mask) {
      final_output.issues.emplace_back(ScanIssue{
          .code = ScanIssueCode::metadata_incomplete,
          .path = full_path,
          .system_error = {},
      });
      continue;
    }

    // TOCTOU Defense 1: Verify inode identity.
    // If the inode changed between `readdir` and `statx`, the object was replaced.
    // Discarding it prevents combining evidence from two different files.
    if (candidate.discovered_inode && *candidate.discovered_inode != stx.stx_ino) {
      final_output.issues.emplace_back(ScanIssue{
          .code = ScanIssueCode::entry_identity_changed,
          .path = full_path,
          .system_error = {},
      });
      continue;
    }

    const auto metadata_type = detail::type_from_mode(stx.stx_mode);
    if (metadata_type == filesystem::FileType::unknown) {
      final_output.issues.emplace_back(ScanIssue{
          .code = ScanIssueCode::metadata_incomplete,
          .path = full_path,
          .system_error = {},
        });
      continue;
    }

    // TOCTOU Defense 2: Verify file type consistency.
    // A type change (e.g., file became a symlink) indicates a race condition.
    if (candidate.discovered_type != metadata_type) {
      final_output.issues.emplace_back(ScanIssue{
          .code = ScanIssueCode::entry_type_changed,
          .path = full_path,
          .system_error = {},
      });
      continue;
    }

    // Map validated metadata to the domain model.
    result_entry.inode = stx.stx_ino;
    result_entry.size = stx.stx_size;
    result_entry.mode = stx.stx_mode;
    result_entry.nlinks = stx.stx_nlink;
    result_entry.uid = stx.stx_uid;
    result_entry.gid = stx.stx_gid;
    result_entry.mtime = stx.stx_mtime.tv_sec;
    result_entry.btime = (stx.stx_mask & STATX_BTIME) ? stx.stx_btime.tv_sec : 0;
    result_entry.type = metadata_type;

    // Extract extension efficiently without allocation if possible.
    if (const std::size_t dot_position = candidate.name.find_last_of('.');
        dot_position != std::string::npos && dot_position > 0) {
      result_entry.extension = candidate.name.substr(dot_position);
    }

    final_output.items.push_back({
      .entry = std::move(result_entry),
      .findings = {},
    });
  } 

  return final_output;
}

} // namespace kls::scanner
