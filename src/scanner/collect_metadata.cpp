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
    kls::scanner::DiscoveredOutput discovered_output
) {

  ScanOutput final_output;
  final_output.items.reserve(discovered_output.candidates.size());

  constexpr unsigned int requested_mask =
      STATX_BASIC_STATS |
      STATX_BTIME;

  constexpr unsigned int required_mask =
      STATX_TYPE |
      STATX_MODE |
      STATX_INO |
      STATX_SIZE |
      STATX_NLINK |
      STATX_UID |
      STATX_GID |
      STATX_MTIME;
  std::string full_path;
  full_path.reserve(PATH_MAX);
  for (const auto& candidate : discovered_output.candidates) {
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
    if(!parent_path.empty() && !parent_path.ends_with('/')){
      full_path.push_back('/');
    }
    full_path.append(candidate.name);

    kls::auditor::AuditEntry result_entry;
    result_entry.name = candidate.name;
    result_entry.full_path = full_path;

    if (candidate.target_symlink_id) {
      const std::size_t target_id =
          *candidate.target_symlink_id;

      if (target_id >= discovered_output.target_symlink.size()) {
        final_output.issues.emplace_back(ScanIssue{
            .code = ScanIssueCode::invalid_discovery_reference,
            .path = full_path,
            .system_error = {},
        });

        continue;
      }

      result_entry.symlink_target =
          discovered_output.target_symlink[target_id];
    }

    struct statx stx {};

    errno = 0;

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
          .code = statx_error == ENOENT
              ? ScanIssueCode::entry_disappeared
              : ScanIssueCode::metadata_failed,
          .path = full_path,
          .system_error = {
              statx_error,
              std::generic_category(),
          },
      });

      continue;
    }

    if ((stx.stx_mask & required_mask) != required_mask) {
      final_output.issues.emplace_back(ScanIssue{
          .code = ScanIssueCode::metadata_incomplete,
          .path = full_path,
          .system_error = {},
      });

      continue;
    }

    if (candidate.discovered_inode &&
        *candidate.discovered_inode != stx.stx_ino) {
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

    if (candidate.discovered_type != metadata_type) {
      final_output.issues.emplace_back(ScanIssue{
          .code = ScanIssueCode::entry_type_changed,
          .path = full_path,
          .system_error = {},
      });

      continue;
    }

    result_entry.inode = stx.stx_ino;
    result_entry.size = stx.stx_size;
    result_entry.mode = stx.stx_mode;
    result_entry.nlinks = stx.stx_nlink;
    result_entry.uid = stx.stx_uid;
    result_entry.gid = stx.stx_gid;
    result_entry.mtime = stx.stx_mtime.tv_sec;

    result_entry.btime =
        (stx.stx_mask & STATX_BTIME)
            ? stx.stx_btime.tv_sec
            : 0;

    result_entry.type = metadata_type;

    if (const std::size_t dot_position =
            candidate.name.find_last_of('.');
        dot_position != std::string::npos &&
        dot_position > 0) {
      result_entry.extension =
          candidate.name.substr(dot_position);
    }
    final_output.items.push_back({
      .entry = std::move(result_entry),
      .health_findings = {},
      .finding_capabilities = {},
    });
  } 

  return final_output;
}

}
