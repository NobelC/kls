#include "../../include/kls/scanner/collect_metadata.hpp"
#include "../../include/kls/audit/audit_entry.hpp"
#include "../../include/kls/scanner/scanner.hpp"
#include "../include/kls/scanner/detail/file_type_conversion.hpp"
#include <cstddef>
#include <fcntl.h>
#include <linux/stat.h>
#include <optional>
#include <string>
#include <sys/stat.h>
#include <system_error>
#include <utility>
#include <cerrno>

namespace kls::scanner {

[[nodiscard]]
kls::scanner::ScanOutput collect_metadata(
    kls::scanner::DiscoveredOutput discovered_output
) {
  ScanOutput output{
      .entries = {},
      .issues = std::move(discovered_output.issues),
  };

  output.entries.reserve(discovered_output.candidates.size());

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

  for (const auto& candidate : discovered_output.candidates) {
    if (candidate.parent >= discovered_output.directory_paths.size()) {
      output.issues.emplace_back(ScanIssue{
          .code = ScanIssueCode::invalid_discovery_reference,
          .path = candidate.name,
          .system_error = {},
      });

      continue;
    }

    const std::string& parent_path =
        discovered_output.directory_paths[candidate.parent];

    std::string full_path;
    full_path.reserve(parent_path.size() + candidate.name.size());
    full_path.append(parent_path);
    full_path.append(candidate.name);

    kls::audit::AuditEntry result_entry;
    result_entry.name = candidate.name;
    result_entry.full_path = full_path;

    if (candidate.target_symlink_id) {
      const std::size_t target_id =
          *candidate.target_symlink_id;

      if (target_id >= discovered_output.target_symlink.size()) {
        output.issues.emplace_back(ScanIssue{
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

      output.issues.emplace_back(ScanIssue{
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
      output.issues.emplace_back(ScanIssue{
          .code = ScanIssueCode::metadata_incomplete,
          .path = full_path,
          .system_error = {},
      });

      continue;
    }

    if (candidate.discovered_inode &&
        *candidate.discovered_inode != stx.stx_ino) {
      output.issues.emplace_back(ScanIssue{
          .code = ScanIssueCode::entry_identity_changed,
          .path = full_path,
          .system_error = {},
      });

      continue;
    }

    const auto metadata_type =
        kls::scanner::detail::type_from_mode(stx.stx_mode);

    if (metadata_type == filesystem::FileType::unknown) {
      output.issues.emplace_back(ScanIssue{
          .code = ScanIssueCode::metadata_incomplete,
          .path = full_path,
          .system_error = {},
      });

      continue;
    }

    if (candidate.discovered_type != metadata_type) {
      output.issues.emplace_back(ScanIssue{
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

    output.entries.emplace_back(std::move(result_entry));
  }

  return output;
}

}
