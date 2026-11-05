#pragma once
#include "kls/audit/audit_entry.hpp"
#include "kls/detail/Id.hpp"
#include "kls/filesystem/file_type.hpp"
#include "kls/platform/unique_fd.hpp"
#include "kls/result.hpp"
#include <cstddef>
#include <cstdint>
#include <limits>
#include <optional>
#include <string>
#include <system_error>
#include <vector>

namespace kls::scanner {

enum class SymlinkMode : uint8_t {
  ignore,
  read,
  traverse_target,
};

struct ScanOptions {
  bool recursive = false;
  bool include_hidden = false;
  bool analyze_health = false;
  bool analyze_capabilities = false;
  SymlinkMode symlink_status = SymlinkMode::read;
  std::size_t maximum_depth = std::numeric_limits<std::size_t>::max();
  std::string audit_root;
};

enum class ScanErrorCode : uint8_t {
  root_not_found,
  root_not_directory,
  root_permission_denied,
  root_open_failed,
  unknown,
};

struct ScanError {
  ScanErrorCode code = ScanErrorCode::unknown;
  std::string path;
  std::error_code system_error;
};

enum class ScanIssueCode : std::uint8_t {
  directory_open_failed,
  directory_read_failed,
  directory_permission_denied,

  entry_disappeared,
  entry_type_detection_failed,
  entry_type_changed,
  entry_identity_changed,

  metadata_failed,
  metadata_incomplete,
  invalid_discovery_reference,

  descriptor_limited,
  global_limited,
  io_error,

  symlink_target_truncated,
  symlink_loop,
  symlink_error_resolve,

  pseudo_filesystem_excluded,
  mount_point_crossed,
};

struct ScanIssue {
  ScanIssueCode code = ScanIssueCode::directory_open_failed;
  std::string path;
  std::error_code system_error;
};

using IDDirectory = std::size_t;

struct CandidateEntry {
  std::string name;
  IDDirectory parent = 0;
  std::string full_path;

  std::uint64_t inode = 0;
  std::uint64_t size = 0;
  mode_t mode = 0;
  nlink_t nlinks = 0;
  uid_t uid = 0;
  gid_t gid = 0;
  time_t mtime = 0;
  time_t btime = 0;
  filesystem::FileType type = filesystem::FileType::unknown;
  std::string extension;

  std::optional<std::string> symlink_target = std::nullopt;

  std::uint32_t dev_major = 0;
  std::uint32_t dev_minor = 0;
  std::optional<std::uint64_t> mount_id = std::nullopt;
};
struct DiscoveredOutput {
  std::vector<std::string> directory_paths;
  std::vector<CandidateEntry> candidates;
  std::vector<std::string> target_symlink;
  std::vector<ScanIssue> issues;
  std::vector<kls::platform::UniqueFd> directory_fds;

  std::size_t excluded_count = 0;
  std::size_t visited_count = 0;
  std::size_t discovered_count = 0;
};

struct AuditItem {
  kls::auditor::AuditEntry entry;
  std::vector<kls::detail::ID> findings;
};

struct ScanOutput {
  std::vector<AuditItem> items;
  std::vector<ScanIssue> issues;

  std::size_t excluded_count = 0;
  std::size_t visited_count = 0;
  std::size_t discovered_count = 0;
};

using ScanResult = kls::Result<ScanOutput, ScanError>;
using DiscoveryResult = kls::Result<DiscoveredOutput, ScanError>;

[[nodiscard]] DiscoveryResult discover_entries(const std::string &root,
                                               const ScanOptions &options);
[[nodiscard]] ScanResult orchestrator(const std::string &root,
                                      const ScanOptions &options);
} // namespace kls::scanner
