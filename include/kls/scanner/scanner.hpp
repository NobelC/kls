#pragma once
#include <cstdint>
#include "../result.hpp"
#include "../audit/audit_entry.hpp"
#include "../filesystem/file_type.hpp"
#include <limits>
#include <optional>
#include <vector>
#include <system_error>
#include <string>
#include <cstddef>
#include "../detail/Id.hpp"

namespace kls::scanner {
  
  enum class SymlinkMode : uint8_t{
    ignore,
    read,
    traverse_target,
  };

  struct ScanOptions {
      bool recursive = false;
      bool include_hidden = false;
      bool analyze_health = false;
      bool analyze_capabilities = false;
      SymlinkMode symlink_status = SymlinkMode::ignore;
      std::size_t maximum_depth = std::numeric_limits<std::size_t>::max(); 
  };

  enum class ScanErrorCode : uint8_t{
      root_not_found,
      root_not_directory,
      root_permission_denied,
      root_open_failed,
  };

  struct ScanError{
      ScanErrorCode code;
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
  };

  struct ScanIssue {
      ScanIssueCode code;
      std::string path;
      std::error_code system_error;
  };

  using IDDirectory = std::size_t;

  struct CandidateEntry{
    std::string name;
    IDDirectory parent;
    std::optional<std::uint64_t> discovered_inode = std::nullopt;
    filesystem::FileType discovered_type = filesystem::FileType::unknown;
    std::optional<std::size_t> target_symlink_id = std::nullopt; 
  };

  
  struct DiscoveredOutput{
    std::vector<std::string> directory_paths;
    std::vector<CandidateEntry> candidates;
    std::vector<std::string>target_symlink;
    std::vector<ScanIssue> issues;    
  };

  struct ScanOutput {
    std::vector<kls::auditor::AuditEntry> entries;
    std::vector<ScanIssue> issues;
    std::optional<std::vector<std::vector<ID>>> health_findings;
    std::optional<std::vector<std::vector<ID>>> finding_capabilities;
  };

  using ScanResult = kls::Result<ScanOutput, ScanError>;
  using DiscoveryResult = kls::Result<DiscoveredOutput, ScanError>; 

  [[nodiscard]] DiscoveryResult discover_entries(const std::string& root,const ScanOptions& options);
  [[nodiscard]] ScanResult orchestrator(const std::string& root, const ScanOptions& options);
}
