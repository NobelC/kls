#pragma once
#include <cstdint>
#include "../result.hpp"
#include "../audit/audit_entry.hpp"
#include <limits>
#include <optional>
#include <vector>
#include <system_error>
#include <string>
#include <cstddef>

namespace kls::scanner {
  
  enum class SymlinkMode : uint8_t{
    ignore,
    read,
    traverse_target,
  };



  struct ScanOptions {
      bool recursive = false;
      bool include_hidden = false;
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

  enum class ScanIssueCode : uint8_t{
     directory_open_failed,
     directory_read_failed,
     metadata_failed,
     entry_disappeared,
     directory_permission_denied,
     entry_type_detection_failed,
     entry_type_changed,
     descriptor_limited,
     global_limited,
     io_error,
     symlink_target_truncated,
     symlink_loop,
     symlink_error_resolve
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
    std::uint64_t inode;
    unsigned char type;
    std::optional<std::size_t> target_symlink_id = std::nullopt; 
  };

  
  struct DiscoveredOutput{
    std::vector<std::string> directory_paths;
    std::vector<CandidateEntry> candidates;
    std::vector<std::string>target_symlink;
    std::vector<ScanIssue> issues;
  };

  struct ScanOutput {
      std::vector<kls::audit::AuditEntry> entries;
      std::vector<ScanIssue> issues;
  };

  using ScanResult = kls::Result<ScanOutput, ScanError>;
  using DiscoveryResult = kls::Result<DiscoveredOutput, ScanError>; 

  [[nodiscard]] DiscoveryResult discover_entries(const std::string& root,const ScanOptions& options);

}
