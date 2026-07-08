#pragma once
#include <cstdint>
#include "../result.hpp"
#include "../audit/audit_entry.hpp"
#include <filesystem>
#include <vector>

namespace kls::scanner {

  struct ScanOptions {
      bool recursive = false;
      bool include_hidden = false;
      bool follow_symlinks = false;
  };

  enum class ScanErrorCode : uint_fast8_t{
      root_not_found,
      root_not_directory,
      root_permission_denied,
     root_open_failed
  };

  struct ScanError{
      ScanErrorCode code;
      std::filesystem::path path;
      std::error_code system_error;
  };

  enum class ScanIssueCode : uint_fast8_t{
     directory_open_failed,
     directory_read_failed,
     metadata_failed,
     entry_disappeared
  };

  struct ScanIssue {
      ScanIssueCode code;
      std::filesystem::path path;
      std::error_code system_error;
  };

  struct ScanOutput {
      std::vector<kls::audit::AuditEntry> entries;
      std::vector<ScanIssue> issues;
  };

  using ScanResult = kls::Result::Result<ScanOutput, ScanError>;

  [[nodiscard]] ScanResult scan(const std::filesystem::path& root,const ScanOptions& options);

}
