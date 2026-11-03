#include "kls/audit/coverage_aggregator.hpp"
#include "kls/scanner/scanner.hpp"
#include <cerrno>

namespace kls::audit {

kls::audit::CoverageReport
coverage_aggregator(kls::scanner::ScanOutput &scan_output) {
  kls::audit::CoverageReport report;

  report.inspected = scan_output.items.size();
  report.visited = scan_output.visited_count;
  report.discovered = scan_output.discovered_count;
  report.excluded = scan_output.excluded_count;

  for (const auto &issue : scan_output.issues) {
    if (issue.code == scanner::ScanIssueCode::directory_permission_denied ||
        (issue.code == scanner::ScanIssueCode::metadata_failed &&
         (issue.system_error.value() == EACCES ||
          issue.system_error.value() == EPERM))) {
      report.denied++;
    } else if (issue.code == scanner::ScanIssueCode::descriptor_limited ||
               issue.code == scanner::ScanIssueCode::global_limited) {
      // Track resource exhaustion explicitly.
      report.limits_reached++;
    } else if (issue.code == scanner::ScanIssueCode::entry_disappeared) {
      report.disappeared++;
    } else if (issue.code == scanner::ScanIssueCode::entry_type_changed ||
               issue.code == scanner::ScanIssueCode::entry_identity_changed) {
      report.unstable++;
    } else if (issue.code == scanner::ScanIssueCode::metadata_incomplete ||
               issue.code ==
                   scanner::ScanIssueCode::entry_type_detection_failed ||
               issue.code == scanner::ScanIssueCode::io_error ||
               issue.code == scanner::ScanIssueCode::directory_read_failed) {
      report.unsupported++;
    } else if (issue.code == scanner::ScanIssueCode::directory_open_failed) {
      // Generic open failures (non-EACCES) are counted as skipped.
      report.skipped++;
    } else if (issue.code ==
               scanner::ScanIssueCode::pseudo_filesystem_excluded) {
      // Already counted via excluded_count, no double-counting needed.
      // This branch is intentionally empty but documented for clarity.
    }

    // Note: symlink errors and invalid references are logged in issues
    // but do not directly increment these high-level coverage counters.
  }

  return report;
}

} // namespace kls::audit
