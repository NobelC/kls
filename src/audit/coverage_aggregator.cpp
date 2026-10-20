#include "kls/audit/coverage_aggregator.hpp"
#include "kls/scanner/scanner.hpp"
#include <cerrno>

namespace kls::audit {
  kls::audit::CoverageReport coverage_aggregator(kls::scanner::ScanOutput& scan_output){
    kls::audit::CoverageReport report;
    report.inspected = scan_output.items.size();
    report.visited = scan_output.visited_count;
    report.discovered = scan_output.discovered_count;
    report.excluded = scan_output.excluded_count;

    for(const auto& issue : scan_output.issues){
      if(issue.code == scanner::ScanIssueCode::metadata_failed){
        if(issue.system_error && (issue.system_error.value() == EACCES || issue.system_error.value() == EPERM)){
          report.denied++;
        }
        else{
          report.unsupported++;
        }
      }
      else if(issue.code == scanner::ScanIssueCode::entry_disappeared){
        report.disappeared++;
      }
      else if(issue.code == scanner::ScanIssueCode::entry_type_changed || issue.code == scanner::ScanIssueCode::entry_identity_changed){
        report.unstable++;
      }
      else if (issue.code == scanner::ScanIssueCode::metadata_incomplete) {
        report.unsupported++;
      }
    }
    return report;
  }
}
