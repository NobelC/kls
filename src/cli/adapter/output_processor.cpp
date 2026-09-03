#include "kls/cli/adapter/output_processor.hpp"
#include "kls/scanner/scanner.hpp"
#include "kls/cli/spec/cli_spec_definition.hpp"
#include <algorithm>
#include <fnmatch.h>
#include <optional>

namespace kls::cli::adapter {

void process_output(scanner::ScanOutput& output, const model::ParsedOptions& opts) {
    
    if (opts.filter.has_value()) {
      definition_options::apply_filter(output, *opts.filter);
    }
    if(opts.min_severity.has_value()){
      definition_options::apply_min_severity(output,*opts.min_severity);
    }
    if (opts.modified_before.has_value()) {
      definition_options::apply_modified_before(output, *opts.modified_before);
    }
    if (opts.modified_after.has_value()) {
      definition_options::apply_modified_after(output, *opts.modified_after);
    }
    if (opts.only_findings) {
      definition_options::apply_only_findings(output);
    }
  
    if (opts.sort.has_value()) {
      definition_options::apply_sort(output, *opts.sort);
    }
    if (opts.dirs_first) {
      definition_options::apply_dirs_first(output);
    }
    if (opts.findings_first) {
      definition_options::apply_findings_first(output);
    }
    
    if (opts.reverse) {
        std::ranges::reverse(output.items);
    }
}

} // namespace kls::cli::adapter
