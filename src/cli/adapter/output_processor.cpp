#include "kls/cli/adapter/output_processor.hpp"
#include "kls/scanner/scanner.hpp"
#include "kls/cli/spec/cli_spec_definition.hpp"
#include <algorithm>
#include <fnmatch.h>
#include <optional>

namespace kls::cli::adapter {

// ARCHITECTURAL NOTE: Deterministic sequential pipeline.
// Operations are applied in a strict order: 
// 1. Filtering (reduces dataset size early, minimizing subsequent work).
// 2. Sorting (orders the reduced set based on primary criteria).
// 3. Reversal (applied last to invert the final state predictably).
// This prevents redundant processing and guarantees consistent output.
void process_output(scanner::ScanOutput& output, const model::ParsedOptions& opts) {
    
    // Phase 1: Filtering (Reduce dataset)
    if (opts.filter.has_value()) {
        definition_options::apply_filter(output, *opts.filter);
    }
    if (opts.min_severity.has_value()) {
        definition_options::apply_min_severity(output, *opts.min_severity);
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
  
    // Phase 2: Sorting (Order the filtered dataset)
    if (opts.sort.has_value()) {
        definition_options::apply_sort(output, *opts.sort);
    }
    if (opts.dirs_first) {
        definition_options::apply_dirs_first(output);
    }
    if (opts.findings_first) {
        definition_options::apply_findings_first(output);
    }
    
    // Phase 3: State inversion (Applied last to guarantee predictable reversal)
    if (opts.reverse) {
        std::ranges::reverse(output.items);
    }
}

} // namespace kls::cli::adapter
