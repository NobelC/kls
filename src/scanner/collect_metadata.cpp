#include "kls/scanner/collect_metadata.hpp"
#include "kls/audit/audit_entry.hpp"
#include "kls/scanner/scanner.hpp"

namespace kls::scanner {

// ============================================================================
// Trivial conversion from CandidateEntry to AuditItem.
// All metadata was already collected during discovery in a single pass.
// This function performs NO syscalls.
//
// Constructs ObjectIdentity and sets StabilityState
// from the single-pass discovery data.
// ============================================================================
[[nodiscard]] kls::scanner::ScanOutput
collect_metadata(const kls::scanner::DiscoveredOutput &discovered_output) {
  ScanOutput final_output;
  final_output.items.reserve(discovered_output.candidates.size());

  for (const auto &candidate : discovered_output.candidates) {
    kls::auditor::AuditEntry result_entry;

    // BASELINE C-09: Build unified identity from discovery data.
    result_entry.identity.dev_major = candidate.dev_major;
    result_entry.identity.dev_minor = candidate.dev_minor;
    result_entry.identity.inode = candidate.inode;
    result_entry.identity.mount_id = candidate.mount_id;

    // Single-pass collection means identity is verified at discovery time.
    result_entry.stability = kls::auditor::StabilityState::stable;

    // Map all fields from CandidateEntry (no syscalls needed).
    result_entry.name = candidate.name;
    result_entry.full_path = candidate.full_path;
    result_entry.inode = candidate.inode;
    result_entry.size = candidate.size;
    result_entry.mode = candidate.mode;
    result_entry.nlinks = candidate.nlinks;
    result_entry.uid = candidate.uid;
    result_entry.gid = candidate.gid;
    result_entry.mtime = candidate.mtime;
    result_entry.btime = candidate.btime;
    result_entry.type = candidate.type;
    result_entry.extension = candidate.extension;
    result_entry.symlink_target = candidate.symlink_target;

    // Legacy fields for backward compatibility.
    result_entry.dev_major = candidate.dev_major;
    result_entry.dev_minor = candidate.dev_minor;
    result_entry.mount_id = candidate.mount_id;

    final_output.items.push_back({
        .entry = std::move(result_entry),
        .findings = {},
    });
  }

  // Propagate discovery-phase issues.
  if (!discovered_output.issues.empty()) {
    final_output.issues.reserve(final_output.issues.size() +
                                discovered_output.issues.size());
    final_output.issues.insert(final_output.issues.end(),
                               discovered_output.issues.begin(),
                               discovered_output.issues.end());
  }

  // Propagate traversal counters for coverage aggregation.
  final_output.visited_count = discovered_output.visited_count;
  final_output.discovered_count = discovered_output.discovered_count;
  final_output.excluded_count = discovered_output.excluded_count;

  return final_output;
}

} // namespace kls::scanner
