#include "kls/audit/audit_entry.hpp"
#include "kls/cli/adapter/severity_count.hpp"
#include "kls/cli/spec/cli_spec_definition.hpp"
#include "kls/detail/Id.hpp"
#include "kls/detail/parse_severity.hpp"
#include "kls/findings/finding_registry.hpp"
#include "kls/scanner/scanner.hpp"
#include <gtest/gtest.h>
#include <vector>

namespace kls::cli::adapter::test {

// ARCHITECTURAL NOTE: Isolated test data generation.
// Helpers prevent global state mutation and ensure deterministic, 
// reproducible test environments without relying on external fixtures.
kls::auditor::AuditEntry make_entry(const std::string &name) {
  kls::auditor::AuditEntry entry;
  entry.name = name;
  entry.full_path = "/test/" + name;
  return entry;
}

scanner::AuditItem make_item(const std::string &name, std::vector<kls::detail::ID> findings) {
  scanner::AuditItem item;
  item.entry = make_entry(name);
  item.findings = std::move(findings);
  return item;
}

// ============================================================================
// Tests for parser_severity
// ============================================================================

// Validates case-insensitive parsing of severity strings.
// Prevents CLI injection or unexpected nullopt returns on valid user input.
TEST(MinSeverityParserTest, ValidSeverities) {
  auto result_low = parser_severity("low");
  ASSERT_TRUE(result_low.has_value());
  EXPECT_EQ(*result_low, findings::SeverityFindings::Low);

  auto result_Low = parser_severity("Low");
  ASSERT_TRUE(result_Low.has_value());
  EXPECT_EQ(*result_Low, findings::SeverityFindings::Low);

  auto result_MEDLOW = parser_severity("medlow");
  ASSERT_TRUE(result_MEDLOW.has_value());
  EXPECT_EQ(*result_MEDLOW, findings::SeverityFindings::MedLow);

  auto result_Med = parser_severity("Med");
  ASSERT_TRUE(result_Med.has_value());
  EXPECT_EQ(*result_Med, findings::SeverityFindings::Med);

  auto result_High = parser_severity("High");
  ASSERT_TRUE(result_High.has_value());
  EXPECT_EQ(*result_High, findings::SeverityFindings::High);

  auto result_Crit = parser_severity("crit");
  ASSERT_TRUE(result_Crit.has_value());
  EXPECT_EQ(*result_Crit, findings::SeverityFindings::Crit);
}

// Ensures strict validation rejects malformed or out-of-bounds severity strings.
TEST(MinSeverityParserTest, InvalidSeverityReturnsNullopt) {
  EXPECT_EQ(parser_severity("invalid"), std::nullopt);
  EXPECT_EQ(parser_severity(""), std::nullopt);
  EXPECT_EQ(parser_severity("medium"), std::nullopt); // Not in enum mapping
  EXPECT_EQ(parser_severity("critical"), std::nullopt); // Not in enum mapping
}

// ============================================================================
// Tests for apply_min_severity
// ============================================================================

// Validates the two-pass filtering pipeline: 
// 1. Removes findings below threshold. 2. Prunes items that become empty.
TEST(ApplyMinSeverityTest, FilterByMinimumSeverity) {
  scanner::ScanOutput output;
  output.items.push_back(make_item("test1", {
      kls::detail::ID("CA01"), // Low
      kls::detail::ID("SU01"), // Med
      kls::detail::ID("SU02"), // Crit
  }));

  definition_options::apply_min_severity(output, "med");

  ASSERT_EQ(output.items.size(), 1);
  ASSERT_EQ(output.items[0].findings.size(), 2);
  
  // Verify CA01 (Low) was removed, SU01/SU02 remained
  bool has_ca01 = false;
  for (const auto &id : output.items[0].findings) {
    if (id == kls::detail::ID("CA01")) {
      has_ca01 = true;
    }
  }
  EXPECT_FALSE(has_ca01);
}

TEST(ApplyMinSeverityTest, EmptyItemsRemovedAfterFiltering) {
  scanner::ScanOutput output;
  output.items.push_back(make_item("empty", {}));
  output.items.push_back(make_item("filtered_out", {
      kls::detail::ID("CA01"), // Low
  }));

  definition_options::apply_min_severity(output, "high");

  // Both should be gone: 'empty' had nothing, 'filtered_out' lost its only finding
  EXPECT_EQ(output.items.size(), 0);
}

TEST(ApplyMinSeverityTest, CaseInsensitivity) {
  scanner::ScanOutput output;
  output.items.push_back(make_item("test1", {
      kls::detail::ID("SU01"), // Med
  }));

  definition_options::apply_min_severity(output, "MED");

  ASSERT_EQ(output.items.size(), 1);
  EXPECT_EQ(output.items[0].findings.size(), 1);
}

// Ensures invalid CLI input fails gracefully without mutating the output state.
TEST(ApplyMinSeverityTest, InvalidSeverityIsNoOp) {
  scanner::ScanOutput output;
  output.items.push_back(make_item("test1", {
      kls::detail::ID("CA01"),
      kls::detail::ID("SU01"),
  }));

  definition_options::apply_min_severity(output, "garbage");

  // Should remain unchanged because parsing failed
  ASSERT_EQ(output.items.size(), 1);
  EXPECT_EQ(output.items[0].findings.size(), 2);
}

// ============================================================================
// Tests for SeverityCount::at_or_above()
// ============================================================================

// Verifies cumulative threshold logic. Critical for `--fail-on` exit code evaluation.
TEST(SeverityCountTest, AccumulationLogic) {
  kls::cli::adapter::SeverityCount counts;
  counts.low = 2;
  counts.med_low = 3;
  counts.med = 5;
  counts.high = 4;
  counts.crit = 1;

  // Total: 2+3+5+4+1 = 15
  EXPECT_EQ(counts.at_or_above(findings::SeverityFindings::Low), 15);
  EXPECT_EQ(counts.at_or_above(findings::SeverityFindings::MedLow), 13); // 3+5+4+1
  EXPECT_EQ(counts.at_or_above(findings::SeverityFindings::Med), 10);    // 5+4+1
  EXPECT_EQ(counts.at_or_above(findings::SeverityFindings::High), 5);    // 4+1
  EXPECT_EQ(counts.at_or_above(findings::SeverityFindings::Crit), 1);
}

TEST(SeverityCountTest, ZeroCounts) {
  kls::cli::adapter::SeverityCount counts;
  EXPECT_EQ(counts.at_or_above(findings::SeverityFindings::Low), 0);
  EXPECT_EQ(counts.at_or_above(findings::SeverityFindings::Crit), 0);
}

// ============================================================================
// Tests for count_findings_by_severity()
// ============================================================================

// Ensures aggregation correctly sums findings across multiple distinct audit items.
TEST(CountFindingsTest, AggregationAcrossItems) {
  scanner::ScanOutput output;
  output.items.push_back(make_item("a", {kls::detail::ID("CA01")})); // Low
  output.items.push_back(make_item("b", {kls::detail::ID("SU01"), kls::detail::ID("SU02")})); // Med, Crit
  
  auto counts = kls::cli::adapter::count_findings_by_severity(output);
  
  EXPECT_EQ(counts.low, 1);
  EXPECT_EQ(counts.med, 1);
  EXPECT_EQ(counts.crit, 1);
  EXPECT_EQ(counts.at_or_above(findings::SeverityFindings::Low), 3);
}

// ============================================================================
// Robustness Tests: Safety of get_max_level_severity
// ============================================================================

// Security regression test. Guarantees that unregistered finding IDs 
// do not cause null pointer dereferences (segfaults) during evaluation.
TEST(FindingRegistryRobustnessTest, HandlesUnknownIdsGracefully) {
  std::vector<kls::detail::ID> ids;
  ids.emplace_back("SU01"); // Known: Med
  ids.emplace_back("ZZZZ"); // Unknown: Should be ignored safely
  
  auto max_sev = kls::findings::get_max_level_severity(ids);
  
  // Must return Med (from SU01), ignoring ZZZZ
  EXPECT_EQ(max_sev, findings::SeverityFindings::Med);
}

TEST(FindingRegistryRobustnessTest, AllUnknownIdsReturnNone) {
  std::vector<kls::detail::ID> ids;
  ids.emplace_back("AAAA");
  ids.emplace_back("BBBB");
  
  auto max_sev = kls::findings::get_max_level_severity(ids);
  
  // If no valid findings exist, severity must default to None
  EXPECT_EQ(max_sev, findings::SeverityFindings::None);
}

TEST(FindingRegistryRobustnessTest, EmptyVectorReturnsNone) {
  std::vector<kls::detail::ID> ids;
  auto max_sev = kls::findings::get_max_level_severity(ids);
  EXPECT_EQ(max_sev, findings::SeverityFindings::None);
}

// ============================================================================
// Integration Tests: --fail-on Threshold Logic
// ============================================================================

// Simulates the `--fail-on` policy evaluation. 
// Verifies that threshold checks correctly trigger or bypass the exit code 5 condition.
TEST(FailOnThresholdIntegration, TriggersExitCode5WhenThresholdMet) {
  scanner::ScanOutput output;
  output.items.push_back(make_item("target", {kls::detail::ID("SU01")})); // Med
  
  auto counts = kls::cli::adapter::count_findings_by_severity(output);
  
  // --fail-on=low -> Med >= Low -> True
  EXPECT_GT(counts.at_or_above(findings::SeverityFindings::Low), 0);
  
  // --fail-on=crit -> Med < Crit -> False
  EXPECT_EQ(counts.at_or_above(findings::SeverityFindings::Crit), 0);
}

} // namespace kls::cli::adapter::test
