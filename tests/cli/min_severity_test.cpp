#include <gtest/gtest.h>
#include "kls/scanner/scanner.hpp"
#include "kls/audit/audit_entry.hpp"
#include "kls/detail/parse_severity.hpp"
#include "kls/cli/spec/cli_spec_definition.hpp"
#include "kls/cli/adapter/severity_count.hpp"
#include <vector>

namespace kls::cli::adapter::test {

kls::auditor::AuditEntry make_entry(const std::string& name) {
    kls::auditor::AuditEntry entry;
    entry.name = name;
    entry.full_path = "/test/" + name;
    return entry;
}

scanner::AuditItem make_item(const std::string& name, std::vector<ID> findings) {
    scanner::AuditItem item;
    item.entry = make_entry(name);
    item.findings = std::move(findings);
    return item;
}

// ============================================================================
// Tests para parser_severity
// ============================================================================

TEST(MinSeverityParserTest, ValidSeverities) {
    auto result_low = parser_severity("low");
    ASSERT_TRUE(result_low.has_value());
    EXPECT_EQ(*result_low, findings::SeverityFindings::Low);
    
    auto result_Low = parser_severity("Low");
    ASSERT_TRUE(result_Low.has_value());
    EXPECT_EQ(*result_Low, findings::SeverityFindings::Low);
    
    auto result_LOW = parser_severity("LOW");
    ASSERT_TRUE(result_LOW.has_value());
    EXPECT_EQ(*result_LOW, findings::SeverityFindings::Low);
    
    auto result_medlow = parser_severity("medlow");
    ASSERT_TRUE(result_medlow.has_value());
    EXPECT_EQ(*result_medlow, findings::SeverityFindings::MedLow);
    
    auto result_MedLow = parser_severity("MedLow");
    ASSERT_TRUE(result_MedLow.has_value());
    EXPECT_EQ(*result_MedLow, findings::SeverityFindings::MedLow);
    
    auto result_med = parser_severity("med");
    ASSERT_TRUE(result_med.has_value());
    EXPECT_EQ(*result_med, findings::SeverityFindings::Med);
    
    auto result_Med = parser_severity("Med");
    ASSERT_TRUE(result_Med.has_value());
    EXPECT_EQ(*result_Med, findings::SeverityFindings::Med);
    
    auto result_high = parser_severity("high");
    ASSERT_TRUE(result_high.has_value());
    EXPECT_EQ(*result_high, findings::SeverityFindings::High);
    
    auto result_High = parser_severity("High");
    ASSERT_TRUE(result_High.has_value());
    EXPECT_EQ(*result_High, findings::SeverityFindings::High);
    
    auto result_crit = parser_severity("crit");
    ASSERT_TRUE(result_crit.has_value());
    EXPECT_EQ(*result_crit, findings::SeverityFindings::Crit);
    
    auto result_Crit = parser_severity("Crit");
    ASSERT_TRUE(result_Crit.has_value());
    EXPECT_EQ(*result_Crit, findings::SeverityFindings::Crit);
}

TEST(MinSeverityParserTest, InvalidSeverityReturnsNullopt) {
    EXPECT_EQ(parser_severity("invalid"), std::nullopt);
    EXPECT_EQ(parser_severity("unknown"), std::nullopt);
    EXPECT_EQ(parser_severity(""), std::nullopt);
    EXPECT_EQ(parser_severity("medium"), std::nullopt);
    EXPECT_EQ(parser_severity("critical"), std::nullopt);
}

// ============================================================================
// Tests para apply_min_severity
// ============================================================================

TEST(ApplyMinSeverityTest, FilterLowSeverityFindings) {
    scanner::ScanOutput output;
    output.items.push_back(make_item("test1", {
        ID("CA01"),  // Low
        ID("SU01"),  // Med
        ID("SU02"),  // Crit
    }));

    definition_options::apply_min_severity(output, "med");

    ASSERT_EQ(output.items.size(), 1);
    ASSERT_EQ(output.items[0].findings.size(), 2);
    
    bool has_ca01 = false;
    bool has_su01 = false;
    bool has_su02 = false;
    
    for (const auto& id : output.items[0].findings) {
        if (id == ID("CA01")) {has_ca01 = true;}
        if (id == ID("SU01")) {has_su01 = true;}
        if (id == ID("SU02")) {has_su02 = true;}
    }
    
    EXPECT_FALSE(has_ca01);  
    EXPECT_TRUE(has_su01);  
    EXPECT_TRUE(has_su02);   
}

TEST(ApplyMinSeverityTest, FilterCriticalOnly) {
    scanner::ScanOutput output;
    output.items.push_back(make_item("test1", {
        ID("CA01"),  // Low
        ID("CA36"),  // MedLow
        ID("SU01"),  // Med
        ID("SU05"),  // High
        ID("SU02"),  // Crit
    }));

  definition_options::apply_min_severity(output, "crit");


    ASSERT_EQ(output.items.size(), 1);
    ASSERT_EQ(output.items[0].findings.size(), 1);
    EXPECT_EQ(output.items[0].findings[0], ID("SU02"));
}

TEST(ApplyMinSeverityTest, NoFilteringWithLow) {
    scanner::ScanOutput output;
    output.items.push_back(make_item("test1", {
        ID("CA01"),  // Low
        ID("SU01"),  // Med
        ID("SU02"),  // Crit
    }));

  definition_options::apply_min_severity(output, "low");
    ASSERT_EQ(output.items.size(), 1);
    EXPECT_EQ(output.items[0].findings.size(), 3);
}

TEST(ApplyMinSeverityTest, EmptyFindingsItemRemoved) {
    scanner::ScanOutput output;
    output.items.push_back(make_item("test1", {}));

  definition_options::apply_min_severity(output, "high");
    ASSERT_EQ(output.items.size(), 0);
}

TEST(ApplyMinSeverityTest, AllFindingsFilteredOutRemovesItem) {
    scanner::ScanOutput output;
    output.items.push_back(make_item("test1", {
        ID("CA01"),  // Low
        ID("CA36"),  // MedLow
    }));

  definition_options::apply_min_severity(output, "high");

    ASSERT_EQ(output.items.size(), 0);
}

TEST(ApplyMinSeverityTest, MultipleItemsFilteredIndependently) {
    scanner::ScanOutput output;
    output.items.push_back(make_item("test1", {
        ID("CA01"),  // Low
        ID("SU02"),  // Crit
    }));
    output.items.push_back(make_item("test2", {
        ID("SU01"),  // Med
        ID("SU05"),  // High
    }));
    output.items.push_back(make_item("test3", {
        ID("CA36"),  // MedLow
    }));

  definition_options::apply_min_severity(output, "high");

    ASSERT_EQ(output.items.size(), 2);
    
    bool has_test1 = false;
    bool has_test2 = false;
    for (const auto& item : output.items) {
        if (item.entry.name == "test1") {
            has_test1 = true;
            EXPECT_EQ(item.findings.size(), 1);
            EXPECT_EQ(item.findings[0], ID("SU02"));
        }
        if (item.entry.name == "test2") {
            has_test2 = true;
            EXPECT_EQ(item.findings.size(), 1);
        }
    }
    EXPECT_TRUE(has_test1);
    EXPECT_TRUE(has_test2);
}

TEST(ApplyMinSeverityTest, CaseInsensitiveSeverity) {
    scanner::ScanOutput output;
    output.items.push_back(make_item("test1", {
        ID("CA01"),  // Low
        ID("SU01"),  // Med
    }));

  definition_options::apply_min_severity(output, "MED");

    ASSERT_EQ(output.items.size(), 1);
    ASSERT_EQ(output.items[0].findings.size(), 1);
    EXPECT_EQ(output.items[0].findings[0], ID("SU01"));
}

TEST(ApplyMinSeverityTest, PreserveOrderOfFindings) {
    scanner::ScanOutput output;
    output.items.push_back(make_item("test1", {
        ID("SU02"),  // Crit
        ID("SU05"),  // High
        ID("SU01"),  // Med
    }));

  definition_options::apply_min_severity(output, "med");

    ASSERT_EQ(output.items.size(), 1);
    ASSERT_EQ(output.items[0].findings.size(), 3);
    EXPECT_EQ(output.items[0].findings[0], ID("SU02"));
    EXPECT_EQ(output.items[0].findings[1], ID("SU05"));
    EXPECT_EQ(output.items[0].findings[2], ID("SU01"));
}

TEST(ApplyMinSeverityTest, InvalidSeverityDoesNotFilter) {
    scanner::ScanOutput output;
    output.items.push_back(make_item("test1", {
        ID("CA01"),  // Low
        ID("SU01"),  // Med
    }));

    definition_options::apply_min_severity(output, "invalid");

    ASSERT_EQ(output.items.size(), 1);
    EXPECT_EQ(output.items[0].findings.size(), 2);
}
// ============================================================================
// Tests para SeverityCount::at_or_above()
// ============================================================================

TEST(SeverityCountTest, AtOrAboveWithMixedFindings) {
    kls::cli::adapter::SeverityCount counts;
    counts.low = 2;
    counts.med_low = 3;
    counts.med = 5;
    counts.high = 4;
    counts.crit = 1;
    
    // Total: 2 + 3 + 5 + 4 + 1 = 15
    
    EXPECT_EQ(counts.at_or_above(findings::SeverityFindings::Low), 15);
    EXPECT_EQ(counts.at_or_above(findings::SeverityFindings::MedLow), 13);
    EXPECT_EQ(counts.at_or_above(findings::SeverityFindings::Med), 10);
    EXPECT_EQ(counts.at_or_above(findings::SeverityFindings::High), 5);
    EXPECT_EQ(counts.at_or_above(findings::SeverityFindings::Crit), 1);
}

TEST(SeverityCountTest, AtOrAboveWithEmptyCounts) {
    kls::cli::adapter::SeverityCount counts;
    // Todos los contadores en 0
    
    EXPECT_EQ(counts.at_or_above(findings::SeverityFindings::Low), 0);
    EXPECT_EQ(counts.at_or_above(findings::SeverityFindings::MedLow), 0);
    EXPECT_EQ(counts.at_or_above(findings::SeverityFindings::Med), 0);
    EXPECT_EQ(counts.at_or_above(findings::SeverityFindings::High), 0);
    EXPECT_EQ(counts.at_or_above(findings::SeverityFindings::Crit), 0);
}

TEST(SeverityCountTest, AtOrAboveWithOnlyCrit) {
    kls::cli::adapter::SeverityCount counts;
    counts.crit = 5;
    
    EXPECT_EQ(counts.at_or_above(findings::SeverityFindings::Low), 5);
    EXPECT_EQ(counts.at_or_above(findings::SeverityFindings::MedLow), 5);
    EXPECT_EQ(counts.at_or_above(findings::SeverityFindings::Med), 5);
    EXPECT_EQ(counts.at_or_above(findings::SeverityFindings::High), 5);
    EXPECT_EQ(counts.at_or_above(findings::SeverityFindings::Crit), 5);
}

TEST(SeverityCountTest, AtOrAboveWithOnlyLow) {
    kls::cli::adapter::SeverityCount counts;
    counts.low = 10;
    
    EXPECT_EQ(counts.at_or_above(kls::findings::SeverityFindings::Low), 10);
    EXPECT_EQ(counts.at_or_above(kls::findings::SeverityFindings::MedLow), 0);
    EXPECT_EQ(counts.at_or_above(kls::findings::SeverityFindings::Med), 0);
    EXPECT_EQ(counts.at_or_above(kls::findings::SeverityFindings::High), 0);
    EXPECT_EQ(counts.at_or_above(kls::findings::SeverityFindings::Crit), 0);
}

// ============================================================================
// Tests para count_findings_by_severity()
// ============================================================================

TEST(CountFindingsTest, EmptyScanOutput) {
    scanner::ScanOutput output;
    
    auto counts = kls::cli::adapter::count_findings_by_severity(output);
    
    EXPECT_EQ(counts.low, 0);
    EXPECT_EQ(counts.med_low, 0);
    EXPECT_EQ(counts.med, 0);
    EXPECT_EQ(counts.high, 0);
    EXPECT_EQ(counts.crit, 0);
}

TEST(CountFindingsTest, ItemsWithoutFindings) {
    scanner::ScanOutput output;
    output.items.push_back(make_item("test1", {}));
    output.items.push_back(make_item("test2", {}));
    
    auto counts = kls::cli::adapter::count_findings_by_severity(output);
    
    EXPECT_EQ(counts.low, 0);
    EXPECT_EQ(counts.med_low, 0);
    EXPECT_EQ(counts.med, 0);
    EXPECT_EQ(counts.high, 0);
    EXPECT_EQ(counts.crit, 0);
}

TEST(CountFindingsTest, MixedFindingsAcrossItems) {
    scanner::ScanOutput output;
    output.items.push_back(make_item("test1", {
        ID("CA01"),  // Low
        ID("SU01"),  // Med
    }));
    output.items.push_back(make_item("test2", {
        ID("CA36"),  // MedLow
        ID("SU05"),  // High
        ID("SU02"),  // Crit
    }));
    
    auto counts = kls::cli::adapter::count_findings_by_severity(output);
    
    EXPECT_EQ(counts.low, 1);      // CA01
    EXPECT_EQ(counts.med_low, 1);  // CA36
    EXPECT_EQ(counts.med, 1);      // SU01
    EXPECT_EQ(counts.high, 1);     // SU05
    EXPECT_EQ(counts.crit, 1);     // SU02
}

TEST(CountFindingsTest, MultipleFindingsOfSameSeverity) {
    scanner::ScanOutput output;
    output.items.push_back(make_item("test1", {
        ID("CA01"),  // Low
        ID("SU03"),  // MedLow
        ID("SU09"),  // MedLow
        ID("SU10"),  // MedLow
    }));
    
    auto counts = kls::cli::adapter::count_findings_by_severity(output);
    
    EXPECT_EQ(counts.low, 1);      // CA01
    EXPECT_EQ(counts.med_low, 3);  // SU03, SU09, SU10
    EXPECT_EQ(counts.med, 0);
    EXPECT_EQ(counts.high, 0);
    EXPECT_EQ(counts.crit, 0);
}

TEST(CountFindingsTest, RealWorldScenario) {
    // Simular un escaneo típico con varios SUID binaries
    scanner::ScanOutput output;
    output.items.push_back(make_item("passwd", {
        ID("SU01"),  // Med - SUID bit set
    }));
    output.items.push_back(make_item("sudo", {
        ID("SU01"),  // Med - SUID bit set
        ID("CA26"),  // Crit - CAP_SETUID
    }));
    output.items.push_back(make_item("ping", {
        ID("CA01"),  // Low - capability assigned
    }));
    
    auto counts = kls::cli::adapter::count_findings_by_severity(output);
    
    EXPECT_EQ(counts.low, 1);      // CA01
    EXPECT_EQ(counts.med_low, 0);
    EXPECT_EQ(counts.med, 2);      // 2x SU01
    EXPECT_EQ(counts.high, 0);
    EXPECT_EQ(counts.crit, 1);     // CA26
    
    // Verificar umbrales
    EXPECT_EQ(counts.at_or_above(findings::SeverityFindings::Low), 4);   // todos
    EXPECT_EQ(counts.at_or_above(findings::SeverityFindings::Med), 3);   // med + crit
    EXPECT_EQ(counts.at_or_above(findings::SeverityFindings::High), 1);  // solo crit
    EXPECT_EQ(counts.at_or_above(findings::SeverityFindings::Crit), 1);  // solo crit
}

// ============================================================================
// Tests de integración: --fail-on threshold logic
// ============================================================================

TEST(FailOnThresholdTest, ShouldFailWhenFindingsExist) {
    scanner::ScanOutput output;
    output.items.push_back(make_item("test1", {
        ID("SU01"),  // Med
    }));
    
    auto counts = kls::cli::adapter::count_findings_by_severity(output);
    
    // --fail-on=low: debe fallar (Med >= Low)
    EXPECT_GT(counts.at_or_above(kls::findings::SeverityFindings::Low), 0);
    
    // --fail-on=med: debe fallar (Med >= Med)
    EXPECT_GT(counts.at_or_above(kls::findings::SeverityFindings::Med), 0);
    
    // --fail-on=high: NO debe fallar (Med < High)
    EXPECT_EQ(counts.at_or_above(kls::findings::SeverityFindings::High), 0);
    
    // --fail-on=crit: NO debe fallar (Med < Crit)
    EXPECT_EQ(counts.at_or_above(findings::SeverityFindings::Crit), 0);
}

TEST(FailOnThresholdTest, ShouldNotFailWhenNoFindings) {
    scanner::ScanOutput output;
    output.items.push_back(make_item("test1", {}));
    
    auto counts = kls::cli::adapter::count_findings_by_severity(output);
    
    // Ningún --fail-on debe disparar exit code 5
    EXPECT_EQ(counts.at_or_above(kls::findings::SeverityFindings::Low), 0);
    EXPECT_EQ(counts.at_or_above(kls::findings::SeverityFindings::Med), 0);
    EXPECT_EQ(counts.at_or_above(kls::findings::SeverityFindings::High), 0);
    EXPECT_EQ(counts.at_or_above(kls::findings::SeverityFindings::Crit), 0);
}

TEST(FailOnThresholdTest, OnlyCritShouldTriggerCritThreshold) {
    scanner::ScanOutput output;
    output.items.push_back(make_item("test1", {
        ID("CA26"),  // Crit
    }));
    
    auto counts = kls::cli::adapter::count_findings_by_severity(output);
    
    // Todos los thresholds deben fallar
    EXPECT_GT(counts.at_or_above(kls::findings::SeverityFindings::Low), 0);
    EXPECT_GT(counts.at_or_above(kls::findings::SeverityFindings::MedLow), 0);
    EXPECT_GT(counts.at_or_above(kls::findings::SeverityFindings::Med), 0);
    EXPECT_GT(counts.at_or_above(kls::findings::SeverityFindings::High), 0);
    EXPECT_GT(counts.at_or_above(kls::findings::SeverityFindings::Crit), 0);
}

} // namespace kls::cli::adapter::test
