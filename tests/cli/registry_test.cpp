// tests/findings/registry_test.cpp
#include "kls/findings/finding_registry.hpp"
#include <gtest/gtest.h>
#include <algorithm>
#include <vector>

namespace kls::findings::test {

TEST(FindingRegistryTest, TotalCountMatchesDocumentation) {
    // El registro tiene 44 entradas totales.
    EXPECT_EQ(ALL_FINDINGS.size(), 44);
}

TEST(FindingRegistryTest, CapabilityFindingsCount) {
    size_t cap_count = 0;
    for (const auto& f : ALL_FINDINGS) {
        if (f.type_findings == CategoryFindings::capabilities) {
            ++cap_count;
        }
    }
    // Según análisis: CA01, CA25-28, CA30-36 -> 12 capabilities
    EXPECT_EQ(cap_count, 12);
}

TEST(FindingRegistryTest, HealthFindingsCount) {
    size_t health_count = 0;
    for (const auto& f : ALL_FINDINGS) {
        if (f.type_findings == CategoryFindings::health) {
            ++health_count;
        }
    }
    // Según análisis: SU01-24, SG01-05, HWBD, IMMU, APND -> 32 health
    EXPECT_EQ(health_count, 32);
}

TEST(FindingRegistryTest, NoDuplicateIds) {
    std::vector<uint32_t> ids;
    ids.reserve(ALL_FINDINGS.size());
    for (const auto& f : ALL_FINDINGS) {
        ids.push_back(f.id.get_value());
    }
    std::ranges::sort(ids);
    auto last = std::ranges::unique(ids);
    EXPECT_EQ(last.begin(), last.end()) << "Found duplicate finding IDs in registry";
}

} // namespace kls::findings::test
