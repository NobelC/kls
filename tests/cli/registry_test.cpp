#include "kls/findings/finding_registry.hpp"
#include <gtest/gtest.h>
#include <algorithm>
#include <vector>

namespace kls::findings::test {

// ARCHITECTURAL NOTE: Registry integrity.
// Ensures the compiled registry matches the documented baseline count.
// Any deviation indicates an undocumented addition or accidental removal.
TEST(FindingRegistryTest, TotalCountMatchesDocumentation) {
  EXPECT_EQ(ALL_FINDINGS.size(), 44);
}

// Validates the exact count of capability-related findings.
// Prevents silent drift in the security detection surface.
TEST(FindingRegistryTest, CapabilityFindingsCount) {
  size_t cap_count = 0;
  for (const auto& f : ALL_FINDINGS) {
    if (f.type_findings == CategoryFindings::capabilities) {
      ++cap_count;
    }
  }
  // CA01, CA25-28, CA30-36 -> 12 capabilities
  EXPECT_EQ(cap_count, 12);
}

// Validates the exact count of health-related findings.
// Ensures SUID/SGID, timestamp, and filesystem anomaly detectors remain intact.
TEST(FindingRegistryTest, HealthFindingsCount) {
  size_t health_count = 0;
  for (const auto& f : ALL_FINDINGS) {
    if (f.type_findings == CategoryFindings::health) {
      ++health_count;
    }
  }
  // SU01-24, SG01-05, HWBD, IMMU, APND -> 32 health
  EXPECT_EQ(health_count, 32);
}

// ARCHITECTURAL NOTE: Unique ID enforcement.
// Duplicate IDs would break the binary search lookup in `get_finding()`.
// This test guarantees that every finding has a distinct, collision-free identifier.
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
