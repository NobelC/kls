#pragma once
#include "kls/filesystem/file_type.hpp"
#include <cstdint>
#include <ctime>
#include <optional>
#include <string>
#include <sys/types.h>

namespace kls::auditor {

// ============================================================================
// complete object identity for TOCTOU defense.
// A pathname is not a stable identity. Device + inode + mount_id uniquely
// identify an object across operations, preventing evidence from being
// combined across different filesystem objects.
// ============================================================================
struct ObjectIdentity {
  std::uint64_t dev_major = 0;
  std::uint64_t dev_minor = 0;
  std::uint64_t inode = 0;
  std::optional<std::uint64_t> mount_id = std::nullopt;

  // Identity comparison for revalidation.
  // Returns true if all captured fields match. Fields that were not
  // captured (e.g., mount_id on older kernels) are skipped.
  [[nodiscard]] constexpr bool
  matches(const ObjectIdentity &other) const noexcept {
    if (dev_major != other.dev_major)
      return false;
    if (dev_minor != other.dev_minor)
      return false;
    if (inode != other.inode)
      return false;
    // Only compare mount_id if both sides captured it.
    if (mount_id.has_value() && other.mount_id.has_value()) {
      if (*mount_id != *other.mount_id)
        return false;
    }
    return true;
  }
};

// ============================================================================
// Stability state for multi-step analysis.
// Analyzers that perform multiple operations on an object must revalidate
// identity between steps. If identity changed, the object is marked unstable
// and no normal finding should be emitted from mixed evidence.
// ============================================================================
enum class StabilityState : std::uint8_t {
  stable,   // Identity verified consistent across all operations
  unstable, // Identity changed between operations
  unknown,  // Identity could not be fully verified
};

struct AuditEntry {
  // Unified identity replaces scattered dev/inode fields.
  ObjectIdentity identity;
  StabilityState stability = StabilityState::unknown;

  // Legacy fields kept for backward compatibility with analyzers/renderers.
  // These mirror identity fields and will be removed once all consumers
  // migrate to ObjectIdentity.
  ino_t inode = 0;
  std::uint64_t size = 0;
  mode_t mode = 0;
  nlink_t nlinks = 0;
  uid_t uid = 0;
  gid_t gid = 0;
  filesystem::FileType type = filesystem::FileType::unknown;
  time_t mtime = 0;
  time_t btime = 0;
  std::string name;
  std::string full_path;
  std::optional<std::string> symlink_target = std::nullopt;
  std::string extension;

  // Mount identity (kept for backward compatibility).
  std::uint32_t dev_major = 0;
  std::uint32_t dev_minor = 0;
  std::optional<std::uint64_t> mount_id = std::nullopt;
};

} // namespace kls::auditor
