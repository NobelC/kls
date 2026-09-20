#pragma once
#include "kls/detail/Id.hpp"
#include "kls/findings/finding_flags.hpp"
#include <algorithm>
#include <array>
#include <cstdint>
#include <span>

namespace kls::findings {

// ============================================================================
// CAPABILITY FINDINGS (12 entries)
// ============================================================================
constexpr auto ALL_FINDINGS = []() {
  std::array<Finding, 44> arr = {
      {{.message = "File has Linux capabilities assigned",
        .id = kls::detail::ID("CA01"),
        .level = SeverityFindings::Low,
        .type_findings = CategoryFindings::capabilities},
       {.message = "Highly dangerous capability assigned",
        .id = kls::detail::ID("CA25"),
        .level = SeverityFindings::Crit,
        .type_findings = CategoryFindings::capabilities},
       {.message = "Identity manipulation capability assigned",
        .id = kls::detail::ID("CA26"),
        .level = SeverityFindings::Crit,
        .type_findings = CategoryFindings::capabilities},
       {.message = "Network promiscuity capability assigned",
        .id = kls::detail::ID("CA27"),
        .level = SeverityFindings::High,
        .type_findings = CategoryFindings::capabilities},
       {.message = "Invalid or unsupported Linux capability version",
        .id = kls::detail::ID("CA28"),
        .level = SeverityFindings::High,
        .type_findings = CategoryFindings::capabilities},
       {.message = "Filesystem bypass capability assigned",
        .id = kls::detail::ID("CA30"),
        .level = SeverityFindings::Crit,
        .type_findings = CategoryFindings::capabilities},
       {.message = "Ownership manipulation capability assigned",
        .id = kls::detail::ID("CA31"),
        .level = SeverityFindings::High,
        .type_findings = CategoryFindings::capabilities},
       {.message = "CAP_SYS_CHROOT assigned",
        .id = kls::detail::ID("CA32"),
        .level = SeverityFindings::High,
        .type_findings = CategoryFindings::capabilities},
       {.message = "Raw hardware access capability assigned",
        .id = kls::detail::ID("CA33"),
        .level = SeverityFindings::Crit,
        .type_findings = CategoryFindings::capabilities},
       {.message = "Audit subsystem capability assigned",
        .id = kls::detail::ID("CA34"),
        .level = SeverityFindings::Crit,
        .type_findings = CategoryFindings::capabilities},
       {.message = "security.capability xattr present but empty",
        .id = kls::detail::ID("CA35"),
        .level = SeverityFindings::Med,
        .type_findings = CategoryFindings::capabilities},
       {.message = "Non-empty inheritable capability set detected",
        .id = kls::detail::ID("CA36"),
        .level = SeverityFindings::MedLow,
        .type_findings = CategoryFindings::capabilities},
       {.message = "SUkls::detail::ID bit set",
        .id = kls::detail::ID("SU01"),
        .level = SeverityFindings::Med,
        .type_findings = CategoryFindings::health},
       {.message = "SUkls::detail::ID bit set on world-writable file",
        .id = kls::detail::ID("SU02"),
        .level = SeverityFindings::Crit,
        .type_findings = CategoryFindings::health},
       {.message = "SUkls::detail::ID bit set on non-executable file",
        .id = kls::detail::ID("SU03"),
        .level = SeverityFindings::MedLow,
        .type_findings = CategoryFindings::health},
       {.message = "SUkls::detail::ID binary found outside standard system "
                   "directories",
        .id = kls::detail::ID("SU04"),
        .level = SeverityFindings::Crit,
        .type_findings = CategoryFindings::health},
       {.message = "SUkls::detail::ID bit set on file not owned by root",
        .id = kls::detail::ID("SU05"),
        .level = SeverityFindings::High,
        .type_findings = CategoryFindings::health},
       {.message = "SUkls::detail::ID bit set on interpreted script",
        .id = kls::detail::ID("SU06"),
        .level = SeverityFindings::Med,
        .type_findings = CategoryFindings::health},
       {.message = "SUkls::detail::ID binary is world-executable",
        .id = kls::detail::ID("SU07"),
        .level = SeverityFindings::High,
        .type_findings = CategoryFindings::health},
       {.message = "SUkls::detail::ID binary is group-writable",
        .id = kls::detail::ID("SU08"),
        .level = SeverityFindings::High,
        .type_findings = CategoryFindings::health},
       {.message = "SUkls::detail::ID bit set on a symbolic link",
        .id = kls::detail::ID("SU09"),
        .level = SeverityFindings::MedLow,
        .type_findings = CategoryFindings::health},
       {.message = "SUkls::detail::ID bit set on a directory",
        .id = kls::detail::ID("SU10"),
        .level = SeverityFindings::MedLow,
        .type_findings = CategoryFindings::health},
       {.message = "SUkls::detail::ID binary owned by unknown Ukls::detail::ID",
        .id = kls::detail::ID("SU11"),
        .level = SeverityFindings::High,
        .type_findings = CategoryFindings::health},
       {.message = "SUkls::detail::ID binary recently modified",
        .id = kls::detail::ID("SU12"),
        .level = SeverityFindings::High,
        .type_findings = CategoryFindings::health},
       {.message = "SUkls::detail::ID binary future timestamp",
        .id = kls::detail::ID("SU13"),
        .level = SeverityFindings::Crit,
        .type_findings = CategoryFindings::health},
       {.message = "SUkls::detail::ID binary shows timestamp manipulation",
        .id = kls::detail::ID("SU14"),
        .level = SeverityFindings::Crit,
        .type_findings = CategoryFindings::health},
       {.message = "SUkls::detail::ID binary world-readable in sensitive path",
        .id = kls::detail::ID("SU15"),
        .level = SeverityFindings::Med,
        .type_findings = CategoryFindings::health},
       {.message = "SUkls::detail::ID binary ELF magic mismatch",
        .id = kls::detail::ID("SU16"),
        .level = SeverityFindings::Crit,
        .type_findings = CategoryFindings::health},
       {.message = "SUkls::detail::ID binary hardlink count warning",
        .id = kls::detail::ID("SU17"),
        .level = SeverityFindings::Med,
        .type_findings = CategoryFindings::health},
       {.message = "SUkls::detail::ID binary not executable but readable",
        .id = kls::detail::ID("SU18"),
        .level = SeverityFindings::MedLow,
        .type_findings = CategoryFindings::health},
       {.message = "SUkls::detail::ID binary with redundant capabilities",
        .id = kls::detail::ID("SU19"),
        .level = SeverityFindings::MedLow,
        .type_findings = CategoryFindings::health},
       {.message = "SUkls::detail::ID binary in /tmp or /var",
        .id = kls::detail::ID("SU20"),
        .level = SeverityFindings::Crit,
        .type_findings = CategoryFindings::health},
       {.message = "SUkls::detail::ID binary in user home directory",
        .id = kls::detail::ID("SU21"),
        .level = SeverityFindings::Crit,
        .type_findings = CategoryFindings::health},
       {.message = "SUkls::detail::ID binary also carries the sticky bit",
        .id = kls::detail::ID("SU22"),
        .level = SeverityFindings::MedLow,
        .type_findings = CategoryFindings::health},
       {.message = "SUkls::detail::ID binary user no longer exists",
        .id = kls::detail::ID("SU23"),
        .level = SeverityFindings::MedLow,
        .type_findings = CategoryFindings::health},
       {.message = "SUkls::detail::ID binary group no longer exists",
        .id = kls::detail::ID("SU24"),
        .level = SeverityFindings::MedLow,
        .type_findings = CategoryFindings::health},
       {.message = "SGkls::detail::ID bit set",
        .id = kls::detail::ID("SG01"),
        .level = SeverityFindings::Med,
        .type_findings = CategoryFindings::health},
       {.message = "SGkls::detail::ID bit set on world-writable directory",
        .id = kls::detail::ID("SG02"),
        .level = SeverityFindings::High,
        .type_findings = CategoryFindings::health},
       {.message = "SGkls::detail::ID bit set on world-writable file",
        .id = kls::detail::ID("SG03"),
        .level = SeverityFindings::Crit,
        .type_findings = CategoryFindings::health},
       {.message = "SGkls::detail::ID binary writable by its own group",
        .id = kls::detail::ID("SG04"),
        .level = SeverityFindings::High,
        .type_findings = CategoryFindings::health},
       {.message =
            "SGkls::detail::ID binary assigned to unknown Gkls::detail::ID",
        .id = kls::detail::ID("SG05"),
        .level = SeverityFindings::High,
        .type_findings = CategoryFindings::health},
       {.message = "Device node found outside standard /dev directory",
        .id = kls::detail::ID("HWBD"),
        .level = SeverityFindings::Crit,
        .type_findings = CategoryFindings::health},
       {.message = "File is marked as immutable",
        .id = kls::detail::ID("IMMU"),
        .level = SeverityFindings::MedLow,
        .type_findings = CategoryFindings::health},
       {.message = "File is marked as append-only",
        .id = kls::detail::ID("APND"),
        .level = SeverityFindings::MedLow,
        .type_findings = CategoryFindings::health}}};
  std::ranges::sort(arr, [](const Finding &a, const Finding &b) {
    return a.id.get_value() < b.id.get_value();
  });
  return arr;
}();

namespace detail {
constexpr bool compare_finding_id(const Finding &f,
                                  std::uint32_t value) noexcept {
  return f.id.get_value() < value;
}

[[nodiscard]] constexpr const Finding *
get_finding_from_span(std::span<const Finding> registry,
                      const kls::detail::ID &id) noexcept {
  const auto target = id.get_value();
  auto it = std::lower_bound(registry.begin(), registry.end(), target,
                             compare_finding_id);
  if (it != registry.end() && it->id.get_value() == target) {
    return &(*it);
  }
  return nullptr;
}
} // namespace detail

[[nodiscard]] constexpr const Finding *
get_finding(const kls::detail::ID &id) noexcept {
  return detail::get_finding_from_span(ALL_FINDINGS, id);
}

inline SeverityFindings
get_max_level_severity(const std::vector<kls::detail::ID> &id) {
  if (id.empty()) {
    return SeverityFindings::None;
  }

  const kls::detail::ID *current = id.data();
  const kls::detail::ID *end = current + id.size();
  std::underlying_type_t<SeverityFindings> max_level = 0;
  while (current < end) {
    const Finding *ID_INFORMATION = get_finding(*current);
    auto current_level = static_cast<std::underlying_type_t<SeverityFindings>>(
        ID_INFORMATION->level);

    max_level = (current_level > max_level) ? current_level : max_level;

    current++;
  }
  return static_cast<SeverityFindings>(max_level);
}

} // namespace kls::findings
