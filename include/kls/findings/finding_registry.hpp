#pragma once
#include "kls/findings/finding_flags.hpp"
#include "kls/detail/Id.hpp"
#include <array>
#include <algorithm>
#include <span>
#include <cstdint>

namespace kls::findings {

// ============================================================================
// CAPABILITY FINDINGS (12 entries)
// ============================================================================
constexpr auto ALL_FINDINGS = []() {
    std::array<Finding, 44> arr = {{
        {.message = "File has Linux capabilities assigned", .id = ID("CA01"), .level = SeverityFindings::Low, .type_findings = CategoryFindings::capabilities},
        {.message = "Highly dangerous capability assigned", .id = ID("CA25"), .level = SeverityFindings::Crit, .type_findings = CategoryFindings::capabilities},
        {.message = "Identity manipulation capability assigned", .id = ID("CA26"), .level = SeverityFindings::Crit, .type_findings = CategoryFindings::capabilities},
        {.message = "Network promiscuity capability assigned", .id = ID("CA27"), .level = SeverityFindings::High, .type_findings = CategoryFindings::capabilities},
        {.message = "Invalid or unsupported Linux capability version", .id = ID("CA28"), .level = SeverityFindings::High, .type_findings = CategoryFindings::capabilities},
        {.message = "Filesystem bypass capability assigned", .id = ID("CA30"), .level = SeverityFindings::Crit, .type_findings = CategoryFindings::capabilities},
        {.message = "Ownership manipulation capability assigned", .id = ID("CA31"), .level = SeverityFindings::High, .type_findings = CategoryFindings::capabilities},
        {.message = "CAP_SYS_CHROOT assigned", .id = ID("CA32"), .level = SeverityFindings::High, .type_findings = CategoryFindings::capabilities},
        {.message = "Raw hardware access capability assigned", .id = ID("CA33"), .level = SeverityFindings::Crit, .type_findings = CategoryFindings::capabilities},
        {.message = "Audit subsystem capability assigned", .id = ID("CA34"), .level = SeverityFindings::Crit, .type_findings = CategoryFindings::capabilities},
        {.message = "security.capability xattr present but empty", .id = ID("CA35"), .level = SeverityFindings::Med, .type_findings = CategoryFindings::capabilities},
        {.message = "Non-empty inheritable capability set detected", .id = ID("CA36"), .level = SeverityFindings::MedLow, .type_findings = CategoryFindings::capabilities},
        {.message = "SUID bit set", .id = ID("SU01"), .level = SeverityFindings::Med, .type_findings = CategoryFindings::health},
        {.message = "SUID bit set on world-writable file", .id = ID("SU02"), .level = SeverityFindings::Crit, .type_findings = CategoryFindings::health},
        {.message = "SUID bit set on non-executable file", .id = ID("SU03"), .level = SeverityFindings::MedLow, .type_findings = CategoryFindings::health},
        {.message = "SUID binary found outside standard system directories", .id = ID("SU04"), .level = SeverityFindings::Crit, .type_findings = CategoryFindings::health},
        {.message = "SUID bit set on file not owned by root", .id = ID("SU05"), .level = SeverityFindings::High, .type_findings = CategoryFindings::health},
        {.message = "SUID bit set on interpreted script", .id = ID("SU06"), .level = SeverityFindings::Med, .type_findings = CategoryFindings::health},
        {.message = "SUID binary is world-executable", .id = ID("SU07"), .level = SeverityFindings::High, .type_findings = CategoryFindings::health},
        {.message = "SUID binary is group-writable", .id = ID("SU08"), .level = SeverityFindings::High, .type_findings = CategoryFindings::health},
        {.message = "SUID bit set on a symbolic link", .id = ID("SU09"), .level = SeverityFindings::MedLow, .type_findings = CategoryFindings::health},
        {.message = "SUID bit set on a directory", .id = ID("SU10"), .level = SeverityFindings::MedLow, .type_findings = CategoryFindings::health},
        {.message = "SUID binary owned by unknown UID", .id = ID("SU11"), .level = SeverityFindings::High, .type_findings = CategoryFindings::health},
        {.message = "SUID binary recently modified", .id = ID("SU12"), .level = SeverityFindings::High, .type_findings = CategoryFindings::health},
        {.message = "SUID binary future timestamp", .id = ID("SU13"), .level = SeverityFindings::Crit, .type_findings = CategoryFindings::health},
        {.message = "SUID binary shows timestamp manipulation", .id = ID("SU14"), .level = SeverityFindings::Crit, .type_findings = CategoryFindings::health},
        {.message = "SUID binary world-readable in sensitive path", .id = ID("SU15"), .level = SeverityFindings::Med, .type_findings = CategoryFindings::health},
        {.message = "SUID binary ELF magic mismatch", .id = ID("SU16"), .level = SeverityFindings::Crit, .type_findings = CategoryFindings::health},
        {.message = "SUID binary hardlink count warning", .id = ID("SU17"), .level = SeverityFindings::Med, .type_findings = CategoryFindings::health},
        {.message = "SUID binary not executable but readable", .id = ID("SU18"), .level = SeverityFindings::MedLow, .type_findings = CategoryFindings::health},
        {.message = "SUID binary with redundant capabilities", .id = ID("SU19"), .level = SeverityFindings::MedLow, .type_findings = CategoryFindings::health},
        {.message = "SUID binary in /tmp or /var", .id = ID("SU20"), .level = SeverityFindings::Crit, .type_findings = CategoryFindings::health},
        {.message = "SUID binary in user home directory", .id = ID("SU21"), .level = SeverityFindings::Crit, .type_findings = CategoryFindings::health},
        {.message = "SUID binary also carries the sticky bit", .id = ID("SU22"), .level = SeverityFindings::MedLow, .type_findings = CategoryFindings::health},
        {.message = "SUID binary user no longer exists", .id = ID("SU23"), .level = SeverityFindings::MedLow, .type_findings = CategoryFindings::health},
        {.message = "SUID binary group no longer exists", .id = ID("SU24"), .level = SeverityFindings::MedLow, .type_findings = CategoryFindings::health},
        {.message = "SGID bit set", .id = ID("SG01"), .level = SeverityFindings::Med, .type_findings = CategoryFindings::health},
        {.message = "SGID bit set on world-writable directory", .id = ID("SG02"), .level = SeverityFindings::High, .type_findings = CategoryFindings::health},
        {.message = "SGID bit set on world-writable file", .id = ID("SG03"), .level = SeverityFindings::Crit, .type_findings = CategoryFindings::health},
        {.message = "SGID binary writable by its own group", .id = ID("SG04"), .level = SeverityFindings::High, .type_findings = CategoryFindings::health},
        {.message = "SGID binary assigned to unknown GID", .id = ID("SG05"), .level = SeverityFindings::High, .type_findings = CategoryFindings::health},
        {.message = "Device node found outside standard /dev directory", .id = ID("HWBD"), .level = SeverityFindings::Crit, .type_findings = CategoryFindings::health},
        {.message = "File is marked as immutable", .id = ID("IMMU"), .level = SeverityFindings::MedLow, .type_findings = CategoryFindings::health},
        {.message = "File is marked as append-only", .id = ID("APND"), .level = SeverityFindings::MedLow, .type_findings = CategoryFindings::health}
    }};
    std::ranges::sort(arr, [](const Finding& a, const Finding& b) {
        return a.id.get_value() < b.id.get_value();
    });
    return arr;
}();

namespace detail {
    constexpr bool compare_finding_id(const Finding& f, std::uint32_t value) noexcept {
        return f.id.get_value() < value;
    }

    [[nodiscard]] constexpr const Finding* get_finding_from_span(std::span<const Finding> registry, const ID& id) noexcept {
        const auto target = id.get_value();
        auto it = std::lower_bound(registry.begin(), registry.end(), target, compare_finding_id);
        if (it != registry.end() && it->id.get_value() == target) {
            return &(*it);
        }
        return nullptr;
    }
}

[[nodiscard]] constexpr const Finding* get_finding(const ID& id) noexcept {
    return detail::get_finding_from_span(ALL_FINDINGS, id);
}

} // namespace kls::findings
