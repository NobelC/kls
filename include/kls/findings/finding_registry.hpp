#pragma once
#include "kls/findings/finding_flags.hpp"
#include "kls/detail/Id.hpp"
#include <array>
#include <algorithm>
#include <cstdint>
#include <span> // <-- Necesario para el refactor de DRY

namespace kls::findings {

// ============================================================================
// CAPABILITY FINDINGS (12 entries)
// ============================================================================
constexpr auto CAPABILITY_FINDINGS = []() {
    std::array<Finding, 12> arr = {{
        {"File has Linux capabilities assigned", ID("CA01"), 1, CategoryFindings::capabilities},
        {"Highly dangerous capability assigned (CAP_SYS_ADMIN/CAP_SYS_PTRACE/CAP_SYS_MODULE)", ID("CA25"), 5, CategoryFindings::capabilities},
        {"Identity manipulation capability assigned (CAP_SETUID/CAP_SETGID/CAP_CHOWN)", ID("CA26"), 5, CategoryFindings::capabilities},
        {"Network promiscuity capability assigned (CAP_NET_RAW/CAP_NET_ADMIN)", ID("CA27"), 4, CategoryFindings::capabilities},
        {"Invalid or unsupported Linux capability version in xattr", ID("CA28"), 4, CategoryFindings::capabilities},
        {"Filesystem bypass capability assigned (CAP_DAC_OVERRIDE or CAP_DAC_READ_SEARCH): all file permission checks bypassed", ID("CA30"), 5, CategoryFindings::capabilities},
        {"Ownership manipulation capability assigned (CAP_FOWNER or CAP_FSETID): can modify permissions on files not owned by the process", ID("CA31"), 4, CategoryFindings::capabilities},
        {"CAP_SYS_CHROOT assigned: process can change root directory, classic container escape vector", ID("CA32"), 4, CategoryFindings::capabilities},
        {"Raw hardware access capability assigned (CAP_SYS_RAWIO): direct access to I/O ports and physical memory", ID("CA33"), 5, CategoryFindings::capabilities},
        {"Audit subsystem capability assigned (CAP_AUDIT_WRITE or CAP_AUDIT_CONTROL): binary can suppress or manipulate audit logs", ID("CA34"), 5, CategoryFindings::capabilities},
        {"security.capability xattr present but effective and permitted capability sets are empty", ID("CA35"), 3, CategoryFindings::capabilities},
        {"Non-empty inheritable capability set detected: may interact unexpectedly with ambient capabilities", ID("CA36"), 2, CategoryFindings::capabilities}
    }};
    // Ordenamiento en tiempo de compilación
    std::ranges::sort(arr, [](const Finding& a, const Finding& b) {
        return a.id.get_value() < b.id.get_value();
    });
    return arr;
}();

// ============================================================================
// HEALTH FINDINGS (32 entries)
// ============================================================================
constexpr auto HEALTH_FINDINGS = []() {
    std::array<Finding, 32> arr = {{
        {"SUID bit set", ID("SU01"), 3, CategoryFindings::health},
        {"SUID bit set on world-writable file", ID("SU02"), 5, CategoryFindings::health},
        {"SUID bit set on non-executable file", ID("SU03"), 2, CategoryFindings::health},
        {"SUID binary found outside standard system directories", ID("SU04"), 5, CategoryFindings::health},
        {"SUID bit set on file not owned by root", ID("SU05"), 4, CategoryFindings::health},
        {"SUID bit set on interpreted script", ID("SU06"), 3, CategoryFindings::health},
        {"SUID binary is world-executable", ID("SU07"), 4, CategoryFindings::health},
        {"SUID binary is group-writable", ID("SU08"), 4, CategoryFindings::health},
        {"SUID bit set on a symbolic link", ID("SU09"), 2, CategoryFindings::health},
        {"SUID bit set on a directory", ID("SU10"), 2, CategoryFindings::health},
        {"SUID binary owned by unknown UID", ID("SU11"), 4, CategoryFindings::health},
        {"SUID binary recently modified", ID("SU12"), 4, CategoryFindings::health},
        {"SUID binary future timestamp", ID("SU13"), 5, CategoryFindings::health},
        {"SUID binary shows timestamp manipulation", ID("SU14"), 5, CategoryFindings::health},
        {"SUID binary world-readable in sensitive path", ID("SU15"), 3, CategoryFindings::health},
        {"SUID binary ELF magic mismatch", ID("SU16"), 5, CategoryFindings::health},
        {"SUID binary hardlink count warning", ID("SU17"), 3, CategoryFindings::health},
        {"SUID binary not executable but readable", ID("SU18"), 2, CategoryFindings::health},
        {"SUID binary with redundant capabilities", ID("SU19"), 2, CategoryFindings::health},
        {"SUID binary in /tmp or /var", ID("SU20"), 5, CategoryFindings::health},
        {"SUID binary in user home directory", ID("SU21"), 5, CategoryFindings::health},
        {"SUID binary also carries the sticky bit", ID("SU22"), 2, CategoryFindings::health},
        {"SUID binary user no longer exists", ID("SU23"), 2, CategoryFindings::health},
        {"SUID binary group no longer exists", ID("SU24"), 2, CategoryFindings::health},
        {"SGID bit set", ID("SG01"), 3, CategoryFindings::health},
        {"SGID bit set on world-writable directory", ID("SG02"), 4, CategoryFindings::health},
        {"SGID bit set on world-writable file", ID("SG03"), 5, CategoryFindings::health},
        {"SGID binary writable by its own group", ID("SG04"), 4, CategoryFindings::health},
        {"SGID binary assigned to unknown GID", ID("SG05"), 4, CategoryFindings::health},
        {"Device node found outside standard /dev directory", ID("HWBD"), 5, CategoryFindings::health},
        {"File is marked as immutable (cannot be modified, deleted, or renamed)", ID("IMMU"), 2, CategoryFindings::health},
        {"File is marked as append-only (can only be written to by appending data)", ID("APND"), 2, CategoryFindings::health}
    }};
    std::ranges::sort(arr, [](const Finding& a, const Finding& b) {
        return a.id.get_value() < b.id.get_value();
    });

    return arr;
}();

// ============================================================================
// LOOKUP FUNCTIONS — O(log n) via std::lower_bound
// ============================================================================

namespace detail {
    constexpr bool compare_finding_id(const Finding& f, std::uint32_t value) noexcept {
        return f.id.get_value() < value;
    }

    // DRY: Template base para buscar en cualquier span de Findings
    [[nodiscard]] constexpr const Finding* get_finding_from_span(std::span<const Finding> registry, const ID& id) noexcept {
        const auto target = id.get_value();
        auto it = std::lower_bound(
            registry.begin(),
            registry.end(),
            target,
            compare_finding_id
        );
        if (it != registry.end() && it->id.get_value() == target) {
            return &(*it);
        }
        return nullptr;
    }
}

[[nodiscard]] constexpr const Finding* get_capability_flag(const ID& id) noexcept {
    return detail::get_finding_from_span(CAPABILITY_FINDINGS, id);
}

[[nodiscard]] constexpr const Finding* get_health_flag(const ID& id) noexcept {
    return detail::get_finding_from_span(HEALTH_FINDINGS, id);
}

} // namespace kls::findings
