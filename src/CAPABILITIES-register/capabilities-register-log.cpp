#include "capabilities-register.hpp"

void CreatedCapabilityFlags() {
    auto type = kls::findings::CategoryFindings::capabilities;
    // --- CAPABILITIES: DIRECT ESCALATION RISK / LAX PERMISSIONS ---
    GeneralCapabilityLog({.message = "File has Linux capabilities assigned", .id = ID("CA01"), .level = 1, .type_findings = type  });
    GeneralCapabilityLog({.message = "Highly dangerous capability assigned (CAP_SYS_ADMIN/CAP_SYS_PTRACE/CAP_SYS_MODULE)", .id = ID("CA25"), .level = 5, .type_findings = type });
    GeneralCapabilityLog({.message = "Identity manipulation capability assigned (CAP_SETUID/CAP_SETGID/CAP_CHOWN)", .id = ID("CA26"), .level = 5, .type_findings = type });
    GeneralCapabilityLog({.message = "Network promiscuity capability assigned (CAP_NET_RAW/CAP_NET_ADMIN)", .id = ID("CA27"), .level = 4, .type_findings = type });
    GeneralCapabilityLog({.message = "Invalid or unsupported Linux capability version in xattr", .id = ID("CA28"), .level = 4, .type_findings = type });
    GeneralCapabilityLog({.message = "Filesystem bypass capability assgined (CAP_DAC_OVERRIDE or CAP_DAC_READ_SEARCH): all file permission checks bypassed", .id = ID("CA30"), .level = 5, .type_findings = type });
    GeneralCapabilityLog({.message = "Ownership manipulation capability assigned (CAP_FOWNER or CAP_FSETID): can modify permissions on files not owned by the process", .id = ID("CA31"), .level = 4, .type_findings = type });
    GeneralCapabilityLog({.message = "CAP_SYS_CHROOT assigned: process can change root directory, classic container escape vector", .id = ID("CA32"), .level = 4, .type_findings = type });
    GeneralCapabilityLog({.message = "Raw hardware access capability assigned (CAP_SYS_RAWIO): direct access to I/O ports and physical memory", .id = ID("CA33"), .level = 5, .type_findings = type });
    GeneralCapabilityLog({.message = "Audit subsystem capability assigned (CAP_AUDIT_WRITE or CAP_AUDIT_CONTROL): binary can suppress or manipulate audit logs", .id = ID("CA34"), .level = 5, .type_findings = type });
    GeneralCapabilityLog({.message = "security.capability xattr present but effective and permitted capability sets are empty", .id = ID("CA35"), .level = 3, .type_findings = type });
    GeneralCapabilityLog({.message = "Non-empty inheritable capability set detected: may interact unexpectedly with ambient capabilities", .id = ID("CA36"), .level = 2, .type_findings = type });
}
