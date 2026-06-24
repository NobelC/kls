#include "capabilities-register.hpp"
#include "option/option-raw-metadata.hpp"

void CreatedHealthFlags() {

    // --- CAPABILITIES: RIESGO DE ESCALADA DIRECTA / PERMISOS LAXOS ---
    GeneralCapabilityLog({.message = "File has Linux capabilities assigned", .id = ID("CAP01"), .level = 1});
    GeneralCapabilityLog({.message = "File with capabilities is world-writable", .id = ID("CAP02"), .level = 5});
    GeneralCapabilityLog({.message = "File with capabilities is non-executable", .id = ID("CAP03"), .level = 2});

    // --- CAPABILITIES: UBICACIÓN Y ENTRENAMIENTO DE ARCHIVOS ---
    GeneralCapabilityLog({.message = "Capability-enabled binary found outside standard system directories", .id = ID("CAP04"), .level = 4});
    GeneralCapabilityLog({.message = "File with capabilities not owned by root", .id = ID("CAP05"), .level = 3});
    GeneralCapabilityLog({.message = "Linux capabilities set on interpreted script", .id = ID("CAP06"), .level = 3});
    GeneralCapabilityLog({.message = "Capability-enabled binary is world-executable", .id = ID("CAP07"), .level = 4});
    GeneralCapabilityLog({.message = "Capability-enabled binary is group-writable", .id = ID("CAP08"), .level = 4});
    
    // --- CAPABILITIES: INTEGRIDAD DEL SISTEMA DE ARCHIVOS Y ANOMALÍAS ---


    GeneralCapabilityLog({.message = "Capability-enabled binary owned by unknown UID", .id = ID("CAP11"), .level = 4});
    GeneralCapabilityLog({.message = "Capability-enabled binary recently modified", .id = ID("CAP12"), .level = 4});
    GeneralCapabilityLog({.message = "Capability-enabled binary future timestamp", .id = ID("CAP13"), .level = 5});
    GeneralCapabilityLog({.message = "Capability-enabled binary shows timestamp manipulation", .id = ID("CAP14"), .level = 5});
    GeneralCapabilityLog({.message = "Capability-enabled binary world-readable in sensitive path", .id = ID("CAP15"), .level = 3});
    
    // --- CAPABILITIES: PARSING Y CORRUPCIÓN DEL ATRIBUTO EXTENDIDO ---
    GeneralCapabilityLog({.message = "Capability-enabled binary ELF magic mismatch", .id = ID("CAP16"), .level = 5});
    GeneralCapabilityLog({.message = "Capability-enabled binary hardlink count warning", .id = ID("CAP17"), .level = 3});
    GeneralCapabilityLog({.message = "Capability-enabled binary not executable but readable", .id = ID("CAP18"), .level = 2});
    GeneralCapabilityLog({.message = "Redundant configurations: Binary has both SUID/SGID and capabilities", .id = ID("CAP19"), .level = 3});
    
    // --- CAPABILITIES: PERSISTENCIA Y ENTORNOS VOLÁTILES ---
    GeneralCapabilityLog({.message = "Capability-enabled binary in /tmp or /var", .id = ID("CAP20"), .level = 5});
    GeneralCapabilityLog({.message = "Capability-enabled binary in user home directory", .id = ID("CAP21"), .level = 5});
    GeneralCapabilityLog({.message = "Capability-enabled binary user no longer exists", .id = ID("CAP23"), .level = 2});
    GeneralCapabilityLog({.message = "Capability-enabled binary group no longer exists", .id = ID("CAP24"), .level = 2});

    // --- CAPABILITIES: ANÁLISIS ESPECÍFICO DE PRIVILEGIOS CRÍTICOS (Reemplazo SGID) ---
    GeneralCapabilityLog({.message = "Highly dangerous capability assigned (CAP_SYS_ADMIN/CAP_SYS_PTRACE/CAP_SYS_MODULE)", .id = ID("CAP25"), .level = 5});
    GeneralCapabilityLog({.message = "Identity manipulation capability assigned (CAP_SETUID/CAP_SETGID/CAP_CHOWN)", .id = ID("CAP26"), .level = 5});
    GeneralCapabilityLog({.message = "Network promiscuity capability assigned (CAP_NET_RAW/CAP_NET_ADMIN)", .id = ID("CAP27"), .level = 4});
    GeneralCapabilityLog({.message = "Invalid or unsupported Linux capability version in xattr", .id = ID("CAP28"), .level = 4});
    GeneralCapabilityLog({.message = "Capability assigned to binary with an unknown GID", .id = ID("CAP29"), .level = 4});

    GeneralCapabilityLog({.message = "Filesystem bypass capability assgined (CAP_DAC_OVERRIDE or CAP_DAC_READ_SEARCH): all file permission checks bypassed", .id = ID("CAP30"), .level = 5});
    GeneralCapabilityLog({.message = "Ownership manipulation capability assigned (CAP_FOWNER or CAP_FSETID): can modify permissions on files not owned by the process", .id = ID("CAP31"), .level = 4});
    GeneralCapabilityLog({.message = "CAP_SYS_CHROOT assigned: process can change root directory, classic container escape vector", .id = ID("CAP32"), .level = 4});
    GeneralCapabilityLog({.message = "Raw hardware access capability assigned (CAP_SYS_RAWIO): direct access to I/O ports and physical memory", .id = ID("CAP33"), .level = 5});
    GeneralCapabilityLog({.message = "Audit subsystem capability assigned (CAP_AUDIT_WRITE or CAP_AUDIT_CONTROL): binary can suppress or manipulate audit logs", .id = ID("CAP34"), .level = 5});


    GeneralCapabilityLog({.message = "security.capability xattr present but effective and permitted capability sets are empty", .id = ID("CAP35"), .level = 3});
    GeneralCapabilityLog({.message = "Non-empty inheritable capability set detected: may interact unexpectedly with ambient capabilities", .id = ID("CAP36"), .level = 2});
}
