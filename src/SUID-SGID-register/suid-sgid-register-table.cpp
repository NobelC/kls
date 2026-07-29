#include "health-register.hpp"

void CreatedHealthFlags() {
    auto type = kls::findings::CategoryFindings::health;

    GeneralHealthFlagsLog({.message = "SUID bit set", .id = ID("SU01"), .level = 3, .type_findings = type});
    GeneralHealthFlagsLog({.message = "SUID bit set on world-writable file", .id = ID("SU02"), .level = 5, .type_findings = type});
    GeneralHealthFlagsLog({.message = "SUID bit set on non-executable file", .id = ID("SU03"), .level = 2, .type_findings = type});

    GeneralHealthFlagsLog({.message = "SUID binary found outside standard system directories", .id = ID("SU04"), .level = 5, .type_findings = type});
    GeneralHealthFlagsLog({.message = "SUID bit set on file not owned by root", .id = ID("SU05"), .level = 4, .type_findings = type});
    GeneralHealthFlagsLog({.message = "SUID bit set on interpreted script", .id = ID("SU06"), .level = 3, .type_findings = type});
    GeneralHealthFlagsLog({.message = "SUID binary is world-executable", .id = ID("SU07"), .level = 4, .type_findings = type});
    GeneralHealthFlagsLog({.message = "SUID binary is group-writable", .id = ID("SU08"), .level = 4, .type_findings = type});
    GeneralHealthFlagsLog({.message = "SUID bit set on a symbolic link", .id = ID("SU09"), .level = 2, .type_findings = type});
    GeneralHealthFlagsLog({.message = "SUID bit set on a directory", .id = ID("SU10"), .level = 2, .type_findings = type});
    GeneralHealthFlagsLog({.message = "SUID binary owned by unknown UID", .id = ID("SU11"), .level = 4, .type_findings = type});
    GeneralHealthFlagsLog({.message = "SUID binary recently modified", .id = ID("SU12"), .level = 4, .type_findings = type});
    GeneralHealthFlagsLog({.message = "SUID binary future timestamp", .id = ID("SU13"), .level = 5, .type_findings = type});
    GeneralHealthFlagsLog({.message = "SUID binary shows timestamp manipulation", .id = ID("SU14"), .level = 5, .type_findings = type});
    GeneralHealthFlagsLog({.message = "SUID binary world-readable in sensitive path", .id = ID("SU15"), .level = 3, .type_findings = type});
    GeneralHealthFlagsLog({.message = "SUID binary ELF magic mismatch", .id = ID("SU16"), .level = 5, .type_findings = type});
    GeneralHealthFlagsLog({.message = "SUID binary hardlink count warning", .id = ID("SU17"), .level = 3, .type_findings = type});
    GeneralHealthFlagsLog({.message = "SUID binary not executable but readable", .id = ID("SU18"), .level = 2, .type_findings = type});
    GeneralHealthFlagsLog({.message = "SUID binary with redundant capabilities", .id = ID("SU19"), .level = 2, .type_findings = type});
    GeneralHealthFlagsLog({.message = "SUID binary in /tmp or /var", .id = ID("SU20"), .level = 5, .type_findings = type});
    GeneralHealthFlagsLog({.message = "SUID binary in user home directory", .id = ID("SU21"), .level = 5, .type_findings = type});
    GeneralHealthFlagsLog({.message = "SUID binary also carries the sticky bit", .id = ID("SU22"), .level = 2, .type_findings = type});
    GeneralHealthFlagsLog({.message = "SUID binary user no longer exists ", .id = ID("SU23"), .level = 2, .type_findings = type});
    GeneralHealthFlagsLog({.message = "SUID binary group no longer exists", .id = ID("SU24"), .level = 2, .type_findings = type});

    GeneralHealthFlagsLog({.message = "SGID bit set", .id = ID("SG01"), .level = 3, .type_findings = type});
    GeneralHealthFlagsLog({.message = "SGID bit set on world-writable directory", .id = ID("SG02"), .level = 4, .type_findings = type});
    GeneralHealthFlagsLog({.message = "SGID bit set on world-writable file", .id = ID("SG03"), .level = 5, .type_findings = type});
    GeneralHealthFlagsLog({.message = "SGID binary writable by its own group", .id = ID("SG04"), .level = 4, .type_findings = type});
    GeneralHealthFlagsLog({.message = "SGID binary assigned to unknown GID", .id = ID("SG05"), .level = 4, .type_findings = type});

    GeneralHealthFlagsLog({.message = "Device node found outside standard /dev directory", .id = ID("HWBD"), .level = 5, .type_findings = type});
    GeneralHealthFlagsLog({.message = "File is marked as immutable (cannot be modified, deleted, or renamed)", .id = ID("IMMU"), .level = 2, .type_findings = type});
    GeneralHealthFlagsLog({.message = "File is marked as append-only (can only be written to by appending data)", .id = ID("APND"), .level = 2, .type_findings = type});
}
