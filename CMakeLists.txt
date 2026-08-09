cmake_minimum_required(VERSION 3.15)
project(kls
    VERSION 0.1.1
    DESCRIPTION "kls is a security-focused directory listing tool."
    LANGUAGES CXX
)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

# 1. Build Configuration
option(ENABLE_SANITIZERS "Enable Address and Undefined Behavior Sanitizers" ON)
option(ENABLE_COVERAGE "Enable code coverage instrumentation" OFF)

add_compile_options(
    -Wall -Wextra -Wpedantic -Wconversion 
    -Wshadow -g -fno-omit-frame-pointer
)

if(ENABLE_SANITIZERS AND (CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang"))
    add_compile_options(-fsanitize=address,undefined)
    add_link_options(-fsanitize=address,undefined)
    message(STATUS "Sanitizers enabled")
endif()

if(ENABLE_COVERAGE AND (CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang"))
    add_compile_options(--coverage -fprofile-arcs -ftest-coverage)
    add_link_options(--coverage)
    message(STATUS "Coverage instrumentation enabled")
endif()

# 4. Configure Generated Files (se declara ANTES de usarse)
configure_file(
    "${PROJECT_SOURCE_DIR}/include/kls/cli/special-option/version-option.hpp.in"
    "${PROJECT_BINARY_DIR}/generated/special-option/version-option.hpp"
)

# ==============================================================================
# NUEVA ARQUITECTURA: CLI declarativa (parser + validator + help_formatter)
# ==============================================================================
add_library(kls_cli STATIC 
    src/cli/parser/cli_parser.cpp
    src/cli/validator/cli_validator.cpp
    src/cli/executor/help_formatter.cpp   # <--- NUEVO (debes crearlo)
)

target_include_directories(kls_cli PUBLIC 
    ${PROJECT_SOURCE_DIR}/include
    ${PROJECT_BINARY_DIR}/generated       # <--- Para version-option.hpp
)

# ==============================================================================
# CORE: Plataforma + Reporte + Legacy (deuda técnica)
# ==============================================================================
# Los archivos legacy de CLI (option, command, error) YA NO ESTÁN aquí.
# Los legacy no-CLI (SUID, white-list, CAPABILITIES) se mantienen hasta migrarlos.
set(CORE_SOURCES
    # --- Legacy registers (deuda D1, D2, D4 - se migrarán después) ---
    src/SUID-SGID-register/health-register.cpp
    src/SUID-SGID-register/print-health-flags.cpp
    src/SUID-SGID-register/suid-sgid-register-table.cpp
    src/white-list-routes/white-list-routes.cpp
    src/CAPABILITIES-register/capabilities-register-log.cpp
    src/CAPABILITIES-register/capabilities-register.cpp
    src/CAPABILITIES-register/print-capabilities.cpp
    # --- Plataforma y reporte (vivos) ---
    src/platform/unique_fd.cpp
    src/platform/identity_resolver.cpp
    src/report/render_report.cpp
)

add_library(kls_core STATIC ${CORE_SOURCES})
target_include_directories(kls_core PUBLIC 
    ${PROJECT_SOURCE_DIR}/include
    ${PROJECT_BINARY_DIR}/generated
)

# ==============================================================================
# SCANNER
# ==============================================================================
add_library(kls_scanner STATIC 
    src/scanner/scanner.cpp
    src/scanner/collect_metadata.cpp
    src/scanner/orchestator.cpp
    src/scanner/detail/file_type_conversion.cpp
)
target_include_directories(kls_scanner PUBLIC
    ${PROJECT_SOURCE_DIR}/include
)

# ==============================================================================
# ANALYSIS
# ==============================================================================
add_library(kls_analysis STATIC
    src/analyzers/analyzer_entries.cpp
    src/audit/audit_orchestrator.cpp
    src/analyzers/health_analyzer.cpp
    src/analyzers/capability_analyzer.cpp
)

target_include_directories(kls_analysis PUBLIC
    ${PROJECT_SOURCE_DIR}/include
)

target_link_libraries(kls_analysis PUBLIC
    kls_scanner
)

# ==============================================================================
# MAIN EXECUTABLE
# ==============================================================================
add_executable(kls src/kls-main.cpp)

# El binario enlaza con toda la arquitectura:
#   - kls_cli       (nueva CLI declarativa)
#   - kls_core      (plataforma, reporte, legacy registers)
#   - kls_analysis  (audit_orchestrator + analyzers)
# Usamos linker groups para tolerar la dependencia circular core <-> analysis
# (esto desaparecerá cuando extraigamos kls_platform del core).
target_link_libraries(kls PRIVATE 
    kls_cli
    -Wl,--start-group 
    kls_core 
    kls_analysis 
    -Wl,--end-group
)

# ==============================================================================
# TESTING
# ==============================================================================
enable_testing()
add_subdirectory(tests)

# ==============================================================================
# INSTALLATION
# ==============================================================================
include(GNUInstallDirs)
install(TARGETS kls RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})

# Compress the man page before installation to avoid lintian warnings
find_program(GZIP_EXECUTABLE gzip)
if(GZIP_EXECUTABLE)
    set(MAN_PAGE_SOURCE "${PROJECT_SOURCE_DIR}/docs/kls.1")
    set(MAN_PAGE_GZ "${PROJECT_BINARY_DIR}/kls.1.gz")
    
    add_custom_command(
        OUTPUT "${MAN_PAGE_GZ}"
        COMMAND ${GZIP_EXECUTABLE} -n -c "${MAN_PAGE_SOURCE}" > "${MAN_PAGE_GZ}"
        DEPENDS "${MAN_PAGE_SOURCE}"
        COMMENT "Compressing man page with gzip"
    )
    add_custom_target(compress_man ALL DEPENDS "${MAN_PAGE_GZ}")
    
    install(FILES "${MAN_PAGE_GZ}" DESTINATION ${CMAKE_INSTALL_MANDIR}/man1 COMPONENT man)
else()
    message(WARNING "gzip not found. Man page will be installed uncompressed.")
    install(FILES docs/kls.1 DESTINATION ${CMAKE_INSTALL_MANDIR}/man1 COMPONENT man)
endif()

# Shell Completions
install(FILES completions/kls.bash
        DESTINATION ${CMAKE_INSTALL_DATADIR}/bash-completion/completions
        RENAME kls)
install(FILES completions/_kls
        DESTINATION ${CMAKE_INSTALL_DATADIR}/zsh/site-functions)
install(FILES completions/kls.fish
        DESTINATION ${CMAKE_INSTALL_DATADIR}/fish/vendor_completions.d)

# ==============================================================================
# PACKAGING (CPack)
# ==============================================================================
set(CPACK_PACKAGE_NAME "kls")
set(CPACK_PACKAGE_VERSION ${PROJECT_VERSION})
set(CPACK_PACKAGE_CONTACT "jeremynobel16@gmail.com")
set(CPACK_PACKAGE_MAINTAINER "Jeremy Nobel <jeremynobel16@gmail.com>")
set(CPACK_PACKAGE_DESCRIPTION_SUMMARY "Security-focused directory listing tool")
set(CPACK_PACKAGE_DESCRIPTION_FILE "${CMAKE_CURRENT_SOURCE_DIR}/DESCRIPTION.txt")
set(CPACK_RESOURCE_FILE_LICENSE "${CMAKE_CURRENT_SOURCE_DIR}/LICENSE")
set(CPACK_STRIP_FILES TRUE)

# Debian (.deb)
set(CPACK_DEBIAN_PACKAGE_SECTION "utils")
if(NOT CPACK_DEBIAN_PACKAGE_ARCHITECTURE)
    if(CMAKE_SYSTEM_PROCESSOR MATCHES "x86_64|amd64|AMD64")
        set(CPACK_DEBIAN_PACKAGE_ARCHITECTURE "amd64")
    elseif(CMAKE_SYSTEM_PROCESSOR MATCHES "aarch64|arm64|ARM64")
        set(CPACK_DEBIAN_PACKAGE_ARCHITECTURE "arm64")
    else()
        set(CPACK_DEBIAN_PACKAGE_ARCHITECTURE "amd64")
    endif()
endif()
set(CPACK_DEBIAN_PACKAGE_DEPENDS "libstdc++6, libc6")
set(CPACK_DEBIAN_PACKAGE_HOMEPAGE "https://github.com/NobelC/kls")

# RPM (.rpm)
set(CPACK_RPM_PACKAGE_LICENSE "MIT")
set(CPACK_RPM_PACKAGE_GROUP "Applications/System")
set(CPACK_RPM_PACKAGE_REQUIRES "libstdc++, glibc")
set(CPACK_RPM_PACKAGE_URL "https://github.com/NobelC/kls")

# Tarball
set(CPACK_GENERATOR "DEB;RPM;TGZ")
set(CPACK_PACKAGE_FILE_NAME "${CPACK_PACKAGE_NAME}-${CPACK_PACKAGE_VERSION}-${CMAKE_SYSTEM_NAME}-${CMAKE_SYSTEM_PROCESSOR}")

include(CPack)

# --- Custom Uninstall Target ---
if(NOT TARGET uninstall)
  configure_file(
    "${CMAKE_CURRENT_SOURCE_DIR}/cmake_uninstall.cmake.in"
    "${CMAKE_CURRENT_BINARY_DIR}/cmake_uninstall.cmake"
    IMMEDIATE @ONLY)

  add_custom_target(uninstall
    COMMAND ${CMAKE_COMMAND} -P ${CMAKE_CURRENT_BINARY_DIR}/cmake_uninstall.cmake)
endif()
