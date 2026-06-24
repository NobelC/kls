cmake_minimum_required(VERSION 3.15)
project(kls
    VERSION 0.1.1
    DESCRIPTION "kls is a security-focused directory listing tool."
    LANGUAGES CXX
)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

# 1. Configuración de Compilación
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

# 2. Fuentes del Core
set(CORE_SOURCES
    src/core-system/tokenization.cpp
    src/core-system/parsing.cpp
    src/core-system/validator.cpp
    src/core-system/executor.cpp
    src/error-register-information/error_hanlder.cpp
    src/option-register-information/option-get-option.cpp
    src/option-register-information/option-information.cpp
    src/option-register-information/special-option/help-handler.cpp
    src/option-register-information/special-option/version-handler.cpp
    src/command-register-information/list.cpp
    src/SUID-SGID-register/health-register.cpp
    src/SUID-SGID-register/print-health-flags.cpp
    src/SUID-SGID-register/suid-sgid-register-table.cpp
    src/white-list-routes/white-list-routes.cpp
)

# 3. Biblioteca Core
add_library(kls_core STATIC ${CORE_SOURCES})
target_include_directories(kls_core PUBLIC 
    ${PROJECT_SOURCE_DIR}/include
    ${PROJECT_BINARY_DIR}/generated
)

# 4. Configurar archivos generados
configure_file(
    "${PROJECT_SOURCE_DIR}/include/special-option/version-option.hpp.in"
    "${PROJECT_BINARY_DIR}/generated/special-option/version-option.hpp"
)

# 5. El Ejecutable Principal
add_executable(kls src/kls-main.cpp)
target_link_libraries(kls PRIVATE kls_core)

# 6. Infraestructura de Tests
#enable_testing()
#add_subdirectory(tests)

# 7. Instalación
include(GNUInstallDirs)
install(TARGETS kls RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})
# Comprimir la man page antes de la instalación para evitar warnings de lintian
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

# Completions para Shells
install(FILES completions/kls.bash
        DESTINATION ${CMAKE_INSTALL_DATADIR}/bash-completion/completions
        RENAME kls)
install(FILES completions/_kls
        DESTINATION ${CMAKE_INSTALL_DATADIR}/zsh/site-functions)
install(FILES completions/kls.fish
        DESTINATION ${CMAKE_INSTALL_DATADIR}/fish/vendor_completions.d)


#8. Empaquetado
# --- Empaquetado con CPack ---
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

