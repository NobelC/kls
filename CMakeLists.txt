cmake_minimum_required(VERSION 3.15)
project(kls
    VERSION 0.1.1
    DESCRIPTION "kls is a security-focused directory listing tool."
    LANGUAGES CXX
)

set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

# 1. Build Configuration
option(ENABLE_SANITIZERS
    "Enable Address and Undefined Behavior Sanitizers" OFF)
option(ENABLE_COVERAGE
    "Enable code coverage instrumentation" OFF)
option(ENABLE_TSAN
    "Enable ThreadSanitizer" OFF)

if(ENABLE_SANITIZERS AND ENABLE_TSAN)
    message(FATAL_ERROR
        "ENABLE_SANITIZERS and ENABLE_TSAN cannot be enabled together")
endif()

# Project-specific usage requirements.
# External dependencies such as GoogleTest do not inherit these options.
add_library(kls_build_options INTERFACE)

target_compile_features(kls_build_options INTERFACE cxx_std_20)

target_compile_options(kls_build_options INTERFACE
    $<$<COMPILE_LANG_AND_ID:CXX,GNU,Clang>:-Wall>
    $<$<COMPILE_LANG_AND_ID:CXX,GNU,Clang>:-Wextra>
    $<$<COMPILE_LANG_AND_ID:CXX,GNU,Clang>:-Wpedantic>
    $<$<COMPILE_LANG_AND_ID:CXX,GNU,Clang>:-Wconversion>
    $<$<COMPILE_LANG_AND_ID:CXX,GNU,Clang>:-Wshadow>
    $<$<AND:$<COMPILE_LANG_AND_ID:CXX,GNU,Clang>,$<CONFIG:Debug>>:-fno-omit-frame-pointer>
    $<$<AND:$<COMPILE_LANG_AND_ID:CXX,GNU,Clang>,$<CONFIG:RelWithDebInfo>>:-fno-omit-frame-pointer>
)

if(ENABLE_SANITIZERS AND
   (CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang"))
    target_compile_options(kls_build_options INTERFACE
        -fsanitize=address,undefined
        -fno-sanitize-recover=all
    )
    target_link_options(kls_build_options INTERFACE
        -fsanitize=address,undefined
        -fno-sanitize-recover=all
    )
    message(STATUS "AddressSanitizer and UBSan enabled")
elseif(ENABLE_TSAN AND
       (CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang"))
    target_compile_options(kls_build_options INTERFACE
        -fsanitize=thread
    )
    target_link_options(kls_build_options INTERFACE
        -fsanitize=thread
    )
    message(STATUS "ThreadSanitizer enabled")
endif()

if(ENABLE_COVERAGE AND
   (CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang"))
    target_compile_options(kls_build_options INTERFACE
        --coverage
        -fprofile-arcs
        -ftest-coverage
    )
    target_link_options(kls_build_options INTERFACE
        --coverage
    )
    message(STATUS "Coverage instrumentation enabled")
endif()

# 2. Core Sources
set(CORE_SOURCES
    src/core-system/tokenization.cpp
    src/core-system/parsing.cpp
    src/core-system/validator.cpp
    src/core-system/executor.cpp
    src/error-register-information/error_handler.cpp
    src/option-register-information/option-get-option.cpp
    src/option-register-information/option-information.cpp
    src/option-register-information/special-option/help-handler.cpp
    src/option-register-information/special-option/version-handler.cpp
    src/command-register-information/list.cpp
    src/SUID-SGID-register/health-register.cpp
    src/SUID-SGID-register/print-health-flags.cpp
    src/SUID-SGID-register/suid-sgid-register-table.cpp
    src/white-list-routes/white-list-routes.cpp
    src/CAPABILITIES-register/capabilities-register-log.cpp
    src/CAPABILITIES-register/capabilities-register.cpp
    src/CAPABILITIES-register/print-capabilities.cpp
)

# 3. Core Library
add_library(kls_core STATIC ${CORE_SOURCES})
target_link_libraries(kls_core PUBLIC kls_build_options)
set_target_properties(kls_core PROPERTIES
    CXX_EXTENSIONS OFF
)
target_include_directories(kls_core PUBLIC 
    ${PROJECT_SOURCE_DIR}/include
    ${PROJECT_BINARY_DIR}/generated
)

# 4. Configure Generated Files
configure_file(
    "${PROJECT_SOURCE_DIR}/include/special-option/version-option.hpp.in"
    "${PROJECT_BINARY_DIR}/generated/special-option/version-option.hpp"
)

# 5. Main Executable
add_executable(kls src/kls-main.cpp)
set_target_properties(kls PROPERTIES
    CXX_EXTENSIONS OFF
)
target_link_libraries(kls PRIVATE kls_core)

# 6. Testing Infrastructure
include(CTest)
if(BUILD_TESTING)
    add_subdirectory(tests)
endif()

# 7. Installation
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


# 8. Packaging
# --- Packaging with CPack ---
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
