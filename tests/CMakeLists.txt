include(FetchContent)

# ARCHITECTURAL NOTE: Pinned test dependencies.
# CONTRIBUTING.md strictly requires pinning external dependencies to a specific 
# release to ensure reproducible builds and prevent silent breakage from upstream changes.
FetchContent_Declare(
  googletest
  URL https://github.com/google/googletest/archive/refs/tags/v1.14.0.zip
  URL_HASH SHA256=8ad598c73ad796e0d8280b082cebd82a630d73e73cd3c70057938a6501bba5d7
  DOWNLOAD_EXTRACT_TIMESTAMP TRUE
)

# Ensure GTest uses the same C++ runtime library as the host project (MSVC best practice).
set(gtest_force_shared_crt ON CACHE BOOL "" FORCE)

# Prevent GTest from installing itself system-wide; we only need it for local testing.
set(INSTALL_GTEST OFF CACHE BOOL "" FORCE)

FetchContent_MakeAvailable(googletest)

# --- TEST TARGET ---
# Isolate the test executable to avoid polluting the main binary with test-only dependencies.
add_executable(kls_cli_tests
    cli/output_processor_test.cpp
    cli/min_severity_test.cpp
    cli/registry_test.cpp
)

# Explicitly request debug symbols for the test binary to aid in failure diagnostics.
target_compile_options(kls_cli_tests PRIVATE -g)

target_link_libraries(kls_cli_tests
    PRIVATE
    kls_cli
    kls_core
    gtest
    gtest_main
)

target_include_directories(kls_cli_tests PRIVATE
    ${PROJECT_SOURCE_DIR}/include
)

include(GoogleTest)

# Automatically register all TEST/TEST_F macros in the executable with CTest.
gtest_discover_tests(kls_cli_tests)
