include(FetchContent)

FetchContent_Declare(
  googletest
  URL https://github.com/google/googletest/archive/refs/heads/main.zip
  DOWNLOAD_EXTRACT_TIMESTAMP TRUE
)
set(gtest_force_shared_crt ON CACHE BOOL "" FORCE)
set(INSTALL_GTEST OFF CACHE BOOL "" FORCE)
FetchContent_MakeAvailable(googletest)


# --- TEST TARGET ---
add_executable(kls_cli_tests
    cli/output_processor_test.cpp
    cli/min_severity_test.cpp
)

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
gtest_discover_tests(kls_cli_tests)
