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
add_executable(kls_tests
    TOKENIZATION_TEST.cpp
    PARSING_TEST.cpp 
    VALIDATION_TEST.cpp
    EXECUTOR_TEST.cpp
    #SPEED_TEST_LIST.cpp
)

target_compile_options(kls_tests PRIVATE -g)

target_include_directories(kls_tests PRIVATE 
    ${PROJECT_SOURCE_DIR}/include
    ${PROJECT_BINARY_DIR}/generated
)

target_link_libraries(kls_tests 
    PRIVATE
    kls_core
    gtest_main 
    gtest
)

include(GoogleTest)
gtest_discover_tests(kls_tests)
