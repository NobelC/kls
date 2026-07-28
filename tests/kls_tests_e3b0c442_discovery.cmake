include("/usr/share/cmake/Modules/GoogleTestAddTests.cmake")
gtest_discover_tests_impl(
  TEST_EXECUTABLE [==[/home/nobelc/Projects/kls/tests/kls_tests]==]
  TEST_EXECUTOR [==[]==]
  TEST_WORKING_DIR [==[/home/nobelc/Projects/kls/tests]==]
  TEST_EXTRA_ARGS [==[]==]
  TEST_PROPERTIES [==[]==]
  TEST_PREFIX [==[]==]
  TEST_SUFFIX [==[]==]
  TEST_FILTER [==[]==]
  NO_PRETTY_TYPES [==[FALSE]==]
  NO_PRETTY_VALUES [==[FALSE]==]
  TEST_LIST [==[kls_tests_TESTS]==]
  CTEST_FILE [==[/home/nobelc/Projects/kls/tests/kls_tests_e3b0c442_tests.cmake]==]
  TEST_DISCOVERY_TIMEOUT [==[5]==]
  TEST_DISCOVERY_EXTRA_ARGS [==[]==]
  TEST_XML_OUTPUT_DIR [==[]==]
  TEST_JSON_OUTPUT_DIR [==[/home/nobelc/Projects/kls/tests]==]
)
