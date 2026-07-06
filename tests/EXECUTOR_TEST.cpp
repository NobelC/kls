#include <gtest/gtest.h>
#include "../include/kls/cli/parser/tokenization.hpp"
#include "../include/kls/cli/parser/parsing.hpp"
#include "../include/kls/cli/parser/validator.hpp"
#include "../include/kls/cli/option/option-implementation.hpp"
#include "../include/kls/cli/parser/executor.hpp"

class ExecutorSuite : public ::testing::Test {
protected:
  // cppcheck-suppress unusedFunction
  static void SetUpTestSuite() {
    CreatedOptionData();
  }
};

TEST_F(ExecutorSuite, HelpFlagCallsHelpHandler) {
  // 1. Prepare input
  std::vector<std::string> input = {"--help"};
  
  // 2. Run pipeline
  auto tokens  = tokenization(input);
  auto parsed  = parsing(tokens);
  ValidationGroupToken(parsed);
  
  // 3. Capture output
  testing::internal::CaptureStdout();
  executor(parsed);
  std::string output = testing::internal::GetCapturedStdout();
  
  // 4. Verify
  EXPECT_FALSE(output.empty());
  EXPECT_NE(output.find("kls [path] [options]"), std::string::npos);
}
