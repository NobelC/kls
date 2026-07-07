#include <gtest/gtest.h>
#include <kls/cli/parser/tokenization.hpp>

namespace{
// 1. Literal tokens
TEST(TokenizationSuite, IdentifyLiteral){
  // Case 1:
  std::vector<std::string> input = {"list"};
  auto result = tokenization(input);
  EXPECT_EQ(result[0].type, TypeToken::LITERAL);
  EXPECT_EQ(result[0].name, "list");

  // Case 2:
  input = {"--all", "list"};
  result = tokenization(input);
  EXPECT_EQ(result[0].type, TypeToken::OPTION_NOT_NORMALIZED);
  EXPECT_EQ(result[1].type, TypeToken::LITERAL);

  // Case 3:
  input = {};
  result = tokenization(input);
  ASSERT_EQ(result.empty(), true);
}

// 2. Options
// cppcheck-suppress syntaxError
TEST(TokenizationSuite, SortOptions){
  // Case 1:
  std::vector<std::string> input = {"--all"};
  auto result = tokenization(input);
  EXPECT_EQ(result[0].type, TypeToken::OPTION_NOT_NORMALIZED);

  // Case 2:
  input = {"-a"};
  result = tokenization(input);
  EXPECT_EQ(result[0].type, TypeToken::OPTION_NOT_NORMALIZED);

  // Case 3:
  input = {"-"};
  result = tokenization(input);
  EXPECT_EQ(result[0].type, TypeToken::POSITIONAL);
}

// 3. Separation Token (--)
TEST(TokenizationSuite, SeparationToken){
  // Case 1: All after -- is positional
  std::vector<std::string> input = {"kls", "--", "--all"};
  auto result = tokenization(input);
  EXPECT_EQ(result[0].type, TypeToken::LITERAL);
  EXPECT_EQ(result[1].type, TypeToken::POSITIONAL);
  EXPECT_EQ(result[1].name, "--all");

  // Case 2: Multiple positionals
  input = {"kls", "--", "src", "--sort"};
  result = tokenization(input);
  EXPECT_EQ(result[0].type, TypeToken::LITERAL);
  EXPECT_EQ(result[1].type, TypeToken::POSITIONAL);
  EXPECT_EQ(result[2].type, TypeToken::POSITIONAL);
}
}
