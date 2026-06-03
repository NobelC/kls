#include <gtest/gtest.h>
#include "../include/core-hpp/tokenization.hpp"
#include "../include/core-hpp/parsing.hpp"
#include "../include/option/option-implementation.hpp"

namespace{
// 1. Option parsing
TEST(ParsingSuite, Options){
  CreatedOptionData();
  
  std::vector<std::string> input = {"--all"};
  auto result = tokenization(input);
  auto result_parsing = parsing(result);
  EXPECT_EQ(result_parsing.options.front().name, "--all");

  input = {"--sort", "size"};
  result = tokenization(input);
  result_parsing = parsing(result);
  EXPECT_EQ(result_parsing.options.front().name, "--sort");
  EXPECT_EQ(result_parsing.options.front().value, "size");
}

// 2. Positional parsing (paths)
// cppcheck-suppress syntaxError
TEST(ParsingSuite, Positional){
  CreatedOptionData();
  
  std::vector<std::string> input = {"./src", "/tmp"};
  auto result = tokenization(input);
  auto result_parsing = parsing(result);
  ASSERT_EQ(result_parsing.positional.size(), 2);
  EXPECT_EQ(result_parsing.positional[0].name, "./src");
  EXPECT_EQ(result_parsing.positional[1].name, "/tmp");
}

// 3. Mixed parsing
TEST(ParsingSuite, Mixed){
  CreatedOptionData();
  
  std::vector<std::string> input = {"-a", "./src"};
  auto result = tokenization(input);
  auto result_parsing = parsing(result);
  ASSERT_EQ(result_parsing.options.size(), 2);
  ASSERT_EQ(result_parsing.positional.size(), 1);
}
}
