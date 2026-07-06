#include <gtest/gtest.h>
#include "../include/kls/cli/parser/tokenization.hpp"
#include "../include/kls/cli/parser/parsing.hpp"
#include "../include/kls/cli/parser/validator.hpp"
#include "../include/kls/cli/option/option-implementation.hpp"

class ValidatorSuite : public ::testing::Test {
protected:
  static void SetUpTestSuite() {
    CreatedOptionData();
  }
};

TEST_F(ValidatorSuite, PositionalValidation){
  // Empty arguments should default to "."
  std::vector<std::string> input = {};
  auto result_tokenization = tokenization(input);
  auto result_parsing = parsing(result_tokenization);
  EXPECT_EQ(ValidationGroupToken(result_parsing), true);
  EXPECT_EQ(result_parsing.positional.front().name, ".");

  input = {"~/.config"};
  result_tokenization = tokenization(input);
  result_parsing = parsing(result_tokenization);
  EXPECT_EQ(ValidationGroupToken(result_parsing), true);
}

TEST_F(ValidatorSuite, ConflictOptions){
  std::vector<std::string> input = {"--quiet", "--verbose"};
  auto result_tokenization = tokenization(input);
  auto result_parsing = parsing(result_tokenization);
  EXPECT_EQ(ValidationGroupToken(result_parsing), false);
}

TEST_F(ValidatorSuite, OptionRequieresValue){
  std::vector<std::string> input = {"--depth", "--recursive"};
  auto result_tokenization = tokenization(input);
  auto result_parsing = parsing(result_tokenization);
  EXPECT_EQ(ValidationGroupToken(result_parsing), false);

  input = {"--depth=2", "--recursive"};
  result_tokenization = tokenization(input);
  result_parsing = parsing(result_tokenization);
  EXPECT_EQ(ValidationGroupToken(result_parsing), true);
}

TEST_F(ValidatorSuite, ValidationTypeDataOption){
  std::vector<std::string> input = {"--sort=size"};
  auto result_tokenization = tokenization(input);
  auto result_parsing = parsing(result_tokenization);
  EXPECT_EQ(ValidationGroupToken(result_parsing), true);

  input = {"--modified-after=2024-01-01"};
  result_tokenization = tokenization(input);
  result_parsing = parsing(result_tokenization);
  EXPECT_EQ(ValidationGroupToken(result_parsing), true);

  input = {"--modified-after=invalid-date"};
  result_tokenization = tokenization(input);
  result_parsing = parsing(result_tokenization);
  EXPECT_EQ(ValidationGroupToken(result_parsing), false);
}
