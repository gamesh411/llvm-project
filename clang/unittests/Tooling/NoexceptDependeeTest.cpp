//===--- NoexceptDependeeTest.cpp - Tests for NoexceptDependeeConsumer ----===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//

#include "../../tools/clang-exception-scan/GlobalExceptionInfo.h"
#include "../../tools/clang-exception-scan/NoexceptDependeeConsumer.h"
#include "clang/Tooling/Tooling.h"
#include "gtest/gtest.h"

using namespace clang;
using namespace clang::tooling;
using namespace clang::exception_scan;

namespace {

class NoexceptDependeeTest : public ::testing::Test {
protected:
  void runToolOnCode(const std::string &Code) {
    GlobalExceptionInfo GCG;
    NoexceptDependeeActionFactory Factory(GCG);

    // Create a tool to run the action
    std::vector<std::string> Args = {"-std=c++17", "-xc++"};
    std::unique_ptr<FrontendAction> Action = Factory.create();

    // Run the tool on the code
    ASSERT_TRUE(
        runToolOnCodeWithArgs(std::move(Action), Code, Args, "input.cpp"));

    // Store the results for testing
    NoexceptDependees = GCG.NoexceptDependees;
  }

  std::vector<NoexceptDependeeInfo> NoexceptDependees;
};

TEST_F(NoexceptDependeeTest, BasicNoexceptDependee) {
  const std::string Code = R"(
    bool g() { return true; }
    
    void f() noexcept(noexcept(g())) {}
  )";

  runToolOnCode(Code);

  // We should find one noexcept-dependee function
  ASSERT_EQ(NoexceptDependees.size(), 1U);

  // Check the function name
  EXPECT_EQ(NoexceptDependees[0].FunctionName, "g");
}

TEST_F(NoexceptDependeeTest, NestedNoexceptDependee) {
  const std::string Code = R"(
    bool h() { return true; }
    bool g() noexcept(noexcept(h())) { return true; }
    
    void f() noexcept(noexcept(g())) {}
  )";

  runToolOnCode(Code);

  // We should find two noexcept-dependee functions
  ASSERT_EQ(NoexceptDependees.size(), 2U);

  // Check the function names
  std::set<std::string> FunctionNames;
  for (const auto &Info : NoexceptDependees) {
    FunctionNames.insert(Info.FunctionName);
  }

  EXPECT_TRUE(FunctionNames.count("g") > 0);
  EXPECT_TRUE(FunctionNames.count("h") > 0);
}

TEST_F(NoexceptDependeeTest, ComplexNoexceptExpression) {
  const std::string Code = R"(
    bool g() { return true; }
    bool h() { return false; }
    
    void f() noexcept(noexcept(g()) && noexcept(h())) {}
  )";

  runToolOnCode(Code);

  // We should find two noexcept-dependee functions
  ASSERT_EQ(NoexceptDependees.size(), 2U);

  // Check the function names
  std::set<std::string> FunctionNames;
  for (const auto &Info : NoexceptDependees) {
    FunctionNames.insert(Info.FunctionName);
  }

  EXPECT_TRUE(FunctionNames.count("g") > 0);
  EXPECT_TRUE(FunctionNames.count("h") > 0);
}

TEST_F(NoexceptDependeeTest, NoNoexceptDependee) {
  const std::string Code = R"(
    void f() noexcept {}
  )";

  runToolOnCode(Code);

  // We should not find any noexcept-dependee functions
  EXPECT_EQ(NoexceptDependees.size(), 0U);
}

TEST_F(NoexceptDependeeTest, ClassMemberFunction) {
  const std::string Code = R"(
    class C {
      bool g() { return true; }
      
      void f() noexcept(noexcept(g())) {}
    };
  )";

  runToolOnCode(Code);

  // We should find one noexcept-dependee function
  ASSERT_EQ(NoexceptDependees.size(), 1U);

  // Check the function name
  EXPECT_EQ(NoexceptDependees[0].FunctionName, "g");
}

TEST_F(NoexceptDependeeTest, TemplateFunction) {
  const std::string Code = R"(
    template<typename T>
    bool g() { return true; }
    
    template<typename T>
    void f() noexcept(noexcept(g<T>())) {}
  )";

  runToolOnCode(Code);

  // We should find one noexcept-dependee function
  ASSERT_EQ(NoexceptDependees.size(), 1U);

  // Check the function name
  EXPECT_EQ(NoexceptDependees[0].FunctionName, "g");
}

} // namespace
