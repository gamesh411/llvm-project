#include "USRMappingConsumer.h"
#include "gtest/gtest.h"

#include "clang/Tooling/CompilationDatabase.h"
#include "clang/Tooling/Tooling.h"

#include <memory>
#include <string>
#include <utility>
#include <vector>

using namespace clang;
using namespace clang::exception_scan;
using namespace clang::tooling;

namespace {

class USRMappingConsumerTest : public ::testing::Test {
protected:
  void SetUp() override {
    GEI.USRToFunctionMap.clear();
    GEI.TUToUSRMap.clear();
    GEI.USRToDefinedInTUMap.clear();
    GEI.CallDependencies.clear();
    GEI.TUDependencies.clear();
    GEI.NoexceptDependees.clear();
    GEI.TotalFunctionDefinitions = 0;
    GEI.TotalTryBlocks = 0;
    GEI.TotalCatchHandlers = 0;
    GEI.TotalThrowExpressions = 0;
    GEI.TotalCallsPotentiallyWithinTryBlocks = 0;
  }

  void runToolOnCode(const std::string &Code, const std::string &FileName) {
    std::vector<std::string> Args = {"-std=c++17", "-fsyntax-only"};
    tooling::runToolOnCodeWithArgs(std::make_unique<USRMappingAction>(GEI),
                                   Code, Args, FileName);
  }

  void runToolOnMultipleFiles(const std::vector<std::string> &Codes,
                              const std::vector<std::string> &FileNames) {
    std::vector<std::string> Args = {"-std=c++17", "-fsyntax-only"};

    // Run the tool for each file individually
    for (size_t i = 0; i < FileNames.size(); ++i) {
      tooling::runToolOnCodeWithArgs(std::make_unique<USRMappingAction>(GEI),
                                     Codes[i], Args, FileNames[i]);
    }
  }

  GlobalExceptionInfo GEI;
};

TEST_F(USRMappingConsumerTest, BasicFunctionDefinition) {
  const std::string Code = R"(
    void foo() {}
  )";

  runToolOnCode(Code, "test.cpp");
  EXPECT_EQ(GEI.USRToFunctionMap.size(), 1u);
  EXPECT_EQ(GEI.TotalFunctionDefinitions, 1u);
  EXPECT_EQ(GEI.TotalTryBlocks, 0u);
  EXPECT_EQ(GEI.TotalCatchHandlers, 0u);
  EXPECT_EQ(GEI.TotalThrowExpressions, 0u);
  EXPECT_EQ(GEI.TotalCallsPotentiallyWithinTryBlocks, 0u);

  const auto &Info = GEI.USRToFunctionMap.begin()->second;
  EXPECT_EQ(Info.FunctionName, "foo");
  EXPECT_TRUE(Info.TU.find("test.cpp") != std::string::npos);
  EXPECT_EQ(Info.USR, "c:@F@foo#");
}

TEST_F(USRMappingConsumerTest, FunctionDeclaration) {
  const std::string Code = R"(
    void foo();  // Declaration only
  )";

  runToolOnCode(Code, "test.cpp");
  EXPECT_EQ(GEI.USRToFunctionMap.size(), 1u);
  EXPECT_EQ(GEI.TotalFunctionDefinitions, 0u); // Declarations don't count
  EXPECT_EQ(GEI.TotalTryBlocks, 0u);
  EXPECT_EQ(GEI.TotalCatchHandlers, 0u);
  EXPECT_EQ(GEI.TotalThrowExpressions, 0u);
  EXPECT_EQ(GEI.TotalCallsPotentiallyWithinTryBlocks, 0u);

  const auto &Info = GEI.USRToFunctionMap.begin()->second;
  EXPECT_EQ(Info.FunctionName, "foo");
  EXPECT_FALSE(Info.IsDefinition);
  EXPECT_TRUE(Info.TU.find("test.cpp") != std::string::npos);
  EXPECT_EQ(Info.USR, "c:@F@foo#");
}

TEST_F(USRMappingConsumerTest, MultipleFunctions) {
  const std::string Code = R"(
    void foo() {}
    int bar(int x) { return x; }
    class MyClass {
      void method() {}
    };
    inline void header_func() {}
  )";

  runToolOnCode(Code, "test.cpp");
  EXPECT_EQ(GEI.USRToFunctionMap.size(), 4u);
  EXPECT_EQ(GEI.TotalFunctionDefinitions, 4u);
  EXPECT_EQ(GEI.TotalTryBlocks, 0u);
  EXPECT_EQ(GEI.TotalCatchHandlers, 0u);
  EXPECT_EQ(GEI.TotalThrowExpressions, 0u);
  EXPECT_EQ(GEI.TotalCallsPotentiallyWithinTryBlocks, 0u);

  // Check foo
  bool foundFoo = false;
  bool foundBar = false;
  bool foundMethod = false;

  for (const auto &Entry : GEI.USRToFunctionMap) {
    if (Entry.second.FunctionName == "foo") {
      foundFoo = true;
      EXPECT_TRUE(Entry.second.IsDefinition);
    } else if (Entry.second.FunctionName == "bar") {
      foundBar = true;
      EXPECT_TRUE(Entry.second.IsDefinition);
    } else if (Entry.second.FunctionName == "method") {
      foundMethod = true;
      EXPECT_TRUE(Entry.second.IsDefinition);
    }
  }

  EXPECT_TRUE(foundFoo);
  EXPECT_TRUE(foundBar);
  EXPECT_TRUE(foundMethod);
}

TEST_F(USRMappingConsumerTest, DifferentTUs) {
  const std::string Code1 = R"(
    void foo() {}
  )";

  const std::string Code2 = R"(
    void bar() {}
  )";

  runToolOnMultipleFiles({Code1, Code2}, {"test1.cpp", "test2.cpp"});
  EXPECT_EQ(GEI.USRToFunctionMap.size(), 2u);
  EXPECT_EQ(GEI.TotalFunctionDefinitions, 2u);
  EXPECT_EQ(GEI.TotalTryBlocks, 0u);
  EXPECT_EQ(GEI.TotalCatchHandlers, 0u);
  EXPECT_EQ(GEI.TotalThrowExpressions, 0u);
  EXPECT_EQ(GEI.TotalCallsPotentiallyWithinTryBlocks, 0u);

  // Check first TU
  bool foundFoo = false;
  bool foundBar = false;

  for (const auto &Entry : GEI.USRToFunctionMap) {
    if (Entry.second.FunctionName == "foo") {
      foundFoo = true;
      EXPECT_TRUE(Entry.second.TU.find("test1.cpp") != std::string::npos);
      EXPECT_TRUE(Entry.second.IsDefinition);
    } else if (Entry.second.FunctionName == "bar") {
      foundBar = true;
      EXPECT_TRUE(Entry.second.TU.find("test2.cpp") != std::string::npos);
      EXPECT_TRUE(Entry.second.IsDefinition);
    }
  }

  EXPECT_TRUE(foundFoo);
  EXPECT_TRUE(foundBar);
}

// New test for exception handling constructs
TEST_F(USRMappingConsumerTest, CountExceptionHandlingConstructs) {
  const std::string Code = R"(
    void g(); // external call
    void h() noexcept;

    void f() {
      try {         // +1 try
        int x = 0;
        g();        // +1 call in try
        try {       // +1 try
           h();     // +1 call in try (nested)
           throw 1; // +1 throw
        } catch(int e) { // +1 catch
           g();     // +0 call (in catch, not try)
           throw;   // +1 throw (rethrow)
        }
      } catch(...) { // +1 catch
         h();       // +0 call (in catch, not try)
      }
      g(); // +0 call (outside try)
    }
  )";

  runToolOnCode(Code, "test.cpp");

  EXPECT_EQ(GEI.TotalFunctionDefinitions, 1u); // Only f()
  EXPECT_EQ(GEI.TotalTryBlocks, 2u);
  EXPECT_EQ(GEI.TotalCatchHandlers, 2u);
  EXPECT_EQ(GEI.TotalThrowExpressions, 2u);
  EXPECT_EQ(GEI.TotalCallsPotentiallyWithinTryBlocks,
            2u); // Calls to g() and h() inside try blocks
}

} // namespace