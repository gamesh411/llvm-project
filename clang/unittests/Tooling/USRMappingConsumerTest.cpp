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
  }

  void runToolOnCode(const std::string &Code, const std::string &FileName) {
    std::vector<std::string> Args = {"-std=c++17", "-fsyntax-only"};

    // Create a fixed compilation database
    std::string BuildDir = ".";
    auto Compilations =
        std::make_unique<FixedCompilationDatabase>(BuildDir, Args);

    // Create a clang tool and run it
    ClangTool Tool(*Compilations, {FileName});

    // Write the code to a temporary file
    std::error_code EC;
    llvm::raw_fd_ostream OS(FileName, EC, llvm::sys::fs::OF_None);
    if (EC) {
      llvm::errs() << "Error: " << EC.message() << "\n";
      return;
    }
    OS << Code;
    OS.close();

    Tool.run(std::make_unique<USRMappingActionFactory>(GEI).get());
  }

  void runToolOnMultipleFiles(const std::vector<std::string> &Codes,
                              const std::vector<std::string> &FileNames) {
    std::vector<std::string> Args = {"-std=c++17", "-fsyntax-only"};

    std::string BuildDir = ".";
    auto Compilations =
        std::make_unique<FixedCompilationDatabase>(BuildDir, Args);

    // Write the codes to temporary files
    for (size_t i = 0; i < Codes.size(); ++i) {
      std::error_code EC;
      llvm::raw_fd_ostream OS(FileNames[i], EC, llvm::sys::fs::OF_None);
      if (EC) {
        llvm::errs() << "Error: " << EC.message() << "\n";
        continue;
      }
      OS << Codes[i];
      OS.close();
    }

    // Run the tool for each file individually
    for (size_t i = 0; i < FileNames.size(); ++i) {
      // Create a clang tool for just this file
      ClangTool Tool(*Compilations, {FileNames[i]});

      Tool.run(std::make_unique<USRMappingActionFactory>(GEI).get());
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
  )";

  runToolOnCode(Code, "test.cpp");
  EXPECT_EQ(GEI.USRToFunctionMap.size(), 3u);

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

} // namespace