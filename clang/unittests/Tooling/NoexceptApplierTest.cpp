//===--- NoexceptApplierTest.cpp - Tests for NoexceptApplier --------------===//
#include "../../tools/clang-exception-scan/ASTBasedExceptionAnalyzer.h"
#include "../../tools/clang-exception-scan/CallGraphGeneratorConsumer.h"
#include "../../tools/clang-exception-scan/GlobalExceptionInfo.h"
#include "../../tools/clang-exception-scan/NoexceptApplier.h"
#include "../../tools/clang-exception-scan/USRMappingConsumer.h"
#include "clang/ASTMatchers/ASTMatchFinder.h"
#include "clang/ASTMatchers/ASTMatchers.h"
#include "clang/Frontend/ASTUnit.h"
#include "clang/Tooling/Tooling.h"
#include "gtest/gtest.h"

using namespace clang;
using namespace clang::ast_matchers;
using namespace clang::tooling;
using namespace clang::exception_scan;

namespace {

class NoexceptApplierTest : public ::testing::Test {
protected:
  void runNoexceptApplier(const std::string &Code,
                          const std::string &FileName = "input.cpp") {
    GEI.USRToFunctionMap.clear();
    GEI.TUToUSRMap.clear();
    GEI.USRToDefinedInTUMap.clear();
    GEI.CallDependencies.clear();
    GEI.USRToExceptionMap.clear();

    std::vector<std::string> Args = {"-std=c++17", "-xc++"};

    // 1. USR Mapping
    ASSERT_TRUE(runToolOnCodeWithArgs(std::make_unique<USRMappingAction>(GEI),
                                      Code, Args, FileName));

    // 2. Call Graph Generation
    std::atomic<bool> ChangedFlag{false};
    ASSERT_TRUE(runToolOnCodeWithArgs(
        std::make_unique<CallGraphGeneratorAction>(GEI, ChangedFlag), Code,
        Args, FileName));

    // 3. Exception Analysis
    std::unique_ptr<ASTUnit> AST = buildASTFromCodeWithArgs(Code, Args);
    ASSERT_TRUE(AST);
    ASTBasedExceptionAnalyzer Analyzer(AST->getASTContext(), GEI);

    for (auto &Entry : GEI.USRToFunctionMap) {
      if (Entry.second.IsDefinition) {
        auto Matcher =
            functionDecl(hasName(Entry.second.FunctionName))
                .bind("fn");
        auto Results =
            match(Matcher, AST->getASTContext());
        if (!Results.empty()) {
          const auto *FD =
              cast<FunctionDecl>(Results[0].getNodeAs<FunctionDecl>("fn"));
          Analyzer.analyzeFunction(FD);
        }
      }
    }

    // 4. Apply Noexcept
    NoexceptApplierOptions Opts;
    NoexceptApplierActionFactory Factory(GEI, RewrittenFiles, Opts);
    ASSERT_TRUE(runToolOnCodeWithArgs(Factory.create(), Code, Args, FileName));
  }

  GlobalExceptionInfo GEI;
  llvm::StringMap<std::string> RewrittenFiles;
};

TEST_F(NoexceptApplierTest, SimpleNoexcept) {
  const std::string Code = R"(
    void f() {}
  )";

  runNoexceptApplier(Code);

  ASSERT_FALSE(RewrittenFiles.empty());
  std::string Rewritten = RewrittenFiles.begin()->second;
  EXPECT_TRUE(Rewritten.find("void f()  noexcept {}") != std::string::npos);
}

TEST_F(NoexceptApplierTest, DependentNoexcept) {
  const std::string Code = R"(
    void g() {}
    void f() { g(); }
  )";

  runNoexceptApplier(Code);

  ASSERT_FALSE(RewrittenFiles.empty());
  std::string Rewritten;
  for (const auto &Entry : RewrittenFiles) {
    if (Entry.first().ends_with("input.cpp")) {
      Rewritten = Entry.second;
      break;
    }
  }
  ASSERT_FALSE(Rewritten.empty());

  // Check with more relaxed whitespace matching
  EXPECT_TRUE(Rewritten.find("void g()  noexcept {}") != std::string::npos);
  EXPECT_TRUE(Rewritten.find("void f()  noexcept( noexcept(g())) {") != std::string::npos);
}

TEST_F(NoexceptApplierTest, TransitiveDependentNoexcept) {
  const std::string Code = R"(
    void h() {}
    void g() { h(); }
    void f() { g(); }
  )";

  runNoexceptApplier(Code);

  ASSERT_FALSE(RewrittenFiles.empty());
  std::string Rewritten;
  for (const auto &Entry : RewrittenFiles) {
    if (Entry.first().ends_with("input.cpp")) {
      Rewritten = Entry.second;
      break;
    }
  }
  ASSERT_FALSE(Rewritten.empty());

  EXPECT_TRUE(Rewritten.find("void h()  noexcept {}") != std::string::npos);
  EXPECT_TRUE(Rewritten.find("void g()  noexcept( noexcept(h())) {") != std::string::npos);
  
  // f should depend on both g and h
  EXPECT_TRUE(Rewritten.find("noexcept( noexcept(g()) && noexcept(h()))") != std::string::npos ||
              Rewritten.find("noexcept( noexcept(h()) && noexcept(g()))") != std::string::npos);
}

} // namespace
