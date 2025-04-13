#include "ExceptionAnalyzer.h"
#include "clang/AST/ASTContext.h"
#include "clang/ASTMatchers/ASTMatchFinder.h"
#include "clang/ASTMatchers/ASTMatchers.h"
#include "clang/Frontend/ASTUnit.h"
#include "clang/Tooling/Tooling.h"
#include "gtest/gtest.h"
#include <memory>

using namespace clang;
using namespace clang::ast_matchers;
using namespace clang::tooling;
using namespace clang::exception_scan;

namespace {

// Helper class to run tests
class ExceptionAnalyzerTest : public ::testing::Test {
protected:
  std::unique_ptr<ASTUnit> buildASTFromCode(StringRef Code) {
    std::unique_ptr<ASTUnit> AST = tooling::buildASTFromCodeWithArgs(
        Code, {"-std=c++17", "-fsyntax-only"});
    return AST;
  }

  const FunctionDecl *findFunction(ASTUnit *AST, const std::string &Name) {
    auto Matcher = functionDecl(hasName(Name)).bind("fn");
    auto Results = ast_matchers::match(Matcher, AST->getASTContext());
    if (Results.empty())
      return nullptr;
    return cast<FunctionDecl>(Results[0].getNodeAs<FunctionDecl>("fn"));
  }

  // Common fake exception declarations to be used across tests
  const char *getFakeExceptionDeclarations() {
    return R"(
      // Minimal fake exception declarations
      namespace std {
        class exception {
        public:
          virtual const char* what() const { return "error"; }
          virtual ~exception() {}
        };
        
        class runtime_error : public exception {
        public:
          runtime_error(const char* msg) {}
        };
        
        class logic_error : public exception {
        public:
          logic_error(const char* msg) {}
        };
        
        class bad_alloc : public exception {
        public:
          bad_alloc() {}
        };
      }
    )";
  }
};

// Test basic function analysis
TEST_F(ExceptionAnalyzerTest, BasicFunctionAnalysis) {
  auto AST = buildASTFromCode(R"(
    void noThrow() {}
    void throwInt() { throw 42; }
    void throwString() { throw "error"; }
  )");

  ASSERT_TRUE(AST != nullptr);
  auto &Context = AST->getASTContext();

  ExceptionAnalyzer Analyzer(Context);

  // Test noThrow function
  const FunctionDecl *NoThrow = findFunction(AST.get(), "noThrow");
  ASSERT_TRUE(NoThrow != nullptr);
  auto NoThrowInfo = Analyzer.analyzeFunction(NoThrow);
  EXPECT_EQ(NoThrowInfo.State, ExceptionState::NotThrowing);
  EXPECT_FALSE(NoThrowInfo.ContainsUnknown);
  EXPECT_TRUE(NoThrowInfo.ThrowEvents.empty());

  // Test throwInt function
  const FunctionDecl *ThrowInt = findFunction(AST.get(), "throwInt");
  ASSERT_TRUE(ThrowInt != nullptr);
  auto ThrowIntInfo = Analyzer.analyzeFunction(ThrowInt);
  EXPECT_EQ(ThrowIntInfo.State, ExceptionState::Throwing);
  EXPECT_FALSE(ThrowIntInfo.ContainsUnknown);
  EXPECT_FALSE(ThrowIntInfo.ThrowEvents.empty());

  // Test throwString function
  const FunctionDecl *ThrowString = findFunction(AST.get(), "throwString");
  ASSERT_TRUE(ThrowString != nullptr);
  auto ThrowStringInfo = Analyzer.analyzeFunction(ThrowString);
  EXPECT_EQ(ThrowStringInfo.State, ExceptionState::Throwing);
  EXPECT_FALSE(ThrowStringInfo.ContainsUnknown);
  EXPECT_FALSE(ThrowStringInfo.ThrowEvents.empty());
}

// Test conditional throw analysis
TEST_F(ExceptionAnalyzerTest, ConditionalThrowAnalysis) {
  auto AST = buildASTFromCode(R"(
    void throwIfNull(int* ptr) {
      if (ptr == nullptr) {
        throw "null pointer";
      }
    }

    void throwInLoop(int n) {
      for (int i = 0; i < n; ++i) {
        if (i == 5) {
          throw i;
        }
      }
    }
  )");

  ASSERT_TRUE(AST != nullptr);
  auto &Context = AST->getASTContext();

  ExceptionAnalyzer Analyzer(Context);

  // Test throwIfNull function
  const FunctionDecl *ThrowIfNull = findFunction(AST.get(), "throwIfNull");
  ASSERT_TRUE(ThrowIfNull != nullptr);
  auto ThrowIfNullInfo = Analyzer.analyzeFunction(ThrowIfNull);
  EXPECT_EQ(ThrowIfNullInfo.State, ExceptionState::Throwing);
  EXPECT_FALSE(ThrowIfNullInfo.ContainsUnknown);
  ASSERT_FALSE(ThrowIfNullInfo.ThrowEvents.empty());
  ASSERT_FALSE(ThrowIfNullInfo.ThrowEvents[0].Conditions.empty());
  EXPECT_EQ(ThrowIfNullInfo.ThrowEvents[0].Conditions[0].Condition,
            "ptr == nullptr");

  // Test throwInLoop function
  const FunctionDecl *ThrowInLoop = findFunction(AST.get(), "throwInLoop");
  ASSERT_TRUE(ThrowInLoop != nullptr);
  auto ThrowInLoopInfo = Analyzer.analyzeFunction(ThrowInLoop);
  EXPECT_EQ(ThrowInLoopInfo.State, ExceptionState::Throwing);
  EXPECT_FALSE(ThrowInLoopInfo.ContainsUnknown);
  ASSERT_FALSE(ThrowInLoopInfo.ThrowEvents.empty());
  ASSERT_FALSE(ThrowInLoopInfo.ThrowEvents[0].Conditions.empty());
  EXPECT_EQ(ThrowInLoopInfo.ThrowEvents[0].Conditions[0].Condition, "i == 5");
}

// Test exception type analysis with minimal fake declarations
TEST_F(ExceptionAnalyzerTest, ExceptionTypeAnalysis) {
  std::string Code = getFakeExceptionDeclarations();
  Code += R"(
    void throwRuntime() { throw std::runtime_error("error"); }
    void throwLogic() { throw std::logic_error("error"); }
    void throwMultiple(bool flag) {
      if (flag) {
        throw std::runtime_error("runtime");
      } else {
        throw std::logic_error("logic");
      }
    }
  )";

  auto AST = buildASTFromCode(Code);

  ASSERT_TRUE(AST != nullptr);
  auto &Context = AST->getASTContext();

  ExceptionAnalyzer Analyzer(Context);

  // Test throwRuntime function
  const FunctionDecl *ThrowRuntime = findFunction(AST.get(), "throwRuntime");
  ASSERT_TRUE(ThrowRuntime != nullptr);
  auto ThrowRuntimeInfo = Analyzer.analyzeFunction(ThrowRuntime);
  EXPECT_EQ(ThrowRuntimeInfo.State, ExceptionState::Throwing);
  ASSERT_FALSE(ThrowRuntimeInfo.ThrowEvents.empty());
  EXPECT_TRUE(ThrowRuntimeInfo.ThrowEvents[0].TypeName.find("runtime_error") !=
              std::string::npos);

  // Test throwLogic function
  const FunctionDecl *ThrowLogic = findFunction(AST.get(), "throwLogic");
  ASSERT_TRUE(ThrowLogic != nullptr);
  auto ThrowLogicInfo = Analyzer.analyzeFunction(ThrowLogic);
  EXPECT_EQ(ThrowLogicInfo.State, ExceptionState::Throwing);
  ASSERT_FALSE(ThrowLogicInfo.ThrowEvents.empty());
  EXPECT_TRUE(ThrowLogicInfo.ThrowEvents[0].TypeName.find("logic_error") !=
              std::string::npos);

  // Test throwMultiple function
  const FunctionDecl *ThrowMultiple = findFunction(AST.get(), "throwMultiple");
  ASSERT_TRUE(ThrowMultiple != nullptr);
  auto ThrowMultipleInfo = Analyzer.analyzeFunction(ThrowMultiple);
  EXPECT_EQ(ThrowMultipleInfo.State, ExceptionState::Throwing);
  ASSERT_FALSE(ThrowMultipleInfo.ThrowEvents.empty());
  EXPECT_EQ(ThrowMultipleInfo.ThrowEvents.size(), 2u);
  bool hasRuntimeError = false;
  bool hasLogicError = false;
  for (const auto &Type : ThrowMultipleInfo.ThrowEvents) {
    if (Type.TypeName.find("runtime_error") != std::string::npos)
      hasRuntimeError = true;
    if (Type.TypeName.find("logic_error") != std::string::npos)
      hasLogicError = true;
  }
  EXPECT_TRUE(hasRuntimeError);
  EXPECT_TRUE(hasLogicError);
}

// Test ignored exceptions with minimal fake declarations
TEST_F(ExceptionAnalyzerTest, IgnoredExceptions) {
  std::string Code = getFakeExceptionDeclarations();
  Code += R"(
    void throwBadAlloc() { throw std::bad_alloc(); }
    void throwRuntime() { throw std::runtime_error("error"); }
  )";

  auto AST = buildASTFromCode(Code);

  ASSERT_TRUE(AST != nullptr);
  auto &Context = AST->getASTContext();

  ExceptionAnalyzer Analyzer(Context);
  Analyzer.ignoreBadAlloc(true);
  Analyzer.ignoreExceptions({"runtime_error"});

  // Test throwBadAlloc function
  const FunctionDecl *ThrowBadAlloc = findFunction(AST.get(), "throwBadAlloc");
  ASSERT_TRUE(ThrowBadAlloc != nullptr);
  auto ThrowBadAllocInfo = Analyzer.analyzeFunction(ThrowBadAlloc);
  EXPECT_EQ(ThrowBadAllocInfo.State, ExceptionState::NotThrowing);

  // Test throwRuntime function
  const FunctionDecl *ThrowRuntime = findFunction(AST.get(), "throwRuntime");
  ASSERT_TRUE(ThrowRuntime != nullptr);
  auto ThrowRuntimeInfo = Analyzer.analyzeFunction(ThrowRuntime);
  EXPECT_EQ(ThrowRuntimeInfo.State, ExceptionState::NotThrowing);
}

// Test nested function calls and conditions
TEST_F(ExceptionAnalyzerTest, NestedCallsAndConditions) {
  auto AST = buildASTFromCode(R"(
    void throwIfZero(int x) {
      if (x == 0) throw "zero";
    }
    void throwIfNegative(int x) {
      if (x < 0) throw "negative";
    }
    void complexCheck(int x, int y) {
      throwIfZero(x);
      if (y > 10) {
        throwIfNegative(x);
      }
    }
  )");

  ASSERT_TRUE(AST != nullptr);
  auto &Context = AST->getASTContext();

  ExceptionAnalyzer Analyzer(Context);

  // Test complexCheck function
  const FunctionDecl *ComplexCheck = findFunction(AST.get(), "complexCheck");
  ASSERT_TRUE(ComplexCheck != nullptr);
  auto ComplexInfo = Analyzer.analyzeFunction(ComplexCheck);
  EXPECT_EQ(ComplexInfo.State, ExceptionState::Throwing);
  EXPECT_FALSE(ComplexInfo.ContainsUnknown);

  // Verify conditions are properly tracked
  bool hasZeroCondition = false;
  bool hasNegativeCondition = false;
  for (const auto &ET : ComplexInfo.ThrowEvents) {
    for (const auto &Cond : ET.Conditions) {
      if (Cond.Condition.find("x == 0") != std::string::npos)
        hasZeroCondition = true;
      if (Cond.Condition.find("x < 0") != std::string::npos)
        hasNegativeCondition = true;
    }
  }
  EXPECT_TRUE(hasZeroCondition);
  EXPECT_TRUE(hasNegativeCondition);
}

// Test template function analysis
TEST_F(ExceptionAnalyzerTest, TemplateAnalysis) {
  auto AST = buildASTFromCode(R"(
    template<typename T>
    void throwIfNull(T* ptr) {
      if (!ptr) throw "null pointer";
    }

    template<typename T>
    void processValue(T value) {
      if (value < T{}) throw "negative";
    }

    void useTemplates() {
      int* ptr = nullptr;
      throwIfNull(ptr);
      processValue(-1);
    }
  )");

  ASSERT_TRUE(AST != nullptr);
  auto &Context = AST->getASTContext();

  ExceptionAnalyzer Analyzer(Context);

  // Test useTemplates function which uses template functions
  const FunctionDecl *UseTemplates = findFunction(AST.get(), "useTemplates");
  ASSERT_TRUE(UseTemplates != nullptr);
  auto UseTemplatesInfo = Analyzer.analyzeFunction(UseTemplates);
  EXPECT_EQ(UseTemplatesInfo.State, ExceptionState::Throwing);
  EXPECT_FALSE(UseTemplatesInfo.ContainsUnknown);
  ASSERT_FALSE(UseTemplatesInfo.ThrowEvents.empty());

  // Verify template instantiations are properly analyzed
  bool hasNullCheck = false;
  bool hasNegativeCheck = false;
  for (const auto &ET : UseTemplatesInfo.ThrowEvents) {
    for (const auto &Cond : ET.Conditions) {
      if (Cond.Condition.find("!ptr") != std::string::npos)
        hasNullCheck = true;
      if (Cond.Condition.find("< T{}") != std::string::npos)
        hasNegativeCheck = true;
    }
  }
  EXPECT_TRUE(hasNullCheck);
  EXPECT_TRUE(hasNegativeCheck);
}

// Test try-catch analysis with minimal fake declarations
TEST_F(ExceptionAnalyzerTest, TryCatchAnalysis) {
  std::string Code = getFakeExceptionDeclarations();
  Code += R"(
    void innerThrow() { throw std::runtime_error("inner"); }
    
    void catchAndRethrow() {
      try {
        innerThrow();
      } catch (const std::runtime_error& e) {
        throw std::logic_error(e.what());
      }
    }

    void catchAndHandle() {
      try {
        innerThrow();
      } catch (const std::exception& e) {
        // handled
      }
    }
  )";

  auto AST = buildASTFromCode(Code);

  ASSERT_TRUE(AST != nullptr);
  auto &Context = AST->getASTContext();

  ExceptionAnalyzer Analyzer(Context);

  // Test catchAndRethrow function
  const FunctionDecl *CatchRethrow = findFunction(AST.get(), "catchAndRethrow");
  ASSERT_TRUE(CatchRethrow != nullptr);
  auto CatchRethrowInfo = Analyzer.analyzeFunction(CatchRethrow);
  EXPECT_EQ(CatchRethrowInfo.State, ExceptionState::Throwing);
  ASSERT_FALSE(CatchRethrowInfo.ThrowEvents.empty());
  bool hasLogicError = false;
  for (const auto &ET : CatchRethrowInfo.ThrowEvents) {
    if (ET.TypeName.find("logic_error") != std::string::npos)
      hasLogicError = true;
  }
  EXPECT_TRUE(hasLogicError);

  // Test catchAndHandle function
  const FunctionDecl *CatchHandle = findFunction(AST.get(), "catchAndHandle");
  ASSERT_TRUE(CatchHandle != nullptr);
  auto CatchHandleInfo = Analyzer.analyzeFunction(CatchHandle);
  EXPECT_EQ(CatchHandleInfo.State, ExceptionState::NotThrowing);
}

} // namespace
