#include "ASTBasedExceptionAnalyzer.h"
#include "clang/AST/ASTContext.h"
#include "clang/ASTMatchers/ASTMatchFinder.h"
#include "clang/ASTMatchers/ASTMatchers.h"
#include "clang/Frontend/ASTUnit.h"
#include "clang/Tooling/Tooling.h"
#include "gtest/gtest.h"
#include <memory>
#include <set>

using namespace clang;
using namespace clang::ast_matchers;
using namespace clang::tooling;
using namespace clang::exception_scan;

// Helper class to run tests
class ASTBasedExceptionAnalyzerTest : public ::testing::Test {
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

TEST_F(ASTBasedExceptionAnalyzerTest, BuildParentMapTest) {
  std::string Code = R"cpp(
    void test() {
      if (true) {
        int x = 42;
      } else {
        int y = 43;
      }
    }
  )cpp";

  auto AST = buildASTFromCode(Code);
  ASSERT_TRUE(AST != nullptr);

  const FunctionDecl *Func = findFunction(AST.get(), "test");
  ASSERT_TRUE(Func != nullptr);

  const auto ParentMap =
      ASTBasedExceptionAnalyzer::buildParentMap(Func->getBody());

  // Find the DeclStmt (int x = 42) by traversing the AST
  const DeclStmt *DeclS = nullptr;
  for (const auto *Child : Func->getBody()->children()) {
    if (const auto *If = dyn_cast<IfStmt>(Child)) {
      if (const auto *Block = dyn_cast<CompoundStmt>(If->getThen())) {
        for (const auto *InnerChild : Block->children()) {
          if (const auto *DS = dyn_cast<DeclStmt>(InnerChild)) {
            DeclS = DS;
            break;
          }
        }
      }
    }
  }
  ASSERT_TRUE(DeclS != nullptr);

  // Verify the parent chain from DeclStmt to function body
  const Stmt *Current = DeclS;
  EXPECT_TRUE(llvm::isa<DeclStmt>(Current));

  Current = ParentMap.lookup(Current);
  ASSERT_TRUE(Current != nullptr);
  EXPECT_TRUE(llvm::isa<CompoundStmt>(Current));

  Current = ParentMap.lookup(Current);
  ASSERT_TRUE(Current != nullptr);
  EXPECT_TRUE(llvm::isa<IfStmt>(Current));

  Current = ParentMap.lookup(Current);
  ASSERT_TRUE(Current != nullptr);
  EXPECT_TRUE(llvm::isa<CompoundStmt>(Current));

  // Verify we've reached the function body
  EXPECT_EQ(Current, Func->getBody());

  // Find the DeclStmt (int y = 43) by traversing the AST
  const DeclStmt *DeclS2 = nullptr;
  for (const auto *Child : Func->getBody()->children()) {
    if (const auto *If = dyn_cast<IfStmt>(Child)) {
      if (const auto *Block = dyn_cast<CompoundStmt>(If->getElse())) {
        for (const auto *InnerChild : Block->children()) {
          if (const auto *DS = dyn_cast<DeclStmt>(InnerChild)) {
            DeclS2 = DS;
            break;
          }
        }
      }
    }
  }
  ASSERT_TRUE(DeclS2 != nullptr);

  // Verify the parent chain from DeclStmt to function body
  Current = DeclS2;
  EXPECT_TRUE(llvm::isa<DeclStmt>(Current));

  Current = ParentMap.lookup(Current);
  ASSERT_TRUE(Current != nullptr);
  EXPECT_TRUE(llvm::isa<CompoundStmt>(Current));

  Current = ParentMap.lookup(Current);
  ASSERT_TRUE(Current != nullptr);
  EXPECT_TRUE(llvm::isa<IfStmt>(Current));

  Current = ParentMap.lookup(Current);
  ASSERT_TRUE(Current != nullptr);
  EXPECT_TRUE(llvm::isa<CompoundStmt>(Current));

  // Verify we've reached the function body
  EXPECT_EQ(Current, Func->getBody());

  // Verify that the definition x = 42 is not related to the definition y = 43
  // via the parent map
  EXPECT_NE(ParentMap.lookup(DeclS), ParentMap.lookup(DeclS2));

  // Verify that the first common parent of x = 42 and y = 43 is the if
  // statement
  const Stmt *CommonParent = nullptr;
  const Stmt *Current1 = DeclS;
  const Stmt *Current2 = DeclS2;
  while (Current1 != Current2) {
    CommonParent = Current1;
    Current1 = ParentMap.lookup(Current1);
    Current2 = ParentMap.lookup(Current2);
  }
  ASSERT_TRUE(CommonParent != nullptr);
  EXPECT_TRUE(llvm::isa<CompoundStmt>(CommonParent));

  CommonParent = ParentMap.lookup(CommonParent);
  ASSERT_TRUE(CommonParent != nullptr);
  EXPECT_TRUE(llvm::isa<IfStmt>(CommonParent));
}

TEST_F(ASTBasedExceptionAnalyzerTest, BuildTransitiveParentMapTest) {
  std::string Code = R"cpp(
    void test() {
      if (true) {
        if (false) {
          int x = 42;
        }
        int y = 43;
      }
    }
  )cpp";

  auto AST = buildASTFromCode(Code);
  ASSERT_TRUE(AST != nullptr);

  const FunctionDecl *Func = findFunction(AST.get(), "test");
  ASSERT_TRUE(Func != nullptr);

  const auto ParentMap =
      ASTBasedExceptionAnalyzer::buildParentMap(Func->getBody());
  const auto TransitiveParentMap =
      ASTBasedExceptionAnalyzer::buildTransitiveParentMap(ParentMap,
                                                          Func->getBody());

  // Find the DeclStmt nodes (x = 42 and y = 43)
  const DeclStmt *DeclX = nullptr;
  const DeclStmt *DeclY = nullptr;
  for (const auto *Child : Func->getBody()->children()) {
    if (const auto *OuterIf = dyn_cast<IfStmt>(Child)) {
      if (const auto *OuterBlock = dyn_cast<CompoundStmt>(OuterIf->getThen())) {
        for (const auto *OuterChild : OuterBlock->children()) {
          if (const auto *InnerIf = dyn_cast<IfStmt>(OuterChild)) {
            if (const auto *InnerBlock =
                    dyn_cast<CompoundStmt>(InnerIf->getThen())) {
              for (const auto *InnerChild : InnerBlock->children()) {
                if (const auto *DS = dyn_cast<DeclStmt>(InnerChild)) {
                  DeclX = DS;
                }
              }
            }
          } else if (const auto *DS = dyn_cast<DeclStmt>(OuterChild)) {
            DeclY = DS;
          }
        }
      }
    }
  }
  ASSERT_TRUE(DeclX != nullptr);
  ASSERT_TRUE(DeclY != nullptr);

  // Verify x has more ancestors than y (deeper nesting)
  auto XAncestors = TransitiveParentMap.lookup(DeclX);
  auto YAncestors = TransitiveParentMap.lookup(DeclY);
  EXPECT_GT(XAncestors.size(), YAncestors.size());

  // Verify common ancestors
  std::set<const Stmt *> CommonAncestors;
  for (const auto *XAncestor : XAncestors) {
    if (YAncestors.contains(XAncestor)) {
      CommonAncestors.insert(XAncestor);
    }
  }

  // Should have at least two common ancestors (outer if's compound stmt and
  // function body)
  ASSERT_GE(CommonAncestors.size(), 2u);

  // First common ancestor should be compound statement, last should be function
  // body
  const auto *FirstCommon = *CommonAncestors.begin();
  const auto *LastCommon = *CommonAncestors.rbegin();
  EXPECT_TRUE(llvm::isa<CompoundStmt>(FirstCommon));
  EXPECT_EQ(LastCommon, Func->getBody());
}

// Test nested try-catch blocks with inner try-catch in outer catch block
TEST_F(ASTBasedExceptionAnalyzerTest, OrderingNestedTryCatchInCatchBlock) {
  std::string Code = getFakeExceptionDeclarations();
  Code += R"(
    void test() {
      try {  // Outer try
        throw "first error";
      } catch (const char*) {
        try {  // Inner try
          throw std::runtime_error("inner");
        } catch (const std::exception& e) {
          // Handle inner exception
        }
      }
    }
  )";

  std::unique_ptr<ASTUnit> AST = buildASTFromCode(Code);
  ASSERT_TRUE(AST);
  ASTContext &Context = AST->getASTContext();

  const FunctionDecl *Func = findFunction(AST.get(), "test");
  ASSERT_TRUE(Func);

  // Find all try-catch blocks
  ASTBasedExceptionAnalyzer::AnalysisOrderedTryCatches TryCatches =
      ASTBasedExceptionAnalyzer::findTryCatchBlocks(Func->getBody(),
                                                    Context.getSourceManager());
  ASSERT_EQ(TryCatches.size(), 2u);

  // Verify inner try is analyzed before outer try by checking source locations
  SourceLocation InnerLoc = TryCatches.begin()->Loc;
  SourceLocation OuterLoc = (++TryCatches.begin())->Loc;
  EXPECT_GT(InnerLoc, OuterLoc);
}

TEST_F(ASTBasedExceptionAnalyzerTest, OrderingMultipleNestedTryCatchBlocks) {
  std::string Code = getFakeExceptionDeclarations();
  Code += R"(
    void test() {
      try {  // try1 (outermost, depth 0)
        try {  // try2 (in try block, depth 1)
          throw std::runtime_error("error2");
        } catch (...) {}

        try {  // try3 (in try block, depth 1)
          throw std::runtime_error("error3");
        } catch (...) {}

      } catch (const std::runtime_error&) {
        try {  // try4 (in first catch block, depth 1)
          throw std::runtime_error("error4");
        } catch (...) {
          try {  // try7 (nested in catch, depth 2)
            throw std::runtime_error("error7");
          } catch (...) {}
        }

        try {  // try5 (in first catch block, depth 1)
          throw std::runtime_error("error5");
        } catch (...) {}

      } catch (const std::exception&) {
        try {  // try6 (in second catch block, depth 1)
          throw std::runtime_error("error6");
        } catch (...) {}
      }
    }
  )";

  std::unique_ptr<ASTUnit> AST = buildASTFromCode(Code);
  ASSERT_TRUE(AST);
  ASTContext &Context = AST->getASTContext();

  const FunctionDecl *Func = findFunction(AST.get(), "test");
  ASSERT_TRUE(Func);

  // Find all try-catch blocks
  ASTBasedExceptionAnalyzer::AnalysisOrderedTryCatches TryCatches =
      ASTBasedExceptionAnalyzer::findTryCatchBlocks(Func->getBody(),
                                                    Context.getSourceManager());

  // Print out all try blocks found
  llvm::errs() << "Found " << TryCatches.size() << " try blocks:\n";
  for (const auto &TC : TryCatches) {
    llvm::errs() << "Try block at "
                 << TC.Loc.printToString(AST->getSourceManager()) << "\n";
  }

  ASSERT_EQ(TryCatches.size(), 7u);
  {
    auto TryCatchesIt = TryCatches.begin();
    ASSERT_EQ(TryCatchesIt->Depth, 2u);
    ++TryCatchesIt;
    ASSERT_EQ(TryCatchesIt->Depth, 1u);
    ++TryCatchesIt;
    ASSERT_EQ(TryCatchesIt->Depth, 1u);
    ++TryCatchesIt;
    ASSERT_EQ(TryCatchesIt->Depth, 1u);
    ++TryCatchesIt;
    ASSERT_EQ(TryCatchesIt->Depth, 1u);
    ++TryCatchesIt;
    ASSERT_EQ(TryCatchesIt->Depth, 1u);
    ++TryCatchesIt;
    ASSERT_EQ(TryCatchesIt->Depth, 0u);
  }

  // Group try blocks by depth
  std::map<unsigned,
           std::vector<const ASTBasedExceptionAnalyzer::TryCatchInfo *>>
      BlocksByDepth;
  for (const auto &TC : TryCatches) {
    BlocksByDepth[TC.Depth].push_back(&TC);
  }

  // Verify source location ordering within each depth
  for (const auto &[Depth, Blocks] : BlocksByDepth) {
    for (size_t i = 0; i < Blocks.size() - 1; ++i) {
      SourceLocation CurrLoc = Blocks[i]->TryStmt->getBeginLoc();
      SourceLocation NextLoc = Blocks[i + 1]->TryStmt->getBeginLoc();
      EXPECT_LT(CurrLoc, NextLoc)
          << "At depth " << Depth << ", try block at index " << i
          << " should appear earlier in source than try block at index "
          << (i + 1);
    }
  }

  // Verify depths
  std::map<const CXXTryStmt *, unsigned> TryDepths;
  for (const auto &TC : TryCatches) {
    TryDepths[TC.TryStmt] = TC.Depth;
  }

  // Verify each try block has the expected depth
  {
    auto TryCatchesIt = TryCatches.begin();
    EXPECT_EQ(TryCatchesIt->Depth, 2u); // try7
    ++TryCatchesIt;
    EXPECT_EQ(TryCatchesIt->Depth, 1u); // try2
    ++TryCatchesIt;
    EXPECT_EQ(TryCatchesIt->Depth, 1u); // try3
    ++TryCatchesIt;
    EXPECT_EQ(TryCatchesIt->Depth, 1u); // try4
    ++TryCatchesIt;
    EXPECT_EQ(TryCatchesIt->Depth, 1u); // try5
    ++TryCatchesIt;
    EXPECT_EQ(TryCatchesIt->Depth, 1u); // try6
    ++TryCatchesIt;
    EXPECT_EQ(TryCatchesIt->Depth, 0u); // try1
  }
}

// Test basic function analysis
TEST_F(ASTBasedExceptionAnalyzerTest, BasicFunctionAnalysis) {
  auto AST = buildASTFromCode(R"(
    void noThrow() {}
    void throwInt() { throw 42; }
    void throwString() { throw "error"; }
  )");

  ASSERT_TRUE(AST != nullptr);
  auto &Context = AST->getASTContext();

  GlobalExceptionInfo GEI;
  ASTBasedExceptionAnalyzer Analyzer(Context, GEI);

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

// Test try-catch analysis
TEST_F(ASTBasedExceptionAnalyzerTest, TryCatchAnalysis) {
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

  GlobalExceptionInfo GEI;
  ASTBasedExceptionAnalyzer Analyzer(Context, GEI);

  // Test catchAndRethrow function
  const FunctionDecl *CatchRethrow = findFunction(AST.get(), "catchAndRethrow");
  ASSERT_TRUE(CatchRethrow != nullptr);
  auto CatchRethrowInfo = Analyzer.analyzeFunction(CatchRethrow);
  EXPECT_EQ(CatchRethrowInfo.State, ExceptionState::Throwing);
  ASSERT_FALSE(CatchRethrowInfo.ThrowEvents.empty());
  bool hasLogicError = false;
  for (const auto &ET : CatchRethrowInfo.ThrowEvents) {
    if (ET.Type.getAsString().find("logic_error") != std::string::npos)
      hasLogicError = true;
  }
  EXPECT_TRUE(hasLogicError);

  // Test catchAndHandle function
  const FunctionDecl *CatchHandle = findFunction(AST.get(), "catchAndHandle");
  ASSERT_TRUE(CatchHandle != nullptr);
  auto CatchHandleInfo = Analyzer.analyzeFunction(CatchHandle);
  EXPECT_EQ(CatchHandleInfo.State, ExceptionState::NotThrowing);
}

// Test ignored exceptions
TEST_F(ASTBasedExceptionAnalyzerTest, IgnoredExceptions) {
  std::string Code = getFakeExceptionDeclarations();
  Code += R"(
    void throwBadAlloc() { throw std::bad_alloc(); }
    void throwRuntime() { throw std::runtime_error("error"); }
  )";

  auto AST = buildASTFromCode(Code);

  ASSERT_TRUE(AST != nullptr);
  auto &Context = AST->getASTContext();

  GlobalExceptionInfo GEI;
  ASTBasedExceptionAnalyzer Analyzer(Context, GEI);
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

TEST_F(ASTBasedExceptionAnalyzerTest, BuildTryCatchHierarchyTest) {
  std::string Code = R"cpp(
    void test() {
      try {  // try1 (outermost)
        try {  // try2
          int x = 1;
        } catch (...) {}
        
        if (true) {
          try {  // try3
            int y = 2;
          } catch (...) {}
        }
        
        try {  // try4
          try {  // try5
            int z = 3;
          } catch (...) {}
        } catch (...) {}
      } catch (...) {}
    }
  )cpp";

  auto AST = buildASTFromCode(Code);
  ASSERT_TRUE(AST != nullptr);

  const FunctionDecl *Func = findFunction(AST.get(), "test");
  ASSERT_TRUE(Func != nullptr);

  // Find all try-catch blocks
  ASTBasedExceptionAnalyzer::AnalysisOrderedTryCatches TryCatches =
      ASTBasedExceptionAnalyzer::findTryCatchBlocks(Func->getBody(),
                                                    AST->getSourceManager());
  ASSERT_EQ(TryCatches.size(), 5u);

  // The blocks should be ordered by depth (higher depth first) and then by
  // source location
  auto It = TryCatches.begin();

  // try5 should be first (depth 2)
  const auto &Try5 = *It++;
  EXPECT_EQ(Try5.Depth, 2u);
  EXPECT_TRUE(Try5.InnerTryCatches.empty());

  // try2, try3, try4 should follow (depth 1)
  const auto &Try2 = *It++;
  EXPECT_EQ(Try2.Depth, 1u);
  EXPECT_TRUE(Try2.InnerTryCatches.empty());

  const auto &Try3 = *It++;
  EXPECT_EQ(Try3.Depth, 1u);
  EXPECT_TRUE(Try3.InnerTryCatches.empty());

  const auto &Try4 = *It++;
  EXPECT_EQ(Try4.Depth, 1u);
  EXPECT_EQ(Try4.InnerTryCatches.size(), 1u);
  EXPECT_EQ(Try4.InnerTryCatches[0].Depth, 2u); // Contains try5

  // try1 should be last (depth 0)
  const auto &Try1 = *It++;
  EXPECT_EQ(Try1.Depth, 0u);
  EXPECT_EQ(Try1.InnerTryCatches.size(), 3u); // Contains try2, try3, try4

  // Verify source order of try1's inner blocks
  EXPECT_LT(Try1.InnerTryCatches[0].Loc, Try1.InnerTryCatches[1].Loc);
  EXPECT_LT(Try1.InnerTryCatches[1].Loc, Try1.InnerTryCatches[2].Loc);

  // Verify we've processed all blocks
  EXPECT_EQ(It, TryCatches.end());
}

// Test builtin function analysis
TEST_F(ASTBasedExceptionAnalyzerTest, BuiltinFunctionAnalysis) {
  auto AST = buildASTFromCode(R"(
    int uses_builtin(int x) {
      return __builtin_abs(x);
    }
    
    int uses_builtin_throw(int x) {
      if (x < 0) throw "negative";
      return __builtin_abs(x);
    }
  )");

  ASSERT_TRUE(AST != nullptr);
  auto &Context = AST->getASTContext();

  GlobalExceptionInfo GEI;
  ASTBasedExceptionAnalyzer Analyzer(Context, GEI);

  // Test uses_builtin function
  const FunctionDecl *UsesBuiltin = findFunction(AST.get(), "uses_builtin");
  ASSERT_TRUE(UsesBuiltin != nullptr);
  auto UsesBuiltinInfo = Analyzer.analyzeFunction(UsesBuiltin);
  EXPECT_EQ(UsesBuiltinInfo.State, ExceptionState::NotThrowing);
  EXPECT_FALSE(UsesBuiltinInfo.ContainsUnknown);
  EXPECT_TRUE(UsesBuiltinInfo.ThrowEvents.empty());

  // Test uses_builtin_throw function
  const FunctionDecl *UsesBuiltinThrow =
      findFunction(AST.get(), "uses_builtin_throw");
  ASSERT_TRUE(UsesBuiltinThrow != nullptr);
  auto UsesBuiltinThrowInfo = Analyzer.analyzeFunction(UsesBuiltinThrow);
  EXPECT_EQ(UsesBuiltinThrowInfo.State, ExceptionState::Throwing);
  EXPECT_FALSE(UsesBuiltinThrowInfo.ContainsUnknown);
  EXPECT_FALSE(UsesBuiltinThrowInfo.ThrowEvents.empty());
}

// Test nested function calls
TEST_F(ASTBasedExceptionAnalyzerTest, NestedFunctionCalls) {
  auto AST = buildASTFromCode(R"(
    void inner() { throw "inner"; }
    
    void middle() {
      inner();
    }
    
    void outer() {
      try {
        middle();
      } catch (...) {
        // handled
      }
    }
  )");

  ASSERT_TRUE(AST != nullptr);
  auto &Context = AST->getASTContext();

  GlobalExceptionInfo GEI;
  ASTBasedExceptionAnalyzer Analyzer(Context, GEI);

  // Test inner function
  const FunctionDecl *Inner = findFunction(AST.get(), "inner");
  ASSERT_TRUE(Inner != nullptr);
  auto InnerInfo = Analyzer.analyzeFunction(Inner);
  EXPECT_EQ(InnerInfo.State, ExceptionState::Throwing);
  EXPECT_FALSE(InnerInfo.ContainsUnknown);
  EXPECT_FALSE(InnerInfo.ThrowEvents.empty());

  // Test middle function
  const FunctionDecl *Middle = findFunction(AST.get(), "middle");
  ASSERT_TRUE(Middle != nullptr);
  auto MiddleInfo = Analyzer.analyzeFunction(Middle);
  EXPECT_EQ(MiddleInfo.State, ExceptionState::Throwing);
  EXPECT_FALSE(MiddleInfo.ContainsUnknown);
  EXPECT_FALSE(MiddleInfo.ThrowEvents.empty());

  // Test outer function
  const FunctionDecl *Outer = findFunction(AST.get(), "outer");
  ASSERT_TRUE(Outer != nullptr);
  auto OuterInfo = Analyzer.analyzeFunction(Outer);
  EXPECT_EQ(OuterInfo.State, ExceptionState::NotThrowing);
  EXPECT_FALSE(OuterInfo.ContainsUnknown);
  EXPECT_TRUE(OuterInfo.ThrowEvents.empty());
}

// Test nested try-catch blocks with inner try-catch in outer try block
TEST_F(ASTBasedExceptionAnalyzerTest, NestedTryCatchInTryBlock) {
  auto AST = buildASTFromCode(R"(
    void inner() {
      throw 42;
    }
    void outer() {
      try {
        try {
          inner();
        } catch (int) {
          // Handle inner exception
        }
        throw "outer error";
      } catch (const char*) {
        // Handle outer exception
      }
    }
  )");

  ASSERT_TRUE(AST != nullptr);
  auto &Context = AST->getASTContext();

  GlobalExceptionInfo GEI;
  ASTBasedExceptionAnalyzer Analyzer(Context, GEI);

  // Test inner function
  const FunctionDecl *Inner = findFunction(AST.get(), "inner");
  ASSERT_TRUE(Inner != nullptr);
  auto InnerInfo = Analyzer.analyzeFunction(Inner);
  EXPECT_EQ(InnerInfo.State, ExceptionState::Throwing);
  ASSERT_EQ(InnerInfo.ThrowEvents.size(), 1u);
  EXPECT_EQ(InnerInfo.ThrowEvents[0].Type.getAsString(), "int");

  // Test outer function
  const FunctionDecl *Outer = findFunction(AST.get(), "outer");
  ASSERT_TRUE(Outer != nullptr);
  auto OuterInfo = Analyzer.analyzeFunction(Outer);
  EXPECT_EQ(OuterInfo.State, ExceptionState::NotThrowing);
  EXPECT_TRUE(OuterInfo.ThrowEvents.empty());
}

// Test pointer type and nullptr_t handling
TEST_F(ASTBasedExceptionAnalyzerTest, PointerAndNullptrHandling) {
  std::string Code = getFakeExceptionDeclarations();
  Code += R"(
    class MyException {};
    void throwNullptr() { throw nullptr; }
    void throwExceptionPtr() { throw new MyException(); }

    void catchPointers() {
      try {
        throwNullptr();
      } catch (MyException*) {
        // Should catch nullptr
      }

      try {
        throwExceptionPtr();
      } catch (const MyException*) {
        // Should catch pointer
      }

      try {
        throw new std::runtime_error("error");
      } catch (const std::exception* e) {
        // Should catch derived class pointer
      }
    }
  )";

  auto AST = buildASTFromCode(Code);
  ASSERT_TRUE(AST != nullptr);
  auto &Context = AST->getASTContext();

  GlobalExceptionInfo GEI;
  ASTBasedExceptionAnalyzer Analyzer(Context, GEI);

  const FunctionDecl *CatchPointers = findFunction(AST.get(), "catchPointers");
  ASSERT_TRUE(CatchPointers != nullptr);
  auto CatchPointersInfo = Analyzer.analyzeFunction(CatchPointers);
  EXPECT_EQ(CatchPointersInfo.State, ExceptionState::NotThrowing);
}

// Test ambiguous and non-public inheritance
TEST_F(ASTBasedExceptionAnalyzerTest, InheritanceEdgeCases) {
  std::string Code = R"(
    class Base {
    public:
      virtual ~Base() {}
    };
    class Middle1 : public Base {};    // First path of diamond
    class Middle2 : public Base {};    // Second path of diamond
    class Derived : public Middle1,    // Diamond creates ambiguity
                   public Middle2 {};   // when catching as Base

    class Base1 {
    public:
      virtual ~Base1() {}
    };
    class Base2 {
    public:
      virtual ~Base2() {}
    };
    class Derived1 : public Base1, public Base2 {};  // Multiple inheritance
    class Derived2 : private Base1 {};               // Private inheritance
    class Derived3 : public Derived2 {};             // Indirect private inheritance

    void throwDerived1() { throw Derived1(); }
    void throwDerived2() { throw Derived2(); }
    void throwDerived3() { throw Derived3(); }
    void throwDerivedAmbiguous() { throw Derived(); }

    void catchAmbiguous() {
      try {
        throwDerived1();
      } catch (const Base1&) {
        // Should catch (unambiguous path)
      }
    }

    void catchPrivate() {
      try {
        throwDerived2();
      } catch (const Base1&) {
        // Should not catch (private inheritance)
      }
    }

    void catchIndirectPrivate() {
      try {
        throwDerived3();
      } catch (const Base1&) {
        // Should not catch (indirect private inheritance)
      }
    }

    void catchDiamondAmbiguous() {
      try {
        throwDerivedAmbiguous();
      } catch (const Base&) {
        // Should not catch (ambiguous inheritance)
      }
    }
  )";

  auto AST = buildASTFromCode(Code);
  ASSERT_TRUE(AST != nullptr);
  auto &Context = AST->getASTContext();

  GlobalExceptionInfo GEI;
  ASTBasedExceptionAnalyzer Analyzer(Context, GEI);

  const FunctionDecl *CatchAmbiguous =
      findFunction(AST.get(), "catchAmbiguous");
  ASSERT_TRUE(CatchAmbiguous != nullptr);
  auto CatchAmbiguousInfo = Analyzer.analyzeFunction(CatchAmbiguous);
  EXPECT_EQ(CatchAmbiguousInfo.State, ExceptionState::NotThrowing);

  const FunctionDecl *CatchPrivate = findFunction(AST.get(), "catchPrivate");
  ASSERT_TRUE(CatchPrivate != nullptr);
  auto CatchPrivateInfo = Analyzer.analyzeFunction(CatchPrivate);
  EXPECT_EQ(CatchPrivateInfo.State, ExceptionState::Throwing);

  const FunctionDecl *CatchIndirectPrivate =
      findFunction(AST.get(), "catchIndirectPrivate");
  ASSERT_TRUE(CatchIndirectPrivate != nullptr);
  auto CatchIndirectPrivateInfo =
      Analyzer.analyzeFunction(CatchIndirectPrivate);
  EXPECT_EQ(CatchIndirectPrivateInfo.State, ExceptionState::Throwing);

  const FunctionDecl *CatchDiamondAmbiguous =
      findFunction(AST.get(), "catchDiamondAmbiguous");
  ASSERT_TRUE(CatchDiamondAmbiguous != nullptr);
  auto CatchDiamondAmbiguousInfo =
      Analyzer.analyzeFunction(CatchDiamondAmbiguous);
  EXPECT_EQ(CatchDiamondAmbiguousInfo.State, ExceptionState::Throwing);
}

// Test rethrow expressions
TEST_F(ASTBasedExceptionAnalyzerTest, RethrowExpressions) {
  std::string Code = getFakeExceptionDeclarations();
  Code += R"(
    void rethrowInCatch() {
      try {
        throw std::runtime_error("original");
      } catch (...) {
        throw;  // Rethrow current exception
      }
    }

    void rethrowNested() {
      try {
        try {
          throw std::runtime_error("nested");
        } catch (const std::exception& e) {
          throw;  // Rethrow from inner catch
        }
      } catch (...) {
        // Handle all
      }
    }

    void rethrowTransformed() {
      try {
        throw std::runtime_error("original");
      } catch (const std::exception& e) {
        try {
          throw;  // Rethrow runtime_error
        } catch (const std::runtime_error&) {
          // Catch specific type after rethrow
        }
      }
    }
  )";

  auto AST = buildASTFromCode(Code);
  ASSERT_TRUE(AST != nullptr);
  auto &Context = AST->getASTContext();

  GlobalExceptionInfo GEI;
  ASTBasedExceptionAnalyzer Analyzer(Context, GEI);

  const FunctionDecl *RethrowInCatch =
      findFunction(AST.get(), "rethrowInCatch");
  ASSERT_TRUE(RethrowInCatch != nullptr);
  auto RethrowInCatchInfo = Analyzer.analyzeFunction(RethrowInCatch);
  EXPECT_EQ(RethrowInCatchInfo.State, ExceptionState::Throwing);
  ASSERT_FALSE(RethrowInCatchInfo.ThrowEvents.empty());
  EXPECT_TRUE(RethrowInCatchInfo.ThrowEvents[0].Type.getAsString().find(
                  "runtime_error") != std::string::npos);

  const FunctionDecl *RethrowNested = findFunction(AST.get(), "rethrowNested");
  ASSERT_TRUE(RethrowNested != nullptr);
  auto RethrowNestedInfo = Analyzer.analyzeFunction(RethrowNested);
  EXPECT_EQ(RethrowNestedInfo.State, ExceptionState::NotThrowing);

  const FunctionDecl *RethrowTransformed =
      findFunction(AST.get(), "rethrowTransformed");
  ASSERT_TRUE(RethrowTransformed != nullptr);
  auto RethrowTransformedInfo = Analyzer.analyzeFunction(RethrowTransformed);
  EXPECT_EQ(RethrowTransformedInfo.State, ExceptionState::NotThrowing);
}

// Test exception specification handling
TEST_F(ASTBasedExceptionAnalyzerTest, ExceptionSpecificationHandling) {
  auto AST = buildASTFromCode(R"(
    // Function with no exception specification
    void noSpec() { throw 42; }
    
    // Function with noexcept(false) specification
    void noexceptFalse() noexcept(false) { throw 42; }
    
    // Function with noexcept(true) specification but actually throws
    void noexceptTrueViolation() noexcept(true) { throw 42; }
    
    // Function with noexcept(true) specification and doesn't throw
    void noexceptTrue() noexcept(true) { int x = 42; }
    
    // Function with noexcept specification and doesn't throw
    void noexceptNoThrow() noexcept { int x = 42; }
    
    // Function with throw() specification (deprecated but still valid)
    void throwEmpty() throw() { int x = 42; }
    
    // Function with throw(...) specification
    void throwEllipsis() throw(...) { throw 42; }
    
    // Function with throw(type) specification
    void throwIntSpec() throw(int) { throw 42; }
    
    // Function with throw(type) specification but throws different type
    void throwIntSpecViolation() throw(int) { throw "error"; }
  )");

  ASSERT_TRUE(AST != nullptr);
  auto &Context = AST->getASTContext();

  GlobalExceptionInfo GEI;
  ASTBasedExceptionAnalyzer Analyzer(Context, GEI);

  // Test noSpec function
  const FunctionDecl *NoSpec = findFunction(AST.get(), "noSpec");
  ASSERT_TRUE(NoSpec != nullptr);
  auto NoSpecInfo = Analyzer.analyzeFunction(NoSpec);
  EXPECT_EQ(NoSpecInfo.State, ExceptionState::Throwing);
  EXPECT_EQ(NoSpecInfo.ExceptionSpecType, EST_None);
  EXPECT_FALSE(NoSpecInfo.ThrowEvents.empty());

  // Test noexceptFalse function
  const FunctionDecl *NoexceptFalse = findFunction(AST.get(), "noexceptFalse");
  ASSERT_TRUE(NoexceptFalse != nullptr);
  auto NoexceptFalseInfo = Analyzer.analyzeFunction(NoexceptFalse);
  EXPECT_EQ(NoexceptFalseInfo.State, ExceptionState::Throwing);
  EXPECT_EQ(NoexceptFalseInfo.ExceptionSpecType, EST_NoexceptFalse);
  EXPECT_FALSE(NoexceptFalseInfo.ThrowEvents.empty());

  // Test noexceptTrueViolation function
  const FunctionDecl *NoexceptTrueViolation =
      findFunction(AST.get(), "noexceptTrueViolation");
  ASSERT_TRUE(NoexceptTrueViolation != nullptr);
  auto NoexceptTrueViolationInfo =
      Analyzer.analyzeFunction(NoexceptTrueViolation);
  EXPECT_EQ(NoexceptTrueViolationInfo.State, ExceptionState::Throwing);
  EXPECT_EQ(NoexceptTrueViolationInfo.ExceptionSpecType, EST_NoexceptTrue);
  EXPECT_FALSE(NoexceptTrueViolationInfo.ThrowEvents.empty());

  // Test noexceptTrue function
  const FunctionDecl *NoexceptTrue = findFunction(AST.get(), "noexceptTrue");
  ASSERT_TRUE(NoexceptTrue != nullptr);
  auto NoexceptTrueInfo = Analyzer.analyzeFunction(NoexceptTrue);
  EXPECT_EQ(NoexceptTrueInfo.State, ExceptionState::NotThrowing);
  EXPECT_EQ(NoexceptTrueInfo.ExceptionSpecType, EST_NoexceptTrue);
  EXPECT_TRUE(NoexceptTrueInfo.ThrowEvents.empty());

  // Test noexceptNoThrow function
  const FunctionDecl *NoexceptNoThrow =
      findFunction(AST.get(), "noexceptNoThrow");
  ASSERT_TRUE(NoexceptNoThrow != nullptr);
  auto NoexceptNoThrowInfo = Analyzer.analyzeFunction(NoexceptNoThrow);
  EXPECT_EQ(NoexceptNoThrowInfo.State, ExceptionState::NotThrowing);
  EXPECT_EQ(NoexceptNoThrowInfo.ExceptionSpecType, EST_BasicNoexcept);
  EXPECT_TRUE(NoexceptNoThrowInfo.ThrowEvents.empty());

  // Test throwEmpty function
  const FunctionDecl *ThrowEmpty = findFunction(AST.get(), "throwEmpty");
  ASSERT_TRUE(ThrowEmpty != nullptr);
  auto ThrowEmptyInfo = Analyzer.analyzeFunction(ThrowEmpty);
  EXPECT_EQ(ThrowEmptyInfo.State, ExceptionState::NotThrowing);
  EXPECT_EQ(ThrowEmptyInfo.ExceptionSpecType, EST_DynamicNone);
  EXPECT_TRUE(ThrowEmptyInfo.ThrowEvents.empty());

  // Test throwEllipsis function
  const FunctionDecl *ThrowEllipsis = findFunction(AST.get(), "throwEllipsis");
  ASSERT_TRUE(ThrowEllipsis != nullptr);
  auto ThrowEllipsisInfo = Analyzer.analyzeFunction(ThrowEllipsis);
  EXPECT_EQ(ThrowEllipsisInfo.State, ExceptionState::Throwing);
  EXPECT_EQ(ThrowEllipsisInfo.ExceptionSpecType, EST_MSAny);
  EXPECT_FALSE(ThrowEllipsisInfo.ThrowEvents.empty());

  // Test throwIntSpec function
  const FunctionDecl *ThrowIntSpec = findFunction(AST.get(), "throwIntSpec");
  ASSERT_TRUE(ThrowIntSpec != nullptr);
  auto ThrowIntSpecInfo = Analyzer.analyzeFunction(ThrowIntSpec);
  EXPECT_EQ(ThrowIntSpecInfo.State, ExceptionState::Throwing);
  EXPECT_EQ(ThrowIntSpecInfo.ExceptionSpecType, EST_Dynamic);
  EXPECT_FALSE(ThrowIntSpecInfo.ThrowEvents.empty());

  // Test throwIntSpecViolation function
  const FunctionDecl *ThrowIntSpecViolation =
      findFunction(AST.get(), "throwIntSpecViolation");
  ASSERT_TRUE(ThrowIntSpecViolation != nullptr);
  auto ThrowIntSpecViolationInfo =
      Analyzer.analyzeFunction(ThrowIntSpecViolation);
  EXPECT_EQ(ThrowIntSpecViolationInfo.State, ExceptionState::Throwing);
  EXPECT_EQ(ThrowIntSpecViolationInfo.ExceptionSpecType, EST_Dynamic);
  EXPECT_FALSE(ThrowIntSpecViolationInfo.ThrowEvents.empty());
}

// Test exception specification in function calls
TEST_F(ASTBasedExceptionAnalyzerTest, ExceptionSpecificationInFunctionCalls) {
  auto AST = buildASTFromCode(R"(
    // Function with noexcept specification
    void noexceptFunc() noexcept(true) { int x = 42; }
    
    // Function that calls a noexcept function
    void callsNoexcept() {
      noexceptFunc();
    }
    
    // Function with noexcept specification but actually throws
    void noexceptViolation() noexcept(true) { throw 42; }
    
    // Function that calls a noexcept function that violates its specification
    void callsNoexceptViolation() {
      noexceptViolation();
    }
    
    // Function with no exception specification
    void noSpecFunc() { throw 42; }
    
    // Function with noexcept specification that calls a function without exception specification
    void noexceptCallsNoSpec() noexcept(true) {
      noSpecFunc();
    }
  )");

  ASSERT_TRUE(AST != nullptr);
  auto &Context = AST->getASTContext();

  GlobalExceptionInfo GEI;
  ASTBasedExceptionAnalyzer Analyzer(Context, GEI);

  // Test callsNoexcept function
  const FunctionDecl *CallsNoexcept = findFunction(AST.get(), "callsNoexcept");
  ASSERT_TRUE(CallsNoexcept != nullptr);
  auto CallsNoexceptInfo = Analyzer.analyzeFunction(CallsNoexcept);
  EXPECT_EQ(CallsNoexceptInfo.State, ExceptionState::NotThrowing);
  EXPECT_EQ(CallsNoexceptInfo.ExceptionSpecType, EST_None);
  EXPECT_TRUE(CallsNoexceptInfo.ThrowEvents.empty());

  // Test callsNoexceptViolation function
  const FunctionDecl *CallsNoexceptViolation =
      findFunction(AST.get(), "callsNoexceptViolation");
  ASSERT_TRUE(CallsNoexceptViolation != nullptr);
  auto CallsNoexceptViolationInfo =
      Analyzer.analyzeFunction(CallsNoexceptViolation);
  EXPECT_EQ(CallsNoexceptViolationInfo.State, ExceptionState::Throwing);
  EXPECT_EQ(CallsNoexceptViolationInfo.ExceptionSpecType, EST_None);
  EXPECT_FALSE(CallsNoexceptViolationInfo.ThrowEvents.empty());

  // Test noexceptCallsNoSpec function
  const FunctionDecl *NoexceptCallsNoSpec =
      findFunction(AST.get(), "noexceptCallsNoSpec");
  ASSERT_TRUE(NoexceptCallsNoSpec != nullptr);
  auto NoexceptCallsNoSpecInfo = Analyzer.analyzeFunction(NoexceptCallsNoSpec);
  EXPECT_EQ(NoexceptCallsNoSpecInfo.State, ExceptionState::Throwing);
  EXPECT_EQ(NoexceptCallsNoSpecInfo.ExceptionSpecType, EST_NoexceptTrue);
  EXPECT_FALSE(NoexceptCallsNoSpecInfo.ThrowEvents.empty());
}

// Test throw expression inside a lambda
TEST_F(ASTBasedExceptionAnalyzerTest, LambdaThrowTest) {
  auto AST = buildASTFromCode(R"(
    void function_with_lambda_throw() {
      auto lambda = []() {
        throw 1;
      };
      lambda(); // Call the lambda
    }

    void function_with_immediately_invoked_lambda_throw() {
      []() {
        throw 1;
      }();
    }

    void function_with_unused_lambda_throw() {
      auto lambda = []() {
        throw 1;
      };
      // Lambda defined but not called
    }

    void function_with_noexcept_lambda() {
      auto lambda = []() noexcept {
        // Does not throw
      };
      lambda();
    }
  )");

  ASSERT_TRUE(AST != nullptr);
  auto &Context = AST->getASTContext();

  GlobalExceptionInfo GEI;
  ASTBasedExceptionAnalyzer Analyzer(Context, GEI);

  // Test function_with_lambda_throw
  const FunctionDecl *LambdaThrowFunc =
      findFunction(AST.get(), "function_with_lambda_throw");
  ASSERT_TRUE(LambdaThrowFunc != nullptr);
  auto LambdaThrowInfo = Analyzer.analyzeFunction(LambdaThrowFunc);
  EXPECT_EQ(LambdaThrowInfo.State, ExceptionState::Throwing);
  EXPECT_FALSE(LambdaThrowInfo.ContainsUnknown);
  ASSERT_EQ(LambdaThrowInfo.ThrowEvents.size(), 1u);
  EXPECT_TRUE(LambdaThrowInfo.ThrowEvents[0]
                  .Type->isIntegerType()); // Lambda throws int

  // Test function_with_immediately_invoked_lambda_throw
  const FunctionDecl *ImmediatelyInvokedLambdaThrowFunc =
      findFunction(AST.get(), "function_with_immediately_invoked_lambda_throw");
  ASSERT_TRUE(ImmediatelyInvokedLambdaThrowFunc != nullptr);
  auto ImmediatelyInvokedLambdaThrowInfo =
      Analyzer.analyzeFunction(ImmediatelyInvokedLambdaThrowFunc);
  EXPECT_EQ(ImmediatelyInvokedLambdaThrowInfo.State, ExceptionState::Throwing);
  EXPECT_FALSE(ImmediatelyInvokedLambdaThrowInfo.ContainsUnknown);
  ASSERT_EQ(ImmediatelyInvokedLambdaThrowInfo.ThrowEvents.size(), 1u);
  EXPECT_TRUE(
      ImmediatelyInvokedLambdaThrowInfo.ThrowEvents[0]
          .Type->isIntegerType()); // Immediately invoked lambda throws int

  // Test function_with_unused_lambda_throw
  const FunctionDecl *UnusedLambdaFunc =
      findFunction(AST.get(), "function_with_unused_lambda_throw");
  ASSERT_TRUE(UnusedLambdaFunc != nullptr);
  auto UnusedLambdaInfo = Analyzer.analyzeFunction(UnusedLambdaFunc);
  // Since the throwing lambda is not called, the function itself doesn't throw
  EXPECT_EQ(UnusedLambdaInfo.State, ExceptionState::NotThrowing);
  EXPECT_FALSE(UnusedLambdaInfo.ContainsUnknown);
  EXPECT_TRUE(UnusedLambdaInfo.ThrowEvents.empty());

  // Test function_with_noexcept_lambda
  const FunctionDecl *NoexceptLambdaFunc =
      findFunction(AST.get(), "function_with_noexcept_lambda");
  ASSERT_TRUE(NoexceptLambdaFunc != nullptr);
  auto NoexceptLambdaInfo = Analyzer.analyzeFunction(NoexceptLambdaFunc);
  EXPECT_EQ(NoexceptLambdaInfo.State, ExceptionState::NotThrowing);
  EXPECT_FALSE(NoexceptLambdaInfo.ContainsUnknown);
  EXPECT_TRUE(NoexceptLambdaInfo.ThrowEvents.empty());
}

// Test recursive function calls
TEST_F(ASTBasedExceptionAnalyzerTest, RecursiveFunctionCalls) {
  auto AST = buildASTFromCode(R"(
    // Recursive function that throws on a condition
    void recursiveThrow(int count) {
      if (count <= 0) {
        throw 1;
      }
      recursiveThrow(count - 1);
    }

    // Recursive function that does not throw
    int recursiveNoThrow(int count) {
      if (count <= 0) {
        return 0;
      }
      return recursiveNoThrow(count - 1) + 1;
    }

    // Function calling the recursive throw function
    void callerThrow() {
      recursiveThrow(5);
    }

    // Function calling the non-throwing recursive function
    void callerNoThrow() {
      recursiveNoThrow(5);
    }
  )");

  ASSERT_TRUE(AST != nullptr);
  auto &Context = AST->getASTContext();

  GlobalExceptionInfo GEI;
  ASTBasedExceptionAnalyzer Analyzer(Context, GEI);

  // Test recursiveThrow function
  const FunctionDecl *RecursiveThrow =
      findFunction(AST.get(), "recursiveThrow");
  ASSERT_TRUE(RecursiveThrow != nullptr);
  auto RecursiveThrowInfo = Analyzer.analyzeFunction(RecursiveThrow);
  // The analysis should detect the possibility of throwing, even with
  // recursion.
  EXPECT_EQ(RecursiveThrowInfo.State, ExceptionState::Throwing);
  EXPECT_FALSE(RecursiveThrowInfo.ContainsUnknown);
  ASSERT_FALSE(RecursiveThrowInfo.ThrowEvents.empty());
  EXPECT_TRUE(RecursiveThrowInfo.ThrowEvents[0].Type->isIntegerType());

  // Test recursiveNoThrow function
  const FunctionDecl *RecursiveNoThrow =
      findFunction(AST.get(), "recursiveNoThrow");
  ASSERT_TRUE(RecursiveNoThrow != nullptr);
  auto RecursiveNoThrowInfo = Analyzer.analyzeFunction(RecursiveNoThrow);
  // This function never throws, despite being recursive.
  EXPECT_EQ(RecursiveNoThrowInfo.State, ExceptionState::NotThrowing);
  EXPECT_FALSE(RecursiveNoThrowInfo.ContainsUnknown);
  EXPECT_TRUE(RecursiveNoThrowInfo.ThrowEvents.empty());

  // Test callerThrow function
  const FunctionDecl *CallerThrow = findFunction(AST.get(), "callerThrow");
  ASSERT_TRUE(CallerThrow != nullptr);
  auto CallerThrowInfo = Analyzer.analyzeFunction(CallerThrow);
  EXPECT_EQ(CallerThrowInfo.State,
            ExceptionState::Throwing); // Calls a throwing function
  EXPECT_FALSE(CallerThrowInfo.ContainsUnknown);
  EXPECT_FALSE(CallerThrowInfo.ThrowEvents.empty());

  // Test callerNoThrow function
  const FunctionDecl *CallerNoThrow = findFunction(AST.get(), "callerNoThrow");
  ASSERT_TRUE(CallerNoThrow != nullptr);
  auto CallerNoThrowInfo = Analyzer.analyzeFunction(CallerNoThrow);
  EXPECT_EQ(CallerNoThrowInfo.State,
            ExceptionState::NotThrowing); // Calls a non-throwing function
  EXPECT_FALSE(CallerNoThrowInfo.ContainsUnknown);
  EXPECT_TRUE(CallerNoThrowInfo.ThrowEvents.empty());
}
