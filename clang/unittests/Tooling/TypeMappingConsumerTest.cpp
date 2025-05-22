#include "TypeMappingConsumer.h"
#include "clang/AST/ASTContext.h"
#include "clang/Frontend/ASTUnit.h"
#include "clang/Tooling/Tooling.h"
#include "gtest/gtest.h"
#include <memory>
#include <string>
#include <unordered_set>

using namespace clang;
using namespace clang::exception_scan;
using namespace clang::tooling;

namespace {

class TypeMappingConsumerTest : public ::testing::Test {
protected:
  std::unique_ptr<ASTUnit> buildASTFromCode(const std::string &Code) {
    return tooling::buildASTFromCodeWithArgs(Code, {"-std=c++17", "-fsyntax-only"});
  }
};

TEST_F(TypeMappingConsumerTest, BasicClassHierarchyMapping) {
  std::string Code = R"cpp(
    class Base {};
    class Derived1 : public Base {};
    class Derived2 : public Base {};
    class Unrelated {};
    void f() {
      try { throw Derived1(); } catch (Base&) {}
      try { throw Derived2(); } catch (Base&) {}
      try { throw Unrelated(); } catch (Base&) {}
    }
  )cpp";

  auto AST = buildASTFromCode(Code);
  ASSERT_TRUE(AST != nullptr);
  ASTContext &Context = AST->getASTContext();

  GlobalExceptionInfo GEI;
  TypeMappingConsumer Consumer("test.cpp", GEI);
  Consumer.HandleTranslationUnit(Context);

  // Check that Base maps to itself, Derived1, and Derived2, but not Unrelated
  std::lock_guard<std::mutex> Lock(GEI.CatchTypeToDescendantsMutex);
  bool foundBase = false, foundD1 = false, foundD2 = false, foundUnrelated = false;
  for (const auto &pair : GEI.CatchTypeToDescendants) {
    llvm::errs() << "Catch type: " << pair.first() << "\n";
    if (pair.first().contains("Base")) {
      foundBase = pair.second.contains(pair.first());
      for (const auto &desc : pair.second) {
        llvm::errs() << "  Descendant: " << desc.getKey() << "\n";
        if (desc.getKey().contains("Derived1")) foundD1 = true;
        if (desc.getKey().contains("Derived2")) foundD2 = true;
        if (desc.getKey().contains("Unrelated")) foundUnrelated = true;
      }
    }
  }
  EXPECT_TRUE(foundBase);
  EXPECT_TRUE(foundD1);
  EXPECT_TRUE(foundD2);
  EXPECT_FALSE(foundUnrelated);
}

TEST_F(TypeMappingConsumerTest, FundamentalTypeQualifierMatching) {
  std::string Code = R"cpp(
    void f() {
      try { throw 42; } catch (int) {}
      try { throw 42; } catch (const int) {}
      try { throw 42; } catch (volatile int) {}
      try { throw 42; } catch (const volatile int) {}
    }
  )cpp";
  auto AST = buildASTFromCode(Code);
  ASSERT_TRUE(AST != nullptr);
  ASTContext &Context = AST->getASTContext();
  GlobalExceptionInfo GEI;
  TypeMappingConsumer Consumer("test.cpp", GEI);
  Consumer.HandleTranslationUnit(Context);
  std::lock_guard<std::mutex> Lock(GEI.CatchTypeToDescendantsMutex);
  // For fundamental types, the mapping should be empty (only class types are mapped)
  EXPECT_TRUE(GEI.CatchTypeToDescendants.empty());
}

TEST_F(TypeMappingConsumerTest, PointerToFundamentalTypeMatching) {
  std::string Code = R"cpp(
    void f() {
      int x = 0;
      int* p = &x;
      const int* cp = &x;
      try { throw p; } catch (int*) {}
      try { throw cp; } catch (const int*) {}
      try { throw nullptr; } catch (int*) {}
    }
  )cpp";
  auto AST = buildASTFromCode(Code);
  ASSERT_TRUE(AST != nullptr);
  ASTContext &Context = AST->getASTContext();
  GlobalExceptionInfo GEI;
  TypeMappingConsumer Consumer("test.cpp", GEI);
  Consumer.HandleTranslationUnit(Context);
  std::lock_guard<std::mutex> Lock(GEI.CatchTypeToDescendantsMutex);
  // For pointer to fundamental types, the mapping should be empty
  EXPECT_TRUE(GEI.CatchTypeToDescendants.empty());
}

TEST_F(TypeMappingConsumerTest, PointerToClassTypeMatching) {
  std::string Code = R"cpp(
    class Base {};
    class Derived1 : public Base {};
    class Derived2 : public Base {};
    class Unrelated {};
    void f() {
      Base b; Derived1 d1; Derived2 d2; Unrelated u;
      Base* pb = &b;
      Derived1* pd1 = &d1;
      Derived2* pd2 = &d2;
      Unrelated* pu = &u;
      try { throw pd1; } catch (Base*) {}
      try { throw pd2; } catch (Base*) {}
      try { throw pb; } catch (Unrelated*) {}
    }
  )cpp";
  auto AST = buildASTFromCode(Code);
  ASSERT_TRUE(AST != nullptr);
  ASTContext &Context = AST->getASTContext();
  GlobalExceptionInfo GEI;
  TypeMappingConsumer Consumer("test.cpp", GEI);
  Consumer.HandleTranslationUnit(Context);
  std::lock_guard<std::mutex> Lock(GEI.CatchTypeToDescendantsMutex);
  bool foundD1 = false, foundD2 = false, foundUnrelated = false;
  for (const auto &pair : GEI.CatchTypeToDescendants) {
    if (pair.first().contains("Base")) {
      for (const auto &desc : pair.second) {
        if (desc.getKey().contains("Derived1")) foundD1 = true;
        if (desc.getKey().contains("Derived2")) foundD2 = true;
        if (desc.getKey().contains("Unrelated")) foundUnrelated = true;
      }
    }
  }
  EXPECT_TRUE(foundD1);
  EXPECT_TRUE(foundD2);
  EXPECT_FALSE(foundUnrelated);
}

TEST_F(TypeMappingConsumerTest, FundamentalTypeMismatch) {
  std::string Code = R"cpp(
    void f() {
      try { throw 42; } catch (double) {}
    }
  )cpp";
  auto AST = buildASTFromCode(Code);
  ASSERT_TRUE(AST != nullptr);
  ASTContext &Context = AST->getASTContext();
  GlobalExceptionInfo GEI;
  TypeMappingConsumer Consumer("test.cpp", GEI);
  Consumer.HandleTranslationUnit(Context);
  std::lock_guard<std::mutex> Lock(GEI.CatchTypeToDescendantsMutex);
  // For fundamental types, the mapping should be empty
  EXPECT_TRUE(GEI.CatchTypeToDescendants.empty());
}

} // namespace 