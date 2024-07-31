#pragma once

#include "ExceptionContext.hpp"
#include "ExceptionInfoConsumer.hpp"
#include "clang/ASTMatchers/ASTMatchFinder.h"
#include "clang/CrossTU/CrossTranslationUnit.h"

class CalledFunctionInfoConsumer
    : public ExceptionInfoConsumer,
      public clang::ast_matchers::MatchFinder::MatchCallback {
public:
  CalledFunctionInfoConsumer(ExceptionInfo &EI, clang::SourceManager &SM)
      : ExceptionInfoConsumer(EI, SM) {}
  virtual void
  run(const clang::ast_matchers::MatchFinder::MatchResult &Result) override {
    const clang::Expr *Expr = nullptr;
    const clang::FunctionDecl *Callee = nullptr;

    if (const clang::CallExpr *Call =
            Result.Nodes.getNodeAs<clang::CallExpr>("invocation")) {
      Expr = Call;
      Callee = Call->getDirectCallee();
    } else if (const clang::CXXConstructExpr *CTOR =
                   Result.Nodes.getNodeAs<clang::CXXConstructExpr>(
                       "invocation")) {
      Expr = CTOR;
      Callee = CTOR->getConstructor();
    }

    if (!Expr || !Callee) {
      return;
    }

    std::string Name =
        clang::cross_tu::CrossTranslationUnitContext::getLookupName(Callee)
            .value_or("<no-lookup-name>");
    EI.Calls.push_back(
        {Expr, Callee, Name, Expr->getSourceRange().printToString(SM)});
  }
};
