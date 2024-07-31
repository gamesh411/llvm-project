#pragma once

#include "ExceptionContext.hpp"
#include "ExceptionInfoConsumer.hpp"
#include "clang/ASTMatchers/ASTMatchFinder.h"

class ThrownExceptionInfoConsumer
    : public ExceptionInfoConsumer,
      public clang::ast_matchers::MatchFinder::MatchCallback {
public:
  ThrownExceptionInfoConsumer(ExceptionInfo &EI, clang::SourceManager &SM)
      : ExceptionInfoConsumer(EI, SM) {}
  virtual void
  run(const clang::ast_matchers::MatchFinder::MatchResult &Result) override {
    if (const clang::CXXThrowExpr *Throw =
            Result.Nodes.getNodeAs<clang::CXXThrowExpr>("throw")) {
      bool IsRethrow = Throw->getSubExpr() == nullptr;
      std::string Description;
      if (IsRethrow)
        Description = "rethrow";
      else {
        const clang::QualType CT = Throw->getSubExpr()->getType();
        if (CT.isNull()) {
          Description = "nulltype";
        } else {
          Description = CT.getAsString();
        }
      }
      EI.Throws.push_back({Throw, IsRethrow, Description,
                           Throw->getSourceRange().printToString(SM)});
    }
  }
};
