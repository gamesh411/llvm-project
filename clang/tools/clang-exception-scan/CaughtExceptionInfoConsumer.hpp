#pragma once

#include "ExceptionContext.hpp"
#include "ExceptionInfoConsumer.hpp"
#include "clang/ASTMatchers/ASTMatchFinder.h"

class CaughtExceptionInfoConsumer
    : public ExceptionInfoConsumer,
      public clang::ast_matchers::MatchFinder::MatchCallback {
public:
  CaughtExceptionInfoConsumer(ExceptionInfo &EI, SourceManager &SM)
      : ExceptionInfoConsumer(EI, SM) {}
  virtual void
  run(const clang::ast_matchers::MatchFinder::MatchResult &Result) override {
    if (const CXXCatchStmt *Catch =
            Result.Nodes.getNodeAs<clang::CXXCatchStmt>("catch")) {
      bool IsCatchAll = Catch->getExceptionDecl() == nullptr;
      std::string Description;
      if (IsCatchAll)
        Description = "...";
      else {
        const clang::QualType CT = Catch->getExceptionDecl()->getType();
        if (CT.isNull()) {
          Description = "nulltype";
        } else {
          Description = CT.getAsString();
        }
      }
      EI.Catches.push_back({Catch, IsCatchAll, Description,
                            Catch->getSourceRange().printToString(SM)});
    }
  }
};
