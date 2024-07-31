#pragma once

#include "ExceptionContext.hpp"
#include "ExceptionInfoConsumer.hpp"
#include "clang/ASTMatchers/ASTMatchFinder.h"

namespace clang {
class SourceManager;

} // namespace clang

class TryBlockInfoConsumer
    : public ExceptionInfoConsumer,
      public clang::ast_matchers::MatchFinder::MatchCallback {
public:
  TryBlockInfoConsumer(ExceptionInfo &EI, clang::SourceManager &SM)
      : ExceptionInfoConsumer(EI, SM) {}
  virtual void
  run(const clang::ast_matchers::MatchFinder::MatchResult &Result) override {
    if (const clang::CXXTryStmt *Try =
            Result.Nodes.getNodeAs<clang::CXXTryStmt>("try")) {
      EI.Tries.push_back({Try, Try->getSourceRange().printToString(SM)});
    }
  }
};
