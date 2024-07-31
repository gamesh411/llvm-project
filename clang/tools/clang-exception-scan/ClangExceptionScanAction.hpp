#pragma once

#include "ClangExceptionScanConsumer.hpp"
#include "ExceptionContext.hpp"
#include "clang/Frontend/CompilerInstance.h"
#include "clang/Tooling/Tooling.h"
#include "llvm/ADT/StringRef.h"

namespace clang {
class ASTConsumer;
} // namespace clang

class ExceptionScanAction : public clang::ASTFrontendAction {
public:
  ExceptionScanAction(ExceptionContext &Index) : Index(Index) {}

protected:
  std::unique_ptr<ASTConsumer> CreateASTConsumer(clang::CompilerInstance &CI,
                                                 llvm::StringRef) override {
    return std::make_unique<ClangExceptionScanConsumer>(CI.getASTContext(),
                                                        Index);
  }

private:
  ExceptionContext &Index;
};

inline std::unique_ptr<clang::tooling::FrontendActionFactory>
newExceptionScanActionFactory(ExceptionContext &EC) {
  class ClangExceptionScanActionFactory
      : public clang::tooling::FrontendActionFactory {
  public:
    ClangExceptionScanActionFactory(ExceptionContext &EC) : EC(EC) {}
    std::unique_ptr<FrontendAction> create() override {
      return std::make_unique<ExceptionScanAction>(EC);
    }

  private:
    ExceptionContext &EC;
  };

  return std::make_unique<ClangExceptionScanActionFactory>(EC);
}
