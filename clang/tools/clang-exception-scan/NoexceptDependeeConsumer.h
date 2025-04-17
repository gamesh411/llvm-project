#ifndef LLVM_CLANG_TOOLS_CLANG_EXCEPTION_SCAN_NOEXCEPT_DEPENDEE_CONSUMER_H
#define LLVM_CLANG_TOOLS_CLANG_EXCEPTION_SCAN_NOEXCEPT_DEPENDEE_CONSUMER_H

#include "GlobalExceptionInfo.h"

#include "clang/AST/ASTConsumer.h"
#include "clang/AST/RecursiveASTVisitor.h"
#include "clang/Basic/SourceManager.h"
#include "clang/Frontend/FrontendAction.h"
#include "clang/Index/USRGeneration.h"
#include "clang/Tooling/Tooling.h"
#include <map>
#include <mutex>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <vector>

namespace clang {
namespace exception_scan {

/// A consumer that identifies functions that appear in noexcept clauses
class NoexceptDependeeConsumer : public ASTConsumer {
public:
  NoexceptDependeeConsumer(const std::string &CurrentTU,
                           GlobalExceptionInfo &GCG)
      : CurrentTU_(CurrentTU), GCG_(GCG) {}

  void HandleTranslationUnit(ASTContext &Context) override;

  std::string CurrentTU_;
  GlobalExceptionInfo &GCG_;
};

/// Frontend action to create NoexceptDependeeConsumer
class NoexceptDependeeAction : public ASTFrontendAction {
public:
  NoexceptDependeeAction(GlobalExceptionInfo &GCG) : GCG_(GCG) {}

  std::unique_ptr<ASTConsumer> CreateASTConsumer(CompilerInstance &CI,
                                                 StringRef InFile) override {
    return std::make_unique<NoexceptDependeeConsumer>(InFile.str(), GCG_);
  }

private:
  GlobalExceptionInfo &GCG_;
};

class NoexceptDependeeActionFactory : public tooling::FrontendActionFactory {
  GlobalExceptionInfo &GCG_;

public:
  NoexceptDependeeActionFactory(GlobalExceptionInfo &GCG) : GCG_(GCG) {}
  std::unique_ptr<FrontendAction> create() override;
  virtual ~NoexceptDependeeActionFactory() = default;
};

} // namespace exception_scan
} // namespace clang

#endif // LLVM_CLANG_TOOLS_CLANG_EXCEPTION_SCAN_NOEXCEPT_DEPENDEE_CONSUMER_H