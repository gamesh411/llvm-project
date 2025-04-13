#ifndef LLVM_CLANG_TOOLS_CLANG_EXCEPTION_SCAN_USR_MAPPING_CONSUMER_H
#define LLVM_CLANG_TOOLS_CLANG_EXCEPTION_SCAN_USR_MAPPING_CONSUMER_H

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
#include <vector>

namespace clang {
namespace exception_scan {

/// A consumer that collects USR to TU and TU to USR mappings
class USRMappingConsumer : public ASTConsumer {
public:
  USRMappingConsumer(const std::string &CurrentTU, GlobalExceptionInfo &GCG)
      : CurrentTU_(CurrentTU), GCG_(GCG) {}

  void HandleTranslationUnit(ASTContext &Context) override;

  std::string CurrentTU_;
  GlobalExceptionInfo &GCG_;
};

/// Frontend action to create USRMappingConsumer
class USRMappingAction : public ASTFrontendAction {
public:
  USRMappingAction(GlobalExceptionInfo &GCG) : GCG_(GCG) {}

  std::unique_ptr<ASTConsumer> CreateASTConsumer(CompilerInstance &CI,
                                                 StringRef InFile) override {
    return std::make_unique<USRMappingConsumer>(InFile.str(), GCG_);
  }

private:
  GlobalExceptionInfo &GCG_;
};

class USRMappingActionFactory : public tooling::FrontendActionFactory {
  GlobalExceptionInfo &GCG_;

public:
  USRMappingActionFactory(GlobalExceptionInfo &GCG) : GCG_(GCG) {}
  std::unique_ptr<FrontendAction> create() override;
  virtual ~USRMappingActionFactory() = default;
};

} // namespace exception_scan
} // namespace clang

#endif // LLVM_CLANG_TOOLS_CLANG_EXCEPTION_SCAN_USR_MAPPING_CONSUMER_H