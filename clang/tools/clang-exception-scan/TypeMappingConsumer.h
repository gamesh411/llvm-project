#ifndef LLVM_CLANG_TOOLS_CLANG_EXCEPTION_SCAN_TYPE_MAPPING_CONSUMER_H
#define LLVM_CLANG_TOOLS_CLANG_EXCEPTION_SCAN_TYPE_MAPPING_CONSUMER_H

#include "GlobalExceptionInfo.h"

#include "clang/AST/ASTConsumer.h"
#include "clang/Frontend/FrontendAction.h"
#include "clang/Tooling/Tooling.h"

#include <string>

namespace clang {
namespace exception_scan {

/// A consumer that collects catch types and builds a mapping from catch type
/// string to all descendant type strings
class TypeMappingConsumer : public ASTConsumer {
public:
  TypeMappingConsumer(const std::string &CurrentTU, GlobalExceptionInfo &GCG)
      : CurrentTU_(CurrentTU), GCG_(GCG) {}

  void HandleTranslationUnit(ASTContext &Context) override;

  std::string CurrentTU_;
  GlobalExceptionInfo &GCG_;
};

/// Frontend action to create TypeMappingConsumer
class TypeMappingAction : public ASTFrontendAction {
public:
  TypeMappingAction(GlobalExceptionInfo &GCG) : GCG_(GCG), CurrentTU_("") {}

  std::unique_ptr<ASTConsumer> CreateASTConsumer(CompilerInstance &CI,
                                                 StringRef InFile) override {
    CurrentTU_ = InFile.str();
    return std::make_unique<TypeMappingConsumer>(CurrentTU_, GCG_);
  }

private:
  GlobalExceptionInfo &GCG_;
  std::string CurrentTU_;
};

class TypeMappingActionFactory : public tooling::FrontendActionFactory {
  GlobalExceptionInfo &GCG_;

public:
  TypeMappingActionFactory(GlobalExceptionInfo &GCG) : GCG_(GCG) {}
  std::unique_ptr<FrontendAction> create() override;
  virtual ~TypeMappingActionFactory() = default;
};

} // namespace exception_scan
} // namespace clang

#endif // LLVM_CLANG_TOOLS_CLANG_EXCEPTION_SCAN_TYPE_MAPPING_CONSUMER_H
