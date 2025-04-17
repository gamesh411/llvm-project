#ifndef LLVM_CLANG_TOOLS_EXTRA_CLANG_EXCEPTION_SCAN_COLLECT_EXCEPTIONINFO_H
#define LLVM_CLANG_TOOLS_EXTRA_CLANG_EXCEPTION_SCAN_COLLECT_EXCEPTIONINFO_H

#include "ExceptionAnalyzer.h"

#include "clang/AST/ASTConsumer.h"
#include "clang/Frontend/FrontendAction.h"
#include "clang/Tooling/Tooling.h"
#include "llvm/ADT/DenseMap.h"

#include <memory>
#include <string>
#include <vector>

namespace clang {

class ASTContext;
class SourceManager;
class Stmt;

namespace exception_scan {

struct GlobalExceptionInfo;

struct PerFunctionExceptionInfo {
  std::string FirstDeclaredInFile;
  std::string DefinedInFile;
  std::string FunctionName;
  std::string FunctionUSRName;
  std::string ExceptionTypeList;
  ExceptionState Behaviour;
  ExceptionSpecificationType ExceptionSpecification;
  bool ContainsUnknown;
  bool IsInMainFile;
  // TODO: add conditions for each throw statement something like this:
  // llvm::DenseMap<const Stmt *, ExceptionCondition> Conditions;
};

struct ExceptionContext {
  std::string CurrentInfile;
  std::vector<PerFunctionExceptionInfo> InfoPerFunction;
};

void reportAllFunctions(ExceptionContext &EC, StringRef PathPrefix);
void reportFunctionDuplications(ExceptionContext &EC, StringRef PathPrefix);
void reportDefiniteMatches(ExceptionContext &EC, StringRef PathPrefix);
void reportUnknownCausedMisMatches(ExceptionContext &EC, StringRef PathPrefix);
void reportNoexceptDependees(const GlobalExceptionInfo &GCG,
                             StringRef PathPrefix);
void reportCallDependencies(const GlobalExceptionInfo &GCG,
                            StringRef PathPrefix);
void reportTUDependencies(const GlobalExceptionInfo &GCG, StringRef PathPrefix);

void serializeExceptionInfo(ExceptionContext &EC, StringRef PathPrefix);

class ExceptionInfoExtractor : public ASTConsumer {
public:
  ExceptionInfoExtractor(ASTContext &Context, ExceptionContext &EC)
      : EC(EC), SM(Context.getSourceManager()) {
    assert(not EC.CurrentInfile.empty());
  }

  void HandleTranslationUnit(ASTContext &Context) override;

private:
  ExceptionContext &EC;
  SourceManager &SM;
};

class CollectExceptionInfoAction : public ASTFrontendAction {
public:
  CollectExceptionInfoAction(ExceptionContext &EC) : EC(EC) {}
  std::unique_ptr<ASTConsumer> CreateASTConsumer(CompilerInstance &CI,
                                                 StringRef) override;

private:
  ExceptionContext &EC;
};

class CollectExceptionInfoActionFactory
    : public tooling::FrontendActionFactory {
  ExceptionContext &EC;

public:
  CollectExceptionInfoActionFactory(ExceptionContext &EC) : EC(EC) {}
  std::unique_ptr<FrontendAction> create() override;
  virtual ~CollectExceptionInfoActionFactory() = default;
};

} // namespace exception_scan
} // namespace clang

#endif
