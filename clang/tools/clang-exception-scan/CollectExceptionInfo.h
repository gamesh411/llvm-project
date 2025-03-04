#pragma once

#include "clang/AST/Decl.h"
#include "clang/Frontend/FrontendAction.h"
#include "clang/Tooling/Tooling.h"
#include <string>

#include "ExceptionAnalyzer.h"

using ExceptionAnalyzer = clang::tidy::utils::ExceptionAnalyzer;
using AnalysisInfo = clang::tidy::utils::ExceptionAnalyzer::ExceptionInfo;
using ExceptionState = clang::tidy::utils::ExceptionAnalyzer::State;

namespace clang {
namespace exception_scan {

struct PerFunctionExceptionInfo {
  std::string FirstDeclaredInFile;
  std::string DefinedInFile;
  std::string FunctionName;
  std::string FunctionUSRName;
  std::string ExceptionTypeList;
  ExceptionState Behaviour;
  ExceptionSpecificationType ES;
  bool ContainsUnknown;
  bool IsInMainFile;
};

struct ExceptionContext {
  std::string CurrentInfile;
  std::vector<PerFunctionExceptionInfo> PFEI;
};

void reportAllFunctions(ExceptionContext &EC, StringRef PathPrefix);
void reportFunctionDuplications(ExceptionContext &EC, StringRef PathPrefix);
void reportDefiniteMatches(ExceptionContext &EC, StringRef PathPrefix);
void reportUnknownCausedMisMatches(ExceptionContext &EC, StringRef PathPrefix);

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
