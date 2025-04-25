#ifndef LLVM_CLANG_TOOLS_EXTRA_CLANG_EXCEPTION_SCAN_COLLECT_EXCEPTIONINFO_H
#define LLVM_CLANG_TOOLS_EXTRA_CLANG_EXCEPTION_SCAN_COLLECT_EXCEPTIONINFO_H

#include "ExceptionAnalysisInfo.h"
#include "GlobalExceptionInfo.h"

#include "llvm/ADT/StringRef.h"

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

void reportAllFunctions(ExceptionContext &EC, llvm::StringRef PathPrefix);
void reportFunctionDuplications(ExceptionContext &EC,
                                llvm::StringRef PathPrefix);
void reportDefiniteMatches(ExceptionContext &EC, llvm::StringRef PathPrefix);
void reportUnknownCausedMisMatches(ExceptionContext &EC,
                                   llvm::StringRef PathPrefix);
void reportNoexceptDependees(const GlobalExceptionInfo &GCG,
                             llvm::StringRef PathPrefix);
void reportCallDependencies(const GlobalExceptionInfo &GCG,
                            llvm::StringRef PathPrefix);
void reportTUDependencies(const GlobalExceptionInfo &GCG,
                          llvm::StringRef PathPrefix);

void serializeExceptionInfo(ExceptionContext &EC, llvm::StringRef PathPrefix);

} // namespace exception_scan
} // namespace clang

#endif
