#ifndef LLVM_CLANG_TOOLS_CLANG_EXCEPTION_SCAN_CALL_GRAPH_GENERATOR_CONSUMER_H
#define LLVM_CLANG_TOOLS_CLANG_EXCEPTION_SCAN_CALL_GRAPH_GENERATOR_CONSUMER_H

#include "GlobalExceptionInfo.h"

#include "clang/AST/ASTConsumer.h"
#include "clang/AST/RecursiveASTVisitor.h"
#include "clang/Frontend/FrontendAction.h"
#include "clang/Tooling/Tooling.h"

#include <map>
#include <set>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <vector>

namespace clang {
class FunctionDecl;
class Decl;
namespace exception_scan {

/// AST visitor for collecting function definitions
class FunctionDefinitionCollector
    : public RecursiveASTVisitor<FunctionDefinitionCollector> {
public:
  explicit FunctionDefinitionCollector(ASTContext &Context,
                                       GlobalExceptionInfo &GCG,
                                       const std::string &CurrentTU)
      : Context_(Context), GCG_(GCG), CurrentTU_(CurrentTU) {}

  bool VisitFunctionDecl(FunctionDecl *FD);

private:
  ASTContext &Context_;
  GlobalExceptionInfo &GCG_;
  std::string CurrentTU_;
};

/// AST visitor for building the call graph
class CallGraphVisitor : public RecursiveASTVisitor<CallGraphVisitor> {
public:
  explicit CallGraphVisitor(ASTContext &Context, GlobalExceptionInfo &GCG,
                            const std::string &CurrentTU)
      : Context_(Context), GCG_(GCG), CurrentTU_(CurrentTU),
        CurrentFunction_(nullptr) {}

  bool VisitCallExpr(CallExpr *Call);
  bool VisitCXXConstructExpr(CXXConstructExpr *Construct);
  bool VisitCXXMethodDecl(CXXMethodDecl *MD);
  bool VisitCXXNewExpr(CXXNewExpr *NewExpr);
  bool VisitCXXDeleteExpr(CXXDeleteExpr *DeleteExpr);
  bool VisitFunctionDecl(FunctionDecl *FD);
  bool VisitLambdaExpr(LambdaExpr *LE);
  bool VisitCXXOperatorCallExpr(CXXOperatorCallExpr *Call);

private:
  void addCall(const FunctionDecl *Caller, const FunctionDecl *Callee,
               const Expr *E);

  ASTContext &Context_;
  GlobalExceptionInfo &GCG_;
  const std::string &CurrentTU_;
  const FunctionDecl *CurrentFunction_ = nullptr;
};

/// AST consumer for generating the call graph
class CallGraphGeneratorConsumer : public ASTConsumer {
public:
  explicit CallGraphGeneratorConsumer(StringRef CurrentTU,
                                      GlobalExceptionInfo &GCG)
      : CurrentTU_(CurrentTU.str()), GCG_(GCG) {}

  void HandleTranslationUnit(ASTContext &Context) override;

private:
  std::string CurrentTU_;
  GlobalExceptionInfo &GCG_;
};

// FrontendAction that uses CallGraphGeneratorConsumer
class CallGraphGeneratorAction : public ASTFrontendAction {
public:
  explicit CallGraphGeneratorAction(GlobalExceptionInfo &GCG) : GCG_(GCG) {}

  std::unique_ptr<ASTConsumer> CreateASTConsumer(CompilerInstance &CI,
                                                 StringRef InFile) override {
    return std::make_unique<CallGraphGeneratorConsumer>(InFile.str(), GCG_);
  }

  GlobalExceptionInfo &GCG_;
};

class CallGraphGeneratorActionFactory : public tooling::FrontendActionFactory {
public:
  explicit CallGraphGeneratorActionFactory(GlobalExceptionInfo &GCG)
      : GCG_(GCG) {}

  std::unique_ptr<FrontendAction> create() override {
    return std::make_unique<CallGraphGeneratorAction>(GCG_);
  }

private:
  GlobalExceptionInfo &GCG_;
};

/// Generates a DOT file representation of the translation unit dependency graph
void generateDependencyDotFile(const GlobalExceptionInfo &GCG,
                               const std::string &OutputPath);

/// Detects cycles in the translation unit dependency graph
std::vector<std::vector<std::string>>
detectTUCycles(const GlobalExceptionInfo &GCG);

/// Builds the translation unit dependency graph from call dependencies
std::map<std::string, std::set<std::string>>
buildTUDependencyGraph(const GlobalExceptionInfo &GCG);

// Compute the transitive closure of a TU dependency graph
void computeTransitiveClosure(
    std::map<std::string, std::set<std::string>> &TUDependencies);

} // namespace exception_scan
} // namespace clang

#endif // LLVM_CLANG_TOOLS_CLANG_EXCEPTION_SCAN_CALL_GRAPH_GENERATOR_CONSUMER_H