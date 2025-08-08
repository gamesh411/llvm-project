//===- ClangRCUAnalyzer.cpp ----------------------------------------------===//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//===----------------------------------------------------------------------===//

#include "clang/AST/AST.h"
#include "clang/AST/ASTContext.h"
#include "clang/AST/ASTTypeTraits.h"
#include "clang/AST/ParentMapContext.h"
#include "clang/AST/RecursiveASTVisitor.h"
#include "clang/Frontend/CompilerInstance.h"
#include "clang/Frontend/FrontendActions.h"
#include "clang/Tooling/CommonOptionsParser.h"
#include "clang/Tooling/Tooling.h"
#include "llvm/Support/CommandLine.h"
#include "llvm/Support/Signals.h"
#include <string>

using namespace clang;
using namespace clang::tooling;
using namespace llvm;

static cl::OptionCategory RCUAnalyzerCategory("clang-rcu-analyzer options");

namespace {

static bool isTargetRCUName(StringRef Name) {
  return Name == "rcu_read_lock" || Name == "rcu_read_unlock" ||
         Name == "rcu_assign_pointer" || Name == "synchronize_rcu" ||
         Name == "call_rcu" || Name == "rcu_dereference";
}

class RCUVisitor : public RecursiveASTVisitor<RCUVisitor> {
public:
  explicit RCUVisitor(ASTContext &Context) : Ctx(Context) {}

  bool VisitCallExpr(CallExpr *CE) {
    const FunctionDecl *FD = CE->getDirectCallee();
    if (!FD)
      return true;

    StringRef CalleeName = FD->getName();
    if (!isTargetRCUName(CalleeName))
      return true;

    // Find the nearest enclosing FunctionDecl by walking parents.
    const FunctionDecl *NearestFD = nullptr;
    DynTypedNode Node = DynTypedNode::create(*CE);
    while (true) {
      auto Parents = Ctx.getParents(Node);
      if (Parents.empty())
        break;
      Node = Parents[0];
      if (const auto *FDp = Node.get<FunctionDecl>()) {
        NearestFD = FDp;
        break;
      }
      // Keep walking up through statements/declarations.
    }
    std::string FuncName;
    if (NearestFD) {
      SmallString<128> S;
      llvm::raw_svector_ostream OS(S);
      NearestFD->printQualifiedName(OS);
      FuncName = std::string(OS.str());
    } else {
      FuncName = "<global>";
    }

    const SourceManager &SM = Ctx.getSourceManager();
    SourceLocation Loc = CE->getExprLoc();
    PresumedLoc PLoc = SM.getPresumedLoc(Loc);

    // Print a single-line JSON-ish record that FileCheck can match without
    // being sensitive to exact paths/columns.
    llvm::outs() << "{\"type\":\"call\",\"name\":\"" << CalleeName
                 << "\",\"function\":\"" << FuncName << "\",\"file\":\""
                 << (PLoc.isValid() ? PLoc.getFilename() : "")
                 << "\",\"line\":" << (PLoc.isValid() ? PLoc.getLine() : 0)
                 << "}\n";

    return true;
  }

private:
  ASTContext &Ctx;
};

class RCUConsumer : public ASTConsumer {
public:
  explicit RCUConsumer(ASTContext &Context) : Visitor(Context) {}
  void HandleTranslationUnit(ASTContext &Context) override {
    Visitor.TraverseDecl(Context.getTranslationUnitDecl());
  }

private:
  RCUVisitor Visitor;
};

class RCUAction : public ASTFrontendAction {
public:
  std::unique_ptr<ASTConsumer> CreateASTConsumer(CompilerInstance &CI,
                                                 StringRef) override {
    return std::make_unique<RCUConsumer>(CI.getASTContext());
  }
};

} // namespace

int main(int argc, const char **argv) {
  sys::PrintStackTraceOnErrorSignal(argv[0], false);
  PrettyStackTraceProgram X(argc, argv);

  auto ExpectedParser = CommonOptionsParser::create(argc, argv,
                                                    RCUAnalyzerCategory);
  if (!ExpectedParser) {
    llvm::errs() << ExpectedParser.takeError();
    return 1;
  }
  CommonOptionsParser &OptionsParser = ExpectedParser.get();

  ClangTool Tool(OptionsParser.getCompilations(),
                 OptionsParser.getSourcePathList());
  return Tool.run(newFrontendActionFactory<RCUAction>().get());
}


