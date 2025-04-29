#include "USRMappingConsumer.h"
#include "clang/AST/Decl.h"
#include "clang/AST/DeclCXX.h"
#include "clang/CrossTU/CrossTranslationUnit.h"
#include <llvm/Support/raw_ostream.h>

using namespace clang;
using namespace clang::exception_scan;

namespace {
class FunctionVisitor : public RecursiveASTVisitor<FunctionVisitor> {
public:
  FunctionVisitor(const std::string &CurrentTU, GlobalExceptionInfo &GCG,
                  ASTContext &Context)
      : CurrentTU_(CurrentTU), GCG_(GCG), Context_(Context) {}

private:
  // Helper to get USR and basic FunctionMappingInfo
  // Returns std::nullopt if USR cannot be determined (or FD is null)
  std::optional<FunctionMappingInfo> GetFunctionInfo(FunctionDecl *FD) {
    if (!FD)
      return std::nullopt;

    std::optional<std::string> USR =
        cross_tu::CrossTranslationUnitContext::getLookupName(FD);
    if (!USR) {
      USR.emplace("<generated>" + FD->getNameAsString() + "#" + CurrentTU_);
    }

    FunctionMappingInfo Info;
    Info.USR = *USR;
    Info.TU = CurrentTU_;
    Info.FunctionName = FD->getNameAsString();
    const SourceManager &SM = Context_.getSourceManager();
    // Use getOuterLocStart for accurate location even for nested
    // functions/lambdas
    SourceLocation Loc = FD->getOuterLocStart();
    Info.SourceLocFile = SM.getBufferName(Loc);
    Info.SourceLocLine = SM.getSpellingLineNumber(Loc);
    Info.SourceLocColumn = SM.getSpellingColumnNumber(Loc);
    Info.IsDefinition = FD->isThisDeclarationADefinition();

    return Info;
  }

  void updateUSRToFunctionMap(const FunctionMappingInfo &Info) {
    std::lock_guard<std::mutex> Lock(GCG_.USRToFunctionMapMutex);
    auto It = GCG_.USRToFunctionMap.find(Info.USR);
    // Always update if it's a definition, or if it's the first time seeing
    // this USR. This ensures definitions overwrite declarations.
    if (It == GCG_.USRToFunctionMap.end() || Info.IsDefinition) {
      GCG_.USRToFunctionMap[Info.USR] = Info;
    }
  }

  void processFunctionDefinition(FunctionDecl *FD,
                                 const FunctionMappingInfo &Info) {
    {
      std::lock_guard<std::mutex> Lock(GCG_.TUToUSRMapMutex);
      GCG_.TUToUSRMap[Info.TU].insert(Info.USR);
    }
    {
      std::lock_guard<std::mutex> Lock(GCG_.USRToDefinedInTUMapMutex);
      GCG_.USRToDefinedInTUMap[Info.USR].insert(Info.TU);
    }

    const SourceManager &SM = Context_.getSourceManager();
    if (!SM.isInSystemHeader(FD->getLocation())) {
      GCG_.TotalFunctionDefinitions++;
    }

    const FunctionDecl *PreviousFunction = CurrentlyDefinedFunction_;
    bool PreviousInTryBlock = IsInTryBlock_;
    CurrentlyDefinedFunction_ = FD;
    IsInTryBlock_ = false;

    if (FD->hasBody()) {
      TraverseStmt(FD->getBody());
    }

    CurrentlyDefinedFunction_ = PreviousFunction;
    IsInTryBlock_ = PreviousInTryBlock;
  }

public:
  bool TraverseFunctionDecl(FunctionDecl *FD) {
    if (!FD)
      return true;

    if (auto MaybeInfo = GetFunctionInfo(FD)) {
      FunctionMappingInfo Info = *MaybeInfo;
      updateUSRToFunctionMap(Info);
      if (Info.IsDefinition) {
        processFunctionDefinition(FD, Info);
      }
    }
    return true;
  }

  bool VisitFunctionDecl(FunctionDecl *FD) {
    if (!FD)
      return true;

    if (auto MaybeInfo = GetFunctionInfo(FD)) {
      FunctionMappingInfo Info = *MaybeInfo;
      updateUSRToFunctionMap(Info);
      if (Info.IsDefinition) {
        processFunctionDefinition(FD, Info);
      }
    }
    return true;
  }

  bool VisitCallExpr(const CallExpr *CE) {
    if (!CurrentlyDefinedFunction_)
      return true;
    const SourceManager &SM = Context_.getSourceManager();
    if (SM.isInSystemHeader(CE->getBeginLoc()))
      return true;

    if (IsInTryBlock_) {
      // Increment the counter (already exists)
      GCG_.TotalCallsPotentiallyWithinTryBlocks++;

      // Get the USR of the callee
      const FunctionDecl *CalleeDecl = CE->getDirectCallee();
      if (CalleeDecl) {
        if (auto CalleeUSR =
                cross_tu::CrossTranslationUnitContext::getLookupName(
                    CalleeDecl)) {
          std::lock_guard<std::mutex> Lock(GCG_.CalledWithinTryUSRSetMutex);
          GCG_.CalledWithinTryUSRSet.insert(*CalleeUSR);
        }
        // else: Could generate a fallback USR if needed, but often
        //       less useful for calls within try blocks where we care about
        //       known functions.
      }
    }
    return true;
  }

  bool TraverseCXXTryStmt(CXXTryStmt *TS) {
    if (!CurrentlyDefinedFunction_)
      return true;
    const SourceManager &SM = Context_.getSourceManager();
    if (!SM.isInSystemHeader(TS->getBeginLoc())) {
      GCG_.TotalTryBlocks++;
    }
    bool StateBeforeThisTry = IsInTryBlock_;
    IsInTryBlock_ = true;
    TraverseStmt(TS->getTryBlock());
    IsInTryBlock_ = false;
    for (unsigned I = 0, E = TS->getNumHandlers(); I != E; ++I) {
      TraverseStmt(TS->getHandler(I));
    }
    IsInTryBlock_ = StateBeforeThisTry;
    return true;
  }

  bool VisitCXXCatchStmt(const CXXCatchStmt *CS) {
    if (!CurrentlyDefinedFunction_)
      return true;
    const SourceManager &SM = Context_.getSourceManager();
    if (!SM.isInSystemHeader(CS->getBeginLoc())) {
      GCG_.TotalCatchHandlers++;
    }
    return true;
  }

  bool VisitCXXThrowExpr(const CXXThrowExpr *TE) {
    if (!CurrentlyDefinedFunction_)
      return true;
    const SourceManager &SM = Context_.getSourceManager();
    if (!SM.isInSystemHeader(TE->getBeginLoc())) {
      GCG_.TotalThrowExpressions++;
    }
    return true;
  }

private:
  // Member variables remain unchanged
  const FunctionDecl *CurrentlyDefinedFunction_ = nullptr;
  std::string CurrentTU_;
  GlobalExceptionInfo &GCG_;
  ASTContext &Context_;
  bool IsInTryBlock_ = false;
};
} // namespace

void USRMappingConsumer::HandleTranslationUnit(ASTContext &Context) {
  FunctionVisitor Visitor(CurrentTU_, GCG_, Context);
  Visitor.TraverseDecl(Context.getTranslationUnitDecl());
}

std::unique_ptr<FrontendAction> USRMappingActionFactory::create() {
  return std::make_unique<USRMappingAction>(GCG_);
}
