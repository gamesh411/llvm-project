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
  FunctionVisitor(const std::string &CurrentTU, GlobalExceptionInfo &GCG)
      : CurrentTU_(CurrentTU), GCG_(GCG) {}

  bool VisitFunctionDecl(FunctionDecl *FD) {
    if (!FD)
      return true;

    // Debug output
    llvm::errs() << "Found function: " << FD->getNameAsString()
                 << " (IsDefinition: " << FD->isThisDeclarationADefinition()
                 << ") " << FD << " in TU: " << CurrentTU_ << '\n';

    std::optional<std::string> USR =
        cross_tu::CrossTranslationUnitContext::getLookupName(FD);

    if (!USR) {
      llvm::errs() << "Failed to generate USR for function: "
                   << FD->getNameAsString() << "\n";
      // Generate a fallback USR based on the function name and TU
      USR.emplace("<generated>" + FD->getNameAsString() + "#" + CurrentTU_);
      llvm::errs() << "Generated fallback USR: " << *USR << "\n";
    }

    // Create function info
    FunctionMappingInfo Info;
    Info.USR = *USR;
    Info.TU = CurrentTU_;
    Info.FunctionName = FD->getNameAsString();
    Info.Loc = FD->getLocation();
    Info.IsDefinition = FD->isThisDeclarationADefinition();

    // Add function to the map, but only if it's a definition or if we haven't
    // seen it before
    {
      std::lock_guard<std::mutex> Lock(GCG_.USRToFunctionMapMutex);
      auto It = GCG_.USRToFunctionMap.find(Info.USR);
      if (It == GCG_.USRToFunctionMap.end() || Info.IsDefinition) {
        GCG_.USRToFunctionMap[Info.USR] = Info;
      }
    }

    // Only add definitions to the TU maps
    if (Info.IsDefinition) {
      {
        std::lock_guard<std::mutex> Lock(GCG_.TUToUSRMapMutex);
        GCG_.TUToUSRMap[Info.TU].insert(Info.USR);
      }

      {
        std::lock_guard<std::mutex> Lock(GCG_.USRToDefinedInTUMapMutex);
        GCG_.USRToDefinedInTUMap[Info.USR] = Info.TU;
      }
    }

    return true;
  }

private:
  std::string CurrentTU_;
  GlobalExceptionInfo &GCG_;
};
} // namespace

void USRMappingConsumer::HandleTranslationUnit(ASTContext &Context) {
  FunctionVisitor Visitor(CurrentTU_, GCG_);
  Visitor.TraverseDecl(Context.getTranslationUnitDecl());
}

std::unique_ptr<FrontendAction> USRMappingActionFactory::create() {
  return std::make_unique<USRMappingAction>(GCG_);
}
