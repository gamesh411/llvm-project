#include "NoexceptDependeeConsumer.h"
#include "clang/AST/Decl.h"
#include "clang/AST/DeclCXX.h"
#include "clang/AST/Expr.h"
#include "clang/AST/ExprCXX.h"
#include "clang/AST/Type.h"
#include "clang/Basic/ExceptionSpecificationType.h"
#include "clang/CrossTU/CrossTranslationUnit.h"
#include "clang/Index/USRGeneration.h"
#include <llvm/Support/raw_ostream.h>

using namespace clang;
using namespace clang::exception_scan;

namespace {
class NoexceptDependeeVisitor
    : public RecursiveASTVisitor<NoexceptDependeeVisitor> {
public:
  NoexceptDependeeVisitor(const std::string &CurrentTU,
                          GlobalExceptionInfo &GCG)
      : CurrentTU_(CurrentTU), GCG_(GCG) {}

  bool VisitFunctionDecl(FunctionDecl *FD) {
    if (!FD)
      return true;

    // Check if this function has a noexcept specification with an expression
    const FunctionProtoType *FPT = FD->getType()->getAs<FunctionProtoType>();
    if (!FPT)
      return true;

    // Check if the function has a computed noexcept specification
    if (!isComputedNoexcept(FPT->getExceptionSpecType()))
      return true;

    // Get the noexcept expression
    Expr *NoexceptExpr = FPT->getNoexceptExpr();
    if (!NoexceptExpr)
      return true;

    // Visit the noexcept expression to find function calls
    VisitNoexceptExpr(NoexceptExpr, FD);
    return true;
  }

private:
  void VisitNoexceptExpr(Expr *E, FunctionDecl *ParentFD) {
    if (!E)
      return;

    llvm::errs() << "Visiting expression: " << E->getStmtClassName() << "\n";

    // Check if this is a call expression
    if (CallExpr *CE = dyn_cast<CallExpr>(E)) {
      llvm::errs() << "Found CallExpr\n";
      // Get the callee
      Expr *Callee = CE->getCallee()->IgnoreParenImpCasts();
      llvm::errs() << "Callee type: " << Callee->getStmtClassName() << "\n";

      // Handle direct function calls
      if (DeclRefExpr *DRE = dyn_cast<DeclRefExpr>(Callee)) {
        llvm::errs() << "Found DeclRefExpr in callee\n";
        if (FunctionDecl *CalleeFD = dyn_cast<FunctionDecl>(DRE->getDecl())) {
          llvm::errs() << "Function name: " << CalleeFD->getNameAsString()
                       << ", Template kind: " << CalleeFD->getTemplatedKind()
                       << "\n";
          AddNoexceptDependee(CalleeFD, ParentFD, CE->getExprLoc());
        }
      }
      // Handle member function calls
      else if (MemberExpr *ME = dyn_cast<MemberExpr>(Callee)) {
        llvm::errs() << "Found MemberExpr in callee\n";
        if (FunctionDecl *CalleeFD =
                dyn_cast<FunctionDecl>(ME->getMemberDecl())) {
          llvm::errs() << "Member function name: "
                       << CalleeFD->getNameAsString()
                       << ", Template kind: " << CalleeFD->getTemplatedKind()
                       << "\n";
          AddNoexceptDependee(CalleeFD, ParentFD, CE->getExprLoc());
        }
      }
      // Handle template function calls
      else if (UnresolvedLookupExpr *ULE =
                   dyn_cast<UnresolvedLookupExpr>(Callee)) {
        llvm::errs() << "Found UnresolvedLookupExpr in callee\n";
        llvm::errs() << "Name: " << ULE->getName().getAsString() << "\n";
        llvm::errs() << "Declarations:\n";
        for (const NamedDecl *D : ULE->decls()) {
          llvm::errs() << "  - Type: " << D->getDeclKindName()
                       << ", Name: " << D->getNameAsString() << "\n";
          if (const FunctionDecl *FD = dyn_cast<FunctionDecl>(D)) {
            llvm::errs() << "    Function template kind: "
                         << FD->getTemplatedKind() << "\n";
            if (FD->getTemplatedKind() != FunctionDecl::TK_NonTemplate) {
              llvm::errs()
                  << "    Adding template function from UnresolvedLookupExpr\n";
              AddNoexceptDependee(FD, ParentFD, CE->getExprLoc());
            }
          } else if (const FunctionTemplateDecl *FTD =
                         dyn_cast<FunctionTemplateDecl>(D)) {
            llvm::errs() << "    Found function template\n";
            if (const FunctionDecl *FD = FTD->getTemplatedDecl()) {
              llvm::errs() << "    Adding function template\n";
              AddNoexceptDependee(FD, ParentFD, CE->getExprLoc());
            }
          }
        }
      }
    }
    // Handle template function calls and other expressions
    else {
      // Check for template function calls
      if (DeclRefExpr *DRE = dyn_cast<DeclRefExpr>(E)) {
        llvm::errs() << "Found DeclRefExpr in non-call context\n";
        if (FunctionDecl *CalleeFD = dyn_cast<FunctionDecl>(DRE->getDecl())) {
          llvm::errs() << "Function name: " << CalleeFD->getNameAsString()
                       << ", Template kind: " << CalleeFD->getTemplatedKind()
                       << "\n";
          // Add template functions
          if (CalleeFD->getTemplatedKind() != FunctionDecl::TK_NonTemplate) {
            llvm::errs() << "Adding template function\n";
            AddNoexceptDependee(CalleeFD, ParentFD, DRE->getLocation());
          }
        }
      }
    }

    // Recursively visit all subexpressions
    for (Stmt *Child : E->children()) {
      if (Expr *ExprChild = dyn_cast<Expr>(Child)) {
        VisitNoexceptExpr(ExprChild, ParentFD);
      }
    }
  }

  void AddNoexceptDependee(const FunctionDecl *FD, const FunctionDecl *ParentFD,
                           SourceLocation NoexceptLoc) {
    if (!FD)
      return;

    // Generate USR for the function
    SmallString<128> USR;
    clang::index::generateUSRForDecl(FD, USR);
    std::string USRStr = USR.str().str();

    // Get source location information
    SourceManager &SM = FD->getASTContext().getSourceManager();
    std::string NoexceptLocFile =
        SM.getFileEntryRefForID(SM.getFileID(NoexceptLoc))->getName().str();
    unsigned NoexceptLocLine = SM.getSpellingLineNumber(NoexceptLoc);
    unsigned NoexceptLocColumn = SM.getSpellingColumnNumber(NoexceptLoc);

    // Create NoexceptDependeeInfo
    NoexceptDependeeInfo Info;
    Info.USR = USRStr;
    Info.TU = CurrentTU_;
    Info.FunctionName = FD->getNameAsString();
    Info.Loc = FD->getLocation();
    Info.NoexceptLocFile = NoexceptLocFile;
    Info.NoexceptLocLine = NoexceptLocLine;
    Info.NoexceptLocColumn = NoexceptLocColumn;

    // Add to the global exception info
    {
      std::lock_guard<std::mutex> Lock(GCG_.NoexceptDependeesMutex);
      GCG_.NoexceptDependees.push_back(Info);
    }

    // Debug output
    llvm::errs() << "Found noexcept dependee: " << FD->getNameAsString()
                 << "\n";
  }

  std::string CurrentTU_;
  GlobalExceptionInfo &GCG_;
};
} // namespace

void NoexceptDependeeConsumer::HandleTranslationUnit(ASTContext &Context) {
  NoexceptDependeeVisitor Visitor(CurrentTU_, GCG_);
  Visitor.TraverseDecl(Context.getTranslationUnitDecl());
}

std::unique_ptr<FrontendAction> NoexceptDependeeActionFactory::create() {
  return std::make_unique<NoexceptDependeeAction>(GCG_);
}