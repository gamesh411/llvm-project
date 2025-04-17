#include "ExceptionAnalyzer.h"
#include "clang/AST/ASTContext.h"
#include "clang/AST/DeclCXX.h"
#include "clang/AST/ExprCXX.h"
#include "clang/AST/RecursiveASTVisitor.h"
#include "clang/AST/StmtCXX.h"
#include "clang/AST/StmtVisitor.h"
#include "clang/AST/Type.h"
#include "clang/Analysis/CFG.h"
#include "clang/Basic/SourceLocation.h"
#include "clang/Basic/SourceManager.h"
#include "clang/Frontend/CompilerInstance.h"
#include "clang/Tooling/Tooling.h"
#include "llvm/ADT/DenseMap.h"
#include "llvm/ADT/SmallSet.h"
#include "llvm/ADT/SmallString.h"
#include "llvm/ADT/StringRef.h"
#include "llvm/Support/raw_ostream.h"
#include <functional>
#include <string>
#include <vector>

using namespace clang;
using namespace clang::exception_scan;

static void
BuildParentMapImpl(const Stmt *S,
                   llvm::DenseMap<const Stmt *, const Stmt *> &ParentMap) {
  if (!S)
    return;
  for (const Stmt *Child : S->children()) {
    if (Child) {
      ParentMap[Child] = S;
      BuildParentMapImpl(Child, ParentMap);
    }
  }
}
static auto BuildParentMap(const Stmt *S)
    -> llvm::DenseMap<const Stmt *, const Stmt *> {
  llvm::DenseMap<const Stmt *, const Stmt *> ParentMap;
  BuildParentMapImpl(S, ParentMap);
  return ParentMap;
}

ExceptionAnalyzer::ExceptionAnalyzer(ASTContext &Context)
    : Context_(Context), IgnoreBadAlloc_(true) {}

FunctionExceptionInfo
ExceptionAnalyzer::analyzeFunction(const FunctionDecl *Func) {
  if (!Func) {
    // Handle null function declarations (should never happen in practice)
    return FunctionExceptionInfo{nullptr, ExceptionState::Unknown, true, {}};
  }

  // Check if we've already analyzed this function
  auto It = FunctionCache_.find(Func);
  if (It != FunctionCache_.end())
    return It->second;

  // Handle functions without a body (declarations only)
  if (!Func->hasBody()) {
    // For functions without a body, we need to check if they're marked as
    // noexcept or if they have an exception specification
    FunctionExceptionInfo Info{Func, ExceptionState::Unknown, true, {}};
    // If the function has an exception specification, we can determine its
    // state
    if (Func->getExceptionSpecType() == EST_None ||
        Func->getExceptionSpecType() == EST_Dynamic) {
      Info.State = ExceptionState::Throwing;
    } else if (Func->getExceptionSpecType() == EST_NoexceptTrue ||
               Func->getExceptionSpecType() == EST_NoexceptFalse ||
               Func->getExceptionSpecType() == EST_NoThrow) {
      Info.State = ExceptionState::NotThrowing;
    }

    // Cache the result
    FunctionCache_[Func] = Info;
    return Info;
  }

  // Build parent map for this function
  ParentMap_ = BuildParentMap(Func->getBody());

  // Start with NotThrowing and no unknown elements
  FunctionExceptionInfo Info{Func, ExceptionState::NotThrowing, false, {}};

  // Analyze the function body
  analyzeStatement(Func->getBody(), Info);

  // Cache the result
  FunctionCache_[Func] = Info;
  return Info;
}

void ExceptionAnalyzer::analyzeStatement(const Stmt *S,
                                         FunctionExceptionInfo &Info) {
  if (!S)
    return;

  // Recursively analyze child statements first
  for (const Stmt *Child : S->children()) {
    analyzeStatement(Child, Info);
  }

  // Handle try-catch blocks
  if (const CXXTryStmt *Try = dyn_cast<CXXTryStmt>(S)) {
    FunctionExceptionInfo TryInfo = {
        nullptr, ExceptionState::NotThrowing, false, {}};
    analyzeStatement(Try->getTryBlock(), TryInfo);

    if (TryInfo.State == ExceptionState::Throwing) {
      bool AllCaught = false;
      bool AnyRethrows = false;
      for (unsigned I = 0; I < Try->getNumHandlers(); ++I) {
        const CXXCatchStmt *Handler = Try->getHandler(I);

        // catch(...) catches everything
        if (!Handler->getExceptionDecl()) {
          AllCaught = true;
          FunctionExceptionInfo HandlerInfo = {
              nullptr, ExceptionState::NotThrowing, false, {}};
          analyzeStatement(Handler->getHandlerBlock(), HandlerInfo);
          if (HandlerInfo.State == ExceptionState::Throwing) {
            AnyRethrows = true;
            Info.ThrowEvents.insert(Info.ThrowEvents.end(),
                                    HandlerInfo.ThrowEvents.begin(),
                                    HandlerInfo.ThrowEvents.end());
          }
          break;
        }

        // Check if the handler catches any of the thrown types
        QualType CaughtType = Handler->getCaughtType();
        bool HandlerCaughtSomething = false;

        for (const auto &ThrowType : TryInfo.ThrowEvents) {
          // Get the unqualified types for comparison
          QualType UnqualifiedCaughtType = CaughtType.getUnqualifiedType();
          QualType UnqualifiedThrowType = ThrowType.Type.getUnqualifiedType();

          // Handle reference types
          if (UnqualifiedCaughtType->isReferenceType()) {
            UnqualifiedCaughtType = UnqualifiedCaughtType->getPointeeType();
          }
          if (UnqualifiedThrowType->isReferenceType()) {
            UnqualifiedThrowType = UnqualifiedThrowType->getPointeeType();
          }

          // Check if caught type is a base class of thrown type
          if (UnqualifiedThrowType->isRecordType() &&
              UnqualifiedCaughtType->isRecordType()) {
            CXXRecordDecl *Thrown = UnqualifiedThrowType->getAsCXXRecordDecl();
            CXXRecordDecl *Caught = UnqualifiedCaughtType->getAsCXXRecordDecl();
            if (Thrown && Caught &&
                (Thrown->isDerivedFrom(Caught) || Thrown == Caught)) {
              HandlerCaughtSomething = true;
              FunctionExceptionInfo HandlerInfo = {
                  nullptr, ExceptionState::NotThrowing, false, {}};
              analyzeStatement(Handler->getHandlerBlock(), HandlerInfo);
              if (HandlerInfo.State == ExceptionState::Throwing) {
                AnyRethrows = true;
                Info.ThrowEvents.insert(Info.ThrowEvents.end(),
                                        HandlerInfo.ThrowEvents.begin(),
                                        HandlerInfo.ThrowEvents.end());
              }
              break;
            }
          }
        }

        if (HandlerCaughtSomething) {
          AllCaught = true;
          break;
        }
      }

      if (!AllCaught) {
        Info.State = ExceptionState::Throwing;
        Info.ThrowEvents.insert(Info.ThrowEvents.end(),
                                TryInfo.ThrowEvents.begin(),
                                TryInfo.ThrowEvents.end());
      } else if (AnyRethrows) {
        Info.State = ExceptionState::Throwing;
      } else {
        Info.State = ExceptionState::NotThrowing;
      }
    }
  }

  // Handle throw expressions
  if (const CXXThrowExpr *Throw = dyn_cast<CXXThrowExpr>(S)) {
    // Get the thrown type
    QualType ThrowType;
    std::string TypeName;
    std::vector<ExceptionCondition> Conditions;

    if (const Expr *SubExpr = Throw->getSubExpr()) {
      ThrowType = SubExpr->getType();
      TypeName = ThrowType.getUnqualifiedType().getAsString();

      // Check if this exception type should be ignored
      const bool ShouldIgnore = [this, &TypeName]() {
        if (IgnoreBadAlloc_ &&
            TypeName.find("bad_alloc") != std::string::npos) {
          return true;
        }
        for (const auto &IgnoredType : IgnoredExceptions_) {
          if (TypeName.find(IgnoredType) != std::string::npos) {
            return true;
          }
        }
        return false;
      }();

      if (!ShouldIgnore) {
        Info.State = ExceptionState::Throwing;

        // Collect conditions from parent statements
        const Stmt *Current = S;
        while (Current) {
          const Stmt *Parent = getParentStmt(Current);
          if (const IfStmt *If = dyn_cast_or_null<IfStmt>(Parent)) {
            if (const Expr *Cond = If->getCond()) {
              ExceptionCondition EC = getConditionInfo(Cond);
              if (EC.Loc.isValid()) {
                const SourceManager &SM = Context_.getSourceManager();
                EC.File = SM.getFilename(EC.Loc).str();
                EC.Line = SM.getExpansionLineNumber(EC.Loc);
                EC.Column = SM.getExpansionColumnNumber(EC.Loc);
              }
              Conditions.push_back(EC);
            }
          }
          Current = Parent;
        }

        ThrowInfo ThrowEvent;
        ThrowEvent.ThrowStmt = S;
        ThrowEvent.Type = ThrowType;
        ThrowEvent.TypeName = TypeName;
        ThrowEvent.Conditions = Conditions;
        Info.ThrowEvents.push_back(ThrowEvent);
      }
    }
  }

  // Handle function calls
  if (const CallExpr *Call = dyn_cast<CallExpr>(S)) {
    if (const FunctionDecl *Callee = Call->getDirectCallee()) {
      // Handle template instantiations
      if (const FunctionTemplateSpecializationInfo *TSI =
              Callee->getTemplateSpecializationInfo()) {
        const TemplateArgumentList *Args = TSI->TemplateArguments;
        for (unsigned I = 0; I < Args->size(); ++I) {
          const TemplateArgument &Arg = Args->get(I);
          if (Arg.getKind() == TemplateArgument::Type) {
            if (const Expr *BoundExpr = Call->getArg(I)) {
              std::string CondStr;
              llvm::raw_string_ostream OS(CondStr);
              BoundExpr->printPretty(OS, nullptr, Context_.getPrintingPolicy());
              OS << " < T{}";

              ExceptionCondition EC;
              EC.Condition = OS.str();
              EC.Loc = BoundExpr->getBeginLoc();
              if (EC.Loc.isValid()) {
                const SourceManager &SM = Context_.getSourceManager();
                EC.File = SM.getFilename(EC.Loc).str();
                EC.Line = SM.getExpansionLineNumber(EC.Loc);
                EC.Column = SM.getExpansionColumnNumber(EC.Loc);
              }

              for (auto &Type : Info.ThrowEvents) {
                Type.Conditions.push_back(EC);
              }
            }
          }
        }
      }

      FunctionExceptionInfo CalleeInfo = analyzeFunction(Callee);

      // If the callee can throw, this function can throw
      if (CalleeInfo.State == ExceptionState::Throwing) {
        Info.State = ExceptionState::Throwing;
        Info.ThrowEvents.insert(Info.ThrowEvents.end(),
                                CalleeInfo.ThrowEvents.begin(),
                                CalleeInfo.ThrowEvents.end());
      }

      // If the callee has unknown behavior, this function has unknown behavior
      if (CalleeInfo.ContainsUnknown) {
        Info.ContainsUnknown = true;
        // If we don't know if the callee throws, we should mark this function
        // as unknown
        if (CalleeInfo.State == ExceptionState::Unknown) {
          Info.State = ExceptionState::Unknown;
        }
      }
    } else {
      // Handle indirect function calls (function pointers, etc.)
      // We can't determine the callee, so mark as unknown
      Info.ContainsUnknown = true;
      Info.State = ExceptionState::Unknown;
    }
  }
}

std::vector<ExceptionCondition>
ExceptionAnalyzer::getExceptionConditions(const FunctionDecl *Func) const {
  auto It = ConditionCache_.find(Func);
  if (It != ConditionCache_.end())
    return It->second;
  return std::vector<ExceptionCondition>();
}

ExceptionCondition ExceptionAnalyzer::getConditionInfo(const Expr *Cond) const {
  ExceptionCondition Result;
  if (!Cond)
    return Result;

  std::string CondStr;
  llvm::raw_string_ostream OS(CondStr);
  Cond->printPretty(OS, nullptr, Context_.getPrintingPolicy());
  Result.Condition = OS.str();

  SourceLocation Loc = Cond->getBeginLoc();
  if (Loc.isValid()) {
    const SourceManager &SM = Context_.getSourceManager();
    Result.Loc = Loc;
    Result.File = SM.getFilename(Loc).str();
    Result.Line = SM.getExpansionLineNumber(Loc);
    Result.Column = SM.getExpansionColumnNumber(Loc);
  }
  return Result;
}

const Stmt *ExceptionAnalyzer::getParentStmt(const Stmt *S) const {
  auto It = ParentMap_.find(S);
  return It != ParentMap_.end() ? It->second : nullptr;
}
