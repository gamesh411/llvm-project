#include "ASTBasedExceptionAnalyzer.h"
#include "clang/AST/ASTContext.h"
#include "clang/AST/CXXInheritance.h"
#include "clang/AST/DeclCXX.h"
#include "clang/AST/ExprCXX.h"
#include "clang/AST/StmtCXX.h"
#include "clang/AST/Type.h"
#include "clang/Basic/SourceLocation.h"
#include "clang/Basic/SourceManager.h"
#include "llvm/ADT/DenseMap.h"
#include "llvm/ADT/SmallSet.h"
#include "llvm/ADT/StringRef.h"
#include "llvm/Support/raw_ostream.h"
#include <functional>
#include <string>
#include <vector>

using namespace clang;
using namespace clang::exception_scan;

namespace {
// Helper function to build parent map
void buildParentMapImpl(const Stmt *S,
                        llvm::DenseMap<const Stmt *, const Stmt *> &ParentMap) {
  if (!S)
    return;
  for (const Stmt *Child : S->children()) {
    if (Child) {
      ParentMap[Child] = S;
      buildParentMapImpl(Child, ParentMap);
    }
  }
}
} // namespace

llvm::DenseMap<const Stmt *, const Stmt *>
ASTBasedExceptionAnalyzer::buildParentMap(const Stmt *S) {
  llvm::DenseMap<const Stmt *, const Stmt *> ParentMap;
  buildParentMapImpl(S, ParentMap);
  return ParentMap;
}

llvm::DenseMap<const Stmt *, llvm::SmallSet<const Stmt *, 4>>
ASTBasedExceptionAnalyzer::buildTransitiveParentMap(
    const llvm::DenseMap<const Stmt *, const Stmt *> &ParentMap,
    const Stmt *Root) {
  llvm::DenseMap<const Stmt *, llvm::SmallSet<const Stmt *, 4>>
      TransitiveParentMap;

  // For each statement in the parent map
  for (const auto &Entry : ParentMap) {
    const Stmt *Current = Entry.first;
    llvm::SmallSet<const Stmt *, 4> Ancestors;

    // Walk up the parent chain until we reach the root
    while (Current != Root) {
      auto It = ParentMap.find(Current);
      if (It == ParentMap.end())
        break;
      Current = It->second;
      Ancestors.insert(Current);
    }

    // Store all ancestors for this statement
    if (!Ancestors.empty())
      TransitiveParentMap[Entry.first] = std::move(Ancestors);
  }

  return TransitiveParentMap;
}

static ASTBasedExceptionAnalyzer::AnalysisOrderedTryCatches
findTryCatchBlocksImpl(
    const Stmt *S, const SourceManager &SM,
    ASTBasedExceptionAnalyzer::TryCatchInfo *Parent = nullptr,
    unsigned Depth = 0u) {
  ASTBasedExceptionAnalyzer::AnalysisOrderedTryCatches TryCatches;
  if (!S)
    return TryCatches;

  const CXXTryStmt *Try = dyn_cast<CXXTryStmt>(S);
  unsigned NewDepth = Try ? Depth + 1 : Depth;

  // If this is a try statement, create its info before processing children
  ASTBasedExceptionAnalyzer::TryCatchInfo *CurrentTryInfo = nullptr;
  if (Try) {
    auto [It, Inserted] = TryCatches.emplace(Try, Try->getBeginLoc(), Depth);
    // std::set returns a const iterator to prevent modification of the
    // elements, because that would affect ordering.
    // It is safe to cast away the constness because we started with a non-const
    // TryCatchInfo object.
    CurrentTryInfo =
        const_cast<ASTBasedExceptionAnalyzer::TryCatchInfo *>(&*It);

    // Link with parent if we have one
    if (Parent) {
      Parent->InnerTryCatches.push_back(*CurrentTryInfo);
    }
  }

  // Process all children with the current try as their parent (if it exists)
  for (const Stmt *Child : S->children()) {
    if (Child) {
      auto ChildTryCatches = findTryCatchBlocksImpl(
          Child, SM, CurrentTryInfo ? CurrentTryInfo : Parent, NewDepth);
      TryCatches.merge(ChildTryCatches);
    }
  }

  return TryCatches;
}

ASTBasedExceptionAnalyzer::AnalysisOrderedTryCatches
ASTBasedExceptionAnalyzer::findTryCatchBlocks(const Stmt *S,
                                              const SourceManager &SM) {
  llvm::errs() << "\n=== Starting try-catch block analysis ===\n";

  auto Result = findTryCatchBlocksImpl(S, SM);

  llvm::errs() << "\n=== Final try-catch block count: " << Result.size()
               << " ===\n";
  for (const auto &TC : Result) {
    llvm::errs() << "Try at " << TC.Loc.printToString(SM)
                 << " depth=" << TC.Depth
                 << " children=" << TC.InnerTryCatches.size() << "\n";
  }

  return Result;
}

#if 0
std::vector<ASTBasedExceptionAnalyzer::TryCatchInfo>
ASTBasedExceptionAnalyzer::buildTryCatchHierarchy(
    const std::set<TryCatchInfo> &TryCatches,
    const llvm::DenseMap<const Stmt *, const Stmt *> &ParentMap) {
  // Sort by source location to maintain source order
  std::vector<TryCatchInfo> TryCatchesVec;
  TryCatchesVec.reserve(TryCatches.size());
  for (const auto &TC : TryCatches) {
    TryCatchesVec.push_back(TC);
  }
  std::sort(TryCatchesVec.begin(), TryCatchesVec.end(),
            [](const TryCatchInfo &A, const TryCatchInfo &B) {
              return A.Loc < B.Loc;
            });

  // Find the root node (function body)
  const Stmt *Root = nullptr;
  if (!TryCatches.empty() && !ParentMap.empty()) {
    const Stmt *Current = TryCatchesVec[0].TryStmt;
    while (Current) {
      auto It = ParentMap.find(Current);
      if (It == ParentMap.end()) {
        Root = Current;
        break;
      }
      Current = It->second;
    }
  }
  if (!Root)
    return {};

  // Build transitive parent map for more efficient ancestor lookup
  auto TransitiveParentMap = buildTransitiveParentMap(ParentMap, Root);

  // For each try block, find its closest parent try block
  for (size_t i = 0; i < TryCatchesVec.size(); ++i) {
    const Stmt *Current = TryCatchesVec[i].TryStmt;

    // Get all ancestors of current try block
    auto AncestorsIt = TransitiveParentMap.find(Current);
    if (AncestorsIt == TransitiveParentMap.end())
      continue;

    const auto &Ancestors = AncestorsIt->second;

    // Find the closest parent try block by checking which ancestor is a try
    // block and appears latest in the source
    TryCatchInfo *ClosestParent = nullptr;
    SourceLocation ClosestLoc;

    for (size_t j = 0; j < TryCatchesVec.size(); ++j) {
      if (i == j)
        continue;

      const CXXTryStmt *PotentialParent = TryCatchesVec[j].TryStmt;
      if (Ancestors.contains(PotentialParent)) {
        // Found an ancestor that is a try block
        if (!ClosestParent || TryCatchesVec[j].Loc > ClosestLoc) {
          ClosestParent = &TryCatchesVec[j];
          ClosestLoc = TryCatchesVec[j].Loc;
        }
      }
    }

    // Set the parent relationship and calculate depth
    if (ClosestParent) {
      // Calculate depth by counting try blocks between current and root
      TryCatchesVec[i].Depth = ClosestParent->Depth + 1;
      ClosestParent->InnerTryCatches.push_back(TryCatchesVec[i]);
    } else {
      // This is a root try block
      TryCatchesVec[i].Depth = 0;
    }
  }

  // Sort inner try-catch blocks by source location
  for (auto &TC : TryCatchesVec) {
    std::sort(TC.InnerTryCatches.begin(), TC.InnerTryCatches.end(),
              [](const TryCatchInfo *A, const TryCatchInfo *B) {
                return A->Loc < B->Loc;
              });
  }

  return TryCatchesVec;
}
#endif

ASTBasedExceptionAnalyzer::ASTBasedExceptionAnalyzer(ASTContext &Context)
    : Context_(Context), IgnoreBadAlloc_(true) {}

bool ASTBasedExceptionAnalyzer::isNoexceptBuiltin(
    const FunctionDecl *FD) const {
  if (!FD)
    return false;

  // Check if this is a builtin function
  unsigned BI = FD->getBuiltinID();
  if (BI != 0)
    return true;

  return false;
}

FunctionExceptionInfo
ASTBasedExceptionAnalyzer::analyzeFunction(const FunctionDecl *Func) {
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

  // Check if this is a noexcept builtin
  if (isNoexceptBuiltin(Func)) {
    FunctionExceptionInfo Info{Func, ExceptionState::NotThrowing, false, {}};
    FunctionCache_[Func] = Info;
    return Info;
  }

  // Save the current try block cache and parent map
  auto SavedTryBlockCache = std::move(TryBlockCache_);
  auto SavedParentMap = std::move(ParentMap_);

  // Find all try-catch blocks in the function
  AnalysisOrderedTryCatches TryCatches =
      findTryCatchBlocks(Func->getBody(), Context_.getSourceManager());

  // Debug print
  llvm::errs() << "Analyzing function: " << Func->getNameAsString() << "\n";
  llvm::errs() << "Found " << TryCatches.size() << " try-catch blocks\n";
  llvm::errs() << "Analysis order: ";
  for (const auto &TC : TryCatches) {
    llvm::errs() << TC.TryStmt << " ";
  }
  llvm::errs() << "\n";

  // First analyze all try-catch blocks in order and cache their results
  for (const auto &TC : TryCatches) {
    FunctionExceptionInfo TryInfo{
        nullptr, ExceptionState::NotThrowing, false, {}};
    analyzeTryCatch(TC.TryStmt, TryInfo);
    TryBlockCache_[TC.TryStmt] = TryInfo;

    // Debug print
    llvm::errs() << "After analyzing try-catch block " << TC.TryStmt
                 << ", state: "
                 << (TryInfo.State == ExceptionState::Throwing ? "Throwing"
                                                               : "NotThrowing")
                 << ", throw events: " << TryInfo.ThrowEvents.size() << "\n";
  }

  // Now analyze the function body, which will use the cached try block results
  FunctionExceptionInfo Info{Func, ExceptionState::NotThrowing, false, {}};
  analyzeStatement(Func->getBody(), Info);

  // Debug print
  llvm::errs() << "Final state: "
               << (Info.State == ExceptionState::Throwing ? "Throwing"
                                                          : "NotThrowing")
               << ", throw events: " << Info.ThrowEvents.size() << "\n";

  // Cache the result
  FunctionCache_[Func] = Info;

  // Restore the previous try block cache and parent map
  TryBlockCache_ = std::move(SavedTryBlockCache);
  ParentMap_ = std::move(SavedParentMap);

  return Info;
}

void ASTBasedExceptionAnalyzer::analyzeStatement(const Stmt *S,
                                                 FunctionExceptionInfo &Info) {
  if (!S)
    return;

  // Handle try-catch blocks by incorporating their already-analyzed state
  if (const CXXTryStmt *Try = dyn_cast<CXXTryStmt>(S)) {
    // Find this try block's info in the cache
    auto It = TryBlockCache_.find(Try);
    assert(It != TryBlockCache_.end() &&
           "Try block not found in cache, but the order of analysis and "
           "pre-analyzing the try-catch block should ensure that once we get "
           "here, the information is already in the cache");
    // Incorporate the cached state
    if (It->second.State == ExceptionState::Throwing) {
      Info.State = ExceptionState::Throwing;
      Info.ThrowEvents.insert(Info.ThrowEvents.end(),
                              It->second.ThrowEvents.begin(),
                              It->second.ThrowEvents.end());
    }
    return;
  }

  // Handle throw expressions
  if (const CXXThrowExpr *Throw = dyn_cast<CXXThrowExpr>(S)) {
    if (!Throw->getSubExpr()) {
      // This is a rethrow
      llvm::errs() << "Found rethrow expression in analyzeStatement\n";
      Info.State = ExceptionState::Throwing;

      // Find the enclosing catch block
      const Stmt *Current = Throw;
      while (Current) {
        const Stmt *Parent = getParentStmt(Current);
        if (const CXXCatchStmt *Catch =
                dyn_cast_or_null<CXXCatchStmt>(Parent)) {
          // Found the enclosing catch block
          const Stmt *TryParent = getParentStmt(Catch);
          if (const CXXTryStmt *Try = dyn_cast_or_null<CXXTryStmt>(TryParent)) {
            // Found the try block
            auto TryIt = TryBlockCache_.find(Try);
            if (TryIt != TryBlockCache_.end()) {
              // Use the original exceptions for the rethrow
              Info.ThrowEvents = TryIt->second.ThrowEvents;
              llvm::errs() << "  Using original exceptions from try block: "
                           << Info.ThrowEvents.size() << " events\n";
            }
          }
          break;
        }
        Current = Parent;
      }
    } else {
      analyzeThrowExpr(Throw, Info);
    }
    return;
  }

  // Handle function calls
  if (const CallExpr *Call = dyn_cast<CallExpr>(S)) {
    analyzeCallExpr(Call, Info);
  }

  // Recursively analyze child statements
  for (const Stmt *Child : S->children()) {
    analyzeStatement(Child, Info);
  }
}

void ASTBasedExceptionAnalyzer::analyzeTryCatch(const CXXTryStmt *Try,
                                                FunctionExceptionInfo &Info) {
  // Create info for this try block
  FunctionExceptionInfo TryInfo{
      nullptr, ExceptionState::NotThrowing, false, {}};

  // Analyze the try block (nested try blocks will be handled via cache)
  analyzeStatement(Try->getTryBlock(), TryInfo);

  llvm::errs() << "\nAnalyzing try block " << Try << ":\n";
  llvm::errs() << "After analyzing try block body: state="
               << (TryInfo.State == ExceptionState::Throwing ? "Throwing"
                                                             : "NotThrowing")
               << ", events=" << TryInfo.ThrowEvents.size() << "\n";

  // If the try block doesn't throw, we're done with this block
  if (TryInfo.State == ExceptionState::NotThrowing) {
    // Cache the result
    TryBlockCache_[Try] = TryInfo;
    Info = TryInfo;
    return;
  }

  // If the try block throws, check if all exceptions are caught
  bool AllCaught = false;
  bool AnyRethrows = false;
  std::vector<ThrowInfo> UncaughtExceptions = TryInfo.ThrowEvents;

  llvm::errs() << "Initial uncaught exceptions: " << UncaughtExceptions.size()
               << "\n";
  for (const auto &Event : UncaughtExceptions) {
    llvm::errs() << "  Type: " << Event.TypeName << "\n";
  }

  // Check each catch block
  for (unsigned I = 0; I < Try->getNumHandlers(); ++I) {
    const CXXCatchStmt *Handler = Try->getHandler(I);
    llvm::errs() << "Checking catch handler " << I << ": ";
    if (!Handler->getExceptionDecl()) {
      llvm::errs() << "catch(...)\n";
    } else {
      llvm::errs() << "catch(" << Handler->getCaughtType().getAsString()
                   << ")\n";
    }

    // Analyze the catch block for throws/rethrows
    FunctionExceptionInfo HandlerInfo{
        nullptr, ExceptionState::NotThrowing, false, {}};

    llvm::errs() << "  Analyzing handler block:\n";
    analyzeStatement(Handler->getHandlerBlock(), HandlerInfo);
    llvm::errs() << "  Handler analysis result: state="
                 << (HandlerInfo.State == ExceptionState::Throwing
                         ? "Throwing"
                         : "NotThrowing")
                 << ", events=" << HandlerInfo.ThrowEvents.size() << "\n";

    // If we have a catch-all handler
    if (!Handler->getExceptionDecl()) {
      AllCaught = true;

      if (HandlerInfo.State == ExceptionState::Throwing) {
        AnyRethrows = true;
        llvm::errs() << "  Catch-all handler throws/rethrows\n";
        // Add any new throw events from the handler
        if (HandlerInfo.ThrowEvents.empty()) {
          llvm::errs()
              << "    Warning: Handler is throwing but has no throw events!\n";
          // Use the original exceptions for rethrow
          TryInfo.ThrowEvents = UncaughtExceptions;
        } else {
          TryInfo.ThrowEvents = HandlerInfo.ThrowEvents;
        }
        llvm::errs() << "  Updated TryInfo throw events: "
                     << TryInfo.ThrowEvents.size() << "\n";
      } else {
        // Handler doesn't throw, clear all throw events
        TryInfo.ThrowEvents.clear();
        llvm::errs() << "  Catch-all handler handles all exceptions\n";
      }
      break;
    }

    // Check if this handler catches any of the uncaught exceptions
    QualType CaughtType = Handler->getCaughtType();
    std::vector<ThrowInfo> StillUncaught;

    for (const auto &ThrowEvent : UncaughtExceptions) {
      if (canCatchType(CaughtType, ThrowEvent.Type)) {
        llvm::errs() << "  Can catch " << ThrowEvent.TypeName << "\n";

        if (HandlerInfo.State == ExceptionState::Throwing) {
          AnyRethrows = true;
          // Add any new throw events from the handler
          TryInfo.ThrowEvents =
              HandlerInfo.ThrowEvents; // Replace instead of append
          llvm::errs() << "  Handler throws new exceptions: "
                       << HandlerInfo.ThrowEvents.size() << "\n";
        } else {
          llvm::errs() << "  Handler handles exception\n";
        }
      } else {
        llvm::errs() << "  Cannot catch " << ThrowEvent.TypeName << "\n";
        // This exception is not caught by this handler
        StillUncaught.push_back(ThrowEvent);
      }
    }

    UncaughtExceptions = StillUncaught;
    llvm::errs() << "  After handler, " << UncaughtExceptions.size()
                 << " exceptions still uncaught\n";

    // If all exceptions are caught, we're done
    if (UncaughtExceptions.empty()) {
      AllCaught = true;
      break;
    }
  }

  // Update the try-catch block's exception state
  if (!AllCaught) {
    // Some exceptions are not caught
    TryInfo.State = ExceptionState::Throwing;
    // Only keep the uncaught exceptions
    TryInfo.ThrowEvents = UncaughtExceptions;
    llvm::errs() << "Final state: Some exceptions not caught ("
                 << UncaughtExceptions.size() << " remaining)\n";
  } else if (AnyRethrows) {
    // All exceptions are caught, but some are rethrown
    TryInfo.State = ExceptionState::Throwing;
    // ThrowEvents already contains only the rethrown exceptions
    llvm::errs() << "Final state: All caught but some rethrown ("
                 << TryInfo.ThrowEvents.size() << " rethrows)\n";
  } else {
    // All exceptions are caught and none are rethrown
    TryInfo.State = ExceptionState::NotThrowing;
    TryInfo.ThrowEvents.clear();
    llvm::errs() << "Final state: All caught and none rethrown\n";
  }

  llvm::errs() << "Final TryInfo state: "
               << (TryInfo.State == ExceptionState::Throwing ? "Throwing"
                                                             : "NotThrowing")
               << ", events=" << TryInfo.ThrowEvents.size() << "\n";

  // Cache the result
  TryBlockCache_[Try] = TryInfo;

  // Update the function's exception state
  Info = TryInfo;
}

void ASTBasedExceptionAnalyzer::analyzeThrowExpr(const CXXThrowExpr *Throw,
                                                 FunctionExceptionInfo &Info) {
  // Get the thrown type
  QualType ThrowType;
  std::string TypeName;
  std::vector<ExceptionCondition> Conditions;

  if (const Expr *SubExpr = Throw->getSubExpr()) {
    ThrowType = SubExpr->getType();
    TypeName = ThrowType.getUnqualifiedType().getAsString();

    // Check if this exception type should be ignored
    const bool ShouldIgnore = [this, &TypeName]() {
      if (IgnoreBadAlloc_ && TypeName.find("bad_alloc") != std::string::npos) {
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
      const Stmt *Current = Throw;
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
      ThrowEvent.ThrowStmt = Throw;
      ThrowEvent.Type = ThrowType;
      ThrowEvent.TypeName = TypeName;
      ThrowEvent.Conditions = Conditions;
      Info.ThrowEvents.push_back(ThrowEvent);
    }
  } else {
    // This is a rethrow (throw;)
    // We need to find the nearest enclosing catch block
    const Stmt *Current = Throw;
    while (Current) {
      const Stmt *Parent = getParentStmt(Current);
      if (const CXXCatchStmt *Catch = dyn_cast_or_null<CXXCatchStmt>(Parent)) {
        // We found the enclosing catch block
        // Now we need to find the try block that contains this catch block
        const Stmt *TryParent = getParentStmt(Catch);
        if (const CXXTryStmt *Try = dyn_cast_or_null<CXXTryStmt>(TryParent)) {
          // We found the try block
          // For a rethrow, we rethrow whatever was caught
          Info.State = ExceptionState::Throwing;

          // If we have a catch-all, we rethrow the original exception
          if (!Catch->getExceptionDecl()) {
            auto TryIt = TryBlockCache_.find(Try);
            if (TryIt != TryBlockCache_.end()) {
              // Use the original throw events from the try block
              Info.ThrowEvents = TryIt->second.ThrowEvents;
            }
          } else {
            // Create a throw event for the caught type
            ThrowInfo ThrowEvent;
            ThrowEvent.ThrowStmt = Throw;
            ThrowEvent.Type = Catch->getCaughtType();
            ThrowEvent.TypeName =
                ThrowEvent.Type.getUnqualifiedType().getAsString();
            Info.ThrowEvents.push_back(ThrowEvent);
          }
        }
        break;
      }
      Current = Parent;
    }
  }
}

void ASTBasedExceptionAnalyzer::analyzeCallExpr(const CallExpr *Call,
                                                FunctionExceptionInfo &Info) {
  if (const FunctionDecl *Callee = Call->getDirectCallee()) {
    // Handle builtin functions first
    if (Callee->getBuiltinID() != 0 && isNoexceptBuiltin(Callee)) {
      // Known non-throwing builtin, no need to analyze further
      return;
    }

    // Analyze the callee
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

bool ASTBasedExceptionAnalyzer::canCatchType(QualType CaughtType,
                                             QualType ThrownType) const {
  llvm::errs() << "\ncanCatchType debug:\n";
  llvm::errs() << "CaughtType: " << CaughtType.getAsString() << "\n";
  llvm::errs() << "ThrownType: " << ThrownType.getAsString() << "\n";

  // If the types are the same, it's a direct catch
  if (Context_.hasSameType(CaughtType, ThrownType)) {
    llvm::errs() << "Direct type match!\n";
    return true;
  }

  // Get the unqualified types and handle references
  if (CaughtType->isReferenceType()) {
    CaughtType = CaughtType->getPointeeType();
  }
  if (ThrownType->isReferenceType()) {
    ThrownType = ThrownType->getPointeeType();
  }
  CaughtType = CaughtType.getUnqualifiedType();
  ThrownType = ThrownType.getUnqualifiedType();

  llvm::errs() << "After unqualified and dereferencing:\n";
  llvm::errs() << "CaughtType: " << CaughtType.getAsString() << "\n";
  llvm::errs() << "ThrownType: " << ThrownType.getAsString() << "\n";

  // Check for direct match after dereferencing
  if (Context_.hasSameType(CaughtType, ThrownType)) {
    llvm::errs() << "Direct type match after dereferencing!\n";
    return true;
  }

  // Handle pointer types
  if (CaughtType->isPointerType() && ThrownType->isPointerType()) {
    llvm::errs() << "Both are pointer types, checking pointee types\n";
    return canCatchType(CaughtType->getPointeeType(),
                        ThrownType->getPointeeType());
  }

  // Handle nullptr_t
  if (ThrownType->isNullPtrType() && CaughtType->isPointerType()) {
    llvm::errs() << "nullptr_t case\n";
    return true;
  }

  // Handle class types
  const CXXRecordDecl *CaughtDecl = CaughtType->getAsCXXRecordDecl();
  const CXXRecordDecl *ThrownDecl = ThrownType->getAsCXXRecordDecl();

  if (!CaughtDecl || !ThrownDecl) {
    llvm::errs() << "Not both class types! CaughtDecl="
                 << (CaughtDecl ? "yes" : "no")
                 << " ThrownDecl=" << (ThrownDecl ? "yes" : "no") << "\n";
    return false;
  }

  llvm::errs() << "CaughtDecl name: " << CaughtDecl->getNameAsString() << "\n";
  llvm::errs() << "ThrownDecl name: " << ThrownDecl->getNameAsString() << "\n";

  // Check if ThrownDecl is derived from CaughtDecl
  CXXBasePaths Paths;
  bool IsDerived = ThrownDecl->isDerivedFrom(CaughtDecl, Paths);
  llvm::errs() << "isDerivedFrom result: " << (IsDerived ? "yes" : "no")
               << "\n";

  if (!IsDerived) {
    llvm::errs() << "Not derived\n";
    return false;
  }

  // Check for ambiguous paths
  bool IsAmbiguous = Paths.isAmbiguous(Context_.getCanonicalType(CaughtType));
  llvm::errs() << "isAmbiguous result: " << (IsAmbiguous ? "yes" : "no")
               << "\n";

  if (IsAmbiguous) {
    llvm::errs() << "Ambiguous inheritance\n";
    return false;
  }

  // Check that at least one path has all public inheritance
  for (const CXXBasePath &Path : Paths) {
    bool AllPublic = true;
    for (const CXXBasePathElement &Element : Path) {
      if (Element.Base->getAccessSpecifier() != AS_public) {
        AllPublic = false;
        llvm::errs() << "Found non-public inheritance\n";
        break;
      }
    }
    if (AllPublic) {
      llvm::errs() << "Found valid public inheritance path\n";
      return true;
    }
  }

  llvm::errs() << "No valid public inheritance path found\n";
  return false;
}

QualType ASTBasedExceptionAnalyzer::getUnqualifiedType(QualType Type) const {
  return Type.getUnqualifiedType();
}

ExceptionCondition
ASTBasedExceptionAnalyzer::getConditionInfo(const Expr *Cond) const {
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

const Stmt *ASTBasedExceptionAnalyzer::getParentStmt(const Stmt *S) const {
  auto It = ParentMap_.find(S);
  return It != ParentMap_.end() ? It->second : nullptr;
}

void ASTBasedExceptionAnalyzer::updateParentMap(const Stmt *S) {
  ParentMap_ = buildParentMap(S);
}