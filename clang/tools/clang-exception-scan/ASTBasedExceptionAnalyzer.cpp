#include "ASTBasedExceptionAnalyzer.h"

#include "clang/AST/ASTContext.h"
#include "clang/AST/CXXInheritance.h"
#include "clang/AST/DeclCXX.h"
#include "clang/AST/ExprCXX.h"
#include "clang/AST/StmtCXX.h"
#include "clang/AST/Type.h"
#include "clang/Basic/SourceLocation.h"
#include "clang/Basic/SourceManager.h"
#include "clang/CrossTU/CrossTranslationUnit.h"
#include "llvm/ADT/DenseMap.h"
#include "llvm/ADT/ScopeExit.h"
#include "llvm/ADT/SmallSet.h"
#include "llvm/ADT/StringRef.h"
#include "llvm/Support/raw_ostream.h"

#include <functional>
#include <mutex>
#include <optional>
#include <string>
#include <unordered_map>
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
  return findTryCatchBlocksImpl(S, SM);
}

ASTBasedExceptionAnalyzer::ASTBasedExceptionAnalyzer(ASTContext &Context,
                                                     GlobalExceptionInfo &GEI)
    : Context_(Context), GEI_(GEI), IgnoreBadAlloc_(true) {}

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

LocalFunctionExceptionInfo
ASTBasedExceptionAnalyzer::analyzeFunction(const FunctionDecl *Func) {
  // Check for recursive entry (should ideally be caught in analyzeFunctionCall,
  // but good safeguard)
  if (AnalyzingFunctions_.count(Func)) {
    return LocalFunctionExceptionInfo{
        Func, ExceptionState::Unknown, true, EST_None, {}};
  }

  // Add function to the set of currently analyzed functions
  AnalyzingFunctions_.insert(Func);
  // Ensure the function is removed from the set when we exit this scope
  auto RemoveFromAnalyzingGuard =
      llvm::make_scope_exit([&]() { AnalyzingFunctions_.erase(Func); });

  if (!Func) {
    // Handle null function declarations (should never happen in practice)
    return LocalFunctionExceptionInfo{
        nullptr, ExceptionState::Unknown, true, EST_None, {}};
  }

  // Check if we've already analyzed this function in our local cache
  auto It = FunctionCache_.find(Func);
  if (It != FunctionCache_.end()) {
    return It->second;
  }

  // Get the USR for this function
  std::optional<std::string> USR =
      cross_tu::CrossTranslationUnitContext::getLookupName(Func);
  if (USR) {
    // Check if we have exception info for this USR in the global cache
    std::lock_guard<std::mutex> Lock(GEI_.USRToExceptionMapMutex);
    auto GlobalIt = GEI_.USRToExceptionMap.find(*USR);
    if (GlobalIt != GEI_.USRToExceptionMap.end()) {
      // Convert the global exception info to our local format
      LocalFunctionExceptionInfo LocalInfo;
      LocalInfo.Function = Func;
      LocalInfo.State = GlobalIt->second.State;
      LocalInfo.ContainsUnknown = GlobalIt->second.ContainsUnknown;
      LocalInfo.ExceptionSpecType = GlobalIt->second.ExceptionSpecType;

      for (const auto &ThrowEvent : GlobalIt->second.ThrowEvents) {
        LocalInfo.ThrowEvents.emplace_back(ThrowEvent.SerializedCanonicalType,
                                           ThrowEvent.Conditions);
      }

      // Cache the result locally
      FunctionCache_[Func] = LocalInfo;
      return LocalInfo;
    }
  }

  // Handle functions without a body (declarations only)
  if (!Func->hasBody()) {
    // For functions without a body, we need to check if they're marked as
    // noexcept or if they have an exception specification
    ExceptionSpecificationType EST = Func->getExceptionSpecType();
    LocalFunctionExceptionInfo Info{
        Func, ExceptionState::Unknown, true, EST, {}};

    // If the function has an exception specification, we can determine its
    // state
    if (EST == EST_None || EST == EST_Dynamic) {
      Info.State = ExceptionState::Throwing;
    } else if (EST == EST_NoexceptTrue || EST == EST_NoexceptFalse ||
               EST == EST_NoThrow) {
      Info.State = ExceptionState::NotThrowing;
    }

    // Cache the result locally
    FunctionCache_[Func] = Info;

    // If we have a USR, cache in the global map as well
    if (USR) {
      std::lock_guard<std::mutex> Lock(GEI_.USRToExceptionMapMutex);
      GlobalFunctionExceptionInfo GlobalInfo;
      GlobalInfo.Function = *USR;
      GlobalInfo.State = Info.State;
      GlobalInfo.ContainsUnknown = Info.ContainsUnknown;
      GlobalInfo.ExceptionSpecType = Info.ExceptionSpecType;
      for (const auto &ThrowEvent : Info.ThrowEvents) {
        GlobalInfo.ThrowEvents.push_back(fromLocal(ThrowEvent, Context_));
      }
      GEI_.USRToExceptionMap[*USR] = std::move(GlobalInfo);
      Changed_ = true;
    }

    return Info;
  }

  // Check if this is a noexcept builtin
  if (isNoexceptBuiltin(Func)) {
    LocalFunctionExceptionInfo Info{
        Func, ExceptionState::NotThrowing, false, EST_NoThrow, {}};
    FunctionCache_[Func] = Info;
    return Info;
  }

  // Save the current try block cache
  auto SavedTryBlockCache = std::move(TryBlockCache_);

  // Find all try-catch blocks in the function
  AnalysisOrderedTryCatches TryCatches =
      findTryCatchBlocks(Func->getBody(), Context_.getSourceManager());

  // First analyze all try-catch blocks in order and cache their results
  for (const auto &TC : TryCatches) {
    LocalFunctionExceptionInfo TryInfo{
        nullptr, ExceptionState::NotThrowing, false, EST_None, {}};
    analyzeTryCatch(TC.TryStmt, TryInfo);
    TryBlockCache_[TC.TryStmt] = TryInfo;
  }

  // Now analyze the function body, which will use the cached try block results
  ExceptionSpecificationType EST = Func->getExceptionSpecType();
  LocalFunctionExceptionInfo Info{
      Func, ExceptionState::NotThrowing, false, EST, {}};
  analyzeStatement(Func->getBody(), Info);

  // Check if the function's exception specification is violated by our analysis
  if (EST == EST_NoexceptTrue || EST == EST_NoexceptFalse ||
      EST == EST_NoThrow) {
    if (Info.State == ExceptionState::Throwing) {
      // TODO: Report this to the user
      // llvm::errs() << "Warning: Function marked as noexcept but analysis
      // found it can throw\n";
      // We keep the throwing state as it's more accurate than the specification
    }
  }

  // Cache the result locally
  FunctionCache_[Func] = Info;

  // If we have a USR, cache in the global map as well
  if (USR) {
    std::lock_guard<std::mutex> Lock(GEI_.USRToExceptionMapMutex);
    GlobalFunctionExceptionInfo GlobalInfo;
    GlobalInfo.Function = *USR;
    GlobalInfo.State = Info.State;
    GlobalInfo.ContainsUnknown = Info.ContainsUnknown;
    GlobalInfo.ExceptionSpecType = Info.ExceptionSpecType;
    for (const auto &ThrowEvent : Info.ThrowEvents) {
      GlobalInfo.ThrowEvents.push_back(fromLocal(ThrowEvent, Context_));
    }
    GEI_.USRToExceptionMap[*USR] = std::move(GlobalInfo);
    Changed_ = true;
  }

  // Restore the previous try block cache
  TryBlockCache_ = std::move(SavedTryBlockCache);

  return Info;
}

void ASTBasedExceptionAnalyzer::analyzeStatement(
    const Stmt *S, LocalFunctionExceptionInfo &Info) {
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

  if (const CXXConstructExpr *Construct = dyn_cast<CXXConstructExpr>(S)) {
    analyzeCXXConstructExpr(Construct, Info);
  }

  // Recursively analyze child statements
  for (const Stmt *Child : S->children()) {
    if (Child) {
      // Check if the current statement 'S' is a LambdaExpr and 'Child' is its
      // body CompoundStmt. If so, skip analyzing the body here; it's only
      // relevant when the lambda is called.
      bool SkipChild = false;
      if (const LambdaExpr *ParentLambda = dyn_cast<LambdaExpr>(S)) {
        if (Child == ParentLambda->getBody()) {
          SkipChild = true;
        }
      }

      if (!SkipChild) {
        analyzeStatement(Child, Info);
      }
    }
  }
}

void ASTBasedExceptionAnalyzer::analyzeTryCatch(
    const CXXTryStmt *Try, LocalFunctionExceptionInfo &Info) {
  // Create info for this try block
  LocalFunctionExceptionInfo TryInfo{
      nullptr, ExceptionState::NotThrowing, false, EST_None, {}};

  // Analyze the try block (nested try blocks will be handled via cache)
  analyzeStatement(Try->getTryBlock(), TryInfo);

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
  llvm::SmallVector<LocalThrowInfo, 2> UncaughtExceptions = TryInfo.ThrowEvents;

  // Check each catch block
  for (unsigned I = 0; I < Try->getNumHandlers(); ++I) {
    const CXXCatchStmt *Handler = Try->getHandler(I);

    // Analyze the catch block for throws/rethrows
    LocalFunctionExceptionInfo HandlerInfo{
        nullptr, ExceptionState::NotThrowing, false, EST_None, {}};

    analyzeStatement(Handler->getHandlerBlock(), HandlerInfo);

    // If we have a catch-all handler
    if (!Handler->getExceptionDecl()) {
      AllCaught = true;

      if (HandlerInfo.State == ExceptionState::Throwing) {
        AnyRethrows = true;
        // Add any new throw events from the handler
        if (HandlerInfo.ThrowEvents.empty()) {
          // Use the original exceptions for rethrow
          TryInfo.ThrowEvents = UncaughtExceptions;
        } else {
          TryInfo.ThrowEvents = HandlerInfo.ThrowEvents;
        }
      } else {
        // Handler doesn't throw, clear all throw events
        TryInfo.ThrowEvents.clear();
      }
      break;
    }

    // Check if this handler catches any of the uncaught exceptions
    QualType CaughtType = Handler->getCaughtType();
    llvm::SmallVector<LocalThrowInfo, 2> StillUncaught;

    for (auto &ThrowEvent : UncaughtExceptions) {
      if (!ThrowEvent.Type) {
        if (canCatchGlobalType(CaughtType,
                               ThrowEvent.SerializedCanonicalType)) {
          // TODO: log that we could not get the effective type of the throw
          // event, and this case we err on the side caution, and assume that
          // the exception is not caught
          StillUncaught.push_back(ThrowEvent);
          continue;
        }
      }

      if (ThrowEvent.Type) {
        if (canCatchLocalType(CaughtType, ThrowEvent.Type.value())) {
          if (HandlerInfo.State == ExceptionState::Throwing) {
            AnyRethrows = true;
            // Add any new throw events from the handler
            TryInfo.ThrowEvents =
                HandlerInfo.ThrowEvents; // Replace instead of append
          }
        } else {
          // This exception is not caught by this handler
          StillUncaught.push_back(ThrowEvent);
        }
      }
    }

    UncaughtExceptions = StillUncaught;
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
  } else if (AnyRethrows) {
    // All exceptions are caught, but some are rethrown
    TryInfo.State = ExceptionState::Throwing;
    // ThrowEvents already contains only the rethrown exceptions
  } else {
    // All exceptions are caught and none are rethrown
    TryInfo.State = ExceptionState::NotThrowing;
    TryInfo.ThrowEvents.clear();
  }

  // Cache the result
  TryBlockCache_[Try] = TryInfo;

  // Update the function's exception state
  Info = TryInfo;
}

void ASTBasedExceptionAnalyzer::analyzeThrowExpr(
    const CXXThrowExpr *Throw, LocalFunctionExceptionInfo &Info) {
  // Get the thrown type
  QualType ThrowType;
  OwningStringTy TypeName;
  llvm::SmallVector<GlobalExceptionCondition, 4> Conditions = [this, Throw]() {
    llvm::SmallVector<GlobalExceptionCondition, 4> Conditions;
    const Stmt *Current = Throw;
    while (Current) {
      const Stmt *Parent = getParentStmt(Current);
      if (const IfStmt *If = dyn_cast_or_null<IfStmt>(Parent)) {
        if (const Expr *Cond = If->getCond()) {
          Conditions.push_back(getConditionInfo(Cond));
        }
      }
      Current = Parent;
    }
    return Conditions;
  }();

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
      Info.ThrowEvents.emplace_back(ThrowType, Conditions);
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
            Info.ThrowEvents.emplace_back(Catch->getCaughtType(), Conditions);
          }
        }
        break;
      }
      Current = Parent;
    }
  }
}

void ASTBasedExceptionAnalyzer::analyzeFunctionCall(
    const FunctionDecl *Callee, LocalFunctionExceptionInfo &Info) {
  if (!Callee) {
    // Handle indirect function calls (function pointers, etc.)
    // We can't determine the callee, so mark as unknown
    Info.ContainsUnknown = true;
    Info.State = ExceptionState::Unknown;
    return;
  }

  // Check if the callee is already being analyzed (recursion)
  if (AnalyzingFunctions_.count(Callee)) {
    // Don't re-analyze; the base case throw will be caught by the initial
    // analyzeFunction call for the recursive function.
    return;
  }

  // Handle builtin functions first
  if (Callee->getBuiltinID() != 0 && isNoexceptBuiltin(Callee)) {
    // Known non-throwing builtin, no need to analyze further
    return;
  }

  // Check local cache first
  auto LocalIt = FunctionCache_.find(Callee);
  if (LocalIt != FunctionCache_.end()) {
    if (LocalIt->second.State == ExceptionState::Throwing) {
      Info.State = ExceptionState::Throwing;
      Info.ThrowEvents.insert(Info.ThrowEvents.end(),
                              LocalIt->second.ThrowEvents.begin(),
                              LocalIt->second.ThrowEvents.end());
    }

    // Check if the callee has a noexcept specification but our analysis found
    // it can throw
    if (LocalIt->second.ExceptionSpecType == EST_NoexceptTrue ||
        LocalIt->second.ExceptionSpecType == EST_NoexceptFalse ||
        LocalIt->second.ExceptionSpecType == EST_NoThrow) {
      if (LocalIt->second.State == ExceptionState::Throwing) {
        // TODO: Report this to the user
        // llvm::errs() << "  Warning: Callee marked as noexcept but analysis "
        //                "found it can throw\n";
      }
    }

    return;
  }

  // Get the USR for the callee
  std::optional<std::string> USR =
      cross_tu::CrossTranslationUnitContext::getLookupName(Callee);
  if (USR) {
    // Check if we have exception info for this USR in the global cache
    std::lock_guard<std::mutex> Lock(GEI_.USRToExceptionMapMutex);
    auto GlobalIt = GEI_.USRToExceptionMap.find(*USR);
    if (GlobalIt != GEI_.USRToExceptionMap.end()) {
      // Use the global exception info directly

      if (GlobalIt->second.State == ExceptionState::Throwing) {
        Info.State = ExceptionState::Throwing;
        // Create a local throw info from the global throw info
        llvm::SmallVector<LocalThrowInfo, 2> LocalThrowEvents;
        for (const auto &ThrowEvent : GlobalIt->second.ThrowEvents) {
          LocalThrowEvents.emplace_back(ThrowEvent.SerializedCanonicalType,
                                        ThrowEvent.Conditions);
        }
        Info.ThrowEvents.insert(Info.ThrowEvents.end(),
                                LocalThrowEvents.begin(),
                                LocalThrowEvents.end());
        // TODO: check if we need to set Changed_ = true;
      }

      // Check if the callee has a noexcept specification but our analysis
      // found it can throw
      if (GlobalIt->second.ExceptionSpecType == EST_NoexceptTrue ||
          GlobalIt->second.ExceptionSpecType == EST_NoexceptFalse ||
          GlobalIt->second.ExceptionSpecType == EST_NoThrow) {
        if (GlobalIt->second.State == ExceptionState::Throwing) {
          // TODO: Report this to the user
          // llvm::errs() << "  Warning: Callee marked as noexcept but analysis
          // "
          //                "found it can throw\n";
        }
      }

      if (GlobalIt->second.ContainsUnknown) {
        if (!Info.ContainsUnknown) {
          Info.ContainsUnknown = true;
          // TODO: check if we need to set Changed_ = true;
        }

        if (GlobalIt->second.State == ExceptionState::Unknown) {
          if (Info.State != ExceptionState::Unknown) {
            Info.State = ExceptionState::Unknown;
            // TODO: check if we need to set Changed_ = true;
          }
        }
      }
      return;
    }
  }

  // If not found in global cache, analyze the callee
  LocalFunctionExceptionInfo CalleeInfo = analyzeFunction(Callee);

  // If the callee can throw, this function can throw
  if (CalleeInfo.State == ExceptionState::Throwing) {
    Info.State = ExceptionState::Throwing;
    // Make sure to propagate the throw events from the callee
    if (!CalleeInfo.ThrowEvents.empty()) {
      // Propagating throw events from callee
      Info.ThrowEvents.insert(Info.ThrowEvents.end(),
                              CalleeInfo.ThrowEvents.begin(),
                              CalleeInfo.ThrowEvents.end());
    } else {
      // TODO: Assert this this never the case
    }
  }

  // Check if the callee has a noexcept specification but our analysis found
  // it can throw
  if (CalleeInfo.ExceptionSpecType == EST_NoexceptTrue ||
      CalleeInfo.ExceptionSpecType == EST_NoexceptFalse ||
      CalleeInfo.ExceptionSpecType == EST_NoThrow) {
    if (CalleeInfo.State == ExceptionState::Throwing) {
      // TODO: Report this to the user
      // llvm::errs() << "  Warning: Callee marked as noexcept but analysis "
      //                "found it can throw\n";
    }
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
}

void ASTBasedExceptionAnalyzer::analyzeCXXConstructExpr(
    const CXXConstructExpr *Construct, LocalFunctionExceptionInfo &Info) {
  analyzeFunctionCall(Construct->getConstructor(), Info);
}

void ASTBasedExceptionAnalyzer::analyzeCallExpr(
    const CallExpr *Call, LocalFunctionExceptionInfo &Info) {
  analyzeFunctionCall(Call->getDirectCallee(), Info);
}

static void collectCXXRecordDecls(
    const DeclContext *DC,
    std::unordered_map<std::string, const CXXRecordDecl *> &typeToDecl) {
  for (const auto *D : DC->decls()) {
    if (const auto *RD = llvm::dyn_cast<CXXRecordDecl>(D)) {
      if (RD->hasDefinition()) {
        QualType QT = RD->getTypeForDecl() ? QualType(RD->getTypeForDecl(), 0)
                                           : QualType();
        if (!QT.isNull()) {
          QualType NormQT = QT.getCanonicalType();
          while (NormQT->isReferenceType() || NormQT->isPointerType())
            NormQT = NormQT->getPointeeType();
          NormQT = NormQT.getUnqualifiedType();
          std::string ThisType = NormQT.getAsString();
          typeToDecl[ThisType] = RD;
        }
      }
    }
    if (const auto *DC2 = llvm::dyn_cast<DeclContext>(D)) {
      collectCXXRecordDecls(DC2, typeToDecl);
    }
  }
}

bool ASTBasedExceptionAnalyzer::canCatchLocalType(QualType CaughtType,
                                                  QualType ThrownType) const {
  if (CaughtType->isReferenceType()) {
    CaughtType = CaughtType->getPointeeType();
  }
  if (ThrownType->isReferenceType()) {
    ThrownType = ThrownType->getPointeeType();
  }

  const void *currentTU =
      static_cast<const void *>(Context_.getTranslationUnitDecl());
  if (lastTU_ != currentTU) {
    typeToDecl_.clear();
    collectCXXRecordDecls(Context_.getTranslationUnitDecl(), typeToDecl_);
    lastTU_ = currentTU;
  }

  if (CaughtType->isPointerType() && ThrownType->isPointerType()) {
    return canCatchLocalType(CaughtType->getPointeeType(),
                             ThrownType->getPointeeType());
  }
  if (ThrownType->isNullPtrType() && CaughtType->isPointerType()) {
    return true;
  }

  QualType NormCaught = CaughtType.getCanonicalType().getUnqualifiedType();
  QualType NormThrown = ThrownType.getCanonicalType().getUnqualifiedType();

  if (!NormCaught->isRecordType() && !NormThrown->isRecordType()) {
    return Context_.hasSameType(NormCaught.getUnqualifiedType(),
                                NormThrown.getUnqualifiedType());
  }

  std::string CatchTypeStr = NormCaught.getAsString();
  std::string ThrownTypeStr = NormThrown.getAsString();

  auto catchIt = typeToDecl_.find(CatchTypeStr);
  auto thrownIt = typeToDecl_.find(ThrownTypeStr);
  if (thrownIt != typeToDecl_.end()) {
    if (catchIt != typeToDecl_.end()) {
      const CXXRecordDecl *CaughtDecl = catchIt->second;
      const CXXRecordDecl *ThrownDecl = thrownIt->second;
      if (CaughtDecl == ThrownDecl) {
        return true;
      }
      CXXBasePaths Paths;
      if (!ThrownDecl->isDerivedFrom(CaughtDecl, Paths)) {
        return false;
      }
      if (Paths.isAmbiguous(CanQualType::CreateUnsafe(
              Context_.getCanonicalType(Context_.getRecordType(CaughtDecl))))) {
        return false;
      }
      for (const CXXBasePath &Path : Paths) {
        bool AllPublic = true;
        for (const CXXBasePathElement &Element : Path) {
          if (Element.Base->getAccessSpecifier() != AS_public) {
            AllPublic = false;
            break;
          }
        }
        if (AllPublic) {
          return true;
        }
      }
      return false;
    }
    return false;
  }
  return false;
}

bool ASTBasedExceptionAnalyzer::canCatchGlobalType(
    QualType CaughtType, const std::string &ThrownTypeStr) const {
  if (CaughtType->isReferenceType()) {
    CaughtType = CaughtType->getPointeeType();
  }
  if (CaughtType->isPointerType()) {
    // For pointer types, we only support exact match for cross-TU
    CaughtType = CaughtType.getCanonicalType().getUnqualifiedType();
    std::string CatchTypeStr = CaughtType.getAsString();
    if (CatchTypeStr == ThrownTypeStr) {
      return true;
    }
    return false;
  }
  QualType NormCaught = CaughtType.getCanonicalType().getUnqualifiedType();
  std::string CatchTypeStr = NormCaught.getAsString();
  std::lock_guard<std::mutex> Lock(GEI_.CatchTypeToDescendantsMutex);
  auto It = GEI_.CatchTypeToDescendants.find(CatchTypeStr);
  if (It != GEI_.CatchTypeToDescendants.end()) {
    if (It->second.contains(ThrownTypeStr)) {
      return true;
    }
  }
  return false;
}

QualType ASTBasedExceptionAnalyzer::getUnqualifiedType(QualType Type) const {
  return Type.getUnqualifiedType();
}

GlobalExceptionCondition
ASTBasedExceptionAnalyzer::getConditionInfo(const Expr *Cond) const {
  GlobalExceptionCondition Result;
  if (!Cond)
    return Result;

  OwningStringTy CondStr;
  llvm::raw_svector_ostream OS(CondStr);
  Cond->printPretty(OS, nullptr, Context_.getPrintingPolicy());
  Result.ConditionStr = OS.str();

  SourceLocation Loc = Cond->getBeginLoc();
  if (Loc.isValid()) {
    const SourceManager &SM = Context_.getSourceManager();
    Result.File = SM.getFilename(Loc).str();
    Result.SourceRange = Cond->getSourceRange().printToString(SM);
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
