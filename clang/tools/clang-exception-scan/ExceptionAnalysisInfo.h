#ifndef LLVM_CLANG_TOOLS_CLANG_EXCEPTION_SCAN_EXCEPTIONANALYSISINFO_H
#define LLVM_CLANG_TOOLS_CLANG_EXCEPTION_SCAN_EXCEPTIONANALYSISINFO_H

#include "CommonTypes.h"

#include "clang/AST/ASTContext.h"
#include "clang/AST/Decl.h"
#include "clang/AST/Expr.h"
#include "clang/AST/Stmt.h"
#include "clang/AST/Type.h"
#include "clang/ASTMatchers/ASTMatchFinder.h"
#include "clang/ASTMatchers/ASTMatchers.h"
#include "clang/Basic/SourceLocation.h"

#include <string>
#include <vector>

namespace clang {
namespace exception_scan {

/// Represents the state of a function regarding its exception behavior
enum class ExceptionState {
  NotThrowing = 0, ///< Function does not throw exceptions
  Throwing = 1,    ///< Function can throw exceptions
  Unknown = 2      ///< Function's exception behavior is unknown
};

struct GlobalExceptionCondition {
  OwningStringTy ConditionStr; ///< String representation of the condition
  OwningStringTy File;         ///< File containing the condition
  OwningStringTy SourceRange;  ///< Source location of the condition
};

/// Represents information about a specific exception type
struct LocalThrowInfo {
  QualType Type; ///< The exception type
  llvm::SmallVector<GlobalExceptionCondition, 4>
      Conditions; ///< Conditions under which this type is thrown

  // Constructor that takes a QualType and a SmallVector of
  // GlobalExceptionCondition
  LocalThrowInfo(
      QualType Type,
      const llvm::SmallVector<GlobalExceptionCondition, 4> &Conditions)
      : Type(Type), Conditions(Conditions) {}
};

struct GlobalThrowInfo {
  OwningStringTy Type; ///< The exception type
  llvm::SmallVector<GlobalExceptionCondition, 4>
      Conditions; ///< Conditions under which this type is thrown
};

inline GlobalThrowInfo fromLocal(const LocalThrowInfo &ThrowInfo,
                                 ASTContext &Context) {
  OwningStringTy Type;
  llvm::raw_svector_ostream TypeOS(Type);
  TypeOS << ThrowInfo.Type.getAsString();

  return GlobalThrowInfo{Type, ThrowInfo.Conditions};
}

inline std::optional<LocalThrowInfo>
fromGlobal(const GlobalThrowInfo &ThrowInfo, ASTContext &Context) {
  using namespace clang::ast_matchers;

  std::optional<LocalThrowInfo> Result;

  // Create a matcher to find the type
  auto Matcher =
      qualType(hasCanonicalType(asString(ThrowInfo.Type.str().str())))
          .bind("exception_type");

  // Create a callback class to handle the match
  class TypeMatchCallback : public MatchFinder::MatchCallback {
  public:
    TypeMatchCallback(std::optional<LocalThrowInfo> &Result,
                      const GlobalThrowInfo &ThrowInfo)
        : Result(Result), ThrowInfo(ThrowInfo) {}

    void run(const MatchFinder::MatchResult &MatchResult) override {
      const QualType *Type =
          MatchResult.Nodes.getNodeAs<QualType>("exception_type");
      if (!Type) {
        return;
      }

      // Use the constructor instead of emplace
      Result = LocalThrowInfo(*Type, ThrowInfo.Conditions);
    }

  private:
    std::optional<LocalThrowInfo> &Result;
    const GlobalThrowInfo &ThrowInfo;
  };

  // Create the callback and add the matcher
  TypeMatchCallback Callback(Result, ThrowInfo);
  MatchFinder Finder;
  Finder.addMatcher(Matcher, &Callback);

  // Run the matcher on the AST
  Finder.matchAST(Context);

  return Result;
}

/// Represents detailed exception information for a function
struct LocalFunctionExceptionInfo {
  const FunctionDecl *Function; ///< The function declaration
  ExceptionState State;         ///< The function's exception state
  bool ContainsUnknown; ///< Whether the function contains unknown elements
  llvm::SmallVector<LocalThrowInfo, 2>
      ThrowEvents; ///< Types of exceptions that can be thrown
};

struct GlobalFunctionExceptionInfo {
  USRTy Function;       ///< The function declaration
  ExceptionState State; ///< The function's exception state
  bool ContainsUnknown; ///< Whether the function contains unknown elements
  llvm::SmallVector<GlobalThrowInfo, 2>
      ThrowEvents; ///< Types of exceptions that can be thrown
};

} // namespace exception_scan
} // namespace clang

#endif // LLVM_CLANG_TOOLS_CLANG_EXCEPTION_SCAN_EXCEPTIONANALYSISINFO_H