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
  std::optional<QualType> Type; ///< The exception type
  std::string
      SerializedCanonicalType; ///< String representation of the exception type,
                               ///< because we use this with AST matchers, we
                               ///< store it as a std::string
  llvm::SmallVector<GlobalExceptionCondition, 4>
      Conditions; ///< Conditions under which this type is thrown

  // Constructor that takes a QualType and a SmallVector of
  // GlobalExceptionCondition
  LocalThrowInfo(
      QualType Type,
      const llvm::SmallVector<GlobalExceptionCondition, 4> &Conditions)
      : Type(Type), SerializedCanonicalType(Type.getAsString()),
        Conditions(Conditions) {}

  LocalThrowInfo(
      const std::string &SerializedCanonicalType,
      const llvm::SmallVector<GlobalExceptionCondition, 4> &Conditions)
      : SerializedCanonicalType(SerializedCanonicalType),
        Conditions(Conditions) {}

  bool ensureAndStoreQualTypeInContext(ASTContext &Context) {
    if (Type) {
      return true;
    }

    if (SerializedCanonicalType.empty()) {
      return false;
    }

    using namespace clang::ast_matchers;
    const auto Matcher =
        qualType(hasCanonicalType(asString(SerializedCanonicalType)))
            .bind("exception_type");

    class TypeMatchCallback : public MatchFinder::MatchCallback {
    public:
      TypeMatchCallback(std::optional<QualType> &Result) : Result(Result) {}

      void run(const MatchFinder::MatchResult &MatchResult) override {
        const QualType *Type =
            MatchResult.Nodes.getNodeAs<QualType>("exception_type");
        if (!Type) {
          return;
        }
        Result = *Type;
      }

    private:
      std::optional<QualType> &Result;
    };

    // Create the callback and add the matcher
    std::optional<QualType> Result;
    TypeMatchCallback Callback(Result);
    MatchFinder Finder;
    Finder.addMatcher(Matcher, &Callback);

    // Run the matcher on the AST
    Finder.matchAST(Context);

    if (Result) {
      Type = *Result;
      return true;
    }

    return false;
  }
};

struct GlobalThrowInfo {
  std::string
      SerializedCanonicalType; ///< We use std::string because we
                               ///< need to pass it to AST matchers eventually
  llvm::SmallVector<GlobalExceptionCondition, 4>
      Conditions; ///< Conditions under which this type is thrown
};

inline GlobalThrowInfo fromLocal(const LocalThrowInfo &ThrowInfo,
                                 ASTContext &Context) {
  if (!ThrowInfo.SerializedCanonicalType.empty()) {
    return GlobalThrowInfo{ThrowInfo.SerializedCanonicalType,
                           ThrowInfo.Conditions};
  };

  if (ThrowInfo.Type) {
    return GlobalThrowInfo{
        ThrowInfo.Type.value().getCanonicalType().getAsString(),
        ThrowInfo.Conditions};
  }

  llvm_unreachable("No serialized canonical type and no type");
}

/// Represents detailed exception information for a function
struct LocalFunctionExceptionInfo {
  const FunctionDecl *Function; ///< The function declaration
  ExceptionState State;         ///< The function's exception state
  bool ContainsUnknown; ///< Whether the function contains unknown elements
  ExceptionSpecificationType
      ExceptionSpecType; ///< The function's exception specification type
  llvm::SmallVector<LocalThrowInfo, 2>
      ThrowEvents; ///< Types of exceptions that can be thrown
};

struct GlobalFunctionExceptionInfo {
  USRTy Function;       ///< The function declaration
  ExceptionState State; ///< The function's exception state
  bool ContainsUnknown; ///< Whether the function contains unknown elements
  ExceptionSpecificationType
      ExceptionSpecType; ///< The function's exception specification type
  llvm::SmallVector<GlobalThrowInfo, 2>
      ThrowEvents; ///< Types of exceptions that can be thrown
};

} // namespace exception_scan
} // namespace clang

#endif // LLVM_CLANG_TOOLS_CLANG_EXCEPTION_SCAN_EXCEPTIONANALYSISINFO_H