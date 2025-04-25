#include "CollectExceptionInfo.h"
#include "GlobalExceptionInfo.h"

#include "clang/AST/ASTContext.h"
#include "clang/AST/Decl.h"
#include "clang/Basic/SourceLocation.h"
#include "clang/CrossTU/CrossTranslationUnit.h"
#include "llvm/ADT/DenseMap.h"
#include "llvm/ADT/DenseSet.h"
#include "llvm/ADT/STLExtras.h"
#include "llvm/ADT/SmallString.h"
#include "llvm/ADT/StringMap.h"
#include "llvm/ADT/StringSet.h"
#include "llvm/Support/YAMLTraits.h"
#include "llvm/Support/raw_ostream.h"

#include <sstream>

using namespace llvm;
using namespace clang;

void clang::exception_scan::reportAllFunctions(
    const clang::exception_scan::GlobalExceptionInfo &GCG,
    StringRef PathPrefix) {
  llvm::SmallString<256> ReportPath(PathPrefix);
  llvm::sys::path::append(ReportPath, "all_functions.txt");
  std::error_code FileOpenError;
  llvm::raw_fd_ostream OS(ReportPath, FileOpenError);

  if (FileOpenError) {
    llvm::errs() << "Error opening file: " << ReportPath << '\n'
                 << FileOpenError.message() << "\n";
    return;
  }

  OS << "All functions:\n";
  {
    std::lock_guard<std::mutex> Lock(GCG.USRToFunctionMapMutex);
    for (const auto &[USR, Info] : GCG.USRToFunctionMap) {
      OS << USR << " defined in " << Info.TU << '\n';
    }
  }
}

void clang::exception_scan::reportFunctionDuplications(
    const clang::exception_scan::GlobalExceptionInfo &GCG,
    StringRef PathPrefix) {
  // Count occurrences of each function
  llvm::StringMap<unsigned> FunctionOccurrence;
  {
    std::lock_guard<std::mutex> Lock(GCG.USRToFunctionMapMutex);
    for (const auto &[USR, Info] : GCG.USRToFunctionMap) {
      ++FunctionOccurrence[USR];
    }
  }

  SmallString<256> ReportPath(PathPrefix);
  llvm::sys::path::append(ReportPath, "function_duplications.txt");
  std::error_code FileOpenError;
  llvm::raw_fd_ostream OS(ReportPath, FileOpenError);

  if (FileOpenError) {
    llvm::errs() << "Error opening file: " << ReportPath << '\n'
                 << FileOpenError.message() << "\n";
    return;
  }

  OS << "Functions that appear in multiple translation units:\n";
  {
    std::lock_guard<std::mutex> Lock(GCG.USRToFunctionMapMutex);
    for (const auto &[USR, Info] : GCG.USRToFunctionMap) {
      if (FunctionOccurrence[USR] > 1) {
        OS << USR << " defined in " << Info.TU << " translation units\n";
      }
    }
  }
}

void clang::exception_scan::reportDefiniteMatches(
    const clang::exception_scan::GlobalExceptionInfo &GCG,
    StringRef PathPrefix) {

  SmallString<256> ReportPath(PathPrefix);
  llvm::sys::path::append(ReportPath, "definite_results.txt");
  std::error_code FileOpenError;
  llvm::raw_fd_ostream OS(ReportPath, FileOpenError);

  if (FileOpenError) {
    llvm::errs() << "Error opening file: " << ReportPath << '\n'
                 << FileOpenError.message() << "\n";
    return;
  }

  struct DefiniteResult {
    llvm::StringRef USR;
    llvm::StringRef TU;
    llvm::StringRef SourceLocFile;
    unsigned SourceLocLine;
    unsigned SourceLocColumn;
  };

  llvm::SmallVector<DefiniteResult, 32> DefiniteResults;
  {
    std::scoped_lock Lock(GCG.USRToExceptionMapMutex,
                          GCG.USRToFunctionMapMutex);
    for (const auto &[USR, Info] : GCG.USRToExceptionMap) {
      if (Info.State == ExceptionState::NotThrowing &&
          Info.ExceptionSpecType == EST_None) {
        const auto FuncIt = GCG.USRToFunctionMap.find(USR);
        if (FuncIt == GCG.USRToFunctionMap.end()) {
          llvm::errs() << "USR not found in USRToFunctionMap: " << USR << "\n";
          continue;
        }
        const auto &FuncInfo = FuncIt->getValue();
        if (FuncInfo.IsDefinition) {
          DefiniteResults.push_back(
              DefiniteResult{USR, FuncInfo.TU, FuncInfo.SourceLocFile,
                             FuncInfo.SourceLocLine, FuncInfo.SourceLocColumn});
        }
      }
    }
  }

  llvm::sort(DefiniteResults,
             [](const DefiniteResult &LHS, const DefiniteResult &RHS) {
               if (LHS.SourceLocFile != RHS.SourceLocFile) {
                 return LHS.SourceLocFile < RHS.SourceLocFile;
               }
               if (LHS.SourceLocLine != RHS.SourceLocLine) {
                 return LHS.SourceLocLine < RHS.SourceLocLine;
               }
               return LHS.SourceLocColumn < RHS.SourceLocColumn;
             });

  OS << "Functions that could be marked noexcept, but are not:\n";
  for (const auto &Result : DefiniteResults) {
    OS << Result.USR << " defined in " << Result.SourceLocFile << ':'
       << Result.SourceLocLine << ':' << Result.SourceLocColumn << '\n';
  }
}

void clang::exception_scan::reportUnknownCausedMisMatches(
    const clang::exception_scan::GlobalExceptionInfo &GCG,
    StringRef PathPrefix) {

  SmallString<256> ReportPath(PathPrefix);
  llvm::sys::path::append(ReportPath, "unknown_caused_mismatches.txt");
  std::error_code FileOpenError;
  llvm::raw_fd_ostream OS(ReportPath, FileOpenError);

  if (FileOpenError) {
    llvm::errs() << "Error opening file: " << ReportPath << '\n'
                 << FileOpenError.message() << "\n";
    return;
  }

  OS << "Functions with unknown exception state because they contain unknown "
        "calls:\n";
  {
    std::lock_guard<std::mutex> Lock(GCG.USRToExceptionMapMutex);
    for (const auto &[USR, Info] : GCG.USRToExceptionMap) {
      if (Info.State == ExceptionState::Unknown && Info.ContainsUnknown) {
        std::lock_guard<std::mutex> Lock(GCG.USRToFunctionMapMutex);
        auto FuncIt = GCG.USRToFunctionMap.find(USR);
        if (FuncIt != GCG.USRToFunctionMap.end()) {
          OS << FuncIt->getValue().FunctionName << '\n';
        }
      }
    }
  }
}

// New reporting functions for the additional data
void clang::exception_scan::reportNoexceptDependees(
    const clang::exception_scan::GlobalExceptionInfo &GCG,
    StringRef PathPrefix) {
  SmallString<256> ReportPath(PathPrefix);
  llvm::sys::path::append(ReportPath, "noexcept_dependees.txt");
  std::error_code FileOpenError;
  llvm::raw_fd_ostream OS(ReportPath, FileOpenError);

  if (FileOpenError) {
    llvm::errs() << "Error opening file: " << ReportPath << '\n'
                 << FileOpenError.message() << "\n";
    return;
  }

  OS << "Functions that appear in noexcept clauses:\n";
  for (const auto &Info : GCG.NoexceptDependees) {
    OS << "Function: " << Info.FunctionName << "\n";
    OS << "  USR: " << Info.USR << "\n";
    OS << "  TU: " << Info.TU << "\n";
    OS << "  Location: " << Info.NoexceptLocFile << ":" << Info.NoexceptLocLine
       << ":" << Info.NoexceptLocColumn << "\n";
  }
}

void clang::exception_scan::reportCallDependencies(
    const clang::exception_scan::GlobalExceptionInfo &GCG,
    StringRef PathPrefix) {
  SmallString<256> ReportPath(PathPrefix);
  llvm::sys::path::append(ReportPath, "call_dependencies.txt");
  std::error_code FileOpenError;
  llvm::raw_fd_ostream OS(ReportPath, FileOpenError);

  if (FileOpenError) {
    llvm::errs() << "Error opening file: " << ReportPath << '\n'
                 << FileOpenError.message() << "\n";
    return;
  }

  OS << "Function call dependencies:\n";
  for (const auto &Call : GCG.CallDependencies) {
    OS << "Caller: " << Call.CallerUSR << "\n";
    OS << "Callee: " << Call.CalleeUSR << "\n";
    OS << "Location: " << Call.CallLocFile << ":" << Call.CallLocLine << ":"
       << Call.CallLocColumn << "\n";
  }
}

void clang::exception_scan::reportTUDependencies(
    const clang::exception_scan::GlobalExceptionInfo &GCG,
    StringRef PathPrefix) {
  SmallString<256> ReportPath(PathPrefix);
  llvm::sys::path::append(ReportPath, "tu_dependencies.txt");
  std::error_code FileOpenError;
  llvm::raw_fd_ostream OS(ReportPath, FileOpenError);

  if (FileOpenError) {
    llvm::errs() << "Error opening file: " << ReportPath << '\n'
                 << FileOpenError.message() << "\n";
    return;
  }

  OS << "Translation unit dependencies:\n";
  for (const auto &[Dependent, _] : GCG.TUs) {
    for (const auto &Dependee : GCG.TUDependencies.getDependencies(Dependent)) {
      OS << Dependent << " -> " << Dependee << "\n";
    }
  }
}
