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
#include "llvm/Support/FileSystem.h"
#include "llvm/Support/Path.h"
#include "llvm/Support/YAMLTraits.h"
#include "llvm/Support/raw_ostream.h"

#include <algorithm> // for std::sort
#include <sstream>
#include <system_error> // for std::error_code

using namespace llvm;
using namespace clang;
using namespace clang::exception_scan;

namespace {
// Helper to open a file for writing
std::unique_ptr<raw_fd_ostream> openOutputFile(StringRef Prefix,
                                               StringRef Suffix) {
  SmallString<128> Path(Prefix);
  sys::path::append(Path, Suffix);
  std::error_code EC;
  auto Out = std::make_unique<raw_fd_ostream>(Path, EC, sys::fs::OF_Text);
  if (EC) {
    errs() << "Error opening file " << Path << ": " << EC.message() << "\n";
    return nullptr;
  }
  return Out;
}
} // namespace

void clang::exception_scan::reportAllFunctions(
    const clang::exception_scan::GlobalExceptionInfo &GCG,
    StringRef PathPrefix) {
  std::unique_ptr<raw_fd_ostream> Out = openOutputFile(PathPrefix, "all_functions.txt");
  if (!Out)
    return;

  *Out << "All functions:\n";
  {
    std::lock_guard<std::mutex> Lock(GCG.USRToFunctionMapMutex);
    for (const auto &[USR, Info] : GCG.USRToFunctionMap) {
      *Out << USR << " defined in " << Info.TU << '\n';
    }
  }
}

void clang::exception_scan::reportFunctionDuplications(
    const clang::exception_scan::GlobalExceptionInfo &GCG,
    StringRef PathPrefix) {
  std::unique_ptr<raw_fd_ostream> Out = openOutputFile(PathPrefix, "function_duplications.txt");
  if (!Out)
    return;

  // Count occurrences of each function
  llvm::StringMap<unsigned> FunctionOccurrence;
  {
    std::lock_guard<std::mutex> Lock(GCG.USRToFunctionMapMutex);
    for (const auto &[USR, Info] : GCG.USRToFunctionMap) {
      ++FunctionOccurrence[USR];
    }
  }

  *Out << "Functions that appear in multiple translation units:\n";
  {
    std::lock_guard<std::mutex> Lock(GCG.USRToFunctionMapMutex);
    for (const auto &[USR, Info] : GCG.USRToFunctionMap) {
      if (FunctionOccurrence[USR] > 1) {
        *Out << USR << " defined in " << Info.TU << " translation units\n";
      }
    }
  }
}

void clang::exception_scan::reportDefiniteMatches(
    const clang::exception_scan::GlobalExceptionInfo &GCG,
    StringRef PathPrefix) {
  std::unique_ptr<raw_fd_ostream> Out = openOutputFile(PathPrefix, "definite_results.txt");
  if (!Out)
    return;

  *Out << "Functions that could be marked noexcept, but are not:\n";

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

  *Out << "Functions that could be marked noexcept, but are not:\n";
  for (const auto &Result : DefiniteResults) {
    *Out << Result.USR << " defined in " << Result.SourceLocFile << ':'
       << Result.SourceLocLine << ':' << Result.SourceLocColumn << '\n';
  }
}

void clang::exception_scan::reportUnknownCausedMisMatches(
    const clang::exception_scan::GlobalExceptionInfo &GCG,
    StringRef PathPrefix) {
  std::unique_ptr<raw_fd_ostream> Out = openOutputFile(PathPrefix, "unknown_caused_mismatches.txt");
  if (!Out)
    return;

  *Out << "Functions with unknown exception state because they contain unknown "
       << "calls:\n";
  {
    std::lock_guard<std::mutex> Lock(GCG.USRToExceptionMapMutex);
    for (const auto &[USR, Info] : GCG.USRToExceptionMap) {
      if (Info.State == ExceptionState::Unknown && Info.ContainsUnknown) {
        std::lock_guard<std::mutex> Lock(GCG.USRToFunctionMapMutex);
        auto FuncIt = GCG.USRToFunctionMap.find(USR);
        if (FuncIt != GCG.USRToFunctionMap.end()) {
          *Out << FuncIt->getValue().FunctionName << '\n';
        }
      }
    }
  }
}

// New reporting functions for the additional data
void clang::exception_scan::reportNoexceptDependees(
    const clang::exception_scan::GlobalExceptionInfo &GCG,
    StringRef PathPrefix) {
  std::unique_ptr<raw_fd_ostream> Out = openOutputFile(PathPrefix, "noexcept_dependees.txt");
  if (!Out)
    return;

  *Out << "Functions that appear in noexcept clauses:\n";
  for (const auto &Info : GCG.NoexceptDependees) {
    *Out << "Function: " << Info.FunctionName << "\n";
    *Out << "  USR: " << Info.USR << "\n";
    *Out << "  TU: " << Info.TU << "\n";
    *Out << "  Location: " << Info.NoexceptLocFile << ":" << Info.NoexceptLocLine
       << ":" << Info.NoexceptLocColumn << "\n";
  }
}

void clang::exception_scan::reportCallDependencies(
    const clang::exception_scan::GlobalExceptionInfo &GCG,
    StringRef PathPrefix) {
  std::unique_ptr<raw_fd_ostream> Out = openOutputFile(PathPrefix, "call_dependencies.txt");
  if (!Out)
    return;

  *Out << "Function call dependencies:\n";
  for (const auto &Call : GCG.CallDependencies) {
    *Out << "Caller: " << Call.CallerUSR << "\n";
    *Out << "Callee: " << Call.CalleeUSR << "\n";
    *Out << "Location: " << Call.CallLocFile << ":" << Call.CallLocLine << ":"
       << Call.CallLocColumn << "\n";
  }
}

void clang::exception_scan::reportTUDependencies(
    const clang::exception_scan::GlobalExceptionInfo &GCG,
    StringRef PathPrefix) {
  std::unique_ptr<raw_fd_ostream> Out =
      openOutputFile(PathPrefix, "tu_dependencies.txt");
  if (!Out)
    return;

  *Out << "Translation Unit Dependencies:\n";
  for (const auto &Dependency : GCG.TUDependencies.getAllTUs()) {
    *Out << Dependency << " -> ";
    for (const auto &Dependency :
         GCG.TUDependencies.getDependencies(Dependency)) {
      *Out << Dependency << " ";
    }
    *Out << "\n";
  }
}

// Implementation for the new report function
void clang::exception_scan::reportFunctionDefinitionCount(
    const clang::exception_scan::GlobalExceptionInfo &GCG,
    StringRef PathPrefix) {
  auto Out = openOutputFile(PathPrefix, "function_definition_count.txt");
  if (!Out)
    return;

  *Out << "Total non-system-header function definitions: "
       << GCG.TotalFunctionDefinitions.load() << "\n";
}
