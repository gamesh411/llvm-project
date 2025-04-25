#include "CollectExceptionInfo.h"
#include "GlobalExceptionInfo.h"
#include "Serialization.h"

#include "clang/AST/ASTContext.h"
#include "clang/AST/Decl.h"
#include "clang/Basic/SourceLocation.h"
#include "clang/CrossTU/CrossTranslationUnit.h"
#include "llvm/ADT/SmallString.h"
#include "llvm/Support/YAMLTraits.h"
#include "llvm/Support/raw_ostream.h"

#include <sstream>

using namespace llvm;
using namespace clang;

void clang::exception_scan::reportAllFunctions(
    clang::exception_scan::ExceptionContext &EC, StringRef PathPrefix) {
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
  for (const auto &EI : EC.InfoPerFunction) {
    OS << EI.FunctionUSRName << '\n';
    OS << " defined in " << EI.DefinedInFile;
    OS << " first declared in " << EI.FirstDeclaredInFile;
    OS << '\n';
  }
}

void clang::exception_scan::reportFunctionDuplications(
    clang::exception_scan::ExceptionContext &EC, StringRef PathPrefix) {
  std::vector<std::string> Functions;
  std::multiset<std::string> FunctionOccurence;
  std::map<std::string, std::multiset<std::string>> FunctionOccurenceForFile;
  for (const auto &Info : EC.InfoPerFunction) {
    Functions.push_back(Info.FunctionUSRName);
    FunctionOccurence.insert(Info.FunctionUSRName);
    FunctionOccurenceForFile[Info.DefinedInFile].insert(Info.FunctionUSRName);
  }

  std::map<std::string, std::pair<std::string, int>> DuplicatedFunctionsPerFile;
  for (const auto &[FileName, FunctionsInFile] : FunctionOccurenceForFile) {
    for (auto It = FunctionsInFile.begin(), End = FunctionsInFile.end();
         It != End;) {
      auto OccurenceCountInFile = FunctionsInFile.count(*It);
      if (OccurenceCountInFile > 1) {
        DuplicatedFunctionsPerFile[FileName].first = *It;
        DuplicatedFunctionsPerFile[FileName].second += OccurenceCountInFile;
      }
      std::advance(It, OccurenceCountInFile);
    }
  }

  std::vector<std::string> TotalDuplicatedFunctions;
  TotalDuplicatedFunctions.reserve(Functions.size());
  std::copy_if(Functions.begin(), Functions.end(),
               std::back_inserter(TotalDuplicatedFunctions),
               [&FunctionOccurence](const std::string &FunctionUSRName) {
                 return FunctionOccurence.count(FunctionUSRName) > 1;
               });

  SmallString<256> ReportPath(PathPrefix);
  llvm::sys::path::append(ReportPath, "function_duplications.txt");
  std::error_code FileOpenError;
  llvm::raw_fd_ostream OS(ReportPath, FileOpenError);

  if (FileOpenError) {
    llvm::errs() << "Error opening file: " << ReportPath << '\n'
                 << FileOpenError.message() << "\n";
    return;
  }

  OS << "Functions that occur more than once:\n";
  for (auto It = FunctionOccurence.begin(), End = FunctionOccurence.end();
       It != End;) {
    auto OccurenceCount = FunctionOccurence.count(*It);
    if (OccurenceCount > 1) {
      OS << *It << " " << OccurenceCount << '\n';
    }
    std::advance(It, OccurenceCount);
  }

  OS << "===" << '\n';

  OS << "\nFunctions that occur more than once in the same file:\n";
  for (const auto &[FileName, FunctionNameOccurencePair] :
       DuplicatedFunctionsPerFile) {
    OS << FileName << ' ' << FunctionNameOccurencePair.first << ' '
       << FunctionNameOccurencePair.second << '\n';
  }
}

void clang::exception_scan::reportDefiniteMatches(
    clang::exception_scan::ExceptionContext &EC, StringRef PathPrefix) {
  SmallString<256> ReportPath(PathPrefix);
  llvm::sys::path::append(ReportPath, "definite_results.txt");

  std::error_code FileOpenError;
  llvm::raw_fd_ostream OS(ReportPath, FileOpenError);

  if (FileOpenError) {
    llvm::errs() << "Error opening file: " << ReportPath << '\n'
                 << FileOpenError.message() << "\n";
    return;
  }

  OS << "Functions that could be marked noexcept, but are not:\n";
  SmallString<256> FunctionList;
  for (const auto &Info : EC.InfoPerFunction) {
    if (Info.Behaviour == clang::exception_scan::ExceptionState::NotThrowing &&
        Info.ExceptionSpecification == EST_None) {
      FunctionList.append(Info.FunctionUSRName);
      FunctionList.append(" defined in ");
      FunctionList.append(Info.DefinedInFile);
      FunctionList.append(" first declared in ");
      FunctionList.append(Info.FirstDeclaredInFile);
      FunctionList.append("\n");
    }
  }
  OS << FunctionList;
}

void clang::exception_scan::reportUnknownCausedMisMatches(
    clang::exception_scan::ExceptionContext &EC, StringRef PathPrefix) {
  SmallString<256> ReportPath(PathPrefix);
  llvm::sys::path::append(ReportPath, "unknown_mismatches.txt");

  std::error_code FileOpenError;
  llvm::raw_fd_ostream OS(ReportPath, FileOpenError);

  if (FileOpenError) {
    llvm::errs() << "Error opening file: " << ReportPath << '\n'
                 << FileOpenError.message() << "\n";
    return;
  }

  OS << "Functions that could NOT be marked noexcept, because they contain "
        "function calls with unknown behaviour:\n";
  SmallString<256> FunctionList;
  for (const auto &Info : EC.InfoPerFunction) {
    if (Info.Behaviour == clang::exception_scan::ExceptionState::Unknown &&
        Info.ExceptionSpecification == EST_None) {
      FunctionList.append(Info.FunctionUSRName);
      FunctionList.append(" defined in ");
      FunctionList.append(Info.DefinedInFile);
      FunctionList.append(" first declared in ");
      FunctionList.append(Info.FirstDeclaredInFile);
      FunctionList.append("\n");
    }
  }
  OS << FunctionList;
}

void clang::exception_scan::serializeExceptionInfo(
    clang::exception_scan::ExceptionContext &EC, StringRef PathPrefix) {
  // Save the exception in the same file hierarchy as the source file, but
  // prefixed with the PathPrefix.
  SmallString<256> Path(PathPrefix);
  llvm::sys::path::append(Path, EC.CurrentInfile);
  StringRef Directory = llvm::sys::path::parent_path(Path);
  llvm::sys::fs::create_directories(Directory);

  std::error_code FileOpenError;
  llvm::raw_fd_ostream OS(Path, FileOpenError);
  if (FileOpenError) {
    llvm::errs() << "Error opening file: " << Path << '\n'
                 << FileOpenError.message() << "\n";
    return;
  }

  llvm::yaml::Output out(OS);
  out << EC;
}

// New reporting functions for the additional data
void clang::exception_scan::reportNoexceptDependees(
    const clang::exception_scan::GlobalExceptionInfo &GCG, StringRef PathPrefix) {
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
    const clang::exception_scan::GlobalExceptionInfo &GCG, StringRef PathPrefix) {
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
    const clang::exception_scan::GlobalExceptionInfo &GCG, StringRef PathPrefix) {
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
