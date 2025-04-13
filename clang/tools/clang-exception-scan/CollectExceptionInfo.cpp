#include "CollectExceptionInfo.h"
#include "ExceptionAnalyzer.h"
#include "Serialization.h"

#include "clang/AST/ASTContext.h"
#include "clang/AST/Decl.h"
#include "clang/Basic/SourceLocation.h"
#include "llvm/Support/YAMLTraits.h"
#include "llvm/Support/raw_ostream.h"

#include <sstream>

void clang::exception_scan::ExceptionInfoExtractor::HandleTranslationUnit(
    ASTContext &Context) {
  for (auto const *TopLevelDecl : Context.getTranslationUnitDecl()->decls()) {
    if (auto *FD = dyn_cast<FunctionDecl>(TopLevelDecl)) {
      auto FA = ExceptionAnalyzer{Context};
      FA.ignoreBadAlloc(false);
      auto AI = FA.analyzeFunction(FD);

      // the the file in which the function was defined
      auto const *FirstDecl = FD->getFirstDecl();
      auto FirstDeclaredInFile =
          std::string{SM.getFilename(FirstDecl->getLocation())};
      auto const *Definition = FD->getDefinition();

      auto DefinedInFile = std::string{};
      if (Definition)
        DefinedInFile = std::string{SM.getFilename(Definition->getLocation())};
      auto *Identifier = FirstDecl->getIdentifier();
      auto FunctionName = std::string{};
      if (Identifier)
        FunctionName = std::string{Identifier->getName()};

      auto FunctionUSRName =
          cross_tu::CrossTranslationUnitContext::getLookupName(FD).value_or(
              "<no_usr_name>");

      auto ss = std::stringstream{};
      for (auto const &T : AI.ThrowEvents) {
        std::string ExceptionTypeName = T.Type.getAsString();
        ss << ExceptionTypeName << ", ";
      }
      auto view = std::string_view{ss.str()};
      if (view.size() > 2)
        view.remove_suffix(2);
      auto ExceptionTypeList = std::string{view};

      auto Behaviour = AI.State;
      auto ES = FD->getExceptionSpecType();
      bool ContainsUnknown = AI.ContainsUnknown;
      bool IsInMainFile = SM.isInMainFile(FD->getOuterLocStart());

      // NOTE: optimization: we use more move semantics here
      EC.InfoPerFunction.push_back(
          {FirstDeclaredInFile, DefinedInFile, FunctionName, FunctionUSRName,
           ExceptionTypeList, Behaviour, ES, ContainsUnknown, IsInMainFile});
    }
  }
}

void clang::exception_scan::reportAllFunctions(ExceptionContext &EC,
                                               StringRef PathPrefix) {
  SmallString<256> ReportPath(PathPrefix);
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
  }
}

void clang::exception_scan::reportFunctionDuplications(ExceptionContext &EC,
                                                       StringRef PathPrefix) {
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

void clang::exception_scan::reportDefiniteMatches(ExceptionContext &EC,
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

  OS << "Functions that could be marked noexcept, but are not:\n";
  SmallString<256> FunctionList;
  for (const auto &Info : EC.InfoPerFunction) {
    if (Info.Behaviour == clang::exception_scan::ExceptionState::NotThrowing &&
        Info.ExceptionSpecification == EST_None) {
      FunctionList.append(Info.FunctionUSRName);
      FunctionList.append(" in ");
      FunctionList.append(Info.DefinedInFile);
      FunctionList.append(" first declared in ");
      FunctionList.append(Info.FirstDeclaredInFile);
      FunctionList.append("\n");
    }
  }
  OS << FunctionList;
}

void clang::exception_scan::reportUnknownCausedMisMatches(
    ExceptionContext &EC, StringRef PathPrefix) {
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
    if (Info.Behaviour == clang::exception_scan::ExceptionState::Unknown) {
      FunctionList.append(Info.FunctionUSRName);
      FunctionList.append(" in ");
      FunctionList.append(Info.DefinedInFile);
      FunctionList.append(" first declared in ");
      FunctionList.append(Info.FirstDeclaredInFile);
      FunctionList.append("\n");
    }
  }
  OS << FunctionList;
}

void clang::exception_scan::serializeExceptionInfo(ExceptionContext &EC,
                                                   StringRef PathPrefix) {
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

std::unique_ptr<clang::ASTConsumer>
clang::exception_scan::CollectExceptionInfoAction::CreateASTConsumer(
    CompilerInstance &CI, StringRef InFile) {
  EC.CurrentInfile = InFile;
  return std::make_unique<ExceptionInfoExtractor>(CI.getASTContext(), EC);
}

std::unique_ptr<clang::FrontendAction>
clang::exception_scan::CollectExceptionInfoActionFactory::create() {
  return std::make_unique<CollectExceptionInfoAction>(EC);
}
