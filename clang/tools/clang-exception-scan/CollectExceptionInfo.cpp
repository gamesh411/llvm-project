#include "CollectExceptionInfo.h"
#include "clang/Analysis/CFG.h"
#include "clang/Basic/ExceptionSpecificationType.h"
#include "clang/Basic/LLVM.h"
#include "clang/CrossTU/CrossTranslationUnit.h"
#include "clang/Frontend/CompilerInstance.h"
#include "llvm/Support/FileSystem.h"
#include "llvm/Support/Path.h"
#include "llvm/Support/YAMLTraits.h"
#include "llvm/Support/raw_ostream.h"

#include "ExceptionAnalyzer.cpp"

#include <sstream>

void clang::exception_scan::ExceptionInfoExtractor::HandleTranslationUnit(
    ASTContext &Context) {
  for (auto const *TopLevelDecl : Context.getTranslationUnitDecl()->decls()) {
    if (auto *FD = dyn_cast<FunctionDecl>(TopLevelDecl)) {
      auto FA = ExceptionAnalyzer{};
      FA.ignoreBadAlloc(false);
      auto AI = FA.analyze(FD);

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
      for (auto const *T : AI.ThrownExceptions) {
        std::string ExceptionTypeName = clang::QualType(T, 0).getAsString();
        ss << ExceptionTypeName << ", ";
      }
      auto view = std::string_view{ss.str()};
      if (view.size() > 2)
        view.remove_suffix(2);
      auto ExceptionTypeList = std::string{view};

      auto Behaviour = AI.Behaviour;
      auto ES = FD->getExceptionSpecType();
      bool ContainsUnknown = AI.ContainsUnknown;
      bool IsInMainFile = SM.isInMainFile(FD->getOuterLocStart());

      // NOTE: optimization: we use more move semantics here
      EC.PFEI.push_back({FirstDeclaredInFile, DefinedInFile, FunctionName,
                         FunctionUSRName, ExceptionTypeList, Behaviour, ES,
                         ContainsUnknown, IsInMainFile});
    }
  }
}

template <> struct llvm::yaml::ScalarEnumerationTraits<ExceptionState> {
  static void enumeration(llvm::yaml::IO &IO, ExceptionState &ES) {
    IO.enumCase(ES, "Throwing", ExceptionState::Throwing);
    IO.enumCase(ES, "NotThrowing", ExceptionState::NotThrowing);
    IO.enumCase(ES, "Unknown", ExceptionState::Unknown);
  }
};

template <>
struct llvm::yaml::ScalarEnumerationTraits<clang::ExceptionSpecificationType> {
  static void enumeration(llvm::yaml::IO &IO,
                          clang::ExceptionSpecificationType &ES) {
    IO.enumCase(ES, "None", clang::EST_None);
    IO.enumCase(ES, "DynamicNone", clang::EST_DynamicNone);
    IO.enumCase(ES, "Dynamic", clang::EST_Dynamic);
    IO.enumCase(ES, "MSAny", clang::EST_MSAny);
    IO.enumCase(ES, "NoThrow", clang::EST_NoThrow);
    IO.enumCase(ES, "BasicNoexcept", clang::EST_BasicNoexcept);
    IO.enumCase(ES, "DependentNoexcept", clang::EST_DependentNoexcept);
    IO.enumCase(ES, "NoexceptFalse", clang::EST_NoexceptFalse);
    IO.enumCase(ES, "NoexceptTrue", clang::EST_NoexceptTrue);
    IO.enumCase(ES, "Unevaluated", clang::EST_Unevaluated);
    IO.enumCase(ES, "Uninstantiated", clang::EST_Uninstantiated);
    IO.enumCase(ES, "Unparsed", clang::EST_Unparsed);
  }
};

template <>
struct llvm::yaml::MappingTraits<
    clang::exception_scan::PerFunctionExceptionInfo> {
  static void mapping(llvm::yaml::IO &IO,
                      clang::exception_scan::PerFunctionExceptionInfo &EC) {
    IO.mapRequired("FirstDeclaredInFile", EC.FirstDeclaredInFile);
    IO.mapRequired("DefinedInFile", EC.DefinedInFile);
    IO.mapRequired("FunctionName", EC.FunctionName);
    IO.mapRequired("FunctionUSRName", EC.FunctionUSRName);
    IO.mapRequired("Behaviour", EC.Behaviour);
    IO.mapRequired("ContainsUnknown", EC.ContainsUnknown);
    IO.mapRequired("ExceptionTypeList", EC.ExceptionTypeList);
    IO.mapRequired("ExceptionSpecification", EC.ES);
    IO.mapRequired("IsInMainFile", EC.IsInMainFile);
  }
};

template <>
struct llvm::yaml::SequenceTraits<clang::exception_scan::ExceptionContext> {
  static size_t size(llvm::yaml::IO &IO,
                     clang::exception_scan::ExceptionContext &EC) {
    return EC.PFEI.size();
  }
  static clang::exception_scan::PerFunctionExceptionInfo &
  element(llvm::yaml::IO &IO, clang::exception_scan::ExceptionContext &EC,
          size_t Index) {
    return EC.PFEI[Index];
  }
};

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
  for (const auto &EI : EC.PFEI) {
    OS << EI.FunctionUSRName << '\n';
  }
}

void clang::exception_scan::reportFunctionDuplications(ExceptionContext &EC,
                                                       StringRef PathPrefix) {
  std::vector<std::string> Functions;
  std::multiset<std::string> FunctionOccurence;
  std::map<std::string, std::multiset<std::string>> FunctionOccurenceForFile;
  for (const auto &PFEI : EC.PFEI) {
    Functions.push_back(PFEI.FunctionUSRName);
    FunctionOccurence.insert(PFEI.FunctionUSRName);
    FunctionOccurenceForFile[PFEI.DefinedInFile].insert(PFEI.FunctionUSRName);
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
  for (const auto &PFEI : EC.PFEI) {
    if (PFEI.Behaviour ==
            clang::tidy::utils::ExceptionAnalyzer::State::NotThrowing &&
        PFEI.ES == EST_None) {
      FunctionList.append(PFEI.FunctionUSRName);
      FunctionList.append(" in ");
      FunctionList.append(PFEI.DefinedInFile);
      FunctionList.append(" first declared in ");
      FunctionList.append(PFEI.FirstDeclaredInFile);
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
  for (const auto &PFEI : EC.PFEI) {
    if (PFEI.Behaviour ==
        clang::tidy::utils::ExceptionAnalyzer::State::Unknown) {
      FunctionList.append(PFEI.FunctionUSRName);
      FunctionList.append(" in ");
      FunctionList.append(PFEI.DefinedInFile);
      FunctionList.append(" first declared in ");
      FunctionList.append(PFEI.FirstDeclaredInFile);
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
