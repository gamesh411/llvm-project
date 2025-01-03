#include "CollectExceptionInfo.h"
#include "clang/AST/ASTDumper.h"
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

void clang::exception_scan::ExceptionInfoExtractor::HandleTranslationUnit(
    ASTContext &Context) {
  for (const Decl *TopLevelDecl : Context.getTranslationUnitDecl()->decls()) {
    if (auto *FD = dyn_cast<FunctionDecl>(TopLevelDecl)) {
      std::optional<std::string> LookupName =
          cross_tu::CrossTranslationUnitContext::getLookupName(FD);
      if (not LookupName)
        continue;
      ExceptionAnalyzer FA;
      EC.PFEI.push_back({EC.CurrentInfile, *LookupName, FA.analyze(FD),
                         FD->getExceptionSpecType(),
                         SM.isInMainFile(FD->getLocation())});
    }
  }
}

using llvm::yaml::IO;
using llvm::yaml::MappingTraits;
using llvm::yaml::ScalarEnumerationTraits;
using llvm::yaml::ScalarTraits;
using llvm::yaml::SequenceTraits;

template <> struct ScalarEnumerationTraits<ExceptionState> {
  static void enumeration(IO &IO, ExceptionState &ES) {
    IO.enumCase(ES, "Throwing", ExceptionState::Throwing);
    IO.enumCase(ES, "NotThrowing", ExceptionState::NotThrowing);
    IO.enumCase(ES, "Unknown", ExceptionState::Unknown);
  }
};

using TypePtr = const clang::Type *;
template <> struct ScalarTraits<TypePtr> {

  // Function to write the value as a string:
  static void output(const TypePtr &value, void *ctxt, llvm::raw_ostream &out) {
    std::string Name;
    llvm::raw_string_ostream SS(Name);
    clang::ASTDumper Dumper(SS, false);
    Dumper.Visit(value);
    out << Name;
  }
  // Function to convert a string to a value.  Returns the empty
  // StringRef on success or an error string if string is malformed:
  static StringRef input(StringRef scalar, void *ctxt, TypePtr &value) {
    value = nullptr;
    return StringRef();
  }
  // Function to determine if the value should be quoted.
  static QuotingType mustQuote(StringRef) { return QuotingType::None; }
};

using ExceptionTypesContainer = llvm::SmallVector<TypePtr, 2>;
template <> struct SequenceTraits<ExceptionTypesContainer> {
  static size_t size(IO &IO, ExceptionTypesContainer &Throwables) {
    return Throwables.size();
  }
  static TypePtr &element(IO &IO, ExceptionTypesContainer &Throwables,
                          size_t Index) {
    return Throwables[Index];
  }
};

template <> struct ScalarEnumerationTraits<clang::ExceptionSpecificationType> {
  static void enumeration(IO &IO, clang::ExceptionSpecificationType &ES) {
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
struct MappingTraits<clang::exception_scan::PerFunctionExceptionInfo> {
  static void mapping(IO &IO,
                      clang::exception_scan::PerFunctionExceptionInfo &EC) {
    IO.mapRequired("Name", EC.FunctionUSRName);
    IO.mapRequired("Behaviour", EC.AI.Behaviour);
    IO.mapRequired("Exceptions", EC.AI.ThrownExceptions);
    IO.mapRequired("ExceptionSpecification", EC.ES);
    IO.mapRequired("IsInMainFile", EC.IsInMainFile);
  }
};

template <> struct SequenceTraits<clang::exception_scan::ExceptionContext> {
  static size_t size(IO &IO, clang::exception_scan::ExceptionContext &EC) {
    return EC.PFEI.size();
  }
  static clang::exception_scan::PerFunctionExceptionInfo &
  element(IO &IO, clang::exception_scan::ExceptionContext &EC, size_t Index) {
    return EC.PFEI[Index];
  }
};

void clang::exception_scan::reportFirstApproximation(ExceptionContext &EC,
                                                     StringRef PathPrefix) {
  SmallString<256> ReportPath(PathPrefix);
  llvm::sys::path::append(ReportPath, "report.txt");

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
    if (PFEI.AI.Behaviour ==
            clang::tidy::utils::ExceptionAnalyzer::State::NotThrowing &&
        PFEI.ES == EST_None) {
      FunctionList.append(PFEI.FunctionUSRName);
      FunctionList.append(" in ");
      FunctionList.append(PFEI.FileName);
      FunctionList.append("\n");
    }
  }
  OS << FunctionList;
}

void clang::exception_scan::serializeExceptionInfo(ExceptionContext &EC,
                                                   StringRef PathPrefix) {
  // open a file
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
