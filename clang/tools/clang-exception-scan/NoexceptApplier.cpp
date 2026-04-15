#include "NoexceptApplier.h"

#include "clang/AST/ASTConsumer.h"
#include "clang/AST/ASTContext.h"
#include "clang/AST/DeclCXX.h"
#include "clang/AST/RecursiveASTVisitor.h"
#include "clang/Basic/SourceManager.h"
#include "clang/Frontend/CompilerInstance.h"
#include "clang/Frontend/FrontendActions.h"
#include "clang/Index/USRGeneration.h"
#include "clang/Rewrite/Core/Rewriter.h"
#include "clang/Tooling/Tooling.h"
#include "llvm/Support/Path.h"
#include "llvm/Support/VirtualFileSystem.h"
#include "llvm/Support/raw_ostream.h"

#include <mutex>

using namespace clang;
using namespace clang::exception_scan;

namespace {

bool isUnderPrefix(llvm::StringRef Path, llvm::StringRef Prefix) {
  if (Prefix.empty())
    return true;
  if (!Path.starts_with(Prefix))
    return false;
  return Path.size() == Prefix.size() ||
         llvm::sys::path::is_separator(Path[Prefix.size()]);
}

llvm::SmallString<256> resolveFilePath(SourceLocation Loc,
                                       const SourceManager &SM) {
  if (Loc.isInvalid())
    return {};
  SourceLocation SpellingLoc = SM.getSpellingLoc(Loc);
  FileID FID = SM.getFileID(SpellingLoc);
  OptionalFileEntryRef Entry = SM.getFileEntryRefForID(FID);
  if (!Entry)
    return {};
  llvm::SmallString<256> RealPath(Entry->getName());
  llvm::sys::fs::make_absolute(RealPath);
  llvm::sys::path::remove_dots(RealPath, /*remove_dot_dot=*/true);
  return RealPath;
}

class NoexceptInsertVisitor
    : public RecursiveASTVisitor<NoexceptInsertVisitor> {
public:
  NoexceptInsertVisitor(ASTContext &Ctx, Rewriter &R,
                        const GlobalExceptionInfo &GEI,
                        const NoexceptApplierOptions &Opts)
      : Ctx_(Ctx), Rewrite_(R), GEI_(GEI), Opts_(Opts) {}

  bool VisitFunctionDecl(FunctionDecl *FD) {
    if (!FD->isThisDeclarationADefinition())
      return true;

    const SourceManager &SM = Ctx_.getSourceManager();

    if (!Opts_.IncludeSystemHeaders && SM.isInSystemHeader(FD->getLocation()))
      return true;

    if (!Opts_.AllowedPathPrefix.empty()) {
      llvm::SmallString<256> FilePath =
          resolveFilePath(FD->getLocation(), SM);
      if (FilePath.empty() || !isUnderPrefix(FilePath, Opts_.AllowedPathPrefix))
        return true;
    }

    SmallString<64> USRBuf;
    if (index::generateUSRForDecl(FD, USRBuf))
      return true;

    {
      std::lock_guard<std::mutex> Lock(GEI_.USRToExceptionMapMutex);
      auto It = GEI_.USRToExceptionMap.find(USRBuf);
      if (It == GEI_.USRToExceptionMap.end())
        return true;
      const auto &Info = It->getValue();
      if (Info.State != ExceptionState::NotThrowing ||
          Info.ExceptionSpecType != EST_None)
        return true;
    }

    const auto *FPT = FD->getType()->getAs<FunctionProtoType>();
    if (!FPT || FPT->getExceptionSpecType() != EST_None)
      return true;

    SourceLocation InsertLoc;
    if (const auto *Body = FD->getBody())
      InsertLoc = Body->getBeginLoc();
    if (InsertLoc.isInvalid() || InsertLoc.isMacroID())
      return true;

    std::string NoexceptStr = " noexcept ";
    {
      std::lock_guard<std::mutex> Lock(GEI_.USRToExceptionMapMutex);
      auto It = GEI_.USRToExceptionMap.find(USRBuf);
      if (It != GEI_.USRToExceptionMap.end()) {
        const auto &Info = It->getValue();
        if (!Info.NoexceptDependencies.empty()) {
          NoexceptStr = " noexcept( ";
          for (size_t i = 0; i < Info.NoexceptDependencies.size(); ++i) {
            if (i > 0)
              NoexceptStr += " && ";
            NoexceptStr += "noexcept(" +
                           std::string(Info.NoexceptDependencies[i].str()) +
                           ")";
          }
          NoexceptStr += ") ";
        }
      }
    }

    Rewrite_.InsertTextBefore(InsertLoc, NoexceptStr);
    return true;
  }

private:
  ASTContext &Ctx_;
  Rewriter &Rewrite_;
  const GlobalExceptionInfo &GEI_;
  const NoexceptApplierOptions &Opts_;
};

class NoexceptApplierConsumer : public ASTConsumer {
public:
  NoexceptApplierConsumer(const GlobalExceptionInfo &GEI,
                          llvm::StringMap<std::string> &RewrittenFiles,
                          std::mutex &OutputMutex,
                          const NoexceptApplierOptions &Opts)
      : GEI_(GEI), RewrittenFiles_(RewrittenFiles),
        OutputMutex_(OutputMutex), Opts_(Opts) {}

  void HandleTranslationUnit(ASTContext &Context) override {
    Rewriter Rewrite(Context.getSourceManager(), Context.getLangOpts());
    NoexceptInsertVisitor Visitor(Context, Rewrite, GEI_, Opts_);
    Visitor.TraverseDecl(Context.getTranslationUnitDecl());

    const SourceManager &SM = Context.getSourceManager();

    for (auto It = Rewrite.buffer_begin(); It != Rewrite.buffer_end(); ++It) {
      FileID FID = It->first;
      OptionalFileEntryRef Entry = SM.getFileEntryRefForID(FID);
      if (!Entry)
        continue;

      if (!Opts_.AllowedPathPrefix.empty()) {
        llvm::SmallString<256> AbsPath(Entry->getName());
        llvm::sys::fs::make_absolute(AbsPath);
        llvm::sys::path::remove_dots(AbsPath, /*remove_dot_dot=*/true);
        if (!isUnderPrefix(AbsPath, Opts_.AllowedPathPrefix))
          continue;
      }

      std::string Buf;
      llvm::raw_string_ostream OS(Buf);
      It->second.write(OS);

      std::lock_guard<std::mutex> Lock(OutputMutex_);
      RewrittenFiles_[Entry->getName()] = std::move(Buf);
    }
  }

private:
  const GlobalExceptionInfo &GEI_;
  llvm::StringMap<std::string> &RewrittenFiles_;
  std::mutex &OutputMutex_;
  NoexceptApplierOptions Opts_;
};

/// FrontendAction that dumps the AST to a string.
class ASTDumpToStringAction : public ASTFrontendAction {
public:
  ASTDumpToStringAction(std::string &Output) : Output_(Output) {}

  std::unique_ptr<ASTConsumer> CreateASTConsumer(CompilerInstance &CI,
                                                 StringRef InFile) override {
    class Consumer : public ASTConsumer {
    public:
      Consumer(std::string &Output) : Output_(Output) {}
      void HandleTranslationUnit(ASTContext &Ctx) override {
        llvm::raw_string_ostream OS(Output_);
        Ctx.getTranslationUnitDecl()->dump(OS);
      }

    private:
      std::string &Output_;
    };
    return std::make_unique<Consumer>(Output_);
  }

private:
  std::string &Output_;
};

} // namespace

// --- Action ---

NoexceptApplierAction::NoexceptApplierAction(
    const GlobalExceptionInfo &GEI,
    llvm::StringMap<std::string> &RewrittenFiles,
    const NoexceptApplierOptions &Opts)
    : GEI_(GEI), RewrittenFiles_(RewrittenFiles), Opts_(Opts) {}

std::unique_ptr<ASTConsumer>
NoexceptApplierAction::CreateASTConsumer(CompilerInstance &CI,
                                         StringRef InFile) {
  static std::mutex OutputMutex;
  return std::make_unique<NoexceptApplierConsumer>(GEI_, RewrittenFiles_,
                                                   OutputMutex, Opts_);
}

// --- Factory ---

NoexceptApplierActionFactory::NoexceptApplierActionFactory(
    const GlobalExceptionInfo &GEI,
    llvm::StringMap<std::string> &RewrittenFiles,
    const NoexceptApplierOptions &Opts)
    : GEI_(GEI), RewrittenFiles_(RewrittenFiles), Opts_(Opts) {}

std::unique_ptr<FrontendAction> NoexceptApplierActionFactory::create() {
  return std::make_unique<NoexceptApplierAction>(GEI_, RewrittenFiles_, Opts_);
}

// --- Overlay VFS ---

llvm::IntrusiveRefCntPtr<llvm::vfs::FileSystem>
clang::exception_scan::buildOverlayVFS(
    const llvm::StringMap<std::string> &RewrittenFiles) {
  auto InMemFS = llvm::makeIntrusiveRefCnt<llvm::vfs::InMemoryFileSystem>();
  for (const auto &[Path, Content] : RewrittenFiles) {
    llvm::SmallString<256> AbsPath(Path);
    llvm::sys::fs::make_absolute(AbsPath);
    InMemFS->addFile(AbsPath, /*ModificationTime=*/0,
                     llvm::MemoryBuffer::getMemBufferCopy(Content));
  }
  // Overlay: in-memory on top of real FS. Files in InMemFS shadow real files.
  auto Overlay = llvm::makeIntrusiveRefCnt<llvm::vfs::OverlayFileSystem>(
      llvm::vfs::createPhysicalFileSystem());
  Overlay->pushOverlay(std::move(InMemFS));
  return Overlay;
}

// --- AST Dump ---

std::string clang::exception_scan::dumpAST(
    const clang::tooling::CompilationDatabase &Compilations,
    const std::string &File,
    llvm::IntrusiveRefCntPtr<llvm::vfs::FileSystem> VFS) {
  std::string Output;
  clang::tooling::ClangTool Tool(
      Compilations, {File}, std::make_shared<PCHContainerOperations>(), VFS);
  Tool.setPrintErrorMessage(false);

  // We need a custom factory since ASTDumpToStringAction takes a reference.
  class DumpFactory : public clang::tooling::FrontendActionFactory {
  public:
    DumpFactory(std::string &Out) : Out_(Out) {}
    std::unique_ptr<FrontendAction> create() override {
      return std::make_unique<ASTDumpToStringAction>(Out_);
    }

  private:
    std::string &Out_;
  };

  DumpFactory Factory(Output);
  Tool.run(&Factory);
  return Output;
}

// --- AST Diff Filtering ---

std::string
clang::exception_scan::normalizeASTLine(llvm::StringRef Line,
                                        const ASTDiffFilterOptions &Opts) {
  std::string Result;
  Result.reserve(Line.size());

  size_t I = 0;
  while (I < Line.size()) {
    // Normalize pointer addresses: 0x[0-9a-fA-F]+ → ADDR
    if (Opts.NormalizeAddresses && I + 1 < Line.size() && Line[I] == '0' &&
        Line[I + 1] == 'x') {
      size_t Start = I;
      I += 2;
      while (I < Line.size() && std::isxdigit(Line[I]))
        ++I;
      if (I > Start + 2) {
        Result += "ADDR";
        continue;
      }
      // Not a real address, emit as-is.
      Result.append(Line.data() + Start, I - Start);
      continue;
    }

    // Normalize column numbers: col:N → col:?
    if (Opts.NormalizeColumns && I + 3 < Line.size() &&
        Line.substr(I).starts_with("col:")) {
      Result += "col:?";
      I += 4;
      while (I < Line.size() && std::isdigit(Line[I]))
        ++I;
      continue;
    }

    // Normalize line numbers: line:N → line:?
    if (Opts.NormalizeColumns && I + 5 < Line.size() &&
        Line.substr(I).starts_with("line:")) {
      Result += "line:?";
      I += 5;
      while (I < Line.size() && std::isdigit(Line[I]))
        ++I;
      continue;
    }

    // Normalize file paths: </path/to/file.cpp: → <file.cpp:
    if (Opts.NormalizeFilePaths && Line[I] == '<' && I + 1 < Line.size() &&
        Line[I + 1] == '/') {
      // Find the closing > or , or space
      size_t End = I + 1;
      size_t LastSlash = I;
      while (End < Line.size() && Line[End] != '>' && Line[End] != ',' &&
             Line[End] != ' ') {
        if (Line[End] == '/')
          LastSlash = End;
        ++End;
      }
      if (LastSlash > I) {
        Result += '<';
        Result.append(Line.data() + LastSlash + 1, End - LastSlash - 1);
        I = End;
        continue;
      }
    }

    Result += Line[I++];
  }

  return Result;
}

bool clang::exception_scan::isTrivialNoexceptChange(llvm::StringRef Removed,
                                                     llvm::StringRef Added) {
  // Strip the leading -/+ if present.
  if (Removed.starts_with("-"))
    Removed = Removed.drop_front(1);
  if (Added.starts_with("+"))
    Added = Added.drop_front(1);

  // Only consider changes trivial on declaration/body nodes — these are the
  // direct result of inserting noexcept on the function we modified.
  // Changes on TemplateArgument, DeclRefExpr, ImplicitCastExpr, ParmVarDecl,
  // FunctionProtoType etc. represent downstream effects and are meaningful.
  bool IsDeclNode = false;
  static const llvm::StringRef TrivialNodeTypes[] = {
      "FunctionDecl",       "CXXMethodDecl", "CXXConstructorDecl",
      "CXXDestructorDecl",  "CompoundStmt",
  };
  for (const auto &NT : TrivialNodeTypes) {
    if (Added.contains(NT)) {
      IsDeclNode = true;
      break;
    }
  }
  if (!IsDeclNode)
    return false;

  // On a decl/body node, check if removing noexcept makes the lines equal.
  std::string StrippedAdded = Added.str();
  for (;;) {
    size_t Pos = StrippedAdded.find(" noexcept");
    if (Pos == std::string::npos)
      break;
    StrippedAdded.erase(Pos, 9);
  }
  for (;;) {
    size_t Pos = StrippedAdded.find(" exceptionspec_basic_noexcept");
    if (Pos == std::string::npos)
      break;
    StrippedAdded.erase(Pos, 29);
  }

  return Removed.str() == StrippedAdded;
}

// --- CallSiteRecord ---

std::string CallSiteRecord::keyWithoutNoexcept() const {
  std::string Sig = CalleeSig;
  for (;;) {
    size_t Pos = Sig.find(" noexcept");
    if (Pos == std::string::npos)
      break;
    Sig.erase(Pos, 9);
  }
  return CallerLoc + " -> " + CalleeName + " " + Sig + " @ " + CalleeLoc;
}

bool CallSiteRecord::operator<(const CallSiteRecord &O) const {
  if (CallLoc != O.CallLoc)
    return CallLoc < O.CallLoc;
  return CalleeSig < O.CalleeSig;
}

// --- Call-site collector ---

namespace {

class CallSiteCollectorVisitor
    : public RecursiveASTVisitor<CallSiteCollectorVisitor> {
public:
  CallSiteCollectorVisitor(ASTContext &Ctx,
                           std::vector<CallSiteRecord> &Records)
      : SM_(Ctx.getSourceManager()), Records_(Records) {}

  bool VisitCallExpr(CallExpr *CE) {
    const FunctionDecl *Callee = CE->getDirectCallee();
    if (!Callee)
      return true;
    addRecord(CE->getBeginLoc(), Callee);
    return true;
  }

  bool VisitCXXConstructExpr(CXXConstructExpr *CE) {
    const CXXConstructorDecl *Ctor = CE->getConstructor();
    if (!Ctor)
      return true;
    addRecord(CE->getBeginLoc(), Ctor);
    return true;
  }

private:
  void addRecord(SourceLocation CallLoc, const FunctionDecl *Callee) {
    if (CallLoc.isInvalid())
      return;

    // Find the enclosing function (caller).
    const FunctionDecl *Caller = findEnclosingFunction(CallLoc);

    CallSiteRecord R;
    R.CallerName = Caller ? Caller->getQualifiedNameAsString() : "<global>";
    R.CallerLoc = Caller ? locStr(Caller->getLocation()) : "<unknown>";
    R.CalleeName = Callee->getQualifiedNameAsString();
    R.CalleeSig = Callee->getType().getAsString();
    R.CalleeLoc = locStr(Callee->getLocation());
    R.CallLoc = locStr(CallLoc);
    Records_.push_back(std::move(R));
  }

  std::string locStr(SourceLocation Loc) const {
    if (Loc.isInvalid())
      return "<invalid>";
    SourceLocation Spelling = SM_.getSpellingLoc(Loc);
    PresumedLoc PLoc = SM_.getPresumedLoc(Spelling);
    if (PLoc.isInvalid())
      return "<invalid>";
    std::string Result;
    llvm::raw_string_ostream OS(Result);
    llvm::StringRef File = PLoc.getFilename();
    // Use basename only for brevity.
    OS << llvm::sys::path::filename(File) << ":" << PLoc.getLine() << ":"
       << PLoc.getColumn();
    return Result;
  }

  const FunctionDecl *findEnclosingFunction(SourceLocation Loc) const {
    // We track the current function during traversal instead.
    return CurrentFunction_;
  }

public:
  // Track current function during traversal.
  bool TraverseFunctionDecl(FunctionDecl *FD) {
    const FunctionDecl *Prev = CurrentFunction_;
    CurrentFunction_ = FD;
    bool Ret = RecursiveASTVisitor::TraverseFunctionDecl(FD);
    CurrentFunction_ = Prev;
    return Ret;
  }
  bool TraverseCXXMethodDecl(CXXMethodDecl *MD) {
    const FunctionDecl *Prev = CurrentFunction_;
    CurrentFunction_ = MD;
    bool Ret = RecursiveASTVisitor::TraverseCXXMethodDecl(MD);
    CurrentFunction_ = Prev;
    return Ret;
  }
  bool TraverseCXXConstructorDecl(CXXConstructorDecl *CD) {
    const FunctionDecl *Prev = CurrentFunction_;
    CurrentFunction_ = CD;
    bool Ret = RecursiveASTVisitor::TraverseCXXConstructorDecl(CD);
    CurrentFunction_ = Prev;
    return Ret;
  }
  bool TraverseCXXDestructorDecl(CXXDestructorDecl *DD) {
    const FunctionDecl *Prev = CurrentFunction_;
    CurrentFunction_ = DD;
    bool Ret = RecursiveASTVisitor::TraverseCXXDestructorDecl(DD);
    CurrentFunction_ = Prev;
    return Ret;
  }

private:
  const SourceManager &SM_;
  std::vector<CallSiteRecord> &Records_;
  const FunctionDecl *CurrentFunction_ = nullptr;
};

class CallSiteCollectorAction : public ASTFrontendAction {
public:
  CallSiteCollectorAction(std::vector<CallSiteRecord> &Records)
      : Records_(Records) {}

  std::unique_ptr<ASTConsumer> CreateASTConsumer(CompilerInstance &CI,
                                                 StringRef InFile) override {
    class Consumer : public ASTConsumer {
    public:
      Consumer(std::vector<CallSiteRecord> &Records) : Records_(Records) {}
      void HandleTranslationUnit(ASTContext &Ctx) override {
        CallSiteCollectorVisitor V(Ctx, Records_);
        V.TraverseDecl(Ctx.getTranslationUnitDecl());
      }

    private:
      std::vector<CallSiteRecord> &Records_;
    };
    return std::make_unique<Consumer>(Records_);
  }

private:
  std::vector<CallSiteRecord> &Records_;
};

} // namespace

std::vector<CallSiteRecord> clang::exception_scan::collectCallSites(
    const clang::tooling::CompilationDatabase &Compilations,
    const std::string &File,
    llvm::IntrusiveRefCntPtr<llvm::vfs::FileSystem> VFS) {
  std::vector<CallSiteRecord> Records;
  clang::tooling::ClangTool Tool(
      Compilations, {File}, std::make_shared<PCHContainerOperations>(), VFS);
  Tool.setPrintErrorMessage(false);

  class Factory : public clang::tooling::FrontendActionFactory {
  public:
    Factory(std::vector<CallSiteRecord> &R) : R_(R) {}
    std::unique_ptr<FrontendAction> create() override {
      return std::make_unique<CallSiteCollectorAction>(R_);
    }

  private:
    std::vector<CallSiteRecord> &R_;
  };

  Factory F(Records);
  Tool.run(&F);
  std::sort(Records.begin(), Records.end());
  return Records;
}
