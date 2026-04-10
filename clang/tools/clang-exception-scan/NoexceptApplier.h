#ifndef LLVM_CLANG_TOOLS_CLANG_EXCEPTION_SCAN_NOEXCEPT_APPLIER_H
#define LLVM_CLANG_TOOLS_CLANG_EXCEPTION_SCAN_NOEXCEPT_APPLIER_H

#include "GlobalExceptionInfo.h"
#include "clang/Rewrite/Core/Rewriter.h"
#include "clang/Tooling/Tooling.h"
#include "llvm/ADT/StringRef.h"

namespace clang {
namespace exception_scan {

/// Options controlling which functions get noexcept applied.
struct NoexceptApplierOptions {
  /// If non-empty, only modify files whose absolute path starts with this.
  std::string AllowedPathPrefix;
  /// If true, also apply noexcept to functions in system headers.
  bool IncludeSystemHeaders = false;
};

/// FrontendAction that applies noexcept to functions identified as NotThrowing
/// with no existing exception specification.
/// Collects rewritten file contents keyed by their original path.
class NoexceptApplierAction : public clang::ASTFrontendAction {
public:
  NoexceptApplierAction(const GlobalExceptionInfo &GEI,
                        llvm::StringMap<std::string> &RewrittenFiles,
                        const NoexceptApplierOptions &Opts);

  std::unique_ptr<ASTConsumer> CreateASTConsumer(CompilerInstance &CI,
                                                 StringRef InFile) override;

private:
  const GlobalExceptionInfo &GEI_;
  llvm::StringMap<std::string> &RewrittenFiles_;
  NoexceptApplierOptions Opts_;
};

class NoexceptApplierActionFactory
    : public clang::tooling::FrontendActionFactory {
public:
  NoexceptApplierActionFactory(const GlobalExceptionInfo &GEI,
                               llvm::StringMap<std::string> &RewrittenFiles,
                               const NoexceptApplierOptions &Opts);
  std::unique_ptr<clang::FrontendAction> create() override;

private:
  const GlobalExceptionInfo &GEI_;
  llvm::StringMap<std::string> &RewrittenFiles_;
  NoexceptApplierOptions Opts_;
};

/// Build an overlay VFS that shadows the real filesystem with the rewritten
/// file contents at their original paths.
llvm::IntrusiveRefCntPtr<llvm::vfs::FileSystem>
buildOverlayVFS(const llvm::StringMap<std::string> &RewrittenFiles);

/// Dump the AST of \p File to a string using the given compilation database
/// and VFS.
std::string dumpAST(const clang::tooling::CompilationDatabase &Compilations,
                    const std::string &File,
                    llvm::IntrusiveRefCntPtr<llvm::vfs::FileSystem> VFS);

/// Controls which normalization/filtering heuristics are applied when
/// producing the AST diff. Each flag can be toggled independently.
struct ASTDiffFilterOptions {
  bool NormalizeAddresses = true;  ///< Replace 0x... with ADDR
  bool NormalizeColumns = true;    ///< Replace col:N with col:?
  bool FilterTrivialNoexcept = true; ///< Drop lines where only change is
                                     ///< noexcept on FunctionDecl/CompoundStmt
  bool NormalizeFilePaths = true;  ///< Replace absolute paths with basenames
  bool FilterMisaligned = true;    ///< Drop pairs where neither side relates
                                   ///< to noexcept (structural misalignment)
};

/// Normalize a single AST dump line according to the filter options.
std::string normalizeASTLine(llvm::StringRef Line,
                             const ASTDiffFilterOptions &Opts);

/// Returns true if a diff line pair (removed, added) represents only a
/// trivial noexcept addition (the function decl itself gaining noexcept,
/// or a CompoundStmt column shift).
bool isTrivialNoexceptChange(llvm::StringRef Removed, llvm::StringRef Added);

/// A single call-site record: who calls what, and where.
struct CallSiteRecord {
  std::string CallerName;     ///< Qualified name of the calling function
  std::string CallerLoc;      ///< Source location of the caller definition
  std::string CalleeName;     ///< Qualified name of the callee
  std::string CalleeSig;      ///< Full type signature of the callee
  std::string CalleeLoc;      ///< Source location of the callee definition
  std::string CallLoc;        ///< Source location of the call expression

  /// Unique key for comparison (ignores noexcept in signature).
  std::string keyWithoutNoexcept() const;

  bool operator==(const CallSiteRecord &O) const {
    return CallerLoc == O.CallerLoc && CalleeLoc == O.CalleeLoc &&
           CallLoc == O.CallLoc && CalleeSig == O.CalleeSig;
  }
  bool operator<(const CallSiteRecord &O) const;
};

/// Collect all call-site records from a translation unit.
std::vector<CallSiteRecord>
collectCallSites(const clang::tooling::CompilationDatabase &Compilations,
                 const std::string &File,
                 llvm::IntrusiveRefCntPtr<llvm::vfs::FileSystem> VFS);

} // namespace exception_scan
} // namespace clang

#endif
