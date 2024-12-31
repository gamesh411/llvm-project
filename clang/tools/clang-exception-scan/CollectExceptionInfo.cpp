#include "CollectExceptionInfo.h"
#include "clang/Analysis/CFG.h"
#include "clang/CrossTU/CrossTranslationUnit.h"
#include "clang/Frontend/CompilerInstance.h"

using namespace clang;
using namespace clang::ast_matchers;
using namespace clang::exception_scan;

std::optional<bool> exception_scan::isInside(const Stmt *Candidate, const Stmt *Container) {
  SourceRange CandidateRange = Candidate->getSourceRange();
  SourceRange ContainerRange = Container->getSourceRange();

  if (CandidateRange.isInvalid() || ContainerRange.isInvalid())
    return std::nullopt;

  return ContainerRange.fullyContains(CandidateRange);
}

CalledFunctions::CalledFunctions(ExceptionInfo &EI, SourceManager &SM)
    : ExceptionInfoConsumer(EI, SM) {}

void CalledFunctions::run(const MatchFinder::MatchResult &Result) {
  const Expr *Expr = nullptr;
  const FunctionDecl *Callee = nullptr;

  if (const CallExpr *Call = Result.Nodes.getNodeAs<CallExpr>("invocation")) {
    Expr = Call;
    Callee = Call->getDirectCallee();
  } else if (const CXXConstructExpr *CTOR =
                 Result.Nodes.getNodeAs<CXXConstructExpr>("invocation")) {
    Expr = CTOR;
    Callee = CTOR->getConstructor();
  }

  if (!Expr || !Callee) {
    return;
  }

  std::string Name =
      cross_tu::CrossTranslationUnitContext::getLookupName(Callee).value_or(
          "<no-lookup-name>");
  EI.Calls.push_back(
      {Expr, Callee, Name, Expr->getSourceRange().printToString(SM)});
}

ThrownExceptions::ThrownExceptions(ExceptionInfo &EI, SourceManager &SM)
    : ExceptionInfoConsumer(EI, SM) {}

void ThrownExceptions::run(const MatchFinder::MatchResult &Result) {
  if (const CXXThrowExpr *Throw =
          Result.Nodes.getNodeAs<CXXThrowExpr>("throw")) {
    bool IsRethrow = Throw->getSubExpr() == nullptr;
    std::string Description;
    if (IsRethrow)
      Description = "rethrow";
    else {
      const QualType CT = Throw->getSubExpr()->getType();
      if (CT.isNull()) {
        Description = "nulltype";
      } else {
        Description = CT.getAsString();
      }
    }
    EI.Throws.push_back(
        {Throw, Description, Throw->getSourceRange().printToString(SM), IsRethrow});
  }
}

CaughtExceptions::CaughtExceptions(ExceptionInfo &EI, SourceManager &SM)
    : ExceptionInfoConsumer(EI, SM) {}

void CaughtExceptions::run(const MatchFinder::MatchResult &Result) {
  if (const CXXCatchStmt *Catch =
          Result.Nodes.getNodeAs<CXXCatchStmt>("catch")) {
    bool IsCatchAll = Catch->getExceptionDecl() == nullptr;
    std::string Description;
    if (IsCatchAll)
      Description = "...";
    else {
      const QualType CT = Catch->getExceptionDecl()->getType();
      if (CT.isNull()) {
        Description = "nulltype";
      } else {
        Description = CT.getAsString();
      }
    }
    EI.Catches.push_back(
        {Catch, Description, Catch->getSourceRange().printToString(SM), IsCatchAll});
  }
}

TryBlocks::TryBlocks(ExceptionInfo &EI, SourceManager &SM)
    : ExceptionInfoConsumer(EI, SM) {}

void TryBlocks::run(const MatchFinder::MatchResult &Result) {
  if (const CXXTryStmt *Try = Result.Nodes.getNodeAs<CXXTryStmt>("try")) {
    EI.Tries.push_back({Try, Try->getSourceRange().printToString(SM)});
  }
}

ExceptionInfoASTConsumer::ExceptionInfoASTConsumer(ASTContext &Context,
                                                 ExceptionContext &EC)
    : AC(Context), SM(Context.getSourceManager()), EC(EC) {}

void ExceptionInfoASTConsumer::HandleTranslationUnit(ASTContext &Context) {
  handleDecl(Context.getTranslationUnitDecl());
}

void ExceptionInfoASTConsumer::handleFunction(const FunctionDecl *FD) {
  EC.FunctionsVisited.insert(FD);

  std::optional<std::string> LookupName =
      cross_tu::CrossTranslationUnitContext::getLookupName(FD);
  std::string CallerName = LookupName.value_or("<no-name>");
  EC.NameIndex[FD] = CallerName;
  EC.ShortNameIndex[FD] = FD->getNameAsString();
  Stmt *Body = FD->getBody();
  if (!Body)
    return;

  auto BO = CFG::BuildOptions{};
  BO.AddEHEdges = true;

  std::unique_ptr<CFG> FDCFG = CFG::buildCFG(FD, Body, &AC, BO);

  if (!FDCFG) {
    return;
  }

  EC.BodyIndex[FD] = Body;
  EC.IsInMainFileIndex[FD] = SM.isInMainFile(FD->getLocation());

  MatchFinder MF;
  ExceptionInfo EI;
  auto CallAction = std::make_unique<CalledFunctions>(EI, SM);
  auto ThrowAction = std::make_unique<ThrownExceptions>(EI, SM);
  auto CatchAction = std::make_unique<CaughtExceptions>(EI, SM);
  auto TryAction = std::make_unique<TryBlocks>(EI, SM);
  MF.addMatcher(stmt().bind("invocation"), CallAction.get());
  MF.addMatcher(cxxThrowExpr().bind("throw"), ThrowAction.get());
  MF.addMatcher(cxxCatchStmt().bind("catch"), CatchAction.get());
  MF.addMatcher(cxxTryStmt().bind("try"), TryAction.get());
  MF.match(*Body, AC);

  EC.ExInfoIndex[FD] = EI;

  for (const CallInfo &CI : EI.Calls) {
    const FunctionDecl *Callee = CI.Callee;
    auto [_, emplaced] = SeenFunctions.insert(Callee);
    if (emplaced) {
      ExplorationWorklist.push(Callee);
    }
  }
}

void ExceptionInfoASTConsumer::handleDecl(const Decl *D) {
  if (!D)
    return;

  if (const auto *FD = dyn_cast<FunctionDecl>(D)) {
    handleFunction(FD);
  }

  if (const DeclContext *DC = dyn_cast<DeclContext>(D)) {
    for (const Decl *SubDecl : DC->decls()) {
      handleDecl(SubDecl);
    }
  }

  while (!ExplorationWorklist.empty()) {
    const FunctionDecl *FD = ExplorationWorklist.front();
    handleFunction(FD);
    ExplorationWorklist.pop();
  }
}

CollectExceptionInfoAction::CollectExceptionInfoAction(ExceptionContext &Index)
    : Index(Index) {}

std::unique_ptr<ASTConsumer>
CollectExceptionInfoAction::CreateASTConsumer(CompilerInstance &CI,
                                            StringRef) {
  return std::make_unique<ExceptionInfoASTConsumer>(CI.getASTContext(), Index);
}

std::unique_ptr<FrontendAction>
CollectExceptionInfoActionFactory::create() {
  return std::make_unique<CollectExceptionInfoAction>(EC);
}