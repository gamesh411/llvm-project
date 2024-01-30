//===--- PthreadLockChecker.cpp - Check for locking problems ---*- C++ -*--===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
//
// This defines PthreadLockChecker, a simple lock -> unlock checker.
// Also handles XNU locks, which behave similarly enough to share code.
//
//===----------------------------------------------------------------------===//

#include "clang/StaticAnalyzer/Core/BugReporter/BugReporter.h"
#include "clang/StaticAnalyzer/Core/BugReporter/BugType.h"
#include "clang/StaticAnalyzer/Core/Checker.h"
#include "clang/StaticAnalyzer/Core/CheckerManager.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CheckerContext.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/ExprEngine.h"

#include <spot/tl/parse.hh>

#include <memory>

using namespace clang;
using namespace ento;

namespace {
class LTLFormulaChecker
    : public Checker<check::PreStmt<Expr>, check::PostStmt<Expr>> {
  std::unique_ptr<BugType> BT{new BugType(this, "LTLFormulaChecker")};

public:
  LTLFormulaChecker() {}
  void checkPreStmt(const Expr *E, CheckerContext &C) const;
  void checkPostStmt(const Expr *E, CheckerContext &C) const;
};
} // end anonymous namespace

void LTLFormulaChecker::checkPreStmt(const Expr *E, CheckerContext &C) const {}

void LTLFormulaChecker::checkPostStmt(const Expr *E, CheckerContext &C) const {
  E->dump();
  C.emitReport(std::make_unique<PathSensitiveBugReport>(
      *BT, "LTLFormulaChecker", C.getPredecessor()));
}

namespace clang::ento {
void registerLTLFormulaChecker(CheckerManager &mgr) {
  mgr.registerChecker<LTLFormulaChecker>();
}

bool shouldRegisterLTLFormulaChecker(const CheckerManager &) { return true; }
} // namespace clang::ento
